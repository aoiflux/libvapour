# S73: Minidump writer and validator; region, coverage and PE-header reads

Version 1, 2026-11-12.

## 1. Purpose

An examiner who finds a process in a memory capture wants it as a user-mode minidump: a file that the Windows debugging tools open, with the process's threads, modules, handles, memory map and memory bytes. `windows.process.dump` gathers those facts; this specification turns them into a minidump (`minidump.Write`) and states the rules a written dump must meet (`minidump.Validate`).

It also specifies the region readers in `extract` that every artefact writer shares: reading an address range with unread pages zero-filled and recorded (`ReadPadded`, `GapMap`), copying a range to a file under a size cap (`Region`), recording which file offsets a set of pieces covers (`Coverage`), and reading a loaded image's PE headers so that an unread page is never mistaken for zeroed headers (`ReadHeaders`).

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| `minidump.Input.System` | `SystemInfo` | Processor architecture, level, revision, processor count, product type, OS version, build, platform, suite mask, service-pack text. |
| `Input.Modules` | `[]Module` | Base, size, path, `TimeDateStamp` and `CheckSum` from the image headers. |
| `Input.Threads` | `[]Thread` | Thread id, suspend count, priorities, TEB, stack (low end and size), CONTEXT bytes, affinity, start address, times, exit status, dump error. |
| `Input.Handles` | `[]Handle` | Handle value, type and object names, attributes, granted access, counts. |
| `Input.Regions` | `[]Region` | One entry per address range: base, allocation base, size, protection, allocation protection, state, type, and whether its bytes are to be written (`Dumpable`). |
| `Input.ReadMemory` | `ReadFunc` | Returns the bytes of an address range and the absolute gaps in it, as `extract.ReadPadded` does. |
| `Input.TimeDateStamp` | `uint32` | The header time stamp (`time_t`); 0 when unknown. |
| `extract.Region` | reader, start, end, writer, `Options` | `end` is the last byte of the range. `Options.MaxSize` caps the size; 0 means `Limits.MaxArtifactBytes`; `Unlimited` removes the cap. |
| `extract.ReadHeaders` | reader, base | The image base in the reader's address space. |

## 3. Facts from the sources

Microsoft Learn pages under learn.microsoft.com/windows/win32/api/minidumpapiset/, each dated 2018-12-05, accessed 2026-11-12.

| # | Fact |
|---|---|
| F1 | `MINIDUMP_HEADER`: `Signature`, `Version`, `NumberOfStreams`, `StreamDirectoryRva` (RVA), `CheckSum`, `TimeDateStamp` (ULONG32 each), `Flags` (ULONG64): 32 bytes. "The low-order word is MINIDUMP_VERSION. The high-order word is an internal value that is implementation specific." `CheckSum` "can be zero". `Flags` holds `MINIDUMP_TYPE` values. The page names `MINIDUMP_SIGNATURE` and `MINIDUMP_VERSION` but gives no values (M1). |
| F2 | `MINIDUMP_DIRECTORY`: `StreamType` (ULONG32) and a `MINIDUMP_LOCATION_DESCRIPTOR` (`DataSize`, `Rva`, ULONG32 each), 12 bytes. The RVA "is the byte offset of the data stream from the beginning of the minidump file". 32-bit locations cover the first 4 GB. |
| F3 | `MINIDUMP_STREAM_TYPE`: `UnusedStream` 0, `ThreadListStream` 3, `ModuleListStream` 4, `MemoryListStream` 5, `ExceptionStream` 6, `SystemInfoStream` 7, `Memory64ListStream` 9, `HandleDataStream` 12, `UnloadedModuleListStream` 14, `MiscInfoStream` 15, `MemoryInfoListStream` 16, `ThreadInfoListStream` 17. "If a program reading the minidump header encounters a stream type it does not recognize, it should ignore the stream altogether." |
| F4 | `MINIDUMP_STRING`: `Length` (ULONG32), "the size of the string in the Buffer member, in bytes. This size does not include the null-terminating character", then the WCHAR buffer, "the null-terminated string". |
| F5 | `MINIDUMP_SYSTEM_INFO`: `ProcessorArchitecture`, `ProcessorLevel`, `ProcessorRevision` (USHORT), `NumberOfProcessors` and `ProductType` (UCHAR), `MajorVersion`, `MinorVersion`, `BuildNumber`, `PlatformId` (ULONG32), `CSDVersionRva` (RVA to a `MINIDUMP_STRING`; "If no Service Pack has been installed, the string is empty"), `SuiteMask` and `Reserved2` (USHORT), `Cpu` (`CPU_INFORMATION`): 56 bytes (M1). `PROCESSOR_ARCHITECTURE_AMD64` 9, `_ARM` 5, `_IA64` 6, `_INTEL` 0, `_UNKNOWN` 0xFFFF; `PlatformId` 2 is `VER_PLATFORM_WIN32_NT`. The `SYSTEM_INFO` page (sysinfoapi.h) adds `PROCESSOR_ARCHITECTURE_ARM64` 12. |
| F6 | `MINIDUMP_MODULE_LIST`: `NumberOfModules` (ULONG32) then the array. `MINIDUMP_MODULE`: `BaseOfImage` (ULONG64), `SizeOfImage`, `CheckSum`, `TimeDateStamp` (ULONG32), `ModuleNameRva` (RVA to a `MINIDUMP_STRING`), `VersionInfo` (`VS_FIXEDFILEINFO`, 13 DWORDs, 52 bytes, signature 0xFEEF04BD per the verrsrc.h page), `CvRecord`, `MiscRecord` (location descriptors), `Reserved0`, `Reserved1` (ULONG64): 108 bytes, with no padding before `Reserved0` (M1). |
| F7 | `MINIDUMP_THREAD_LIST`: `NumberOfThreads` (ULONG32) then the array. `MINIDUMP_THREAD`: `ThreadId`, `SuspendCount`, `PriorityClass`, `Priority` (ULONG32), `Teb` (ULONG64), `Stack` (`MINIDUMP_MEMORY_DESCRIPTOR`: `StartOfMemoryRange` ULONG64 and a location descriptor), `ThreadContext` (location descriptor): 48 bytes. |
| F8 | `MINIDUMP_THREAD_INFO_LIST`: `SizeOfHeader`, `SizeOfEntry`, `NumberOfEntries` (ULONG), "generally" `sizeof` the list and of `MINIDUMP_THREAD_INFO`; the entries follow the header. `MINIDUMP_THREAD_INFO`: `ThreadId`, `DumpFlags`, `DumpError`, `ExitStatus` (ULONG32), `CreateTime`, `ExitTime`, `KernelTime`, `UserTime`, `StartAddress`, `Affinity` (ULONG64): 64 bytes. `DumpFlags`: `MINIDUMP_THREAD_INFO_ERROR_THREAD` 0x1 ("A placeholder thread due to an error accessing the thread. No thread information exists beyond the thread identifier."), `MINIDUMP_THREAD_INFO_EXITED_THREAD` 0x4 ("has exited"), `_INVALID_CONTEXT` 0x10 ("could not be retrieved"), `_INVALID_TEB` 0x20. Times are FILETIME units. |
| F9 | `MINIDUMP_HANDLE_DATA_STREAM`: `SizeOfHeader`, `SizeOfDescriptor`, `NumberOfDescriptors`, `Reserved` (ULONG32; "must be zero"): 16 bytes. `SizeOfDescriptor` "is sizeof(MINIDUMP_HANDLE_DESCRIPTOR) or sizeof(MINIDUMP_HANDLE_DESCRIPTOR_2)". `MINIDUMP_HANDLE_DESCRIPTOR`: `Handle` (ULONG64), `TypeNameRva`, `ObjectNameRva` (RVA; "can be zero"), `Attributes`, `GrantedAccess`, `HandleCount`, `PointerCount` (ULONG32): 32 bytes. `_2` adds `ObjectInfoRva` and `Reserved0`: 40 bytes. |
| F10 | `MINIDUMP_MEMORY_INFO_LIST`: `SizeOfHeader`, `SizeOfEntry` (ULONG), `NumberOfEntries` (ULONG64): 16 bytes; "generally" `sizeof` the structures. `MINIDUMP_MEMORY_INFO`: `BaseAddress`, `AllocationBase` (ULONG64), `AllocationProtect`, alignment (ULONG32), `RegionSize` (ULONG64), `State`, `Protect`, `Type`, alignment (ULONG32): 48 bytes. `State`: `MEM_COMMIT` 0x1000, `MEM_RESERVE` 0x2000 ("without any physical storage being allocated"), `MEM_FREE` 0x10000 ("not accessible"; for free pages `AllocationBase`, `AllocationProtect`, `Protect` and `Type` are undefined). `Type`: `MEM_IMAGE` 0x1000000, `MEM_MAPPED` 0x40000, `MEM_PRIVATE` 0x20000. |
| F11 | `MINIDUMP_MEMORY64_LIST`: `NumberOfMemoryRanges` (ULONG64), `BaseRva` (RVA64), then `MINIDUMP_MEMORY_DESCRIPTOR64` entries (`StartOfMemoryRange`, `DataSize`, ULONG64 each). "It is used for full-memory minidumps where all of the raw memory is sequential at the end of the minidump … the RVA is the base RVA plus the sum of the preceding data blocks." |
| F12 | `MINIDUMP_TYPE`: `MiniDumpWithFullMemory` 0x2 ("The raw memory data is included at the end"), `MiniDumpWithHandleData` 0x4, `MiniDumpWithFullMemoryInfo` 0x800 ("Include memory region information. For more information, see MINIDUMP_MEMORY_INFO_LIST"), `MiniDumpWithThreadInfo` 0x1000 ("Include thread state information … MINIDUMP_THREAD_INFO_LIST"). |

CONTEXT and the processor, accessed 2026-11-12:

| # | Fact |
|---|---|
| C1 | Microsoft Learn, "CONTEXT structure (x86 64-bit)" (winnt.h), dated 2018-12-05: members in order `P1Home`…`P6Home` (DWORD64), `ContextFlags`, `MxCsr` (DWORD), `SegCs`, `SegDs`, `SegEs`, `SegFs`, `SegGs`, `SegSs` (WORD), `EFlags` (DWORD), `Dr0`…`Dr3`, `Dr6`, `Dr7`, `Rax`, `Rcx`, `Rdx`, `Rbx`, `Rsp`, `Rbp`, `Rsi`, `Rdi`, `R8`…`R15`, `Rip` (DWORD64), a union whose largest member is `XMM_SAVE_AREA32 FltSave`, `VectorRegister[26]` (M128A), `VectorControl`, `DebugControl`, `LastBranchToRip`, `LastBranchFromRip`, `LastExceptionToRip`, `LastExceptionFromRip` (DWORD64). The page states no flag values. |
| C2 | Intel SDM Vol. 2A, FXSAVE: the save area is 512 bytes. With C1 the structure is 0x30 + 4 + 4 + 12 + 4 + 48 + 136 + 512 + 416 + 48 = 1232 bytes; `ContextFlags` at 0x30, `MxCsr` 0x34, `SegCs` 0x38 … `SegSs` 0x42, `EFlags` 0x44, `Rax` 0x78 … `Rip` 0xF8, `FltSave` 0x100. |
| C3 | The `_CONTEXT` type in the ntoskrnl PDBs of all five Windows captures (builds 26100, 19045, 14393; M2) has these offsets and size 1232, `_XSAVE_FORMAT` 512 bytes and `_M128A` 16. |
| C4 | No listed source gives the `ContextFlags` values. The exported constants keep the existing values: architecture bit 0x00100000, control 0x1, integer 0x2, segments 0x4, floating point 0x8, debug registers 0x10. Every context in a dump written by Windows carries 0x0010001F, the architecture bit with all five group bits (M1). Open point O2. |
| I1 | Intel SDM Vol. 3A 4.5: the smallest page of 4-level and 5-level paging is 4 KB, so a translated read fails or succeeds in 4 KB units at the finest. |

Microsoft Learn, "PE Format", page dated 2026-09-10: `e_lfanew` (offset 0x3C) locates the PE signature; the COFF file header (20 bytes) holds `NumberOfSections` and `SizeOfOptionalHeader`; the section table (40 bytes per entry) follows the optional header. These sizes are all image bytes, so a hostile image can claim any span (P1).

### Measurements

All from `minidumpfacts`, run on 2026-11-12.

| # | Measured |
|---|---|
| M1 | `-dump` on `msedge_server2016.dmp`, a full-memory dump written by Windows on Server 2016 (14393), 629,890,032 bytes. Signature bytes `MDMP` (0x504D444D), version 0xA0F1A793 (low word 0xA793), 16 directory entries at 0x20 (5 `UnusedStream` with size 0 and two types the format page lists without a structure, 21 and 22), checksum 0, flags 0x21826. Entry sizes: thread 48 (57 threads), thread info header 12 entry 64, module 108 (111 modules, no remainder), system info 56, handle header 16 descriptor 40 (1,303), memory info header 16 entry 48 (3,212), Memory64 16 + 16 × 1,939. `BaseRva` 0x63BF0 equals the end of the Memory64 list; the memory data runs to the end of the file. All 57 contexts are 1232 bytes with `ContextFlags` 0x0010001F; all 57 stacks have a location. Stream RVAs are 4-aligned, not all 8-aligned. The validator of section 5 reports no problem. |
| M2 | `-types` on mem1_win11, mem2_win10, mem5_server2016, mem6_server2025, mem7_server2025: C3. |
| M3 | `-image` on the five Windows captures: every process dumped through `windows.process.dump` and read back with `ValidateReaderAt` (table in section 9). |
| M4 | `-headers` on the five Windows captures: `extract.ReadHeaders` on every kernel module (855) and every process library (24,765). Kernel: 841 decode, 14 unreadable. Libraries: 15,472 decode, 9,279 unreadable, 14 not an image. The largest header span (section table end) is 0x7D0 and the largest `SizeOfHeaders` 0x1000; no image needs the second read. |

## 4. Algorithm

### 4.1 Writing a minidump (`minidump.Write`)

1. **Check the input.** Copy the regions and sort them by base address. Refuse with:
   - `ErrModuleTooLarge` a module whose size does not fit `SizeOfImage` (F6);
   - `ErrRegionRange` a region of size 0 or one that passes 2^64 (F10, `RegionSize` > 0);
   - `ErrRegionOverlap` a region that starts inside the one before it (F10 describes disjoint regions);
   - `ErrRegionAttributes` a state other than commit, reserve or free, or a type other than image, mapped or private on a region that is not free (F10);
   - `ErrNoMemoryReader` a committed dumpable region with no `ReadMemory`.
   Nothing is written before these checks pass.
2. **Layout.** The file is built in this order, each stream on an 8-byte boundary so its ULONG64 members are naturally aligned (Windows itself aligns to 4, M1; any boundary is allowed by F2): header (F1), directory (F2), `SystemInfoStream`, `ModuleListStream`, `ThreadListStream`, `ThreadInfoListStream`, then `HandleDataStream` when there are handles, `MemoryInfoListStream` when there are regions, then strings and contexts, then `Memory64ListStream`, then the memory bytes. The first four are always written, an empty module list included, so a reader always finds the architecture and the module and thread lists.
3. **Strings.** Each name is UTF-16LE (the Unicode Standard, from Go's UTF-8, invalid bytes as U+FFFD) in a `MINIDUMP_STRING` with its byte length and a terminating NUL (F4), on a 4-byte boundary. Equal strings share one copy. `CSDVersionRva` always names a string, empty when there is no service pack (F5). A handle's empty type or object name is RVA 0 (F9).
4. **Streams.** `SystemInfo` per F5 with `Cpu` zero. Modules per F6 with `VersionInfo`, `CvRecord`, `MiscRecord` and the reserved members zero. Threads per F7: `Stack.StartOfMemoryRange` is the low end of the stack; the context bytes are copied as given, location 0 when there are none. A process with no thread gets one placeholder thread, id 0 and every member 0, whose thread info carries `MINIDUMP_THREAD_INFO_ERROR_THREAD` (F8): a dump without a thread does not open (D2). Thread info per F8; `DumpFlags` is derived: error thread for the placeholder, exited when `ExitTime` is nonzero, invalid context when no context was given, invalid TEB when the TEB address is 0. Handles use the 32-byte descriptor (F9). Memory info per F10, one entry per region in address order.
5. **Memory list.** Every region that is dumpable and committed becomes one Memory64 range in address order. Reserved and free regions have no storage (F10), so a dumpable flag on them is ignored. `BaseRva` is the end of the Memory64 list, and range *i* starts at `BaseRva` plus the sizes of ranges 0…*i*−1 (F11).
6. **Stack locations.** A thread's `Stack.Memory` names the stack bytes inside the memory data when the whole stack `[StackBase, StackBase+StackSize)` lies in written ranges that are contiguous in address (and so in the file, F11), its size fits 32 bits and the RVA plus size is at most 2^32 (F2). Otherwise the location is 0 and the descriptor carries the address alone.
7. **32-bit limit.** Everything up to the end of the Memory64 list is addressed by 32-bit RVAs (F2). If it would pass 2^32 bytes the write fails with `ErrTooLarge` before any byte is written. The memory data behind `BaseRva` may pass 4 GB (F11).
8. **Header.** `Signature`, `Version` = `VersionLow` with high word 0 (F1 leaves it to the implementation), the stream count, `StreamDirectoryRva` 32, `CheckSum` 0, `TimeDateStamp` from the input, and `Flags` = `MiniDumpWithFullMemory`, plus `MiniDumpWithThreadInfo` (the thread info list is always written), and `MiniDumpWithHandleData` and `MiniDumpWithFullMemoryInfo` for each of those streams written (F12). The full-memory flag is always set because a Memory64 list is always written (D1).
9. **Memory bytes.** Each range is read through `ReadMemory` in pieces of at most 1 MiB (a page multiple, I1, so the reader's per-page gaps are not split), and written in order. A reader that returns fewer bytes than asked has the rest zero-filled and recorded as a gap; more bytes are cut. Gaps outside the piece asked for are ignored. `Result.MemoryGaps` is the merged set of gaps, `Result.MemoryBytes` the bytes of the ranges less the gaps, `Result.Size` the file length.

### 4.2 Validating a minidump (`minidump.Validate`, `ValidateReaderAt`)

The header, the directory and every stream this package decodes are read and checked against section 5. The memory data is never read, so a file far larger than memory can be checked through `ValidateReaderAt`. Long arrays are read in 64 KiB blocks. Stream types this package does not decode are only located (F3). The result lists the directory (`Streams`), the file size and the problems found.

### 4.3 Reading a range (`extract.RegionSize`, `ReadPadded`, `Region`)

1. `RegionSize(start, end)` is `end − start + 1`: address-range listings give the last byte. It fails when `end < start` and when the range is all 2^64 bytes (the size does not fit).
2. `ReadPadded(r, addr, size)` returns `size` bytes. One read of the whole range is tried first; if it fails, the range is read page by page on 4 KB boundaries (I1), each failed page zero-filled and recorded as a gap at its absolute address. Adjacent gaps are merged. A range that would pass the top of the address space is cut there. A nil reader yields one gap over the whole range.
3. `GapMap` is a list of gaps in ascending order: `PaddedBytes` sums them, `Contains` tests an address, and `Runs(start, size)` returns the readable pieces of `[start, start+size)` as offsets from `start`.
4. `Region(r, start, end, w, opts)` refuses a nil reader (`ErrNoReader`), a nil writer (`ErrNoWriter`), a range `RegionSize` rejects (`ErrInvalidRange`) and a size over `opts.Limit()` (`ErrRegionTooLarge`) before writing. It then reads and writes 1 MiB at a time through `ReadPadded`. `Result.Size` is the bytes written, `Captured` the bytes read, `Gaps` the merged gaps; a write error stops the copy.
5. `Options.Limit()` is 0 (no cap) with `Unlimited`, else `MaxSize` when nonzero, else `limits.Default().MaxArtifactBytes`.

### 4.4 Covered offsets (`extract.Coverage`)

`Add(start, length)` records a piece (cut at 2^64; empty pieces ignored). On any read the pieces are sorted and merged where they overlap or touch. `Covered` returns a copy of the merged pieces, `Bytes` their total, `End` the end of the last, and `Holes(total)` the parts of `[0, total)` no piece covers.

### 4.5 Reading PE headers (`extract.ReadHeaders`)

1. Read `HeaderProbeSize` (4 KB) at the base with `ReadPadded`. The resident part is the prefix before the first gap.
2. No resident byte: `ErrHeadersUnreadable`.
3. Decode the resident prefix with `pe.ParseHeaders`. Any result other than a truncation is returned as it is (`pe.ErrNotPE` and the others say what the readable bytes are).
4. A truncation whose resident prefix is shorter than what was read stopped at an unread page: `ErrHeadersUnreadable` wrapping the truncation. A truncation that needs more than `MaxHeaderSpan` (0x10000) bytes is returned as an error wrapping the truncation, not as unreadable (P1). Otherwise read the span the parser needs and decode again. Each round needs strictly more bytes and never more than `MaxHeaderSpan`, so the loop ends.

## 5. Validity rules

The writer's own output meets every rule; `minidump/write_test.go` and `FuzzWrite` check that each written dump validates.

| # | Rule | Justification | On failure |
|---|---|---|---|
| V1 | The file holds the 32-byte header | F1 | Problem; nothing more is checked |
| V2 | `Signature` is `MDMP` | F1, M1 | Problem |
| V3 | The low word of `Version` is 0xA793 | F1, M1 | Problem |
| V4 | The directory lies inside the file | F2 | Problem; no stream is checked |
| V5 | Every stream lies inside the file (an `UnusedStream` of size 0 is skipped) | F2 | Problem; the stream is not decoded |
| V6 | No decoded stream type appears twice | F3 (one list of each kind per dump) | Problem; the second is ignored |
| V7 | The header, directory, streams and memory data do not overlap | F2, F11 | Problem |
| V8 | A `SystemInfoStream` exists and is at least 56 bytes | F5; without it a thread context has no architecture | Problem |
| V9 | Every RVA this package follows to a `MINIDUMP_STRING` (CSD version, module names, nonzero handle names) holds an even length, the string and a NUL inside the file | F4, F5, F6, F9 | Problem |
| V10 | Module and thread lists hold their counted entries (4 + 108·n, 4 + 48·n bytes at least); module `CvRecord` and `MiscRecord` lie inside the file | F6, F7 | Problem |
| V11 | A nonzero thread context lies inside the file; on AMD64 it is at least 1232 bytes and its `ContextFlags` has the architecture bit | F7, C1–C4, M1 | Problem |
| V12 | A nonzero stack location lies inside the file and, when it points into the memory data, at the bytes of `StartOfMemoryRange` | F7, F11 | Problem |
| V13 | Thread info: header ≥ 12 and entry ≥ 64 bytes, all entries inside the stream, every thread id in the thread list | F8 | Problem |
| V14 | Handle data: descriptor 32 or 40 bytes, header ≥ 16, `Reserved` 0, all descriptors inside the stream; a nonzero `ObjectInfoRva` inside the file | F9 | Problem |
| V15 | Memory info: header ≥ 16 and entry ≥ 48 bytes, all entries inside the stream; each entry nonempty, not past 2^64, at or after the end of the one before | F10 | Problem |
| V16 | Memory info: state commit, reserve or free; type image, mapped or private unless free | F10 | Problem |
| V17 | Memory64: the descriptors fit the stream; ranges ascending without overlap, none past 2^64; the data `[BaseRva, BaseRva + ΣDataSize)` inside the file | F11 | Problem; later ranges are not checked |
| V18 | Every Memory64 range lies in memory info entries whose state is commit, when a memory info list exists | F10 (reserved and free pages have no storage) | Problem |
| V19 | `Flags` carries `MiniDumpWithFullMemory` when a Memory64 list exists, and the handle, memory-info and thread-info flags when those streams exist | F12, D1 | Problem |
| V20 | Stream types not in F3's decoded set are only located | F3 | None |
| V21 | The thread list holds at least one thread | D2 | Problem |

Writer input rules (section 4.1 step 1):

| # | Rule | Justification | On failure |
|---|---|---|---|
| W1 | Module size fits 32 bits | F6 | `ErrModuleTooLarge` |
| W2 | Region nonempty and inside the address space | F10 | `ErrRegionRange` |
| W3 | Regions disjoint | F10, V15 | `ErrRegionOverlap` |
| W4 | Region state and type defined | F10, V16 | `ErrRegionAttributes` |
| W5 | A reader for committed dumpable regions | 4.1 step 9 | `ErrNoMemoryReader` |
| W6 | Streams before the memory data within 4 GB | F2 | `ErrTooLarge` |

### Loadability

| # | Fact |
|---|---|
| D1 | A dump that has a Memory64 list but lacks `MiniDumpWithFullMemory` in `Flags` is refused by the Windows debugging tools as a partial-memory dump that may not have a Memory64 list. Rule V19 states it. |
| D2 | A dump whose thread list is empty is refused by the Windows debugging tools (target only partly initialised), measured 2026-11-12 on the five exited processes of mem6_server2025 that have no thread, and on a synthetic dump. A dump with one thread and nothing else opens. Rule V21 states it; section 4.1 step 4 writes the placeholder. |

## 6. Failure modes

| Case | Result |
|---|---|
| Input outside W1–W6 | The sentinel; nothing written |
| Write error on `w` | The error; `w` holds a partial file that the caller discards (`windows.process.dump` removes it) |
| Unread memory | Zeros in the file; `Result.MemoryGaps` and `MemoryBytes` say which |
| Corrupt dump given to `Validate` | Problems of the form `<object> at 0x<rva>: <what failed>`; a rule that fails more than once is listed once with `(and N more)` so a forged count cannot make the list unbounded |
| `extract.Region` refusals | `ErrNoReader`, `ErrNoWriter`, `ErrInvalidRange`, `ErrRegionTooLarge` (wrapped with the range or size) |
| `ReadHeaders` | `ErrHeadersUnreadable` (wrapped, with the base), the `pe` sentinels for readable non-images, a wrapped `*pe.TruncatedError` for a span over `MaxHeaderSpan` |

None of these depend on strict mode; the calling tools decide.

## 7. Result schema

- `minidump.Result`: `Size` (file bytes), `Streams` (directory: type, RVA, size), `MemoryBytes` (bytes read from the capture), `MemoryGaps` (merged absolute gaps).
- `minidump.Audit`: `Size`, `NumberOfStreams`, `Streams`, `Problems`; `OK()` when there are none.
- `extract.Result`: `Start`, `End` (last byte), `Size`, `Captured`, `Gaps`; `Complete()` when there is no gap.

The `windows.process.dump` row is unchanged in shape.

## 8. Limits

- `MaxArtifactBytes` (through `Options.Limit`): the default cap of `extract.Region`.
- 4 GB: the 32-bit RVA space of the streams (F2), not configurable.
- 1 MiB pieces in `Write` and `Region`, 64 KiB blocks in `Validate`, `MaxHeaderSpan` 0x10000: memory held at once, not output caps.

## 9. Acceptance

1. Synthetic fixtures (`minidump/write_test.go`, `validate_test.go`, `context_x64_test.go`): header, directory order and alignment, flags; every stream's fields decoded back by offset; empty input; empty CSD version; shared strings; stacks over contiguous ranges and outside written ranges; thread-info flags; the placeholder thread; memory info order; Memory64 placement and contents; short and long reader results; chunked reads; every writer refusal before any byte; write errors; one mutation per rule V1–V19 and V21 flagged; repeated problems counted; unknown and unused streams accepted; CONTEXT offsets and size from the member list. `extract`: inclusive sizes, the fast and per-page paths, gap merging, the top of the address space, `Runs`, `Contains`, `Limit`, region copies across 1 MiB pieces, refusals; coverage merging, holes, copies; headers in the first page, past it, unread, at an unaligned base, over the cap, not an image.
2. Fuzz targets, each run for 30 s on 2026-11-12: `FuzzValidate` (arbitrary bytes; no panic; the audit is consistent), `FuzzWrite` (regions, threads, modules and handles from bytes; every accepted input validates), `FuzzReadHeaders` (arbitrary image bytes and unread pages; no header decoded across an unread page). `FuzzValidate` 2.0 million executions, `FuzzWrite` 1.33 million, `FuzzReadHeaders` 70 thousand; no failure.
3. Windows-written dump (M1): the validator reports no problem.
4. Process dumps of the captures (M3, 2026-11-12, with `windows.process.dump` as it stood that day). Every dump validates; no writer refusal; every stream area is far below 4 GB; every context carries 0x00100005 (architecture, control, segments).

| Capture | Dumps | Bytes | Largest dump | Largest stream area | Threads (placeholders) | Contexts | Stacks located | Handles | Memory info | Memory ranges | Problems |
|---|---|---|---|---|---|---|---|---|---|---|---|
| mem1_win11 | 83 | 2,399,978,848 | 240,696,936 | 0x21A2E8 | 1,128 (5) | 768 | 274 | 46,853 | 229,032 | 114,530 | 0 |
| mem2_win10 | 153 | 2,632,243,584 | 148,557,352 | 0x114E28 | 1,978 (4) | 1,197 | 345 | 57,560 | 306,110 | 149,967 | 0 |
| mem5_server2016 | 71 | 1,721,923,168 | 262,828,184 | 0xD40B0 | 1,306 (3) | 1,131 | 400 | 25,190 | 145,437 | 73,854 | 0 |
| mem6_server2025 | 101 | 2,033,867,016 | 298,417,984 | 0x13DF40 | 1,303 (5) | 830 | 245 | 40,072 | 208,975 | 102,513 | 0 |
| mem7_server2025 | 90 | 769,473,656 | 81,862,144 | 0xE3E00 | 1,211 (1) | 634 | 74 | 34,206 | 121,654 | 57,013 | 0 |

   An earlier run the same day, before the tool's region listing changed under S68, wrote 498 dumps of 81.9 GB in all (largest 1,501,990,800 bytes); all validated too.
5. PE headers on the captures (M4): no decoded header crosses an unread page (by construction, and `FuzzReadHeaders`), and `MaxHeaderSpan` is 32 times the largest span measured.
6. Loadability, outside the repository, 2026-11-12: all 101 dumps of mem6_server2025 and all 71 of mem5_server2016 open in the Windows debugging tools as user-mode full-memory dumps with at least one thread listed (D2's five no-thread processes included, through the placeholder). Before the placeholder, those five were the only dumps of mem6 that did not open. Warnings for missing image files and for threads with no context are expected: the capture holds no files, and a trap frame is not always recovered.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | `MINIDUMP_SIGNATURE` and `MINIDUMP_VERSION` values come from a Windows-written dump (M1), not from a document. | A Learn page that states them |
| O2 | The `ContextFlags` group bits (C4) have no listed source; only their union with the architecture bit is measured. | A Learn page that states them |
| O3 | `VersionInfo` is written as zeros, without the 0xFEEF04BD signature, because the input carries no version resource. Owner decision: keep zero (default) or carry the image's `VS_FIXEDFILEINFO` from `windows.pe.version`. | Owner decision |
| O4 | `ErrTooLarge` now names the stream area rather than the whole dump: memory data past 4 GB is valid (F11). The message changed to `minidump: streams pass the 32-bit rva limit`. Owner decision: accept the rewording. | Owner decision |
| O5 | `MaxHeaderSpan` 0x10000 is a design bound, held against M4. | Owner decision |
| O6 | New exports: `ValidateReaderAt`, `ErrNoMemoryReader`, `ErrRegionRange`, `ErrRegionOverlap`, `ErrRegionAttributes`, `ErrModuleTooLarge`. Owner decision (Q2): their names. | Owner decision |
| O7 | Overlapping regions refuse the whole dump (W3) rather than dropping one region. | Owner decision |
| O8 | A process with no thread gets a placeholder thread (D2) instead of no dump. Owner decision: keep the placeholder (default) or refuse such a process. | Owner decision |
| O9 | No `MiscInfoStream` is written, so a debugger shows no process id; `Input` carries none. Owner decision: add a process id to `Input` (an export change) in a later wave. | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep measured values |
| O2 | Keep measured |
| O3 | Keep zero |
| O4 | Accept |
| O5 | Keep |
| O6 | Keep names |
| O7 | Refuse |
| O8 | Placeholder thread |
| O9 | Add in a later wave |

## 11. Provenance

Written from the Microsoft Learn minidumpapiset.h, winnt.h, verrsrc.h and sysinfoapi.h reference pages, the PE Format page, the Intel SDM, the ntoskrnl PDB types of the captures and the project's measurements. Every rule rests on the sources and measurements above.
