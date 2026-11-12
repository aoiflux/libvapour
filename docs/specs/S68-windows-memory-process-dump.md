# S68: Windows process memory, minidumps and image identity

Version 1, 2026-11-12.

## 1. Purpose

Five tools look at a Windows process through its own address space:

| Tool | Package | Question |
|---|---|---|
| `windows.memory.tree` | `tools/windows/memorytree` | How are the process's VADs linked: each node's parent, left and right child and range? |
| `windows.memory.find_pattern` | `tools/windows/memorypattern` | Where in the process's VAD ranges does a regular expression match? |
| `windows.memory.dump` | `tools/windows/memorydump` | What bytes does each VAD range hold, as one file per range with the unread pages marked? |
| `windows.process.dump` | `tools/windows/processdump` | Can the process be opened in a debugger: a user-mode minidump of its modules, threads with stacks and registers, handles and memory? |
| `windows.process.check_identity` | `tools/windows/processidentity` | Does the image path in the process's own parameter block agree with the image name the kernel recorded at creation, and do its image path and command line strings still have the layout the loader gave them? |

The first four read only what the VAD walk (S24) and the process list (S25) give, through the process's own page-table root. The minidump writer must never present bytes the capture does not hold as process memory: the format has no way to mark a hole inside a memory range. The identity check compares a user-writable record (the parameter block) with two kernel records; a process can rewrite its own parameter block, the kernel's records it cannot.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | `_EPROCESS`, the audit name, `KUSER_SHARED_DATA`, thread objects. |
| Process space | `tools.Context.ProcessSpace` of the process list's `DirectoryTableBase` (S25 4.5 step 3): the PEB, parameter block, TEBs, module headers and VAD contents. A root of 0 is never passed: the reader would fall back to whichever process the capture's root belongs to. |
| Physical memory | `windows.memory.find_pattern` only: the page-table walk and the frames (S64 4.11). |
| Symbol table | The types of section 3. |
| Rows of other tools | `any.process.list` (S25), the S24 VAD walk (`memoryranges.Run`, `TreeWalker`, `ProcessVADs`), `windows.library.list` (S56), `windows.thread.list` and `threadlist.ReadTrapFrame` (S50), `windows.handle.list` (S30), the build reader (S03). |
| Options | `pid` (all five); `windows.memory.find_pattern.pattern` (string, required) and `.maxsize` (unsigned); `windows.memory.dump.address` (unsigned, the S24 4.10 filter); `output_dir` (required by the two writers); `max_dump_size`; `strict`; `diagnostics`. |
| Limits | `MaxListEntries` (VAD nodes, through S24), `MaxMatchesPerChunk`, `RowPreviewBytes` and `MaxBufferBytes` (find_pattern, S64), `MaxArtifactBytes` (the default dump limit). |

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | `UNICODE_STRING`: `Length` is "the length, in bytes, of the string stored in Buffer"; `MaximumLength` is "the length, in bytes, of Buffer". "If the string is null-terminated, Length does not include the trailing null character." | Microsoft Learn, "_UNICODE_STRING (ntdef.h)", updated 2024-02-22, accessed 2026-11-12. |
| D2 | `RTL_USER_PROCESS_PARAMETERS` "contains process parameter information"; `ImagePathName` is "the path of the image file for the process", `CommandLine` "the command-line string passed to the process", both `UNICODE_STRING`. "This structure may be altered in future versions of Windows." | Microsoft Learn, "RTL_USER_PROCESS_PARAMETERS (winternl.h)", updated 2024-02-22, accessed 2026-11-12. |
| D3 | `NtQueryInformationProcess` with `ProcessImageFileName` "retrieves a UNICODE_STRING value containing the name of the image file for the process"; with `ProcessBasicInformation`, `PebBaseAddress` "points to a PEB structure". | Microsoft Learn, "NtQueryInformationProcess function (winternl.h)", updated 2025-11-25, accessed 2026-11-12. |
| D4 | `MINIDUMP_SYSTEM_INFO`: `ProcessorArchitecture` 9 is x64, 0 is x86, 0xffff unknown; `NumberOfProcessors` (one byte) "the number of processors in the system"; `ProductType` `VER_NT_WORKSTATION` 1, `VER_NT_DOMAIN_CONTROLLER` 2, `VER_NT_SERVER` 3; `MajorVersion`, `MinorVersion`, `BuildNumber`; `PlatformId` `VER_PLATFORM_WIN32_NT` 2; `SuiteMask` (two bytes) the `VER_SUITE_*` flags, all below 0x10000. | Microsoft Learn, "MINIDUMP_SYSTEM_INFO (minidumpapiset.h)", updated 2024-02-22, accessed 2026-11-12. |
| D5 | `MINIDUMP_THREAD`: `ThreadId`, `SuspendCount` ("if greater than zero, the thread is suspended"), `PriorityClass`, `Priority`, `Teb` ("the thread environment block"), `Stack` (a memory descriptor), `ThreadContext`. | Microsoft Learn, "MINIDUMP_THREAD (minidumpapiset.h)", updated 2024-02-22, accessed 2026-11-12. |
| D6 | `MINIDUMP_THREAD_INFO`: `DumpError` is "an HRESULT value that indicates the dump status"; `MINIDUMP_THREAD_INFO_INVALID_CONTEXT` 0x10 "thread context could not be retrieved"; `CreateTime` and `ExitTime` are "in 100-nanosecond intervals since January 1, 1601 (UTC)"; `StartAddress` is "the starting address of the thread". | Microsoft Learn, "MINIDUMP_THREAD_INFO (minidumpapiset.h)", updated 2024-02-22, accessed 2026-11-12. |
| D7 | `MINIDUMP_MODULE`: `BaseOfImage`, `SizeOfImage` ("the size of the module executable image in memory"), `CheckSum` and `TimeDateStamp` "of the module executable image", `ModuleNameRva`. | Microsoft Learn, "MINIDUMP_MODULE (minidumpapiset.h)", updated 2024-02-22, accessed 2026-11-12. |
| D8 | `MINIDUMP_HANDLE_DESCRIPTOR`: `Handle` "the operating system handle value"; `ObjectNameRva` "specifies the object name of the handle. This member can be zero." `GrantedAccess` "depends on the handle type and the operating system". | Microsoft Learn, "MINIDUMP_HANDLE_DESCRIPTOR (minidumpapiset.h)", updated 2024-02-22, accessed 2026-11-12. |
| D9 | `MINIDUMP_MEMORY_INFO`: `BaseAddress` "the base address of the region of pages"; `AllocationBase`; `RegionSize` "the size of the region beginning at the base address in which all pages have identical attributes"; `State` `MEM_COMMIT` 0x1000, `MEM_RESERVE` 0x2000, `MEM_FREE` 0x10000; `Type` `MEM_IMAGE` 0x1000000, `MEM_MAPPED` 0x40000, `MEM_PRIVATE` 0x20000. | Microsoft Learn, "MINIDUMP_MEMORY_INFO (minidumpapiset.h)", updated 2024-02-22, accessed 2026-11-12. |
| D10 | `ERROR_PARTIAL_COPY` is 299 (0x12B): "Only part of a ReadProcessMemory or WriteProcessMemory request was completed." `HRESULT_FROM_WIN32(x)` is `(x & 0xFFFF) | (FACILITY_WIN32 << 16) | 0x80000000` for a positive `x`; `FACILITY_WIN32` is 7. | Microsoft Learn, "System Error Codes (0-499)", dated 2025-07-14, and "HRESULT_FROM_WIN32 macro (winerror.h)", updated 2025-08-27, accessed 2026-11-12. |
| D11 | `KUSER_SHARED_DATA`: `NtProductType` "product type" (`NT_PRODUCT_TYPE`), `ActiveProcessorCount` "number of active processors", `SuiteMask` "suite support", `NtMajorVersion` and `NtMinorVersion` "the NT major (minor) version". | Microsoft Learn, "KUSER_SHARED_DATA (ntddk.h)", updated 2026-06-29, accessed 2026-11-12. |
| D12 | `PAGE_NOACCESS` 0x01 "disables all access to the committed region of pages"; `PAGE_GUARD` 0x100 is a modifier. | Microsoft Learn, "Memory Protection Constants", dated 2022-05-18, accessed 2026-11-12. |

### Earlier specifications

| # | Fact | Source |
|---|---|---|
| E1 | The VAD walk keeps only nodes inside the interval their ancestors allow, each once, and reports what it leaves out; `TreeWalker.Walk` gives each kept node with its raw links and its parent, `ProcessVADs` the ranges, `memoryranges.Run` the `Mapping` rows with protection names and kinds. | S24 4.2, 4.8 |
| E2 | `Process.DirectoryTableBase` is the root to read the process's user space with; 0 when no root reads. | S25 4.5 step 3, T4 |
| E3 | `ReadTrapFrame` returns the frame's registers only for a frame saved from user mode (CS privilege level 3, user `Rip` and `Rsp`); R12 to R15 have no trap frame member. | S50 4, T5, D6 |
| E4 | Handle names: `Process` and `Thread` handles carry the label `<ImageFileName> pid <n>` and `tid <n> pid <n>`, built from the target, not an object name; neither type has name information. Key names are full `\REGISTRY\…` paths. | S30 4.3 to 4.5, M6 |
| E5 | `ImageFileName` is the audit name's last component, or its first 14 bytes when the component is longer (14 = array length − 1). | S43 M7, T1 |
| E6 | The NT version and build come from the build reader: `KUSER_SHARED_DATA.NtMajorVersion`, `NtMinorVersion`, and the low 28 bits of the kernel's `NtBuildNumber`, else the shared build. | S03 4.2 to 4.4 |
| E7 | Pattern search machinery: RE2 option, Latin-1 byte matching, 16 MiB chunks with a page of lookahead, sections matched on masked addresses, `MaxMatchesPerChunk`. | S64 4.11 |
| E8 | Artefact names: kind `region` with start and end for a range, kind `process` with the process object and the image name label for a minidump, extensions `bin` and `dmp`. | S00 |

### Kernel types

Read through the project's kernel tables with `memdumpfacts`: builds 26100 (mem1; mem6 and mem7 share one table), 19045 (mem2), 14393 (mem5).

| # | Fact |
|---|---|
| T1 | `_EPROCESS.Peb` (`_PEB *`) 0x2e0, 0x550, 0x3f8; `SeAuditProcessCreationInfo` (`_SE_AUDIT_PROCESS_CREATION_INFO`, 8 bytes) 0x350, 0x5c0, 0x468; `ImageFileName` (unsigned char [15]) 0x338, 0x5a8, 0x450 (26100, 19045, 14393). `_SE_AUDIT_PROCESS_CREATION_INFO.ImageFileName` (`_OBJECT_NAME_INFORMATION *`) 0; `_OBJECT_NAME_INFORMATION.Name` (`_UNICODE_STRING`) 0, size 16. |
| T2 | `_PEB.ProcessParameters` (`_RTL_USER_PROCESS_PARAMETERS *`) 0x20 in all. `_RTL_USER_PROCESS_PARAMETERS` (1,096, 1,088, 1,040 bytes): `MaximumLength` (unsigned int) 0, `Length` (unsigned int) 4, `Flags` (unsigned int) 8, `ImagePathName` 0x60 and `CommandLine` 0x70 (`_UNICODE_STRING`). `_UNICODE_STRING`: `Length` (unsigned short) 0, `MaximumLength` (unsigned short) 2, `Buffer` (wchar_t *) 8. |
| T3 | `_TEB.NtTib` (`_NT_TIB`, 56 bytes) 0; `_NT_TIB.StackBase` (void *) 8, `StackLimit` (void *) 0x10. |
| T4 | `_KUSER_SHARED_DATA.NtProductType` (int) 0x264, `ProductTypeIsValid` (unsigned char) 0x268, `NativeProcessorArchitecture` (unsigned short) 0x26a, `SuiteMask` (unsigned int) 0x2d0, `ActiveProcessorCount` (unsigned int) 0x3c0 in all. |

### Measurements

M1 to M12 come from `memdumpfacts -identity -threads -regions` on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100); figures are in that order. The process list holds 83, 153, 71, 101 and 90 processes.

| # | Measured |
|---|---|
| M1 | Every process's audit pointer and name read. The name starts `\Device\` in 79, 149, 70, 99, 87; it is empty in 2, 2, 1, 1, 2 (System and Idle-like entries) and is a bare `Registry` or `MemCompression` in the rest. Every audit string has `MaximumLength` = `Length` + 2 and a NUL at `Length`. |
| M2 | `ImageFileName` equals the audit name's last component in 74, 131, 65, 78, 67 processes and is its first 14 bytes in the other 7, 20, 5, 22, 21 with a non-empty name; it never differs (E5). |
| M3 | The parameter block reads in 75, 142, 67, 84, 78 processes. `Peb` is 0 in 4, 4, 1, 2, 2; the `ProcessParameters` pointer does not read in 4, 5, 3, 11, 10 and the block's `Length` in 0, 2, 0, 4, 0 (pages in the page file). `Flags` bit 0 is set in every block read. |
| M4 | The `ImagePathName` file name (last component) equals the audit name's ignoring case in every read block (446). The paths after the volume (the drive letter `X:` of the Win32 form, `\Device\<volume>` of the NT form) are equal ignoring case in all but one per capture, `smss.exe`, whose image path is `\SystemRoot\System32\smss.exe`. Exact case differs in 49 to 85 per capture. |
| M5 | Every `ImagePathName` (446): `Length` even, `MaximumLength` = `Length` + 2, the unit at `Length` is NUL, no NUL inside `Length`, and `Buffer` to `Buffer` + `MaximumLength` lies inside the block (`ProcessParameters` to `ProcessParameters` + `Length`). |
| M6 | Every `CommandLine` (446): the same, except that 1, 3, 4, 4, 4 hold NUL units inside `Length` (NUL-separated arguments). |
| M7 | Threads: 1,123, 1,974, 1,303, 1,298, 1,210. A TEB is set in 770, 1,333, 1,130, 960, 868. Where it is set and reads, `StackLimit` < `StackBase` with both inside one VAD range in 739, 1,097, 1,079, 808, 612; not ordered in 2, 2, 0, 0, 0; inside no single range in 27, 16, 50, 21, 12; the TEB does not read in 2, 218, 1, 131, 244. |
| M8 | Trap frames: user mode 768, 1,197, 1,132, 832, 634; kernel mode 23, 23, 8, 27, 16; no frame 249, 482, 149, 182, 206; the frame does not read 83, 272, 14, 257, 354. Of the user frames whose thread has a stack range, `Rsp` lies inside it for all but 0, 0, 1, 2, 0. |
| M9 | System values: NT version 10.0 on all; build 26100, 19045, 14393, 26100, 26100. `NtProductType` 1, 1, 3, 3, 3 with `ProductTypeIsValid` 1. `NativeProcessorArchitecture` 9. `ActiveProcessorCount` 16, 8, 8, 4, 4, equal to the 4 bytes at `KeNumberProcessors` on every capture. `SuiteMask` 0x110, 0x110, 0x110, 0x190, 0x190. |
| M10 | Modules (S56 rows): 4,351, 8,038, 3,524, 4,694, 4,158. The PE headers read in 4,341, 4,809, 3,473, 2,129, 720; wherever they read, `SizeOfImage` equals the loader's size. A full path exists for all but 0, 108, 0, 85, 95. |
| M11 | VAD ranges: 10,747, 21,783, 9,808, 14,093, 10,921; above 1 GiB 155, 329, 95, 184, 157 (the 2 TB and 4 GB reservations). Of the rest, the pages that read hold 2,270, 2,487, 1,630, 1,924, 724 MiB of 14,215, 25,825, 19,646, 14,759, 11,870 MiB spanned (8 to 16 %). No page reads in 904, 4,767, 253, 3,399, 4,949 ranges. The pages that read form 114,530, 149,967, 73,854, 102,513, 57,013 runs in 9,688, 16,687, 9,460, 10,510, 5,815 ranges. |
| M12 | A private range with commit charge 0 is not reserved-only: 14 of 27, 6 of 22, 0 of 9, 15 of 26, 5 of 17 have pages that read. `PAGE_NOACCESS` ranges (93, 391, 221, 235, 121) have pages that read in 16, 180, 119, 132, 10. No range is `PAGE_GUARD`. |

## 4. Algorithm

Every tool: `ctx.Validate`; a non-Windows profile is refused; the process list (S25) gives the processes in list order, and `pid` keeps those it names.

### 4.1 `windows.memory.tree`

1. `memoryranges.NewTreeWalker` (S24); a table without `_RTL_BALANCED_NODE.ParentValue` or another walk member is `memoryranges.ErrVADLayout` and the run fails.
2. Per process: `TreeWalker.Walk` (E1). Its nodes become rows in start order: `Address` the VAD, `Parent`, `Left`, `Right`, `Start`, `End`, `Tag`.
3. A walk that fails (the root does not read, the tree is refused) is the diagnostic of 6 and the process has no rows; in strict mode, and when the walk itself stops in strict mode on a node left out, the run fails with that error.

### 4.2 `windows.memory.find_pattern`

1. The pattern option is required and compiled as E7; the match-size option as E7. Physical memory is required (`kernelpattern.ErrNoPhysical`).
2. Per process: a root of 0 is counted and skipped (E2). `ProcessVADs` gives the ranges; a walk that fails is counted, or fails the run in strict mode. A process with no range is skipped.
3. The S53 translator on the root, the VAD ranges as sections, the shared scanner with `MaxMatchesPerChunk` (E7). A process whose page tables do not walk is counted and skipped; an unknown paging mode fails the run.
4. A row is the PID, the process name, the match address, its kept bytes and their text (`util.DecodeUTF8Replace`). Rows are in process order, then address order.

### 4.3 `windows.memory.dump`

1. `output_dir` is required (`ErrNoOutputDir`). `windows.memory.dump.address` filters the ranges (S24 4.10).
2. The ranges are `memoryranges.Run`'s rows (E1), in their order.
3. For each range: the S00 `region` name of start and end, extension `bin` (E8).
   1. Size = End − Start + 1. A range larger than the dump limit (`max_dump_size` when it is set and below `MaxArtifactBytes`, else `MaxArtifactBytes`) is listed with `ErrOverLimit` and not written; this is the examiner's limit, so strict mode does not stop on it (M11: the CFG and 4 GB reservations).
   2. The process space comes from the range's `DirectoryTableBase`. A root of 0 (`ErrNoRoot`) or a space that does not build is the row's reason; in strict mode the run fails.
   3. The file is created new (`extract.CreateNew`; an existing file is never replaced) and written with `extract.Region`: pages that do not read are zero-filled and listed in `Gaps`.
   4. A write error removes the partial file and is the row's reason; in strict mode the run fails.
   5. A range of which no page reads is removed again and listed with `ErrNothingRead`: zero fill alone holds nothing from the capture (M11).

### 4.4 `windows.process.dump`

1. `output_dir` is required (`ErrNoOutputDir`). The process space of each kept process is built once (E2); a root of 0 is `ErrNoRoot`.
2. **System values** (D4, D11, E6, M9):
   1. `ProcessorArchitecture`: AMD64 for an 8-byte table, Intel for a 4-byte one, else unknown. `PlatformId` 2.
   2. Version from the build reader; build = kernel build, else shared build.
   3. `NumberOfProcessors` = `ActiveProcessorCount` when it reads and is 1 to 255 (one byte); else 0 with a diagnostic.
   4. `ProductType` = `NtProductType` when it reads and is 1 to 3; the `NT_PRODUCT_TYPE` values are the `VER_NT_*` values (D4, M9). Else 0.
   5. `SuiteMask` = `KUSER_SHARED_DATA.SuiteMask` when it reads and fits 16 bits.
3. **Modules**: the S56 rows of the process, each base once. Name = full path when read, else the base name. Size = the loader's size, else the header's `SizeOfImage` (M10). `TimeDateStamp` and `CheckSum` from the PE headers read in the process space (D7); headers that do not read leave them 0 and are counted. A module with no size is left out and counted.
4. **Ranges**: the process's `memoryranges.Run` rows. Each becomes memory-info entries with `AllocationBase` = the range start, `Type` from the kind (`image` → `MEM_IMAGE`, `mapped` → `MEM_MAPPED`, else `MEM_PRIVATE`), `Protect` = `AllocationProtect` = the parsed protection (S24 4.4), `State` `MEM_COMMIT` (D9; O3).
   1. Protection unknown, no process space, or a range above the dump limit: one entry, no contents.
   2. Otherwise the range is cut at every page where readability changes: each run of pages that read is an entry with contents, each run that does not is an entry without (D9 "identical attributes"; M11). No byte written is zero fill.
   3. `PAGE_NOACCESS` and commit charge do not withhold contents: such ranges hold captured pages (M12).
5. **Threads**: the S50 rows of the process.
   1. `ThreadId`, `Teb` (0 when not read), `SuspendCount` and `Priority` (negative read values as 0), `CreateTime` and `ExitTime` as FILETIME (D6), `StartAddress` = `Win32StartAddress` when read.
   2. Stack: `_NT_TIB.StackLimit` and `StackBase` read through the TEB in the process space (T3). Kept when `0 < StackLimit < StackBase` and both lie in one VAD range of the process (M7); the dump gets the low end and the size.
   3. Registers: on a 64-bit kernel, `ReadTrapFrame` (E3). A user-mode frame gives the context when the thread has no stack range or `Rsp` lies inside it (M8); the flags name `CONTEXT_CONTROL` and `CONTEXT_SEGMENTS` only, since R12 to R15 are not in the frame.
   4. `DumpError` = `HRESULT_FROM_WIN32(ERROR_PARTIAL_COPY)` = 0x8007012B (D6, D10) when the TEB, suspend count, priority or trap frame pointer did not read, or the frame itself did not read.
6. **Handles**: the S30 rows of the process: handle value, type name, granted access, and the object name, except empty for `Process` and `Thread` handles (E4, D8) and for names that did not read.
7. The file: S00 `process` name of the `_EPROCESS` with the image name label, extension `dmp` (E8); created new; written by `minidump.Write`. A write error removes the partial file and is the row's reason; in strict mode the run fails.

### 4.5 `windows.process.check_identity`

1. **Layout.** `_EPROCESS.Peb` and `_PEB.ProcessParameters` are required (`ErrLayout`); at least one of `ImagePathName` and `CommandLine` (`ErrNoProcessString`). The block's `Length`, the other string and the audit chain (`SeAuditProcessCreationInfo` → `ImageFileName` → `Name`, T1) are optional: each absent one is named in a diagnostic and its rules are not applied.
2. **Kernel path.** The audit pointer at `_EPROCESS` + `SeAuditProcessCreationInfo` + `ImageFileName`; 0 is no kernel path; else the `UNICODE_STRING` at the pointer + `Name` (D3, M1).
3. **Short name rule** (`NameDiffers`): `ImageFileName` differs, ignoring ASCII case, from the kernel path's last component cut to 14 bytes (E5, M2). Not applied when either is empty.
4. **Parameter block.** `Peb` from kernel memory; 0 is absent. The root 0 is unread (`ErrNoRoot`). In the process space: `ProcessParameters`; 0 is absent. The block end is `ProcessParameters` + `Length` when `Length` reads.
5. **Image path rule** (`ImagePathDiffers`): the path after the volume of `ImagePathName` and of the kernel path differ ignoring case; when either has no volume form, their last components are compared instead (M4).
6. **Layout rule** (`ImagePathRewritten`, `CommandLineRewritten`), each string read with up to 65,535 bytes: the string is rewritten when any of the following holds (M5, M6, D1):
   1. `Length` is odd, or `MaximumLength` ≠ `Length` + 2;
   2. the block end is known and `Buffer` .. `Buffer` + `MaximumLength` is not inside the block;
   3. the unit at `Length` reads and is not NUL;
   4. for `ImagePathName` only, a NUL unit inside `Length`.
   A string with `Length` 0 and `Buffer` 0 is not judged.
7. One row per kept process, in process-list order.

## 5. Validity rules

| Tool | Rule | Justification | On failure |
|---|---|---|---|
| all | User memory is read under the process's own root, never root 0 | E2 | `ErrNoRoot`, row or process skipped |
| memory.tree | Nodes as the S24 walk keeps them | E1 | S24 diagnostics; strict fails |
| memory.dump | Range within the dump limit | M11 | `ErrOverLimit`, listed |
| memory.dump | At least one page of the range reads | M11 | `ErrNothingRead`, listed, no file |
| process.dump | Memory contents only for pages that read | D9, M11 | Entry without contents |
| process.dump | Stack `0 < StackLimit < StackBase`, inside one VAD range | T3, M7 | No stack range, counted |
| process.dump | Registers only from a user-mode frame whose `Rsp` lies in the stack | E3, M8 | No context, counted |
| process.dump | `ActiveProcessorCount` 1 to 255, `NtProductType` 1 to 3 | D4, D11, M9 | Written as 0, diagnostic |
| process.dump | No object name for process and thread handles | D8, E4 | Name empty |
| check_identity | `ImageFileName` is the kernel path's file name cut to 14 bytes | E5, M2 | `NameDiffers` |
| check_identity | Image path names the kernel's file | D2, D3, M4 | `ImagePathDiffers` |
| check_identity | String layout as the loader builds it | D1, M5, M6 | `ImagePathRewritten`, `CommandLineRewritten` |

## 6. Failure modes

| Case | Result |
|---|---|
| Non-Windows profile | `<tool>: unsupported profile os "<os>"` |
| Missing VAD walk member | `memoryranges.ErrVADLayout`; the run fails (tree) |
| A process's VAD tree does not read | `<tool>: pid <pid> _EPROCESS at 0x<addr>: VAD tree not read: <error>` (tree, find_pattern in strict mode); find_pattern counts `<n> processes whose VAD tree did not read, not searched, first: …` |
| find_pattern: no root, page tables that do not walk | `<tool>: <n> processes without a page-table root, not searched, first: …`; `… whose page tables did not walk, not searched, first: …` |
| find_pattern: chunks unread, capped | `<tool>: <n> chunks of mapped frames did not read and were not searched`; `<n> chunks held more than MaxMatchesPerChunk (<n>) matches; …` |
| memory.dump: limit, empty ranges, no space | `<tool>: <n> ranges of <lo> to <hi> bytes over the <limit>-byte dump limit, not written`; `<n> ranges with no page in the capture, not written`; `<tool>: pid <pid>: user memory not read, its ranges not written: <error>` |
| memory.dump / process.dump: file not created or not written | `<tool>: pid <pid> VAD at 0x<addr>: not written: <error>` / `<tool>: pid <pid> _EPROCESS at 0x<addr>: minidump not written: <error>`; strict fails |
| process.dump: a source tool fails | `<tool>: module list (thread list, handle list) not read, no modules (threads, handles) written: <error>`; `VAD ranges not read, no memory or stacks written: <error>` |
| process.dump: counts | `<tool>: <n> of <n> threads with registers; without: <n> no trap frame, <n> kernel-mode trap frame, <n> trap frame not read, <n> stack pointer outside the stack`; `<n> of <n> threads without a stack range: …`; `<n> of <n> threads with a member not read, written as 0 with DumpError 0x8007012b`; `<n> module headers not read, …`; `<n> VAD ranges over the <limit>-byte dump limit listed without contents`; `<n> VAD ranges with protection unknown listed without contents`; `<tool>: pid <pid> _EPROCESS at 0x<addr>: user memory not read, regions listed without contents: <error>` |
| process.dump: system values | `system version not read, written as 0.0: …`; `build number not read, written as 0: …`; `_KUSER_SHARED_DATA.ActiveProcessorCount not read or outside 1-255, processor count written as 0`; the same for `NtProductType` |
| check_identity: absent members | `<tool>: <type.member> not in the symbol table, its check not made` |
| check_identity: unread records | `<tool>: <n> processes whose <kernel image name / parameter block / ImagePathName / CommandLine> did not read, first: pid <pid> _EPROCESS at 0x<addr>: <error>`; strict mode fails on the parameter block: `<tool>: pid <pid> _EPROCESS at 0x<addr>: parameter block not read: <error>` |

## 7. Result schema

`windows.memory.tree` (`memorytree.Row`): `PID`, `Process` (invalid UTF-8 replaced), `Address` (the VAD), `Parent`, `Left`, `Right`, `Start`, `End` (inclusive), `Tag`. Process order, then `Start`.

`windows.memory.find_pattern` (`memorypattern.Match`): `PID`, `Process`, `Address`, `Text`, `Bytes`. Process order, then address.

`windows.memory.dump` (`memorydump.Artifact`): `PID`, `Process`, `VadAddress`, `Start`, `End`, `Protection`, `Type` (new; the S24 kind), `Path` (new; the S24 file name when read), `Tag`, `FileName`, `Size`, `Captured`, `Gaps`, `Skipped`; `Written()`, `Complete()`. The order of `memoryranges.Run`.

`windows.process.dump` (`processdump.Artifact`): `PID`, `Process`, `FileName`, `Size`, `Modules`, `Threads`, `ThreadsWithContext` (new), `Handles`, `Regions` (memory-info entries), `RegionsWithoutContents`, `BytesWithoutContents`, `MemoryBytes`, `Gaps`, `Skipped`; `Written()`. Process order.

`windows.process.check_identity` (`processidentity.Row`): `PID`, `Process` (`ImageFileName`), `Address` (`_EPROCESS`), `KernelPath`, `KernelPathRead`, `Parameters` (`read`, `absent`, `unread`), `ImagePath`, `ImagePathRead`, `CommandLineRead`, `NameDiffers`, `ImagePathDiffers`, `ImagePathRewritten`, `CommandLineRewritten`. Findings are false when their inputs did not read. Process order.

## 8. Limits

`MaxListEntries` bounds each VAD tree (S24). `MaxMatchesPerChunk`, `RowPreviewBytes` and `MaxBufferBytes` bound find_pattern (S64). The dump limit (`max_dump_size` when it is set and below `MaxArtifactBytes`, else `MaxArtifactBytes`, default 1 GiB) bounds each range file and each minidump memory range; ranges above it are listed (M11). Strings are read up to `util.MaxUnicodeStringBytes`.

## 9. Acceptance

1. Synthetic fixtures (`tools/windows/*/` tests of the five packages, on the shared process fixture with the 26100 offsets of T2 to T4, `SeAuditProcessCreationInfo` at its 19045 offset 0x5c0 (T1, the build the process fixture lays out, S79 P1), and the S50 thread fixture): links and order checked against the range listing; a node left out and strict mode; a table without `ParentValue`; matches only inside VAD ranges, across a page break, cut to the match size, per process root, with `pid`; a range written with a gap, an image range, an empty range, the limit in strict mode, an existing file, a process without a space; a minidump's system values, module, memory runs that skip an unread page, info entries covering every range, a thread with stack and registers, one whose stack pointer is outside its stack, a kernel-mode frame; check_identity's clean process, each finding alone, the 14-byte name, case, the command line NUL, absent and unread records, strict mode, absent members.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzResidentPieces` (processdump; arbitrary residency of up to 512 pages: pieces cover the range in order, alternate residency, keep the allocation base): 2,608,518 executions. `FuzzStringShape` (processidentity; arbitrary string fields and units: a kept string always has the loader layout, a loader-built string is never flagged except an image path with a NUL): 1,360,950 executions. `FuzzPathRules` (a path never differs from itself, the kernel's own short name never differs, the two volume forms of one path agree): 3,313,521 executions.
3. On the captures, `memdumpfacts -tool` on 2026-11-12 (writers on smss, csrss, winlogon, explorer and the first svchost):

| Capture | memory.tree rows (= `any.memory.list` rows) | find_pattern matches (processes) | check_identity rows: block read, absent, unread; findings | memory.dump rows: written (MiB read), no page read, over the limit | process.dump: memory written, threads with registers, memory ranges |
|---|---|---|---|---|---|
| mem1_win11 | 10,747 | 4,678 (77) | 83: 75, 4, 4; none | 1,308: 1,071 (292), 227, 10 | 289 MiB; 104 of 111; 12,199 |
| mem2_win10 | 21,783 | 5,258 (145) | 153: 144, 4, 5; none | 1,199: 981 (187), 208, 10 | 185 MiB; 92 of 104; 10,141 |
| mem5_server2016 | 9,808 | 4,064 (66) | 71: 67, 1, 3; none | 857: 828 (123), 24, 5 | 122 MiB; 116 of 118; 5,518 |
| mem6_server2025 | 14,093 | 2,525 (78) | 101: 88, 2, 11; none | 443: 269 (30), 166, 8 | 28 MiB; 27 of 36; 2,228 |
| mem7_server2025 | 10,921 | 768 (53) | 90: 78, 2, 10; none | 1,320: 638 (98), 672, 10 | 96 MiB; 71 of 108; 7,161 |

   - find_pattern searched for `This program cannot be run in DOS mode`; every match reads back equal through its process's space.
   - memory.dump: every page outside `Gaps` equals the capture's page (74,823, 47,882, 31,575, 7,706, 25,133), every gap page is zero.
   - process.dump: all 25 minidumps pass `minidump.Validate`; every memory range lies inside one VAD range and equals the capture's bytes; no byte is padding. The mem6 explorer.exe process has no ranges, modules or threads left; its dump holds the system values only.
   - check_identity flags no process on any capture: the clean baseline of O2. `Parameters` counts a block whose `Length` does not read as read (4 on mem6, 2 on mem2; M3).
   - All 25 minidumps open in the console debugger of the Windows SDK (10.0.28000) as user-mode dumps with full memory, naming the capture's build and processor count; it lists the modules of each and shows the threads written without registers as context retrieval failures with Win32 error 299 (O6).

4. The real-image pid-option test keeps, for all five tools, only the processes `pid` names.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision (Q2): row fields renamed. `memorytree.Row.Offset` is `Address`; `memorypattern.Match.Offset` and `Hex` are `Address` and `Bytes` (as the Linux tool); `processdump.Artifact.RegionsOmitted` and `OmittedBytes` are `RegionsWithoutContents` and `BytesWithoutContents`, `ThreadsWithContext` is new and `Regions` now counts memory-info entries; `memorydump.Artifact` gains `Type` and `Path`; `processidentity.Row` `EPROCESSImageFileName`, `SeAuditImageFileName`, `PEBImageFilePath`, `ImagePathSpoofed`, `CommandLineSpoofed`, `PEBUnreadable`, `ImagePathUnreadable`, `CommandLineUnreadable` are `Process`, `KernelPath`, `ImagePath`, `ImagePathRewritten`, `CommandLineRewritten`, `Parameters`, `ImagePathRead`, `CommandLineRead`, with `Address`, `KernelPathRead`, `NameDiffers` and `ImagePathDiffers` new. `processdump.FileName` is removed. Tool names and option keys are kept. | Owner decision |
| O2 | The layout rule (4.5 step 6) rests on measurements of clean processes only (M5, M6): no capture holds a process known to have rewritten its parameters. | A capture with a process that rewrites its own image path and command line |
| O3 | Memory-info `State` is `MEM_COMMIT` for every entry: the VAD has no reliable reserved-only marker (M12), so pages that do not read may be reserved, paged out or never touched. | Owner decision; a source for a VAD's committed pages |
| O4 | `PAGE_NOACCESS` ranges get their captured pages (M12); a debugger reads them as if accessible. | Owner decision |
| O5 | `StartAddress` is `Win32StartAddress`, the routine the thread's creator named; `_ETHREAD.StartAddress` is not written. Learn's "starting address" does not say which. | Owner decision |
| O6 | `DumpError` 0x8007012B is a choice of HRESULT for "part of the state did not read"; Learn does not list the values a writer should use. | Owner decision |
| O7 | Owner decision: memory.dump writes no file for a range with no page in the capture (`ErrNothingRead`, M11). In 0.1.0 such a range was a file of zeros. Follow-up Mem-M9 (pid 3804, mem2, 2026-11-12): 0x146689a0000-0x146689a1fff and 0x7df501aa0000-0x7df503aa0fff are two such ranges; libvapour lists them with `ErrNothingRead` and writes no file for them. | Owner decision |
| O8 | The `\SystemRoot\` form of `smss.exe`'s image path (M4) is compared by file name only. | A source for the `\SystemRoot` link target, or the owner's acceptance |
| O9 | WOW64 threads run 32-bit code on a 32-bit stack that the 64-bit TEB's `NtTib` does not describe; their registers are dropped when `Rsp` is outside the 64-bit stack (M8: 3 threads in all). The 32-bit context and stack are not written. | A capture with busy WOW64 processes; a source for the 32-bit TEB |
| O10 | x86 kernels: no context is written and the minidump architecture is Intel; no 32-bit capture was measured. | A 32-bit capture (Q7) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Apply the renames |
| O2 | Keep measured rule |
| O3 | MEM_COMMIT for all |
| O4 | Include captured pages |
| O5 | Win32StartAddress |
| O6 | 0x8007012B |
| O7 | Write no file, error |
| O8 | File name only |
| O9 | Drop and count |
| O10 | Keep as is |

## 11. Provenance

Author: the project, 2026-11-12. Sources: Microsoft Learn pages as cited in section 3 with their dates; the ntoskrnl types through the project's symbol tables; S00, S03, S24, S25, S30, S43, S50, S56 and S64. Measurements: `memdumpfacts` on the five captures. Every rule rests on the sources and measurements above.
