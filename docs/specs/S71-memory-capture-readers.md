# S71: Memory capture readers

Version 1, 2026-11-12.

## 1. Purpose

Every question an examiner asks of a capture starts with one: which bytes of the file are which physical addresses? A raw image answers it by position. Other containers interleave headers with memory, leave out ranges the machine never had, or hold something that is not physical memory at all. Read as raw, a crash dump's header would be served as page 0 and every later page would sit 8 KiB from its true address; a process core would give one process's virtual memory as if it were the machine's RAM.

This specification covers package `memory`: the reader contract every layer and tool reads through, the file reader, the segment map, the scan helpers that walk only held bytes, the small wrappers (buffer, fallback, layers, scatter), format detection, the three container formats (Windows 64-bit full crash dump, the lime range format, ELF core), and the acquisition providers the session opens a capture with. Address translation above physical memory is S53; minidumps are their own package.

## 2. Inputs

| Input | Meaning |
|---|---|
| Capture file | A path, or an open `*os.File`, read with `ReadAt` only. |
| Backing reader | Any `MemoryReader`; the detectors and the segment map read their container through it. |
| Detectors | `Detectors(limits)` or a caller's list; none given means the defaults. |
| Limits | `MaxTableEntries` (lime ranges, ELF program headers), `MaxListEntries` (ELF notes), `MaxBufferBytes` (one ELF note segment). A zero `Limits` is taken through `Effective`, which gives the defaults. |
| Acquisition config | `Source` (path), `Strict`, `Options` (`live_reader` for the deprecated live provider), `Limits`. |

## 3. Facts from the sources

### 3.1 Windows crash dumps

| # | Fact | Source |
|---|---|---|
| W1 | `KeInitializeCrashDumpHeader` "supplies the header information the system requires for a crash dump file". "To create a crash-dump file, call KeInitializeCrashDumpHeader to create the header, then append the contents of memory to the header." `DumpType`: "The only valid value is DUMP_TYPE_FULL." From Windows 8 the routine "always writes the base address of the system process page directory to the crash-dump header". | Microsoft Learn, "KeInitializeCrashDumpHeader function (ntddk.h)", ms.date 2018-04-30, accessed 2026-11-12 |
| W2 | `_PHYSICAL_MEMORY_DESCRIPTOR` is 0x20 bytes: `NumberOfRuns` (unsigned int) at 0, `NumberOfPages` (unsigned long long) at 8, `Run` (`_PHYSICAL_MEMORY_RUN[1]`) at 0x10. `_PHYSICAL_MEMORY_RUN` is 0x10 bytes: `BasePage` at 0, `PageCount` at 8, both unsigned long long. Same on all four kernel tables. | ntkrnlmp PDBs through the project's symbol tables (`capturefacts -vsym`): 26100 (0D960CE103763A6097E839406D8B369F, 953A8DE880B0818C32DA2DEC1D79C2D9), 19045 (F57E740B088E5056E8AF0772F1CC5BEB), 14393 (3DFC5F7228304C26859E55E481700385) |
| W3 | `_KUSER_SHARED_DATA.InterruptTime` is at 0x8 and `SystemTime` at 0x14, both `_KSYSTEM_TIME` (`LowPart` at 0, `High1Time` at 4) on all four tables. The structure sits at `KI_USER_SHARED_DATA`, 0xFFFFF78000000000 on x64 (S66 CD2). | Same tables; WDK `wdm.h` as documented on Microsoft Learn |
| W4 | No kernel table has a type for the dump header itself. | Same tables |
| W5 | `IMAGE_FILE_MACHINE_AMD64` is 0x8664. | Microsoft Learn, "PE Format", Machine Types, accessed 2026-11-12 |

### 3.2 The lime range format

| # | Fact | Source |
|---|---|---|
| L1 | Each range is preceded by a packed header: `unsigned int magic` (0x4C694D45), `unsigned int version`, `unsigned long long s_addr` ("Starting address of range"), `unsigned long long e_addr` ("Ending address of range"), `unsigned char reserved[8]` ("Currently all zeros"): 32 bytes. The document describes version 1 only. | The format's published description, `docs/README.md` of its distribution, section "Memory Range Header Version 1 Specification", accessed 2026-11-12 (the program is not named here, by the owner's rule) |
| L2 | The same distribution offers three output formats: one where "each range [is] prepended with fixed-size header", one that "pads all non-System RAM ranges with 0s, starting from physical address 0", and one that "concatenates all System RAM ranges" and loses their positions. Compression, when chosen, makes the whole file a zlib stream. | Same distribution, `README.md`, accessed 2026-11-12 |

The document does not say whether `e_addr` is inclusive, and says nothing about bytes after the last range. Both were measured (C6, C7).

### 3.3 ELF core files

| # | Fact | Source |
|---|---|---|
| E1 | `e_ident`: magic `ELF`, `EI_CLASS` (byte 4) 1 = 32-bit, 2 = 64-bit; `EI_DATA` (byte 5) 1 = little-endian, 2 = big-endian. `e_type` (offset 16) `ET_CORE` = 4. ELF64 header 64 bytes with `e_phoff` 32, `e_shoff` 40, `e_phentsize` 54, `e_phnum` 56, `e_shentsize` 58; ELF32 header 52 bytes with 28, 32, 42, 44, 46. `sh_info` is at offset 44 of an ELF64 section header and 28 of an ELF32 one. | System V ABI, generic ABI, "ELF Header" and "Sections" (DRAFT, 10 June 2013, sco.com/developers/gabi/latest), accessed 2026-11-12; `ET_CORE` in `include/uapi/linux/elf.h` at v4.19, v6.1, v6.4, v6.14, v6.17 |
| E1a | A core with more than 0xfffe segments stores `PN_XNUM` (0xffff) in `e_phnum` and the real count in `sh_info` of its one section header. The 2013 gABI draft does not describe this. | `PN_XNUM` in `elf.h` v4.19:62, v6.1:67, v6.4:67, v6.14:67, v6.17:69; `fs/binfmt_elf.c` (`shdr4extnum->sh_info = segs`, `e_phnum = segs > PN_XNUM ? PN_XNUM : segs`) v4.19:2202, 2261; v6.1:2186, 2220; v6.4:2016, 2050; v6.14:2003, 2037; v6.17:1959, 1993 |
| E2 | Program header: ELF64 `p_type` 0, `p_offset` 8, `p_paddr` 24, `p_filesz` 32, `p_memsz` 40, `p_align` 48 (56 bytes); ELF32 `p_type` 0, `p_offset` 4, `p_paddr` 12, `p_filesz` 16, `p_memsz` 20, `p_align` 28 (32 bytes). `PT_LOAD` = 1, `PT_NOTE` = 4. `p_paddr`: "On systems for which physical addressing is relevant, this member is reserved for the segment's physical address." If `p_memsz` exceeds `p_filesz`, "the 'extra' bytes are defined to hold the value 0". A note entry is `namesz`, `descsz`, `type` (4-byte words), then the name and the descriptor; the gABI pads them to 8 bytes in a 64-bit file and 4 in a 32-bit one, while Linux core files pad to 4 in both (E5, E6). | gABI, "Program Header", "Note Section"; `elf.h` at the five tags (PT_LOAD line 27, 27, 27, 27, 29) |
| E3 | The kernel's capture header for a crash kernel has one `PT_NOTE` per possible CPU, one `PT_NOTE` for VMCOREINFO, an optional `PT_LOAD` for the kernel text with `p_paddr = __pa_symbol(_text)`, and one `PT_LOAD` per RAM range with `p_paddr = mstart` and `p_filesz = p_memsz = mend - mstart + 1`. Its own comment: the kernel text "will be mapped in two ELF headers". | `kernel/kexec_file.c` v4.19:1148-1222, v6.1:1240-1310, v6.4:1255-1325; `kernel/crash_core.c` v6.14:177-251, v6.17:192-266 |
| E4 | `/proc/kcore` sets `p_paddr = __pa(addr)` for RAM, `__pa_symbol` for kernel text and `(elf_addr_t)-1` for anything else, and writes notes `CORE`/`NT_PRSTATUS`, `CORE`/`NT_PRPSINFO`, `CORE`/`NT_TASKSTRUCT` and a VMCOREINFO note. | `fs/proc/kcore.c` v4.19:367-423, v6.1:391-447, v6.4:389-444, v6.14:403-459, v6.17:403-459 |
| E5 | The VMCOREINFO note's name is `"VMCOREINFO"`, type 0. `/proc/vmcore` walks notes until `n_namesz` is 0, rounding name and descriptor sizes to 4. | `include/linux/crash_core.h` v4.19:24, v6.1:24, v6.4:24; `include/linux/vmcore_info.h` v6.14:24, v6.17:23; `fs/proc/vmcore.c` v4.19:699, v6.1:747, v6.4:746, v6.14:763, v6.17:763 |
| E6 | A process core written by the kernel carries `CORE` notes `NT_PRSTATUS`, `NT_PRPSINFO`, `NT_AUXV` (6), `NT_SIGINFO` (0x53494749) and `NT_FILE` (0x46494c45), sets `p_paddr = 0` on every segment, and aligns notes to 4 bytes. `NT_AUXV`, `NT_SIGINFO` and `NT_FILE` appear only there. | `fs/binfmt_elf.c`: auxv/siginfo/file notes v4.19:1579, 1589, 1677; v6.1:1623, 1630, 1723; v6.4:1622, 1629, 1722; v6.14:1606, 1613, 1709; v6.17:1555, 1562, 1658. `p_paddr = 0` v4.19:2337, v6.1:2278, v6.4:2108, v6.14:2095, v6.17:2051. 4-byte note alignment v4.19:1441, v6.1:1487, v6.4:1486, v6.14:1470, v6.17:1416 |

### 3.4 Files that are not memory images

| # | Fact | Source |
|---|---|---|
| Z1 | A zlib stream starts with `CMF` and `FLG`. `CM` (bits 0 to 3 of `CMF`) 8 is deflate; for it `CINFO` (bits 4 to 7) is the window size's base-2 logarithm less 8, and values above 7 "are not allowed". `FCHECK` (bits 0 to 4 of `FLG`) makes `CMF*256 + FLG` "a multiple of 31". `FDICT` (bit 5) means a 4-byte dictionary identifier follows; a format that uses no preset dictionary "must not set the FDICT flag", and a decompressor "must reject" a stream that sets it. | RFC 1950, "ZLIB Compressed Data Format Specification version 3.3", sections 2.2 and 2.3, accessed 2026-11-12 |
| Z2 | A minidump starts with `MINIDUMP_HEADER.Signature`, the bytes `MDMP` on a dump Windows wrote. | S73 F1, M1 |

### 3.5 Measurements

All from `capturefacts`, run 2026-11-12 on the captures in E:\dataset\memory. The script reads each container itself, without the package, then opens the file through `DetectFormat` and compares 4 KiB at the start, middle and end of every piece (up to 64 pieces) with the file bytes its own parse placed there, and reads the first byte of every hole.

| # | Measured |
|---|---|
| C1 | Inventory: mem1_win11 (0x288000000 bytes), mem2_win10 (0x108000000), mem5_server2016 (0x108000000) begin with zeros and carry no signature. mem6_server2025 (0x744F2000) and mem7_server2025 (0x7FEF2000) begin `PAGEDU64`. mem3_ubuntu24 (0x7CEE801B) and mem4_fedora40 (0x7FEE709B) begin with the lime magic, little-endian. The five headerless process region captures (`*.exe.bin`) and the minidump `msedge_server2016.dmp` (`MDMP`) carry none of the three signatures. |
| C2 | Crash dump header fields, found by matching values known from elsewhere: `MajorVersion` 0x08 (15) and `MinorVersion` 0x0C (26100, the build); `DirectoryTableBase` 0x10 (0x7D5000, the System root S53 finds); `PfnDataBase` 0x18; `PsLoadedModuleList` 0x20 and `PsActiveProcessHead` 0x28 (the kernel symbols' addresses, S66 CM4); `MachineImageType` 0x30 (0x8664, W5); `NumberProcessors` 0x34 (4); `BugCheckCode` 0x38; `KdDebuggerDataBlock` 0x80; the physical memory descriptor at 0x88 (W2: `NumberOfRuns` 0x88, `NumberOfPages` 0x90, runs from 0x98; the word at 0x8C is fill). Unset header words hold `PAGE` (785 of 2,048 words on mem6, 1,678 on mem7). |
| C3 | mem7, 4 runs (array ends at 0xD8): `DumpType` 0xF98 = 1; 0xFA0 = 0x7FEF2000, the file size; `SystemTime` 0xFA8; a 128-byte comment field at 0xFB0 holding only `PAGE`; `SystemUpTime` 0x1030. Against `_KUSER_SHARED_DATA` (W3) read through the header's root, the header's up time is 605,087 ticks behind `InterruptTime` and its system time 605,087 ticks behind `SystemTime`: the same moment, 60.5 ms earlier. |
| C4 | mem6, 309 runs (array ends at 0x13E8, past 0xF98): the 8 bytes at 0xFA0, run 240's `PageCount`, hold 0x744F2000, the file size, as on mem7. The page counts then add up to 0x745664EF against the header's 0x744F0; the header total less the other 308 runs is 1, and run 241 starts 3 pages after run 240. Every other run is ascending and apart. |
| C5 | On both dumps the file is exactly 0x2000 + `NumberOfPages` × 0x1000 bytes, and the runs' pages follow the header in run order: with run 240 recounted to 1, every compared read matches (234 on mem6, 12 on mem7), and the root at 0x10 translates `KI_USER_SHARED_DATA` to a page whose clocks agree with the header (C3). |
| C6 | Lime: mem3 has 129 ranges, mem4 5, all version 1, all reserved bytes zero, ascending, no bytes after the last range. Every next header sits at `pos + 32 + e_addr − s_addr + 1`, never at `e_addr − s_addr`: `e_addr` is inclusive. Every `s_addr` is page-aligned. |
| C7 | The ranges that end a contiguous run of RAM (5 on mem3, all 5 on mem4) end one byte below a page boundary (`e_addr` 0x9FFFE, 0x7EBFDFFE, ...); mem3's 124 other ranges, 16 MiB pieces of one run, end on a page's last byte. The RAM ranges the machine had end on page boundaries (mem7, a VM of the same kind, holds 0x1000–0xA0000), so the capture lacks the last byte of each RAM range. |
| C8 | A process core written by a debugger on Linux 6.18 (WSL2, `/bin/sleep`): `ET_CORE`, 7 `PT_LOAD`, all with `p_paddr` 0; notes `CORE` types 1, 2, 3, 6, 0x46494C45, 0x53494749, `LINUX` 0x202, and one note under the debugger's own owner name; note segment `p_align` 1. No ELF capture of physical memory is present (O5). |

## 4. Algorithm

### 4.1 Reader contract

1. `ReadAt(offset, size)` returns exactly `size` bytes or an error; a short slice with no error is never returned.
2. A zero-byte read returns an empty slice and no error, wherever it points.
3. A size above `math.MaxInt` fails with `ErrSizeOverflow` before anything is allocated. A span that wraps or ends past `Size()` fails with `ErrOutOfBounds`. An address below `Size()` that no segment holds fails with `ErrUnmapped`.
4. A reader whose bytes never change says so through `ImmutableSnapshot()`; `IsImmutableSnapshot` is true only for a reader that has the method and returns true. Caches above (S53's entry cache) use it.

### 4.2 File reader

`NewFileMemoryReader` opens the path; `NewFileMemoryReaderFromFile` takes an open file, refuses a directory and records its size once. Reads are `os.File.ReadAt` at the offset, safe from several goroutines. A short read is `io.ErrUnexpectedEOF`. The reader is an immutable snapshot (a capture file is not written while read). `Close` closes the file.

### 4.3 Segment map

1. Segments of length 0 are dropped.
2. A segment whose physical end or file end wraps, or whose file end passes the backing's size, is refused (`ErrSegments`).
3. The rest are sorted by physical base; a segment starting below the previous end is refused as overlap.
4. `Size()` is the highest physical end.
5. A read first finds the segment holding its first byte (binary search), then proves every byte up to its end is held by consecutive segments, then allocates once and copies from the backing. A hole fails with `ErrUnmapped` naming its first address; a short backing read fails with `ErrOutOfBounds`.
6. `Segments()` returns a copy. Immutability follows the backing.

### 4.4 Held ranges and scan windows

1. `MappedRanges`: a reader with `Segments()` gives its segments sorted, with touching or overlapping ones joined. Any other reader gives `[0, Size())`, or nothing when empty.
2. `ScanWindows(r, step, overlap, visit)`: for each held range, windows start at the range start and every `step` bytes after it, each `step + overlap` bytes long (saturating) and cut at the range end. A window that cannot be read is counted in `Unreadable`, its first failure kept, and the scan goes on. `visit` returning true stops the scan. A step of 0 or no reader scans nothing and reports it.
3. A record of up to `overlap + 1` bytes starting at offset `o` in a window's first `step` bytes is whole in that window; every held offset lies in the first `step` bytes of exactly one window. Windows never cross a hole, so a record across a hole is never seen.
4. `Coverage.Incomplete` is nil when every window read; otherwise `ErrIncompleteScan` wrapping the count, the first failing address and its error.

### 4.5 Wrappers

1. `BufferedMemoryReader` keeps a copy of every successful read by exact offset and size until `Clear`; callers get copies, so changing a result cannot change the cache. Failed reads are not kept.
2. `FallbackReader` reads the primary, then each non-nil fallback in order, and returns the first success; when all fail the error joins every source's error. `Size` is the primary's.
3. `LayeredMemoryReader`: the first layer reads the base, each later layer reads the reader below it, and reads go to the last. `Size` is the base's.
4. `ScatterRead` reads each request on its own and keeps request order; a failure fills that result's `Error` and leaves the rest.

### 4.6 Detection

1. Detectors run in the order given (defaults: crash dump, lime, ELF, minidump, zlib). Each claims a file only by the signature at offset 0.
2. The first detector that claims the file and returns a reader decides the format, named by `Name()` (`crashdump`, `lime`, `elf`). The `minidump` and `zlib` detectors return no reader: they only refuse.
3. A detector that claims the file and fails returns its error, and detection stops: a claimed file is never read as raw, because its header bytes would be served as memory.
4. A file no detector claims is the backing reader itself, format `raw`. File names and extensions are not looked at.
5. `MDMP` at offset 0 (Z2) is a minidump of one process and is refused with `ErrMinidump` (O9).
6. A zlib stream is refused with `ErrCompressed` (O8), as a compressed file read as raw would serve its compressed bytes as memory. The file is claimed only when all of these hold: it has at least 3 bytes; `CM` is 8, `CINFO` at most 7 and `CMF*256 + FLG` a multiple of 31 (Z1); `FDICT` is clear (Z1: a capture program has no dictionary to name, and the stream could not be decoded here); and the deflate data after the two header bytes, taken from the first 64 KiB of the file, decodes to 4 KiB, or to at least one byte before that input runs out, without a corrupt-data error. About one random file in two thousand passes the two-byte check alone, so the decode is what keeps a raw capture from being refused by chance. A stream that sets `FDICT` is not claimed and opens as raw.

### 4.7 Windows 64-bit full crash dump

1. Claimed by `PAGEDU64` at offset 0. `PAGEDUMP` (the 32-bit form) is claimed and refused: its layout was not measured (O3).
2. The header is the first 0x2000 bytes (C5); a shorter file is refused.
3. Fields are read at the offsets of C2 and C3. `NumberOfRuns` must be 1 to 502, the most whose 16-byte entries (W2) fit between 0x98 and 0x2000.
4. The fields from `DumpType` on are given only when the run array ends at or before 0xF98 (`DumpTypeIntact`): past it those bytes are run entries (C4). When given, `DumpType` must be 1, `DUMP_TYPE_FULL` (W1, value C3).
5. The page counts must add up to `NumberOfPages`. When they do not and the array reaches run 240, the one entry C4 shows the writer overwrites, run 240's count is set to the total less the other runs, provided that is at least 1 and fits before run 241. `RepairedRun` and `RepairedPageCount` record it, otherwise `RepairedRun` is −1. Any other mismatch is refused.
6. Runs must be ascending and apart (`BasePage + PageCount` ≤ next `BasePage`), and no page number may pass the 64-bit address space.
7. The file must hold 0x2000 + `NumberOfPages` × 0x1000 bytes (C5).
8. Run `i` maps physical `BasePage × 0x1000` from file offset 0x2000 plus 0x1000 times the pages of the runs before it (W1, C5). Runs of 0 pages map nothing.

### 4.8 Lime ranges

1. Claimed by the magic 0x4C694D45 (little-endian) at offset 0.
2. From offset 0, read 32-byte headers (L1). Each must carry the magic and version 1; `e_addr` must not be below `s_addr`, and the range may not be the whole 64-bit space.
3. The range is `e_addr − s_addr + 1` bytes (C6), stored right after its header, and must fit in the file. The next header follows its data.
4. More ranges than `MaxTableEntries` are refused.
5. Bytes after the last range that do not start a header are accepted only when all are zero, and noted; anything else is refused, so a damaged header in the middle stops the open rather than hiding the rest. The tail is checked a page at a time.
6. The ranges become segments; overlapping ranges are refused (4.3). Reserved bytes are not checked (O8).

### 4.9 ELF core

1. Claimed by `\x7fELF` at offset 0. Class, data encoding and `e_type` = `ET_CORE` are required (E1); the header is read in either class and byte order.
2. Program headers: `e_phentsize` must be at least the class's entry size; `PN_XNUM` takes the count from section header 0 (E1a); the count must be 1 to `MaxTableEntries` and the table must fit in the file.
3. Notes: every `PT_NOTE` segment with bytes, at most `MaxBufferBytes` long and inside the file, is walked. Alignment is 4 bytes, as Linux writes it (E5, E6), or 8 when the segment's `p_align` is 8, as the gABI's 64-bit rule would have it (E2). The walk of a segment ends at `namesz` 0 (E5) or at an entry that does not fit; at most `MaxListEntries` notes are walked in all.
4. A note named `VMCOREINFO` marks a kernel capture (E3, E4, E5), whatever else is present. Otherwise a `CORE` note of type `NT_AUXV`, `NT_SIGINFO` or `NT_FILE`, which only process dumps carry (E6), refuses the file with `ErrProcessCore`, before any address is looked at. A core with neither is read.
5. Each `PT_LOAD` with file bytes and a physical address becomes a segment of `p_filesz` bytes at `p_paddr` from `p_offset`. A `p_paddr` of all ones (E4) has no physical place and is left out, noted. Bytes past `p_filesz` up to `p_memsz` are not mapped (O6).
6. Segments are sorted by base, longer first at equal bases. One lying wholly inside an earlier one is the same memory mapped twice (E3) and is left out, noted. A partial overlap is refused.
7. A core with no segment left is refused.

### 4.10 Acquisition

1. `ValidateProviderContract` opens one session: the name must be non-empty, `Open` must give a session or an error, the session a reader, every diagnostic a known category and the provider's own name, and `Close` must succeed.
2. The file provider (`file`) needs `Source`, opens the file, runs `DetectFormat` with `Detectors(config.Limits)`, and closes the file if detection fails. With `Strict` set, a container that needed a repair (a recounted run, 4.7 step 5, or a zero tail, 4.8 step 5) is refused with `ErrStrictRepair` naming each repair, and the file is closed (O7); left-out ELF segments (4.9 steps 5 and 6) are not repairs and do not refuse. Otherwise its session reports `provider_open` "opened as <format>" and one `provider_read` diagnostic per container note (repairs first, then left-out ELF segments). `Close` closes the file once.
3. The reader provider (`reader`) serves the reader it was built with and never closes it. The deprecated live provider (`live`) serves the `MemoryReader` in option `live_reader`.
4. `NewProviderSelector` refuses no providers, a nil provider, an empty name or a repeated name. `Select` tries the preferred names in the caller's order (repeats ignored, an unknown name refused), then the rest by name, and returns the first session with the provider's name. When all fail the error is `ErrNoProvider` joined with each provider's error, so a refusal such as `ErrProcessCore` reaches the caller.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Read size fits `int` | 4.1, allocation | `ErrSizeOverflow` |
| Read inside `Size()` | 4.1 | `ErrOutOfBounds` |
| Every byte of a read held | 4.3 | `ErrUnmapped` |
| Segments inside the file, not wrapping, not overlapping | 4.3 | `ErrSegments` |
| Crash dump header complete, 1 to 502 runs | C5, W2 | `ErrCrashDump` |
| `DumpType` 1 when intact | W1, C3 | `ErrCrashDump` |
| Run counts add up, at most run 240 recounted, within the gap to run 241 | C4 | `ErrCrashDump` |
| Runs ascending and apart, inside the address space | W2, C4 | `ErrCrashDump` |
| File holds every page | C5 | `ErrCrashDump` |
| Lime magic and version 1 on every header | L1, C6 | `ErrLime` |
| Lime range inside the file, end not below start | L1, C6 | `ErrLime` |
| Lime tail zero | 4.8 step 5 | `ErrLime` |
| ELF class, encoding, `ET_CORE`, program table inside the file | E1, E2 | `ErrELFCore` |
| No process-dump notes without VMCOREINFO | E5, E6, C8 | `ErrProcessCore` |
| Load segments inside the file, nested or apart | E3, E4 | `ErrELFCore` |
| Not a minidump | Z2, O9 | `ErrMinidump` |
| Not a decodable zlib stream | Z1, O8 | `ErrCompressed` |
| No repaired container in strict mode | O7 | `ErrStrictRepair` |

## 6. Failure modes

| Case | Result |
|---|---|
| Capture cannot be opened or is a directory | `memory: open <path>: <os error>`, `memory: <path> is a directory` |
| Claimed container breaks a rule | `ErrCrashDump`, `ErrLime`, `ErrELFCore` or `ErrProcessCore` with the offset and values, for example `memory: crash dump unusable: run page counts do not add up to the header's 0x10 pages` |
| 32-bit crash dump | `memory: crash dump unusable: 32-bit dump layout is not read` |
| Limits hit | `memory: lime capture unusable: more than <n> ranges, the MaxTableEntries limit`; the ELF program-header, note and note-segment equivalents |
| Repaired run, zero tail, left-out segments | Opened; a `provider_read` diagnostic, e.g. `memory: crash dump: run 240 page count 0x1 taken from the page total; its slot held 0x744f2000` |
| Unreadable scan window | Counted; `Coverage.Incomplete()`: `memory: scan windows unreadable: 1 of 4 windows, first at 0x10: <error>` |
| No provider opens the source | `memory: no acquisition provider opened the source: provider file: <error>` |
| Minidump | `memory: minidump of one process, not a memory image: signature MDMP at offset 0` |
| Zlib stream | `memory: zlib stream, not a memory image: rfc 1950 header and a deflate stream at offset 0; decompress it first` |
| Strict mode and a repaired container | `memory: open <path>: memory: strict mode refuses a container that needed a repair: <each repair, joined by "; ">` (O7) |

## 7. Result schema

The exported API is kept as it was; this lists what each name means.

- `MemoryReader` (`ReadAt`, `Size`); `ImmutableSnapshot`, `IsImmutableSnapshot`; sentinels `ErrOutOfBounds`, `ErrSizeOverflow`, `ErrUnmapped`, `ErrProcessCore`.
- `FileMemoryReader`: `NewFileMemoryReader`, `NewFileMemoryReaderFromFile`, `ReadAt`, `Size`, `ImmutableSnapshot`, `Close`.
- `Segment{PhysicalBase, FileOffset, Length}` (bytes); `SegmentedReader`: `NewSegmentedReader`, `ReadAt`, `Size`, `Segments`, `ImmutableSnapshot`.
- `Range{Start, End}` (physical, `End` exclusive); `MappedRanges`; `ScanWindows`; `Coverage{Windows, Unreadable}` with `Incomplete`.
- `BufferedMemoryReader` (`NewBufferedMemoryReader`, `Clear`), `FallbackReader` (`NewFallbackReader`), `Layer`, `LayeredMemoryReader` (`NewLayeredMemoryReader`), `ScatterRequest{Offset, Size, Tag}`, `ScatterResult{Request, Data, Error}`, `ScatterRead`.
- `FormatDetector` (`Name`, `Detect`), `DefaultDetectors`, `Detectors`, `DetectFormat` (reader, format name, error).
- `CrashDumpReader` (embeds `*SegmentedReader`; `CrashHeader`) and `CrashDumpHeader`: `MajorVersion`, `MinorVersion`, `DirectoryTableBase`, `PfnDataBase`, `PsLoadedModuleList`, `PsActiveProcessHead`, `MachineImageType`, `NumberProcessors`, `BugCheckCode`, `KdDebuggerDataBlock`, `NumberOfRuns`, `NumberOfPages` as stored; `DumpType`, `SystemTime` (FILETIME ticks), `SystemUpTime` (100 ns ticks) and `Comment` (128 bytes as stored) only when `DumpTypeIntact`, zero otherwise; `RepairedRun` (−1 when none) and `RepairedPageCount`.
- Acquisition: `AcquisitionConfig`, `AcquisitionDiagnostic{Category, Provider, Message}` (JSON `category`, `provider`, `message`), `DiagnosticCategory` (`provider_config`, `provider_open`, `provider_read`, `provider_close`), `AcquisitionProvider`, `AcquisitionSession`, `ValidateProviderContract`, `NewFileProvider`, `NewReaderProvider`, `NewLiveProvider` (deprecated), `ProviderSelector` with `NewProviderSelector` and `Select`.
- New sentinels: `ErrSegments`, `ErrIncompleteScan`, `ErrCrashDump`, `ErrLime`, `ErrELFCore`, `ErrProviderConfig`, `ErrProviderContract`, `ErrNoProvider`; from the owner decisions of 2026-11-12, `ErrMinidump`, `ErrCompressed` and `ErrStrictRepair`.

## 8. Limits

- `MaxTableEntries`: lime ranges and ELF program headers, each a table read from the file.
- `MaxListEntries`: ELF notes walked across all note segments.
- `MaxBufferBytes`: one ELF note segment, read whole.
- The crash dump needs no limit: its run array is bounded by the 0x2000-byte header (502 runs).
- `ScanWindows` reads one window at a time; the caller's step and overlap bound it.

## 9. Acceptance

1. Synthetic fixtures (`memory/*_test.go`, 47 tests and 2 examples): the reader contract on files and segment maps (exact spans, zero-byte reads, wrap, overflow, holes, a refused 1 TiB hole read allocating almost nothing, short backings); segment lists refused for overlap, equal bases, file end, wraps; held ranges joined across touching segments; every short record whole in exactly one window, windows cut at holes, unreadable windows counted, a stopping visitor, a zero step, a window at the top of the address space; buffer copies and `Clear`, fallback order and joined errors, layer order, scatter order; detection by signature, raw fallback, a claimed damaged file not read as raw; crash dumps mapped in run order with every header field at its offset, the overrun boundary at 240 runs, run 240 recounted, and 13 refusals; lime inclusive ends, zero tails, 8 refusals and the range cap; ELF cores in both classes and byte orders and with `PN_XNUM`, register-only cores read, process cores refused for each of the three note types, another owner's type 6 ignored, VMCOREINFO winning, 8-byte note alignment, nested and unplaced segments left out, 8 refusals and three limits; providers, the contract check and the selector's order and errors; a minidump refused; zlib streams of zeros, a pattern and a few bytes refused, while a two-byte header, wrong check bits, a window above 7, another method, a preset dictionary and corrupt deflate data open as raw; strict mode refusing a recounted run and a zero tail that open without it, and opening a clean lime file.
2. Fuzz targets, each run 30 s on 2026-11-12 with no failure: `FuzzCrashDump` (96,066 executions; accepted dumps' segments hold exactly `NumberOfPages` and serve their file bytes), `FuzzLime` (5,578,975), `FuzzELFCore` (4,372,548), `FuzzSegmentedRead` (5,581,854; every served byte is its segment's file byte), `FuzzScanWindows` (4,995,440; every offset owned once, windows equal the data), `FuzzZlibDetect` (3,851,392; nothing served, and a claimed file carries a valid RFC 1950 header).
3. On the captures (`capturefacts`, 2026-11-12):

| Capture | Format | Pieces | Held ranges | Bytes held | Size | Compared reads differing | Holes giving `ErrUnmapped` |
|---|---|---|---|---|---|---|---|
| mem1_win11 | raw | 1 | 1 | 10,871,635,968 | 0x288000000 | 0 of 3 | none |
| mem2_win10 | raw | 1 | 1 | 4,429,185,024 | 0x108000000 | 0 of 3 | none |
| mem5_server2016 | raw | 1 | 1 | 4,429,185,024 | 0x108000000 | 0 of 3 | none |
| mem6_server2025 | crashdump, run 240 recounted to 1 | 309 | 309 | 1,951,334,400 | 0x80000000 | 0 of 234 | 309 of 309 |
| mem7_server2025 | crashdump | 4 | 4 | 2,146,369,536 | 0x80000000 | 0 of 12 | 4 of 4 |
| mem3_ubuntu24 | lime | 129 | 6 | 2,096,001,019 | 0x7FFFFFFF | 0 of 195 | 6 of 6 |
| mem4_fedora40 | lime | 5 | 5 | 2,146,332,667 | 0x7FFFFFFF | 0 of 15 | 5 of 5 |

   Every detection took under 1.1 ms. The process region captures open as raw (C1); the debugger-written process core is refused with `ErrProcessCore` (C8). `capturefacts -strict`, 2026-11-12, on every capture file in E:\dataset\memory (the seven captures, the five process region captures and the minidump): the zlib detector claims none; the minidump is refused with `ErrMinidump`; in strict mode mem6 is refused with `ErrStrictRepair` (run 240 recounted, C4) and every other capture opens. The crash dump header the reader gives agrees with the script's own parse on both dumps. Sessions open through the file provider and identify their kernel on mem2, mem6, mem7, mem3 and mem4 (`bannerfacts -tool -nofacts`, 2026-11-12).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | No primary source documents the 64-bit dump header past the physical memory descriptor. Every offset of C2 and C3 rests on two Server 2025 dumps of build 26100. | Owner decision: accept the measured layout (default), or a Microsoft source; a dump from another build |
| O2 | The recount of run 240 rests on one capture (C4). Whether the writer overwrites other run slots (`DumpType` at 0xF98 was not overwritten on mem6) is unknown, so only that slot is recounted. | More dumps with over 240 runs |
| O3 | 32-bit (`PAGEDUMP`) and bitmap or kernel-only dumps are refused: neither layout was measured, and `DUMP_TYPE_FULL`'s value is not in the public headers (S66 CO2). A non-full dump whose run array hides `DumpType` is caught only by the file-size rule. | Owner decision; captures of those kinds |
| O4 | Each RAM range in both lime captures lacks its last byte (C7), so a page-sized read of the last page of every RAM range fails with `ErrUnmapped`. The reader serves what the file holds. Owner decision: keep (default), or serve the missing byte of a range ending one below a page boundary as zero. | Owner decision; a capture from the current writer |
| O5 | No ELF capture of physical memory (crash-kernel `/proc/vmcore`, `/proc/kcore`) was available; the ELF reader rests on the kernel sources and synthetic files. | A vmcore from a lab VM |
| O6 | Bytes past `p_filesz` up to `p_memsz` are not mapped, though the gABI defines them as zero; for a capture they were never read. | Owner decision |
| O7 | `AcquisitionConfig.Strict` changes nothing here. A recounted run or a zero tail is opened with a diagnostic even in strict mode. | Owner decision: refuse them in strict mode. Owner decision 2026-11-12: refuse in strict mode. Done: the file provider refuses a repaired container with `ErrStrictRepair` in strict mode (4.10 step 2); mem6 is refused in strict mode; memory/providers.go, memory/segments.go, memory/crashdump.go, memory/lime.go, memory/acquire_test.go. Owner decision 2026-11-12 (follow-up D17): accept that strict mode refuses mem6, whose run 240 is recounted. Done: no change. |
| O8 | Lime reserved bytes are not checked (L1 says "currently" zero; C6 found them zero). The padded and plain-concatenation outputs of L2 have no header: the first reads correctly as raw, the second cannot be placed and also opens as raw. A compressed file opens as raw. | Owner decision: refuse a zlib stream (RFC 1950 header). Owner decision 2026-11-12: refuse zlib streams. Done: a `zlib` detector refuses a file whose RFC 1950 header is valid and whose deflate data decodes (4.6 step 6, Z1) with `ErrCompressed`; no capture in E:\dataset\memory is claimed; memory/detect.go, memory/detect_test.go, `FuzzZlibDetect`. Reserved bytes and the headerless outputs are unchanged. |
| O9 | A minidump (`MDMP`) and other non-memory files open as raw (C1). Refusing them like a process core is the alternative. | Owner decision. Owner decision 2026-11-12: refuse MDMP files. Done: a `minidump` detector refuses `MDMP` at offset 0 with `ErrMinidump` (4.6 step 5, Z2); `msedge_server2016.dmp` is refused; memory/detect.go, memory/detect_test.go. Other headerless non-memory files still open as raw. |
| O10 | The live provider captures nothing; it is kept, deprecated, because it is exported. | Owner decision: remove in a later version |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept measured layout |
| O2 | Recount that slot only |
| O3 | Refuse |
| O4 | Serve what the file holds |
| O5 | Provide a vmcore |
| O6 | Unmapped |
| O7 | Refuse in strict mode |
| O8 | Refuse zlib streams |
| O9 | Refuse MDMP files |
| O10 | Keep deprecated |

## 11. Provenance

Written from Microsoft Learn, RFC 1950, the kernel PDB types of the captures' own kernels read through the project's symbol tables, the ELF gABI, the Linux kernel sources at v4.19, v6.1, v6.4, v6.14 and v6.17, the lime format's published description, and the project's measurements. The previous implementation was read only for exported names, signatures, callers and the option key `live_reader`. Every rule rests on the sources and measurements above.
