# S55: Windows kernel modules and the PE dump

Version 1, 2026-11-12.

## 1. Purpose

An examiner asks which drivers the kernel had loaded, where each one lay, and which of them owns an address seen elsewhere: a callback routine, a service table entry, a thread start, a timer routine. Windows keeps that inventory in the loader's list of loaded kernel images. Many tools need the same answers, so this specification defines one reader of that list, one rule for where system space starts, one way to attribute an address to a module, and the base and name filters over the list.

The second half is the PE dump. An examiner who has found a module wants it as a file. The dump rebuilds each loaded image, of a process or of the kernel, through the S18 rebuild and writes it under an S00 artefact name. It also dumps a single image at an address the examiner gives.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | Kernel virtual reads (`tools.Context.Memory`). |
| Process spaces | `tools.Context.ProcessSpace` for process modules, and for the sessions of session-space drivers. |
| Symbol table | The kernel types of section 3 and the globals `PsLoadedModuleList` and `MmSystemRangeStart`. |
| Paging mode | `paging_mode`: a name ending in `la57` means 5-level paging. |
| Options, module list | `windows.module.list.base` (unsigned), `windows.module.list.name` (text). |
| Options, PE dump | `output_dir` (required), `pid`, `windows.pe.dump.base` (unsigned), `windows.pe.dump.kernel_module` (boolean). |
| Limits | `MaxListEntries` (list walk), `MaxArtifactBytes` (largest image written, and the S18 cap). |
| Strict mode | A broken list fails the module list; a failed list fails the dump. |

On a Linux profile, `windows.module.list` lists the kernel's module list through the S06 and S07 model; section 4.2 covers it.

## 3. Facts from the sources

### Documentation and specifications

| # | Fact | Source |
|---|---|---|
| D1 | `ntddk.h` declares `extern NTKERNELAPI PVOID MmSystemRangeStart;` and `#define MM_SYSTEM_RANGE_START MmSystemRangeStart`, both for x86 and for AMD64, next to `MmHighestUserAddress` and `MmUserProbeAddress`. On x86 it also defines `MM_SYSTEM_SPACE_END 0xFFFFFFFF`. | WDK 10.0.28000.0 `km/ntddk.h` (NuGet Microsoft.Windows.WDK.x64 10.0.28000.1839), accessed 2026-11-12. |
| D2 | "All code that runs in kernel mode shares a single virtual address space called system space." "In 32-bit Windows … typically, the lower 2 gigabytes are used for user space, and the upper 2 gigabytes are used for system space"; with `increaseuserva` user space can grow "to as much as 3 gigabytes, leaving only 1 gigabyte for system space". "A 64-bit process on 64-bit Windows has a virtual address space within the 128-terabyte range 0x000'00000000 through 0x7FFF'FFFFFFFF." | Microsoft Learn, "Virtual Address Spaces" (windows-hardware/drivers/gettingstarted), dated 2024-06-28, accessed 2026-11-12. |
| D3 | "4-level paging translates the low 48 bits of each linear address, while 5-level paging translates the low 57 bits." "A linear address is canonical for 4-level paging (48-bit canonical) if bits 63:47 of the address are identical; it is canonical for 5-level paging (57-bit canonical) if bits 63:56 are identical." | Intel SDM Vol. 3A (253668-093US), 4.5. |
| D4 | CR4.LA57 set in IA-32e mode selects 5-level paging of 57-bit linear addresses; 32-bit paging and PAE paging translate 32-bit linear addresses. | Intel SDM Vol. 3A (253668-093US), 2.5, 5.3, 5.4. |
| D5 | `SizeOfImage` is "the size (in bytes) of the image, including all headers, as the image is loaded in memory". `AddressOfEntryPoint` is relative to the image base. | Microsoft Learn, "PE Format", accessed 2026-11-12 (S18 P3). |
| D6 | `LIST_ENTRY` links and the walk rules: S03 L1 to L4. | S03. |
| D7 | `UNICODE_STRING` is `{ USHORT Length; USHORT MaximumLength; PWSTR Buffer; }`, `Length` in bytes. | Microsoft Learn, "UNICODE_STRING structure (ntdef.h)", accessed 2026-11-12. |
| D8 | "Do not assume case sensitivity. For example, consider the names OSCAR, Oscar, and oscar to be the same." | Microsoft Learn, "Naming Files, Paths, and Namespaces", dated 2024-08-28, updated 2025-04-11, accessed 2026-11-12. |

### Kernel types

Read through the project's kernel tables with `kmodfacts -types` for builds 26100 (mem1, GUID 0D960CE103763A6097E839406D8B369F; mem6 and mem7, 953A8DE880B0818C32DA2DEC1D79C2D9), 19045 (mem2, F57E740B088E5056E8AF0772F1CC5BEB) and 14393 (mem5, 3DFC5F7228304C26859E55E481700385).

| # | Fact |
|---|---|
| T1 | `_KLDR_DATA_TABLE_ENTRY` is 0xa0 bytes in all five: `InLoadOrderLinks` (`_LIST_ENTRY`) 0, `DllBase` (pointer) 0x30, `EntryPoint` (pointer) 0x38, `SizeOfImage` (`unsigned int`) 0x40, `FullDllName` (`_UNICODE_STRING`) 0x48, `BaseDllName` (`_UNICODE_STRING`) 0x58, `Flags` 0x68, `TimeDateStamp` 0x9c. The 26100 tables add `NtDataTableEntry` at 0x90. |
| T2 | The tables also describe `_LDR_DATA_TABLE_ENTRY` (0x138 bytes on 26100, 0x120 on the others), with `InLoadOrderLinks`, `DllBase`, `SizeOfImage`, `FullDllName` and `BaseDllName` at the same offsets as T1. |
| T3 | `_UNICODE_STRING` is 16 bytes: `Length` 0, `MaximumLength` 2 (`unsigned short`), `Buffer` 8. `_LIST_ENTRY` is 16 bytes: `Flink` 0, `Blink` 8. |
| T4 | The tables have the globals `PsLoadedModuleList`, `PsLoadedModuleResource`, `MmSystemRangeStart`, `MmHighestUserAddress` and `MmUserProbeAddress`. None records a type for them. |

### Measurements

M1 to M8 come from `kmodfacts -raw -list` and `-tool -pid 0` on 2026-11-12 over mem1_win11, mem2_win10, mem5_server2016, mem6_server2025 and mem7_server2025, in that order. The raw mode walks `PsLoadedModuleList` with the S03 recovering walk and reads T1 directly; it does not use the tools of this specification.

| # | Measured |
|---|---|
| M1 | The walk lists 195, 195, 142, 158 and 165 entries. No walk breaks; no entry is found through `Blink`. The first entry is `ntoskrnl.exe`, at the session's kernel base, and the second `hal.dll`, in all five. |
| M2 | `MmSystemRangeStart` holds 0xFFFF800000000000 in all five; `MmHighestUserAddress` 0x7FFFFFFEFFFF and `MmUserProbeAddress` 0x7FFFFFFF0000. Every `DllBase` lies at or above `MmSystemRangeStart`, and is page-aligned; 3 on mem5 are not 64 KB aligned. |
| M3 | Every `SizeOfImage` is nonzero and a multiple of 0x1000; no range wraps and no two module ranges overlap. Every `EntryPoint` lies inside its own module; it equals the base plus the header's `AddressOfEntryPoint` for 190, 187, 137, 149 and 153 modules. |
| M4 | Every `BaseDllName` and `FullDllName` reads, with an even nonzero `Length`. Paths start with `\SystemRoot\` (194, 194, 141, 156, 164) or `\??\` (1, 1, 1, 2, 1). The base name differs from the path's last element for `kdcom.dll` (path `kd.dll`) and `mcupdate.dll` (path `mcupdate_AuthenticAMD.dll`) in all five, and for `dump_storport.sys` (path `dump_diskdump.sys`) on mem2, mem5, mem6 and mem7. |
| M5 | PE headers at each base read through the kernel space for 195, 188, 136, 154 and 158 modules, and only through a process of a session for 0, 4, 6, 0 and 0 (sessions with a process whose space opens: 2, 3, 3, 3, 3). They read nowhere for 0, 3, 0, 4 and 7: `volmgrx.sys`, `Fs_Rec.sys` and `Null.SYS` on mem2, mem6 and mem7, `msrpc.sys` on mem6 and mem7, and `win32k.sys`, `win32kbase.sys` and `win32kfull.sys` on mem7. Wherever the headers read, the header `SizeOfImage` equals the entry's. |
| M6 | The addresses of `PsLoadedModuleList`, `PsActiveProcessHead`, `KiServiceTable`, `MmSystemRangeStart` and `NtBuildNumber` lie inside `ntoskrnl.exe` and no other module in all five. |
| M7 | The process list names PID 4 `System` in all five. |
| M8 | A 64-bit kernel table and `x64` paging on all five; no capture uses 5-level paging or 4-byte pointers. |

## 4. Algorithm

### 4.1 The loaded-module list (Windows)

1. **Entry type.** `_KLDR_DATA_TABLE_ENTRY` when the table has its `InLoadOrderLinks` (T1); otherwise `_LDR_DATA_TABLE_ENTRY`, whose members of step 2 sit at the same offsets (T2). Neither: `ErrNoLoaderEntry`.
2. **Members.** `InLoadOrderLinks`, `DllBase`, `SizeOfImage` and `BaseDllName` are required; a missing one is an error naming it. `FullDllName` is optional: without it, paths are not read, with one diagnostic. `SizeOfImage` is read at the width the table gives; a table that gives none is read as 4 bytes, the `unsigned int` of T1. Reading 4 bytes, never a pointer's width, keeps the padding after it out of the size.
3. **Walk.** The head is the global `PsLoadedModuleList` (T4); none is `ErrNoListHead`. Walk it with the S03 recovering walk over the native `_LIST_ENTRY` layout (T3), with `MaxListEntries`, strict mode and the context's diagnostics. Each walked link minus the `InLoadOrderLinks` offset is an entry (S03 4.6). A link below that offset is skipped with a diagnostic. When the backward walk added entries, one diagnostic says how many.
4. **Each entry.** `Entry` is the entry's address. `Base` is `DllBase` as a pointer of the table's width, `Size` is `SizeOfImage`, `Name` is `BaseDllName` and `Path` is `FullDllName`, each `UNICODE_STRING` read with `util.ReadUnicodeString` (D7). A member that does not read leaves its value 0 or empty and sets its `…Unreadable` flag; an unread base or size adds a diagnostic. The module stays in the list either way.
5. **System-space check.** A base below the start of system space (4.3), or a `SizeOfImage` of 0, gives a diagnostic. The row stays as read: on the captures no entry breaks either rule (M2, M3), so one that does is damaged or forged, and hiding it would hide that.
6. **Order.** Walk order, which is load order (M1). No sort.

### 4.2 The module list on Linux

A Linux profile lists the module list view of the S06 model (`linuxmodule.New`, then `List`), with every address read in the canonical form of 4.3. The view's losses are reported as S07 reports them; in strict mode a lossy view is an error. Each module maps to `Entry` = the `struct module` address, `Base` = its text base, `InitSize` = the sum of its init regions, `Name` = its name, and the Linux fields: `Regions`, every region of the model in its order with its kind (`text`, `data`, `rodata`, `ro_after_init`, `init_text`, `init_data`, `init_rodata`, S06 F8), base and size, and `SeparateRegions`, true when the table has the v6.4 `module.mem` form. From v6.4 the kernel allocates each region on its own (`move_module` calls `module_memory_alloc` per type; up to v6.1 one `module_alloc` of `core_layout.size`; `kernel/module/main.c` v6.1, v6.4, v6.14, v6.17, `kernel/module.c` v4.19). So `Size` is the text region's size with separate regions, which keeps `[Base, Base + Size)` one allocation, and the sum of the core regions, one allocation, in the `core_layout` form. Linux has no path: `Path` is empty and not flagged.

### 4.3 Address space rules

1. **Address mask.** 32 bits with a 4-byte table (D4), 57 bits when the paging mode name ends in `la57` (D3, D4), otherwise 48 bits (D3). `AddressBits` is the number of bits in the mask.
2. **Canonical form.** With 4-byte pointers the masked address. Otherwise the masked address with the bits above the mask set when its top translated bit is set (D3).
3. **Upper half.** With 4-byte pointers 0x80000000, where system space starts by default (D2). Otherwise the lowest canonical address with the top translated bit set: 0xFFFF800000000000 with 4-level paging and 0xFF00000000000000 with 5-level paging (D3).
4. **System space start.** The pointer-wide value of `MmSystemRangeStart` (D1, T4). It is the kernel's own boundary and moves up on a 32-bit system that gave user space more than 2 GB (D2), so it is preferred to the upper half. A table without the symbol makes `KernelSpaceStart` return `ErrNoSystemRangeStart`. `windows.module.list` (`newSystemSpace`) drops that error and takes the upper half, with no diagnostic (O15); `windows.module.scan` (S64) fails with it. A value that does not read, lies below the upper half or is not canonical is replaced by the upper half, with a diagnostic. On every capture the value equals the upper half (M2).

### 4.4 Attribution

1. **Range.** A module's range is `[Base, Base + Size)`, known only when both read; a Linux module with separate regions holds an address when one of its `Regions` does. `Containing` gives every module with a known range that holds the address, in list order; the test is `address − Base < Size`, which cannot overflow.
2. **Placed.** `Placed` keeps the modules with a known range and names the entries of the others in one diagnostic, since no address can be given to them.
3. **Display name.** The base name with its last extension removed, unless that leaves only dots or nothing before the dot; separators are `\` and `/`.
4. **Kernel image.** Symbols come from the kernel's table and name only addresses inside the kernel image; outside it they would name an unrelated kernel symbol. The kernel image is, in order: the module holding the caller's anchor address (an address the caller read from kernel data, such as a service table); the module whose base is the session's kernel base (M1); the module that holds the address of `PsLoadedModuleList`, a kernel global (M6). None found: no symbols are given, and `SymbolModuleKnown` is false.
5. **At.** For each module holding the address, one attribution per symbol name at that address when the module is the kernel image, otherwise one with no symbol. Each carries the display name and whether the name read.

### 4.5 Filters

1. `windows.module.list.base` keeps the modules whose base is the value, or whose base with the bits above the address mask cleared is the value: paging ignores those bits, so the examiner may give either form (D3). 0 filters nothing, with a diagnostic.
2. `windows.module.list.name` keeps the modules whose base name contains the text, compared without case (D8): each character of the Basic Multilingual Plane in both is mapped to its simple upper case, as Windows upcases a name one UTF-16 unit at a time, and a character outside that plane keeps its case. A module whose name does not read is kept, so a read failure never hides a module. Text that is not UTF-8 is a type error: no name decoded from UTF-16 contains it.
3. A filter on a non-Windows profile is `ErrFilterUnsupported`. A run with a filter reports how many of how many modules it kept, how many it kept only because their name did not read, and, when the base was given sign-extended, that the masked form names the same module.
4. `ReadFilter`, `BaseOption`, `IsBase` and `NoteCanonicalBase` apply the same rules to the base and name options of other tools.

### 4.6 The PE dump of loaded modules

1. The profile must be Windows (`ErrNotWindows`) and `output_dir` set (`ErrNoOutputDir`).
2. **Process modules.** Each module of the library list (`windows.library.list`, which applies `pid`) is read through its own process's space only: the kernel reader runs on some other process's page tables and would file that process's bytes under this PID. A process whose space does not open gives skipped rows and one diagnostic. A module whose `DllBase` did not read (`BaseUnreadable`, S56 4.1 step 6) is a skipped row with `Skipped` `DllBase does not read`; a base of 0 is a skipped row with `DllBase is 0`.
3. **Kernel modules.** Each module of 4.1. An unread or zero base is skipped with a diagnostic. Session-space drivers are mapped only in the page tables of processes in their session (M5), so the reader is the first of the kernel space and one process space per session whose PE headers parse at the base; with none, the kernel space.
4. **Write.** Read the PE headers (`extract.ReadHeaders`). Refuse an image whose header `SizeOfImage` is above `MaxArtifactBytes`. Read `SizeOfImage` bytes from the base with holes padded (`extract.ReadPadded`), rebuild with `pe.Rebuild` at the canonical base (S18), and write with `extract.CreateNew`. A write or close that fails removes the file. The row then gets the file length, the bytes captured, the gap map, the original image base, whether it was replaced, and the section count. The two S18 diagnostics are given as S18 6 words them.
5. **Artefact names (S00).** A listed module: kind `module`, scope `pid<N>` or `kernel`, addresses base and loader entry, label the path's file name, or the base name when the path did not read or is empty, extension `pe`.
6. **Order.** Process modules in library list order, then kernel modules in list order. Kernel modules are dumped whatever `pid` says (O4).

### 4.7 The PE dump at a given base

1. `windows.pe.dump.kernel_module` without `windows.pe.dump.base` is `ErrNoBase`; with `pid` it is `ErrKernelModuleAndPID`. A base without either is `ErrNoDumpTarget`.
2. The base is taken in canonical form (4.3). A value with bits above the mask that are not its sign extension gives a diagnostic.
3. **Kernel.** One row, PID 4 and process `System` (M7), read through the reader of 4.6 step 3, named kind `image`, scope `kernel`, address base.
4. **Process.** One row per listed process that `pid` keeps, read through the process's kernel page-table root (`processlist.KernelDirectoryTableBase`), which maps system space as well as user space, so the base may lie in either half. Named kind `image`, scope `pid<N>`, addresses base and `_EPROCESS`. No process kept: a diagnostic.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Loader entry type with the four required members | T1, T2 | `ErrNoLoaderEntry` or an error naming the member |
| List walk rules | S03 5 | S03 breaks; strict mode fails |
| Link at or above the `InLoadOrderLinks` offset | S03 4.6 | Entry skipped, diagnostic |
| `SizeOfImage` read at 4 bytes | T1 | — |
| `DllBase` at or above system space | D1, D2, M2 | Diagnostic; row kept |
| `SizeOfImage` nonzero | D5, M3 | Diagnostic; row kept |
| `MmSystemRangeStart` in the table | D1, T4 | Module list: upper half used, no diagnostic (O15) |
| `MmSystemRangeStart` canonical, at or above the upper half | D1 to D3, M2 | Upper half used, diagnostic |
| Address inside `[Base, Base + Size)` with both read | D5, M3 | Not attributed |
| Symbols only inside the kernel image | 4.4 step 4, M6 | No symbol |
| Name filter text is UTF-8 | 4.5 step 2 | Option type error |
| Image within `MaxArtifactBytes` | Limits, S18 | Row skipped, diagnostic |
| PE headers parse at the base | S18, M5 | Row skipped, diagnostic |

## 6. Failure modes

| Case | Result |
|---|---|
| Table without a loader type, a required member or `PsLoadedModuleList` | `windows.module.list: modulelist: …` error |
| List head unreadable | The S03 `ErrListUnreadable` error |
| A walk break | S03 diagnostic; entries before it kept; strict mode returns the break |
| Member unread | `windows.module.list: <type> at 0x<entry>: <member> does not read: <err>`; flag set |
| Base below system space, empty image | `windows.module.list: loader entry at 0x<entry>: DllBase 0x<base> lies below system space at 0x<start>`; `…: SizeOfImage is 0` |
| `MmSystemRangeStart` unread or out of range | `<tool>: MmSystemRangeStart at 0x<addr> does not read: system space taken to start at 0x<half>: <err>`; `<tool>: MmSystemRangeStart at 0x<addr> holds 0x<value>, outside the upper half: …` |
| Table without `MmSystemRangeStart` (module list) | No diagnostic; system space taken to start at the upper half (O15) |
| Modules without a range | `<tool>: loader entries at 0x<entry>, …: base or size does not read: no address is attributed to them` |
| Linux model or view failure | `windows.module.list: <err>`; strict: `windows.module.list: strict mode: the module list view left modules out` |
| Library or module list fails in the dump | Strict: `windows.pe.dump: <process modules or kernel modules> not listed: <err>`; otherwise a diagnostic and no rows of that kind |
| Image not written | Row with `Skipped` the reason; diagnostic `windows.pe.dump: <source> <name> at 0x<base>: <reason>` |

Sentinels: `modulelist.ErrNoLoaderEntry`, `ErrNoListHead`, `ErrUnsupportedOS`, `ErrNoSystemRangeStart`, `ErrFilterUnsupported`; `pedump.ErrNoOutputDir`, `ErrNotWindows`, `ErrNoBase`, `ErrKernelModuleAndPID`, `ErrNoDumpTarget`.

## 7. Result schema

`windows.module.list` row (`modulelist.Module`): `Base`, `Size` (bytes; on Linux 4.2), `InitSize` (bytes, Linux only), `Name`, `Entry` (loader entry or `struct module` address), `Path`, the flags `NameUnreadable`, `PathUnreadable`, `BaseUnreadable`, `SizeUnreadable`, `InitSizeUnreadable`, and, on Linux only, `Regions` (`modulelist.Region`: `Kind`, `Base`, `Size`) and `SeparateRegions` (4.2). Values are as read; an unread value is 0 or empty with its flag set. Order: list order.

`modulelist.Attribution`: `Module` (display name), `Symbol` (empty when none), `ModuleUnreadable`.

`windows.pe.dump` row (`pedump.Artifact`): `Source` (`process` or `kernel`), `PID`, `Process`, `Name`, `Path`, `NameUnreadable`, `PathUnreadable`, `Base`, `Entry`, `FileName` (S00), `Size` (file bytes), `Captured` (bytes read), `Gaps`, `OriginalImageBase`, `ImageBaseFixed`, `Sections`, `Skipped` (empty when written). `Written` is `Skipped` empty; `Complete` is written without gaps.

## 8. Limits

- `MaxListEntries`: the loader list walk (S03).
- `MaxArtifactBytes`: the largest `SizeOfImage` written, and the S18 rebuild cap.
- Names: `util.MaxUnicodeStringBytes` per string.

## 9. Acceptance

1. Synthetic fixtures (`tools/windows/modulelist/s55_fixture_test.go`, on the T1 offsets): the list in load order; `SizeOfImage` read at 4 bytes with junk after it; an entry whose members cross into an unmapped page; a broken `Flink` recovered through `Blink`; strict mode on a back-link break; an unreadable head; the process loader type; no `FullDllName`; a missing type, member or head; a base below system space and an empty image; an unsupported profile; the Linux branch on the shared module fixture; the address mask, canonical form, upper half and system space start for 4-byte, 4-level and 5-level layouts; containment at both ends and at the top of the address space; display names; the kernel image chosen by anchor, kernel base and list head; symbols only inside it; every filter rule and message. `tools/windows/pedump` (on the shared process fixture): the option rules; kernel modules written and parsed with `debug/pe`, with `ImageBase` the load address; the artefact names; skipped rows for unread headers, the artefact cap and an existing file; a session driver read through its session; the reader choice; the base dumps of a kernel and a process image; strict and lenient list failures; a non-Windows profile and a missing output directory. The carve-all path runs on one world shared with the library list (`internal/testsupport/s55_fixture.go`: the shared process fixture plus the loaded-module list and session spaces); the test requires explorer.exe's process row before the kernel rows, and `tools/windows/librarylist` lists that module from the same world (O11).
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzLoadedModules` (an arbitrary entry and first link: no panic, no entry twice, at most `MaxListEntries`, unread values 0, sizes 4 bytes wide); `FuzzCanonicalAddress` (canonical form keeps the masked bits, has equal bits above the mask, and is idempotent). Executions: 1,507,689 and 4,342,864, no failure.
3. On the captures (`kmodfacts -tool -pid 0`, 2026-11-12), the tool lists 195, 195, 142, 158 and 165 modules, none with an unread member; system space starts at 0xFFFF800000000000 and the address mask is 48 bits on all five; each of the five pointers of M6 is attributed to `ntoskrnl` with its own symbol name. The dump, with explorer.exe's modules and the kernel modules:

| Capture | Kernel complete | Kernel with gaps | Kernel skipped (headers unread) | Process written | Process skipped (headers unread) | Bytes captured of written |
|---|---|---|---|---|---|---|
| mem1_win11 | 5 | 190 | 0 | 301 | 0 | 251,330,560 of 495,312,896 |
| mem2_win10 | 5 | 187 | 3 | 144 | 171 | 115,818,496 of 273,010,688 |
| mem5_server2016 | 5 | 137 | 0 | 217 | 0 | 99,852,288 of 262,844,416 |
| mem6_server2025 | 2 | 152 | 4 | 0 | 0 | 55,980,032 of 81,498,112 |
| mem7_server2025 | 2 | 156 | 7 | 28 | 271 | 67,973,120 of 136,695,808 |

   - The kernel skips are exactly the images of M5 whose headers read nowhere; the session-space images of mem2 and mem5 are written.
   - The library list gave no module of explorer.exe on mem6.
   - `windows.pe.dump.base` at the kernel base with `windows.pe.dump.kernel_module` writes one image under PID 4 `System`: 36, 33, 24, 36 and 36 sections, with 13,967,360 of 21,299,200, 17,063,936 of 17,063,936, 8,519,680 of 8,519,680, 12,226,560 of 21,295,104 and 11,943,936 of 21,295,104 bytes captured.
4. On the Linux captures (`kmodfacts -linux`, 2026-11-12), the tool lists 63 modules on mem3_ubuntu24 (6.17) and 61 on mem4_fedora40 (6.14), each with a nonzero text base, through the S06 list view. Every module on both captures has separate regions. With the summed core size, 63 of 63 modules on mem3_ubuntu24 and 57 of 61 on mem4_fedora40 had a core region outside `[Base, Base + Size)` (159 and 73 regions); `Size` is now the text size (1609728 and 1572864 text bytes in all). Regions by kind: mem3_ubuntu24 `text` 63, `data` 63, `rodata` 63, `ro_after_init` 33; mem4_fedora40 61, 61, 61, 24; no init region on either.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision (Q2): `windows.module.list` also lists Linux modules (4.2), as before; the tool name keeps its `windows.` prefix. | Owner decision on the tool name |
| O2 | Owner decision: the name filter is a case-sensitive substring of `BaseDllName`, as before, although Windows file names compare without case. Owner decision 2026-11-12: make case-insensitive. Done: 4.5 step 2 and D8; `Filter.Keeps` compares upper-cased forms, so `windows.module.scan.name` (S64, same rules) follows; test in `tools/windows/modulelist/filter_test.go`. | Owner decision |
| O3 | Owner decision: a kernel image dumped at a given base is reported under PID 4 with process `System` (M7); the previous value was `Kernel`. | Owner decision on row values |
| O4 | Owner decision: kernel modules are dumped whatever `pid` says, as before. | Owner decision |
| O5 | On Linux `Size` is the sum of the core regions. From v6.4 the regions are separate allocations, so `[Base, Base + Size)` is not one range there. Owner decision 2026-11-12: add a Linux-specific row. Done: Linux rows carry `Regions` and `SeparateRegions`, `Size` is the text size when the regions are separate, and `Containing` uses the regions (4.2, 4.4, section 7, section 9 item 4). `tools/windows/modulelist/module_list.go`, `linux.go`, `attribution.go`, `linux_test.go`; `linuxmodule.Model.SeparateRegions` in `tools/linuxmodule/model.go`. | Owner decision on a Linux row of its own |
| O6 | Modules found through `Blink` carry no row flag; a diagnostic counts them. No capture had any (M1). | Owner decision on a row field |
| O7 | `_KLDR_DATA_TABLE_ENTRY` and `PsLoadedModuleList` are not documented by Microsoft; their layout and role rest on the PDB types and the measurements only. The fallback to `_LDR_DATA_TABLE_ENTRY` rests on T2. | A Microsoft source |
| O8 | 32-bit kernels, `increaseuserva` and 5-level paging are covered by D1 to D4 only; no capture uses them (M8). | A 32-bit or LA57 capture (Q7) |
| O9 | A listed module whose path does not read takes its base name as the artefact label (S00 "file base name"); before, it had no label. | Owner decision |
| O10 | Owner decision (Q3): the result field names are kept from 0.1.0. | Owner decision on field names |
| O11 | The carve-all process path has no synthetic test while the library list and the shared process fixture disagree (S56 in progress); the captures exercise it (9.3). Owner decision 2026-11-12: Schedule now. Done: `BuildS55World` in `internal/testsupport/s55_fixture.go` builds the world both read; `tools/windows/pedump/pe_dump_test.go` now requires the process row (and only it when the kernel list fails), and `tools/windows/librarylist/s55_shared_test.go` checks the library list reads the same loader data. | A fixture both S56 and S55 read |
| O12 | A process module whose `DllBase` did not read carries `BaseUnreadable` (S56 O8); 4.6 step 2 makes it a skipped row. | Owner decision 2026-11-12 (follow-up D14): add to both specs. Done: 4.6 step 2 names the flag and both skip texts; S66 names it for its tools (S66 LO7); no code change (`tools/windows/pedump/pe_dump.go` already skipped such rows). |
| O13 | `modulelist.Module` holds the `Regions` slice, so a `Module` can no longer be compared with `==`; a caller that needs one size sums `Regions`. | Owner decision 2026-11-12 (follow-up D9): accept, with a Changes row in the README. Done. |
| O14 | Follow-up Mem-M9: the real-image dump tests ran once per image (mem1 pid 11172 and 9616, mem2 3804 and 844, mem5 668, mem6 768, mem7 776). The base dumps at the kernel base list PID 4 `System` (O3). mem7 pid 776: the ntdll.dll module header pages are not in the capture, so that base case is skipped with the reason logged. mem5: the host's antivirus quarantines the written volmgrx.sys, so the smoke test fails to read it back (S19 9.3 notes the same host behaviour). | Owner decision 2026-11-12 (follow-up Mem-M9): run the dump tests once per image. Done; no code change. |

| O15 | `newSystemSpace` (`tools/windows/modulelist/addressspace.go`) drops `ErrNoSystemRangeStart`: with no `MmSystemRangeStart` in the table, `windows.module.list` takes system space to start at the upper half and reports nothing. Owner decision 2026-11-12: kept for v0.1.0; a diagnostic for the fallback in v0.2.0. | v0.2.0 |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep as is |
| O2 | Make case-insensitive |
| O3 | PID 4, System |
| O4 | Dump regardless of pid |
| O5 | Add Linux-specific row |
| O6 | Diagnostic count only |
| O7 | Accept |
| O8 | Defer to v0.2.0 |
| O9 | Use base name |
| O10 | Keep 0.1.0 names |
| O11 | Schedule now |
| O12 | Add to both specs |
| O14 | Follow-up Mem-M9: dump tests once per image |

## 11. Provenance

Written from the WDK headers, Microsoft Learn, the Intel SDM, the ntoskrnl types in the project's symbol tables, and the project's measurements. The previous implementation was read only for its exported names, its callers, the tool names and the option keys. Every rule rests on the sources and measurements above.
