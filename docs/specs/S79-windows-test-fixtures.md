# S79: Windows test fixtures

Version 1, 2026-11-12.

## 1. Purpose

The tool tests cannot ship memory captures, so they run on synthetic memory that `internal/testsupport` lays out: a physical address space with x64 page tables, a kernel with processes, their page tables, loader lists, VAD trees, file views and handle tables, a kernel version, pool headers, and PE images mapped into a process. A test only proves something about a tool when the layout it runs on is the layout the tool meets on a real kernel. This specification fixes where each fixture structure comes from: every member offset, size, bit field and constant is a kernel type in the captures' own symbol tables, a documented format, a measurement on the captures, or the specification of the tool whose tests use it. It also fixes the fixture's contract: the exported names, the values tests read back, and the address plan.

The shared files named `s<NN>_fixture.go` in the same package were written from the specifications named by their prefix (S19, S24, S43, S45, S50, S51, S55, S56, S64, S66, S69; the S66 file is `s66_c_fixture.go`). They are not part of this specification; section 11 lists their records.

## 2. Inputs

| Input | Meaning |
|---|---|
| Process descriptions | `FixtureProcess`: PID, name, parent, loader modules (native and WoW64), VADs, handle count, flags for no PEB, unlinked, null WoW64 PEB, section and image base, uncounted VADs. |
| Exports | `FixtureExport`: name, body, forwarder, RVA. |
| Image base | For the PE builders. |
| Version | Major, minor and build for `WithWindowsVersion`. |
| Text | For the `UNICODE_STRING` fixtures. |
| Limits | None. A fixture that does not fit its page or its image panics: it is a test bug. |

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | At offset 0x3c of an image the MS-DOS stub holds the file offset of the signature `PE\0\0`. The COFF file header follows it, 20 bytes: `Machine` 0, `NumberOfSections` 2, `TimeDateStamp` 4, `PointerToSymbolTable` 8, `NumberOfSymbols` 12, `SizeOfOptionalHeader` 16, `Characteristics` 18. `IMAGE_FILE_MACHINE_AMD64` is 0x8664. `IMAGE_FILE_EXECUTABLE_IMAGE` 0x0002, `IMAGE_FILE_LARGE_ADDRESS_AWARE` 0x0020, `IMAGE_FILE_DLL` 0x2000. | Microsoft Learn, "PE Format", accessed 2026-11-12. |
| D2 | PE32+ optional header: magic 0x20b at 0, `AddressOfEntryPoint` 16, `BaseOfCode` 20, `ImageBase` (8 bytes) 24, `SectionAlignment` 32, `FileAlignment` 36, `MajorOperatingSystemVersion` 40, `MinorOperatingSystemVersion` 42, `MajorSubsystemVersion` 48, `SizeOfImage` 56, `SizeOfHeaders` 60, `CheckSum` 64, `Subsystem` 68, `NumberOfRvaAndSizes` 108, data directories from 112, 8 bytes each, the export table first. `FileAlignment` is a power of 2 from 512 to 64 K, default 512. `SizeOfHeaders` is the size of the stub, PE header and section headers "rounded up to a multiple of FileAlignment". `IMAGE_SUBSYSTEM_WINDOWS_CUI` is 3. | Same. |
| D3 | A section header is 40 bytes: `Name` (8) 0, `VirtualSize` 8, `VirtualAddress` 12, `SizeOfRawData` 16, `PointerToRawData` 20, `Characteristics` 36. `SizeOfRawData` and `PointerToRawData` are multiples of `FileAlignment`. `IMAGE_SCN_CNT_CODE` 0x20, `IMAGE_SCN_MEM_EXECUTE` 0x20000000, `IMAGE_SCN_MEM_READ` 0x40000000. | Same. |
| D4 | The export directory table is 40 bytes: `Ordinal Base` 16, `Address Table Entries` 20, `Number of Name Pointers` 24, `Export Address Table RVA` 28, `Name Pointer RVA` 32, `Ordinal Table RVA` 36; `Name RVA` 12. Address table entries are 4 bytes; an entry that points inside the export section given by the optional header's export data directory is a forwarder string. The name pointer table is "ordered lexically" for binary search. The ordinal table holds 16-bit unbiased indexes into the address table. | Same. |
| D5 | `PAGE_NOACCESS` 0x01, `PAGE_READONLY` 0x02, `PAGE_READWRITE` 0x04, `PAGE_WRITECOPY` 0x08, `PAGE_EXECUTE` 0x10, `PAGE_EXECUTE_READ` 0x20, `PAGE_EXECUTE_READWRITE` 0x40, `PAGE_EXECUTE_WRITECOPY` 0x80; `PAGE_GUARD` 0x100, `PAGE_NOCACHE` 0x200, `PAGE_WRITECOMBINE` 0x400. | Microsoft Learn, "Memory Protection Constants", accessed 2026-11-12. |
| D6 | `LIST_ENTRY` has `Flink` and `Blink`; a list head's `Flink` names the first entry and its `Blink` the last; an empty list's head points to itself. | Microsoft Learn, "LIST_ENTRY structure (ntdef.h)" and "Singly and Doubly Linked Lists", accessed 2026-11-12. |
| D7 | 4-level paging: CR3 bits M−1:12 hold the physical address of the PML4 table; linear address bits 47:39, 38:30, 29:21 and 20:12 select an 8-byte entry in each of four tables of 512 entries; bit 0 of an entry is P (present); bit 6 of a PTE is D (dirty); bits M−1:12 of an entry hold the next table's or page's physical address, M at most 52; bit 63 is XD. CR3 bits 11:0 hold flags or a PCID, not address bits. | Intel 64 and IA-32 Architectures SDM, Vol. 3A, sections 4.5 and 4.10.1. |
| D8 | `UNICODE_STRING`: `Length` (USHORT) is the length in bytes, without a terminating NUL; `MaximumLength` (USHORT) the buffer size in bytes; `Buffer` a pointer to wide characters. | Microsoft Learn, "UNICODE_STRING structure (ntdef.h)", accessed 2026-11-12. |
| D9 | `KUSER_SHARED_DATA` holds `NtBuildNumber`, `NtMajorVersion` and `NtMinorVersion`. | Microsoft Learn, "KUSER_SHARED_DATA structure (ntddk.h)", accessed 2026-11-12. |
| D10 | A 64-bit process's user-mode range ends at 0x7FFF'FFFFFFFF; system space lies above. | Microsoft Learn, "Virtual address spaces", accessed 2026-11-12. |

### Kernel types

Read with `fixturefacts` through the project's kernel tables: 26100 (mem1, mem6, mem7; `ntkrnlmp-0D960CE103763A6097E839406D8B369F-1` for mem1, `ntkrnlmp-953A8DE880B0818C32DA2DEC1D79C2D9-1` for mem6 and mem7), 19045 (mem2; `ntkrnlmp-F57E740B088E5056E8AF0772F1CC5BEB-1`) and 14393 (mem5; `ntkrnlmp-3DFC5F7228304C26859E55E481700385-1`). Where the builds differ, all three are given; the process fixture lays out the 19045 column (decision P1).

| # | Fact |
|---|---|
| T1 | `_EPROCESS`, sizes 0x840 / 0xa40 / 0x7b0 (26100 / 19045 / 14393): `Pcb` 0 (`_KPROCESS`, 0x1c8 / 0x438 / 0x2d8 bytes); `UniqueProcessId` (void*) 0x1d0 / 0x440 / 0x2e8; `ActiveProcessLinks` 0x1d8 / 0x448 / 0x2f0; `SectionBaseAddress` 0x2b0 / 0x520 / 0x3c0; `InheritedFromUniqueProcessId` 0x2d0 / 0x540 / 0x3e0; `Peb` 0x2e0 / 0x550 / 0x3f8; `ObjectTable` 0x300 / 0x570 / 0x418; `WoW64Process` 0x310 / 0x580 / 0x428; `ImageFileName` (unsigned char[15]) 0x338 / 0x5a8 / 0x450; `VadRoot` (`_RTL_AVL_TREE`) 0x558 / 0x7d8 / 0x620; `VadCount` (unsigned long long) 0x568 / 0x7e8 / 0x630. For the members other fixtures and tests add: `Token` 0x248 / 0x4b8 / 0x358, `ThreadListHead` 0x370 / 0x5e0 / 0x488, `Job` 0x2a0 / 0x510 / 0x3b0, `JobLinks` 0x358 / 0x5c8 / 0x470, `Session` 0x2e8 / 0x558 / 0x400, `SeAuditProcessCreationInfo` 0x350 / 0x5c0 / 0x468, `CreateTime` 0x1f8 / 0x468 / 0x308, `ExitTime` 0x5c0 / 0x840 / 0x688. |
| T2 | All builds: `_LIST_ENTRY` 16 bytes, `Flink` 0, `Blink` 8; `LIST_ENTRY32` 8 bytes, `Flink` 0, `Blink` 4 (unsigned int); `_UNICODE_STRING` 16 bytes, `Length` (unsigned short) 0, `MaximumLength` 2, `Buffer` (wchar_t*) 8; `_STRING32` 8 bytes, `Length` 0, `MaximumLength` 2, `Buffer` (unsigned int) 4. |
| T3 | All builds: `_KPROCESS.DirectoryTableBase` (unsigned long long) 0x28. |
| T4 | All builds: `_PEB.ImageBaseAddress` 0x10, `Ldr` 0x18, `ProcessParameters` 0x20 (`_PEB` 0x7d0 / 0x7c8 / 0x7a0 bytes); `_PEB_LDR_DATA` 0x58 bytes, `InLoadOrderModuleList` 0x10; `_LDR_DATA_TABLE_ENTRY` 0x138 / 0x120 / 0x120 bytes: `InLoadOrderLinks` 0, `DllBase` 0x30, `SizeOfImage` (unsigned int) 0x40, `FullDllName` 0x48, `BaseDllName` 0x58, `ObsoleteLoadCount` (unsigned short) 0x6c, `LoadTime` (`_LARGE_INTEGER`) 0x100; `_EWOW64PROCESS` 0x10 bytes, `Peb` (void*) 0; `_PEB32` 0x488 / 0x480 / 0x460 bytes, `Ldr` (unsigned int) 0xc. No table has `_PEB_LDR_DATA32` or `_LDR_DATA_TABLE_ENTRY32` (as S56 T4). |
| T5 | All builds: `_RTL_AVL_TREE` 8 bytes, `Root` 0; `_RTL_BALANCED_NODE` 0x18 bytes, `Left` 0, `Right` 8, `ParentValue` 0x10, `Balance` bits 0..1 of the byte at 0x10; `_MMVAD_SHORT` 0x40 bytes: `VadNode` 0, `StartingVpn` (unsigned int) 0x18, `EndingVpn` 0x1c, `StartingVpnHigh` (unsigned char) 0x20, `EndingVpnHigh` 0x21, `u` 0x30; `_MMVAD` 0x88 bytes, `Core` 0, `Subsection` 0x48. `_MMVAD_FLAGS` (4 bytes): `VadType` 3 bits at 4 / 4 / 0, `Protection` 5 bits at 7 / 7 / 3, `PrivateMemory` at bit 21 / 20 / 15 (as S24 T5). |
| T6 | All builds: `_POOL_HEADER` 16 bytes: `PreviousSize` bits 0..7 and `PoolIndex` bits 8..15 of the unsigned short at 0, `BlockSize` bits 0..7 and `PoolType` bits 8..15 of the unsigned short at 2, `PoolTag` (unsigned int) 4. `_POOL_TRACKER_BIG_PAGES` 0x18 bytes on 19045 and 14393 with `PoolType` bits 8..19 of the unsigned int at 0xc; 0x20 bytes on 26100, no `PoolType` (as S52 T1, T2). |
| T7 | All builds: `_HANDLE_TABLE` 0x80 bytes, `NextHandleNeedingPool` (unsigned int) 0, `TableCode` (unsigned long long) 8; `_HANDLE_TABLE_ENTRY` 16 bytes: `Unlocked` bit 0 and `ObjectPointerBits` bits 20..63 of the unsigned long long at 0, `GrantedAccessBits` bits 0..24 of the unsigned int at 8, `LeafHandleValue` at 8 (as S66 HT1, HT2). |
| T8 | All builds: `_SUBSECTION` 0x38 bytes, `ControlArea` 0; `_CONTROL_AREA` 0x80 bytes, `FilePointer` (`_EX_FAST_REF`) 0x40; `_EX_FAST_REF` 8 bytes, `Object` 0, `RefCnt` bits 0..3, `Value` 0; `_FILE_OBJECT` 0xd8 bytes, `Type` (short) 0, `Size` (short) 2, `FileName` 0x58. |
| T9 | All builds: `_OBJECT_HEADER` 0x38 bytes, `PointerCount` (long long) 0, `Body` 0x30. |
| T10 | All builds: `_KUSER_SHARED_DATA` (0xa80 / 0x720 / 0x708 bytes) `NtBuildNumber` 0x260, `NtMajorVersion` 0x26c, `NtMinorVersion` 0x270, each unsigned int; `_DBGKD_GET_VERSION64` 0x28 bytes, `MajorVersion` 0, `MinorVersion` 2 (unsigned short). |

### Measurements

`fixturefacts` on mem1_win11, mem2_win10, mem5_server2016, mem6_server2025 and mem7_server2025.

| # | Measurement |
|---|---|
| M1 | `MmProtectToValue` holds the same 32 unsigned ints on all five: 1, 2, 0x10, 0x20, 4, 8, 0x40, 0x80, then three more rows of eight that add `PAGE_NOCACHE` (0x200), `PAGE_GUARD` (0x100) and `PAGE_WRITECOMBINE` (0x400) to entries 1 to 7, each row starting with 1. Index 4 is `PAGE_READWRITE`, 6 `PAGE_EXECUTE_READWRITE`, 7 `PAGE_EXECUTE_WRITECOPY` (D5). |
| M2 | Reading `_KUSER_SHARED_DATA` at 0xFFFFF78000000000 in kernel space gives `NtBuildNumber` 26100, 19045, 14393, 26100, 26100, `NtMajorVersion` 10 and `NtMinorVersion` 0 on all five. |
| M3 | The global `NtBuildNumber` reads 0xF00065F4, 0xF0004A65, 0xF0003839, 0xF00065F4, 0xF00065F4: the build in the low 16 bits and 0xF in the top four. |
| M4 | `KdVersionBlock` → `_DBGKD_GET_VERSION64.MinorVersion` is the build on 26100 and 14393, and 19041 on 19045. |

## 4. Algorithm

### 4.1 Physical memory and page tables

1. `NewPagedMemory` allocates the requested size, at least four pages. Frames are handed out in order from 0x1000; frame 0 is held back so that no zero pointer or zero entry names a page the fixture wrote. Running out of frames panics.
2. `NewAddressSpace` takes one frame for the top table; `DTB` is its physical address, as CR3 holds it (D7).
3. `MapFlags(va, pa, flags)` walks the four levels from bits 47:39 down (D7). A missing table on the way gets a fresh frame and an entry with P only, so the flags a test gives the page are the only ones any reader sees. The leaf entry is `pa` bits 51:12, P, and the given flags. `PTEDirty` is D (bit 6).
4. `MapPage` and `MapPageFlags` map a fresh zeroed frame; mapping a page twice gives a fresh frame and drops what was written through the first. `MapData` maps one page of data; `MapImage` maps data page by page and returns the page count.

### 4.2 Process fixture

1. The kernel space maps the process list head at its plan address (4.6). Each process gets one kernel page for its `_EPROCESS` and its own address space. In the pooled form the page starts with a `_POOL_HEADER` (tag from the process scan filter, blocks for both headers and the body, `PoolType` nonpaged, T6 and S31 T5) and an `_OBJECT_HEADER` with `PointerCount` 1 (T9); the body follows the object header's `Body` offset, 0x40 into the page. 0x40 + 0xa40 stays inside the page, as the pool scan requires of an allocation.
2. Processes not marked unlinked are chained on `ActiveProcessLinks` in input order, with both links, and the list closes on its head (D6).
3. `UniqueProcessId`, `InheritedFromUniqueProcessId`, `ImageFileName` (the name and a NUL), the page table root, `SectionBaseAddress` and `VadCount` (the VADs given plus `UncountedVADs`) are written at the T1 / T3 19045 offsets.
4. Unless the process has no PEB: `Peb` names the PEB page in the process's space, holding `ImageBaseAddress` and `Ldr` (T4). The loader data's `InLoadOrderModuleList` chains one record per module, each record on its own page, all mapped before any is written (4.1 step 4). A record holds `DllBase`, `SizeOfImage` (the given size, else the image length, else the mapped PE fixture's size), a nonzero pattern in the four padding bytes after `SizeOfImage` (so a reader that takes eight bytes there gets a wrong size), `ObsoleteLoadCount`, `LoadTime`, and the two names as `UNICODE_STRING`s on pages of their own (D8). A module with an image has it mapped at its base.
5. A process with WoW64 modules or a null WoW64 PEB gets an `_EWOW64PROCESS` page in kernel space; its `Peb` names the 32-bit PEB unless it is to be null. With WoW64 modules, `_PEB32.Ldr` (T4) names 32-bit loader data laid out as S56 L1: `InLoadOrderModuleList` 0xc, records with `LIST_ENTRY32` links at 0, `DllBase` 0x18, `SizeOfImage` 0x20, `FullDllName` 0x24 and `BaseDllName` 0x2c as `_STRING32` (T2).
6. A process with VADs gets one kernel page per VAD. The node sits one pool header into the page with its tag 12 bytes in front of it (T6: tag at header + 4): the given tag, else `Vad ` for a file view and `VadS` for private memory (S24 M11). `StartingVpn`, `EndingVpn` and their high bytes (bits 43:12 and 51:44 of the addresses), and the flags word at `u` (T5, 19045 bits: `Protection`, `VadType`, and `PrivateMemory` set exactly for VADs without a path) are written. The tree is S24's balanced tree over the VADs in start order; `Left`, `Right` and `ParentValue` name node addresses, and `Balance` is the right subtree's height less the left's as a 2-bit value (S24 T2, M7). `VadRoot` names the root.
7. A file view continues in its page at 16-byte steps: `_MMVAD.Subsection` → `_SUBSECTION.ControlArea` → `_CONTROL_AREA.FilePointer`, an `_EX_FAST_REF` with all four count bits set (T8) so a reader that clears only three misses the object → `_FILE_OBJECT` with `Type` 5 and `Size` 0xd8 (S19 D1, T8) and `FileName` naming the path text after it. A path that does not fit the page panics.
8. A process with handles gets a one-level handle table: `ObjectTable` names it, `TableCode` names one leaf page, `NextHandleNeedingPool` is 1,024 per leaf page (S66 HM3). Entry 0 is unused (S66 HM4); entries 1 to n hold `ObjectPointerBits` = the process's object header address (body − `Body`) bits 47:4, and `Unlocked` set (T7, S66 HM5, HM6).
9. With any VAD, `MmProtectToValue` names a kernel page holding the M1 table, so the `Protection` index of a VAD maps to its documented constant (D5).
10. The symbol table (4.3) is built last.
11. Fixtures and tests that add `_EPROCESS` members to this table place them at their 19045 offsets (T1, P1): `Token` 0x4b8 (S45), `ThreadListHead` 0x5e0 (S50), `Job` 0x510, `JobLinks` 0x5c8, `SeAuditProcessCreationInfo` 0x5c0, `Session` 0x558 and `CreateTime` 0x468 (S69), `SeAuditProcessCreationInfo` 0x5c0 (S68's tests), `Session` 0x558 (S55's tests), `ExitTime` 0x840 (S65's tests). `_PEB.ProcessParameters` goes at 0x20 (T4). None overlaps a member the fixture writes.

### 4.3 Process fixture symbol table

1. Always: `_LIST_ENTRY`, `LIST_ENTRY32`, `_UNICODE_STRING`, `_STRING32` (T2); `_EPROCESS` with `DirectoryTableBase`, `UniqueProcessId`, `ActiveProcessLinks`, `Peb`, `WoW64Process`, `ImageFileName`; `_PEB.Ldr`; `_PEB_LDR_DATA`, `_LDR_DATA_TABLE_ENTRY`, `_EWOW64PROCESS`, `_PEB32` (T4); the symbol `PsActiveProcessHead`. Sizes are the 19045 type sizes.
2. Only when a process has a parent: `InheritedFromUniqueProcessId`. Only with VADs: `SectionBaseAddress`, `VadRoot`, `VadCount`, `_PEB.ImageBaseAddress`, the T5 and T8 types and `MmProtectToValue`. Only with handles: `ObjectTable` and the T7 types. Only in the pooled form: `_POOL_HEADER`, `_POOL_TRACKER_BIG_PAGES` (the 19045 form), `_OBJECT_HEADER` and the symbol `ObHeaderCookie`, which names an unmapped address. The table names only what the fixture fills: a member present but left zero would read as a real zero.
3. `DirectoryTableBase` is named as an `_EPROCESS` member at `Pcb` (0) + 0x28 (T1, T3), and `Pcb` is not declared (P2).

### 4.4 PE images

1. Both builders write the D1 to D3 headers: `MZ`, `e_lfanew` 0x80, the signature, an AMD64 COFF header with the fixture's time stamp, a PE32+ optional header of 240 bytes (112 + 16 directories) with the image base, `SectionAlignment` 0x1000, `FileAlignment` 0x200 (D2 default), OS version 10.0, subsystem version 6, `SizeOfImage`, `SizeOfHeaders` 0x400 (the first section's raw data start, a multiple of `FileAlignment`), the fixture's check sum, `Subsystem` 3, 16 directories, and one section header per section with `Characteristics` code, execute and read (D3).
2. `BuildMappedPE`: 0x4000 bytes, executable and large-address-aware, two sections `.text` 0x1000 + 0x800 filled 0xCC and `.data` 0x2000 + 0x400 filled 0xDD, `SizeOfRawData` equal to `VirtualSize` (a multiple of `FileAlignment`), and raw pointers 0x400 and 0xC00: the file layout the image was loaded from, at which nothing sits once mapped.
3. `BuildExportingPE`: 0x8000 bytes, a DLL with one `.text` section over 0x1000 to 0x8000. Export i's code is at 0x1000 + 16 i unless an RVA is given; a body is copied there. From 0x2000 the export data follows in one run: the 40-byte directory, the address table, the name pointer table and ordinal table for the named exports sorted by name (D4), then the forwarder and name strings. Forwarder entries point at their strings, inside the range the export data directory gives, which is what marks them as forwarders (D4). `Ordinal Base` is 1; `Name RVA` is left 0 (P5). Data past the image panics.

### 4.5 Smaller fixtures

1. `WithWindowsVersion` serves `_KUSER_SHARED_DATA` at 0xFFFFF78000000000 (M2) as one page with the build, major and minor at their T10 offsets, the global `NtBuildNumber` as 4 bytes with 0xF in the top four bits (M3), and `KdVersionBlock` as a 0x28-byte `_DBGKD_GET_VERSION64` with the build in `MinorVersion` (T10; P4). It answers the four member lookups and the two globals and passes every other lookup and read through. A read is served only when it lies wholly inside one region.
2. `NewUnicodeStringMemory` and `NewUnicodeString32Memory` put a `UNICODE_STRING` at 0x1000 with its text at 0x2000, `Buffer` at 8 or 4 (T2). The 16-bit counts wrap for text over 65,535 bytes, as a damaged string would carry; `LongPath` and `LongCJKName` are such texts. `UnicodeStringSymbols` declares the T2 type.
3. Pool headers (T6): `WritePoolHeader` writes `BlockSize` and `PoolType` as the word at 2 and the tag at 4, leaving `PreviousSize` and `PoolIndex` 0, values in the measured range (S31 M7). `BlocksFor` rounds up to 16-byte blocks (S31 M7). `ReadPoolHeader` decodes the T6 bit fields. `AddPoolHeaderSymbols` adds the T6 types.
4. Process-space wrappers: `HoleInProcess` makes one process's reads that touch a range fail; `PatchInProcess` overlays bytes on one process's reads; `RefuseProcessSpace` refuses one page table root (compared without CR3 bits 11:0, D7) and records every kernel-layer read at a user address (at most 0x7FFF'FFFFFFFF, D10), since such a read resolves in whatever process the capture caught running.

### 4.6 Address plan

The kernel addresses the fixtures use are kept from the plan the tests across the tree were written around, so the pages tests map themselves do not collide: list head 0xfffff80000001000, `ObHeaderCookie` 0xfffff80000002000, `MmProtectToValue` 0xfffff80000003000, `NtBuildNumber` 0xfffff80000004000, `KdVersionBlock` 0xfffff80000005000 (moved from 0xfffff80000003000, where it hid the first 0x28 bytes of `MmProtectToValue` from a process fixture wrapped in `WithWindowsVersion`), processes from 0xfffff80000010000 at 0x10000 steps, VAD pages from 0xfffff80000200000 (0x100000 per process), WoW64 records from 0xfffff80000900000, handle tables from 0xfffff80000a00000 (0x2000 per process); user PEB 0x7ff600010000, loader data 0x7ff600020000, records from 0x7ff600030000 and names from 0x7ff600100000 at 0x2000 steps, the 32-bit ones at 0x60000000 to 0x63000000 (P3).

## 5. Validity rules

A fixture states facts rather than checking them. Its rules are on its own input:

| Rule | Reason | On failure |
|---|---|---|
| A VAD's path fits its page after the file object | One page per VAD (4.2 step 6) | panic |
| Export data stays inside the image | 4.4 step 3 | panic |
| A physical write lies inside the buffer; a frame is left | 4.1 | panic |
| `MapData` takes at most a page | 4.1 step 4 | panic |
| A process-space wrapper gets a context with a process-memory factory | 4.5 step 4 | panic |

## 6. Failure modes

| Case | Result |
|---|---|
| Physical read outside the buffer | `memory.ErrOutOfBounds` |
| Read across a hole | `memory.ErrOutOfBounds` |
| Read under a refused root | `testsupport: page table root 0x<root> refused` |
| `ReadPoolHeader` on another type | `testsupport: no fixture layout for <type>` |
| Process memory for root 0 | `memory.ErrOutOfBounds` |

## 7. Result schema

The exported API is frozen for this wave and is kept whole. Constants whose values come from this specification: the `Fixture…Offset`, `Fixture…Off`, `FixtureVad…`, `FixtureEntry32…`, `FixtureUnicode…` members (T1 to T5, T7, T8, S56 L1), `FixtureProtection…` (M1 indexes), `FixtureVadTypeImage` 2 (S24 M11), `FixtureVadParentBalance` 0x3 (the `Balance` bits, T5), `PoolHeaderSize`, `PoolTagOffset`, `PoolAlignment`, the pool types (T6, S31), `KUserSharedData`, `Nt…Offset`, `KdMinorVersionOffset`, `FreeBuildDecoration` (T10, M2, M3), the PE header values (D1 to D4). Values that are the fixture's own and that tests read back: `MappedPESize` 0x4000, `MappedPELfanew` 0x80, `MappedPETimeDateStamp` 0x5F000000, `MappedPECheckSum` 0xABCDE, the OS version 10.0, `MappedPESections`, `ExportImageSize` 0x8000, `ExportCodeRVA` 0x1000, `ExportDirRVA` 0x2000, `ExportOrdinalBase` 1, `UnicodeStringAt` 0x1000, `UnicodeTextAt` 0x2000, `LongPath`, `LongCJKName`, the address plan (4.6), the default module paths `C:\Windows\System32\` and `C:\Windows\SysWOW64\` (P5).

## 8. Limits

None: fixtures are bounded by their own inputs. The process fixture's physical memory is 64 MB.

## 9. Acceptance

1. `internal/testsupport/processfixture_test.go`: every declared member is at its T1 to T8 19045 offset and `_EPROCESS` is 0xa40 bytes; the process list is circular with consistent `Blink`s, skips an unlinked process, and closes on its head; `ImageFileName` and `DirectoryTableBase` read back; the pooled form has the tag, nonpaged type, blocks covering headers and body, `PointerCount` 1 and an allocation inside its page; the VAD tree reads back in start order with parents and `Balance` right; a file view leads to a `_FILE_OBJECT` of `Type` 5 whose name reads back, and clearing three count bits misses it; both loader widths list their records with the default size; handle entries 1 to 3 name the process's object header with `Unlocked` set, entry 0 is empty, the ceiling is 1,024; `MmProtectToValue` holds the M1 values.
2. `internal/testsupport/pagedmemory_test.go`: a virtual read goes through the tables and the physical read at the same number fails; each space resolves its own pages and a third space does not see them; table entries carry P only and the leaf the requested flags; size, frame 0, empty and crossing reads, exhaustion; `MapImage` page count and zero tail.
3. `internal/testsupport/s79_fixture_test.go`: the mapped PE parses (`pe.ParseHeaders`) with the D1 to D3 values; the exporting PE's directory lies below 0x3000, its name table is in lexical order, ordinals, a body, a given RVA and a forwarder inside the directory parse back (`pe.ParseExports`); pool header write, decode and table read agree; the three version sources agree and the 4-byte global is not over-read; hole, patch and refusal wrappers; the user-read recorder.
4. Fuzz target `FuzzPoolHeaderRoundTrip`, run 30 s: any tag, block count and type survive a write and a decode.
5. `go test ./...` across the tree: every package that uses the fixtures passes on the new layout (section 10 lists no failing test).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| P1 | The process fixture lays out the 19045 `_EPROCESS`. Tests and the S45, S50 and S69 fixtures add members of their own to its table at offsets from 0xB0 to 0x430 (`Token` 0x248, `ThreadListHead` 0x100, `Job` 0x300 to 0x330, `ProcessParameters` 0x40, `SeAuditProcessCreationInfo` 0x400, `Session` 0xB0, `ExitTime` 0x200); on 19045 these fall inside `Pcb`, where the fixture writes only the page table root, while on 26100 they would overlap `UniqueProcessId` to `ImageFileName`. The added members are therefore not at their T1 offsets for any one build. | Owner decision: move the added members to their 19045 offsets in the owning specs' fixtures and tests. Owner decision 2026-11-12: move to 19045 offsets. Done: the offsets of 4.2 step 11, read from the mem2 kernel table with `fixturefacts` (T1, with `JobLinks`, `Session` and `CreateTime` added to its member list); internal/testsupport/s45_fixture.go, s50_fixture.go, s69_fixture.go, tools/windows/processidentity/s68_fixture_test.go (`_PEB.ProcessParameters` to 0x20), tools/windows/pedump/pe_dump_test.go, tools/any/processenvironment/s65_block_test.go; S45, S68 and S69 acceptance updated. The `_EJOB`, `_TOKEN` and `_ETHREAD` layouts of those fixtures are unchanged. |
| P2 | `DirectoryTableBase` is named on `_EPROCESS` without `Pcb`, as the PDB does not; declaring `Pcb` would make the S17 page-table-root check apply, and a memory-pattern test zeroes the root on purpose. | Owner decision. |
| P3 | The address plan (4.6) has no source: it is kept because the tests around it place their pages by it. | Owner decision on a re-plan. |
| P4 | `WithWindowsVersion` writes the full build into `KdVersionBlock.MinorVersion`; mem2 holds 19041 there for build 19045 (M4). No test needs the split. | Owner decision. |
| P5 | Values the fixture chose and tests read back are kept (section 7), as are the DLL name RVA 0 of the exporting PE and both mapped sections marked code, execute, read. | Owner decision. |
| P6 | A VAD node has only its tag in front of it, not a full pool header: no source here gives the pool type of VAD allocations. | A measurement of VAD pool headers. |
| P7 | No table has an enumeration for `VadType`; 2 for an image view is S24 M11's measurement. | As S24 O2. |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| P1 | Move to 19045 offsets |
| P2 | Keep |
| P3 | Keep |
| P4 | Keep |
| P5 | Keep |
| P6 | Keep tag only |
| P7 | Keep measured |

## 11. Provenance

Written from the PE format and the memory protection, list, string, shared-data and address-space pages of Microsoft Learn, the Intel SDM, the ntoskrnl types in the project's symbol tables, the project's measurements (`fixturefacts`), and the specifications S19, S24, S31, S52, S56 and S66. Every rule rests on the sources and measurements above. Records: `docs/provenance/internal/testsupport/{exportfixture,pagedmemory,pefixture,poolfixture,processfixture,processspace,unicodestring,windowsversion}.go.yaml`. The `s<NN>_fixture.go` files carry records naming S19, S24, S43, S45, S50, S51, S55, S56, S64, S66 and S69, with `replaces: []`.
