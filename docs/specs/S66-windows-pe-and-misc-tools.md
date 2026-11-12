# S66: Windows PE, library, handle and image tools

Version 1, 2026-11-12.

This specification covers ten tools, one group of subsections per tool in each section: `windows.pe.read_version`, `windows.pe.list_imports`, `windows.pe.resolve_symbols`, `windows.handle.list`, the options of `windows.file.dump`, `windows.library.compare`, `windows.credential.find_truecrypt`, `windows.image.map_strings`, `windows.image.read_crash_header` and `windows.disk.scan_boot_records`. Fact, measurement and open-point ids carry a per-tool prefix: V, I, Y, H, F, L, T, G, C and B. Documentation facts are `<p>D<n>`, type facts `<p>T<n>`, measurements `<p>M<n>` and open points `<p>O<n>`. Measurements come from `petoolfacts` on mem1_win11, mem2_win10, mem5_server2016, mem6_server2025 and mem7_server2025, given in that order.

## 1. Purpose

### windows.pe.read_version

An examiner asks which build of each driver and each process module was loaded: the product version a module's own version resource states. The answer dates a module against a patch level and exposes a driver whose version does not fit its neighbours. The tool reads the `VS_FIXEDFILEINFO` of every kernel module and every process module through the page tables that map it. The resource pages of most drivers are not mapped at capture time, so on request the tool also matches a driver to a copy of its version resource left in physical memory as file cache.

### windows.pe.list_imports

An examiner asks which functions a process's main image imports, and where the slot the loader fills for each one lies, so that a slot holding an address outside the named library can be found. The tool reads the import directory of each process's main image and gives one row per import, naming ordinal imports from the library the same process mapped.

### windows.pe.resolve_symbols

Many tools need the address of a function or global in a user module or a driver (ntdll's system call stubs, the ETW write functions, tcpip's partition table), or the name at an address. The tool and its exported functions answer both questions for every mapping of a module: first from the module's PDB, found through the CodeView record of its debug directory, then from its export directory. A mapping whose pages are not resident in one process is answered from another process that maps the same image.

### windows.handle.list

An examiner asks which objects a process had open: the files, keys, events, sections, processes and threads it held a handle to, with the access each handle grants. Windows keeps one handle table per process, reached from `_EPROCESS.ObjectTable`. This tool walks that table for every listed process and gives, per handle, its value, the object header it names, the granted access, the object type and the name S30 reads. The walker is shared: process compare, process dump and file dump use it.

### windows.file.dump options

`windows.file.dump` (S19) carves the cached bytes of file objects. Its options say which file objects: the ones given by virtual or physical address, or every file object the processes reach, kept by a pattern on the file's name. This section defines those options; the carve itself is S19.

### windows.library.compare

An examiner asks which images a process has mapped that its loader does not list. The user-mode loader keeps one record per loaded module, linked into three lists in the PEB's loader data; the memory manager keeps one VAD per mapped view, and an image view is a view of an image section. Code that maps an image itself, or that cuts its record out of the lists, leaves an image view that no list, or only some lists, name. The tool gives one row per image view of each process, with the lists whose records have their `DllBase` at the view's start.

### windows.credential.find_truecrypt

An examiner asks whether a TrueCrypt driver in the capture still holds a passphrase. The tool scans the writable data sections of every loaded `truecrypt.sys` for counted printable strings: a 4-byte length followed by that many printable bytes and a NUL. No allowed source documents how the driver stores a passphrase, and no capture holds the driver, so every rule of this tool is an owner decision (TO1 to TO6); the rows are candidates, not proven passphrases.

### windows.image.map_strings

An examiner has run a strings listing over the image file and found text of interest: a URL, a command line, a key. The listing gives only where the text lies in the file. The tool says which address spaces held it: for each line, every kernel virtual address and every process virtual address whose page is the physical page holding the text.

### windows.image.read_crash_header

An examiner opening a Windows crash dump asks what the dump itself records: the kernel's page-table root, the kernel lists, the processor count, the bug check, the dump type and when it was taken. The tool gives the header the session's crash dump layer read, as one row.

### windows.disk.scan_boot_records

An examiner asks whether memory holds a copy of a disk's master boot record: from a file the system read, a disk driver's buffer, or a tool that wrote one. A boot record carries the disk signature that identifies the disk, the boot code that firmware runs, and the partition table. The tool scans physical memory for records whose partition table is well formed and lists each with its signature, boot code hashes, a listing of its boot code and its partition entries.

## 2. Inputs

### windows.pe.read_version

| Input | Meaning |
|---|---|
| Kernel modules | `windows.module.list` (S55), read through the S55 PE dump reader choice (`pedump.KernelReaders`, `ReaderForModule`), which covers session-space drivers. |
| Process modules | `windows.library.list` (S56), read through each module's own process space only. The `pid` option narrows the processes. |
| Physical memory | `tools.OptionPhysicalMemory`, used only with the extensive option. |
| Options | `windows.pe.read_version.extensive` (boolean; a wrong type is an error). |
| Limits | The S18 resource limits through `pe.ReadVersion` (`MaxTableEntries`). |

### windows.pe.list_imports

| Input | Meaning |
|---|---|
| Processes | `any.process.list`; the `pid` option narrows them. |
| Symbol table | `_EPROCESS.Peb`, `_PEB.ImageBaseAddress` (required), `_EPROCESS.SectionBaseAddress` (optional). |
| Process spaces | `tools.Context.ProcessSpace`. |
| Process modules | `windows.library.list` for ordinal names, only once an ordinal import is met. |
| Ordinal table | `pe/peparse.OrdinalName`, the project's measured table of ordinal names. |
| Limits | `pe.ParseImports` (`MaxTableEntries`, `MaxNameBytes`). |

### windows.pe.resolve_symbols

| Input | Meaning |
|---|---|
| Options | `windows.pe.resolve_symbols.module` (text, required), `.symbols` (text list) or `.addresses` (unsigned list), exactly one of them; `.source` (`processes`, the default, or `kernel`); `.loader_list` (boolean). |
| Mappings | Source `processes`: the section views of every process (S24 VAD walk, S19 file names), or with `loader_list` the S56 loader lists; the `pid` option is not applied. Source `kernel`: `windows.module.list`. |
| Kernel table | For `ntoskrnl.exe` with source `kernel`, the session's kernel symbol table. |
| PDB loader | `tools.Context.LoadPDB` (S32), optional. |
| Limits | `pe.ParseExports` (`MaxTableEntries`, `MaxNameBytes`); `MaxBufferBytes` caps the one-read cache of an export directory. |

### windows.handle.list

| Input | Meaning |
|---|---|
| Kernel memory | `tools.Context.Memory`: handle tables, their pages, object headers and the type table are kernel virtual reads. |
| Symbol table | The types and members of section 3 (HT1 to HT4) and the globals `ObTypeIndexTable` and `ObHeaderCookie`. |
| Processes | The S25 process list, kept by `pid`; or, with `windows.handle.list.offset` (unsigned), the process the pool scan finds at that physical offset (`processscan.ProcessesAtOffset`). |
| Limits | `MaxTableEntries` (entries per table), `MaxPathSteps` (S30 names). |
| Strict mode | A table not read whole fails the run after the rows are built. |

### windows.file.dump options

| Option | Type | Meaning |
|---|---|---|
| `windows.file.dump.virtaddr` | unsigned list | Kernel virtual addresses of `_FILE_OBJECT` bodies. |
| `windows.file.dump.physaddr` | unsigned list | Physical addresses of `_FILE_OBJECT` bodies; needs `physical_memory`. |
| `windows.file.dump.filter` | RE2 pattern | Keeps walked file objects whose name matches. |
| `windows.file.dump.ignore_case` | boolean | Folds case in the filter. |
| `pid` | PID set | Applies to the process walk only. |

The paging mode (`paging_mode`) sets the address mask (S55 4.3).

### windows.library.compare

| Input | Meaning |
|---|---|
| Process list | `processlist.Run` (S25), narrowed by `pid`. |
| Loader records | `librarylist.Run` (S56 4.1): every record of the three native and three 32-bit lists, with its `DllBase`, its list membership and whether it came from the 32-bit lists. |
| Image views | `memoryranges.NewDecoder` and `Decoder.Mappings` (S24): each VAD with its kind (`image`, `mapped`, `private`, `unknown`) and the file name of a section view. |
| `pid` | The project's PID set. |
| `strict` | A VAD tree that does not read fails the run; S56 and S24 strict rules apply inside them. |
| Limits | Those of S56 (`MaxListEntries`) and S24 (VAD node budget). |

### windows.credential.find_truecrypt

| Input | Meaning |
|---|---|
| Kernel memory | Kernel virtual reads (`tools.Context.Memory`). |
| Module list | `modulelist.Run` (S55 4.1): base and base name of each loaded kernel module. |
| `truecrypt_min_length` | Unsigned, 1 to 128; default 4. Shortest text reported (TO3). |
| `strict` | PE headers that do not read fail the run. |
| Limits | `MaxRegionScanBytes`: the most bytes scanned per section. |

### windows.image.map_strings

| Input | Meaning |
|---|---|
| `windows.image.map_strings.file` | Text, required: the path of a strings listing. |
| Physical memory | `tools.OptionPhysicalMemory`; its segments, when it has them, give the file offset of each physical run. |
| Kernel page-table root | `kernel_dtb` and `paging_mode` of the session. |
| Process list | `processlist.Run` (S25), walked whatever `pid` says; `pid` then narrows which processes are mapped. |
| Limits | `MaxTextBytes` (longest line), `MaxRowsPerObject` (most lines). |

### windows.image.read_crash_header

| Input | Meaning |
|---|---|
| Physical memory | The session's physical layer; only the crash dump layer (`memory.CrashDumpReader`) has a header. |

### windows.disk.scan_boot_records

| Input | Meaning |
|---|---|
| Physical memory | `tools.OptionPhysicalMemory`, scanned over `memory.MappedRanges`. |
| `windows.disk.scan_boot_records.full` | Boolean, default false: also list records whose partition table breaks a rule (BO1). |
| `strict` | Physical memory that does not read whole fails the run after the scan. |
| Limits | `MaxRowsPerObject` (records listed), `MaxTextBytes` (one boot code listing). |

## 3. Facts from the sources

### windows.pe.read_version

| # | Fact | Source |
|---|---|---|
| VD1 | `VS_VERSIONINFO` is `wLength`, `wValueLength`, `wType`, `szKey` "VS_VERSION_INFO", `Padding1`, `Value` (a `VS_FIXEDFILEINFO`), `Padding2`, `Children`. `wLength` is the length of the structure; the padding words align `Value` and `Children` on a 32-bit boundary. `Children` are `StringFileInfo` and `VarFileInfo` structures. | Microsoft Learn, "VS_VERSIONINFO structure", accessed 2026-11-12. |
| VD2 | `StringFileInfo` (`szKey` "StringFileInfo") holds `StringTable` children; a `StringTable` (`szKey` an 8-digit hexadecimal language and code page) holds `String` children; a `String` has `wValueLength` "the size, in words, of the Value member", `wType` 1 for text, `szKey` and `Value`, padding aligning `Value` on 32 bits. One documented key is "OriginalFilename", "the original name of the file, not including a path". | Microsoft Learn, "StringFileInfo structure", "StringTable structure", "String structure", accessed 2026-11-12. |
| VD3 | `VS_FIXEDFILEINFO`: `dwSignature` 0xFEEF04BD, `dwStrucVersion`, `dwFileVersionMS/LS`, `dwProductVersionMS/LS` ("the most significant 32 bits of the binary version number of the product with which this file was distributed"), flags, OS, type, subtype, date. | Microsoft Learn, "VS_FIXEDFILEINFO structure (verrsrc.h)", accessed 2026-11-12. |
| VD4 | The version resource is resource type `RT_VERSION` (16) in the resource directory named by data directory 2. | Microsoft Learn, "PE Format" (.rsrc section); "Resource Types". |

### windows.pe.list_imports

| # | Fact | Source |
|---|---|---|
| ID1 | Data directory 1 names the import directory table: one 20-byte descriptor per DLL (`Import Lookup Table RVA`, `Time/Date Stamp`, `Forwarder Chain`, `Name RVA`, `Import Address Table RVA`), ended by an all-zero descriptor. The time/date stamp "is set to zero until the image is bound". | Microsoft Learn, "PE Format", Import Directory Table. |
| ID2 | A lookup entry is 32 bits in PE32 and 64 bits in PE32+; its top bit set means import by ordinal (low 16 bits), otherwise its low 31 bits are the RVA of a hint/name entry. The import address table "is identical to the import lookup table until the image is bound". | Microsoft Learn, "PE Format", Import Lookup Table, Import Address Table. |
| ID3 | Windows file names compare without case. | Microsoft Learn, "Naming Files, Paths, and Namespaces". |
| ID4 | An export's ordinal is the ordinal base plus its index in the export address table, independent of the name table. | Microsoft Learn, "PE Format", Export Ordinal Table; parsed by `pe.ParseExports` (S18). |

### windows.pe.resolve_symbols

| # | Fact | Source |
|---|---|---|
| YD1 | The export directory maps names to ordinals and RVAs; an RVA inside the export directory is a forwarder string, not code. | Microsoft Learn, "PE Format", Export Directory Table; `pe.ParseExports`. |
| YD2 | Data directory 6 is the debug directory; type 2 (`IMAGE_DEBUG_TYPE_CODEVIEW`) entries carry the CodeView record, whose "RSDS" form holds the PDB GUID, age and path. | Microsoft Learn, "PE Format", Debug Directory; record layout as `pe.ReadCodeView` reads it (S18). |
| YD3 | A PDB symbol's address in the project's tables is an RVA from the image base. | S32. |
| YD4 | `MAX_PATH` is 260 characters. | Microsoft Learn, "Maximum Path Length Limitation". |

#### Kernel types

| # | Fact |
|---|---|
| IT1 | `_EPROCESS.Peb` and `_EPROCESS.SectionBaseAddress` at 0x2e0 and 0x2b0 (26100: mem1, mem6, mem7), 0x550 and 0x520 (19045: mem2), 0x3f8 and 0x3c0 (14393: mem5); `_PEB.ImageBaseAddress` at 0x10 on all five; read through the project's tables (`petoolfacts -tool peimports`). |
| VT1 | The loader entry members and `PsLoadedModuleList` of S55 T1 to T4. |

#### Measurements

All from `petoolfacts -tool pesymbols,peimports,peversion` on 2026-11-12 over mem1_win11, mem2_win10, mem5_server2016, mem6_server2025 and mem7_server2025, in that order.

| # | Measured |
|---|---|
| VM1 | Kernel rows 195, 195, 142, 158, 165; with a version from the mapped image 10, 10, 7, 8, 8. The rest: resource bytes do not read 182, 179, 133, 143, 147; no version resource 3, 3, 2, 3, 3; headers do not read 0, 3, 0, 4, 7. |
| VM2 | Wherever the headers read, the header `SizeOfImage` equals the loader's (195, 192, 142, 154, 158; none differ). Every version read has `dwStrucVersion` 0x10000. |
| VM3 | Process rows 4351, 8038, 3524, 4694, 4158; with a version 3744, 3113, 2799, 1033, 303. |
| VM4 | Physical memory holds 2481, 1147, 4169, 1006 and 1353 UTF-16 "VS_VERSION_INFO" keys. A block parses as `VS_VERSIONINFO` with a signed `VS_FIXEDFILEINFO` for 2424, 1118, 4108, 960 and 1291; every one that parses starts on a 4-byte boundary, and none of the 57, 29, 61, 45 and 62 that start off one parses. 2346, 1092, 3876, 935 and 1214 name an OriginalFilename, 1161, 818, 1519, 790 and 984 distinct names; 14, 8, 14, 19 and 28 names have copies with different product versions. |
| VM5 | For each kernel module whose mapped image gives a version and which has a cached copy, the copy's product version equals the image's: 10, 7, 5, 6 and 6 modules, no disagreement. |
| VM6 | The extensive option gives a version to 85 of 185, 9 of 185, 62 of 135, 13 of 150 and 43 of 157 kernel modules without one, in 18, 18, 4, 10 and 6 s. Of those still without, a cached copy names `<name>.mui` for 1, 0, 9, 0 and 3. |
| IM1 | Rows 15159, 8964, 12001, 4513, 778 from 74, 45, 66, 23 and 5 processes. Every IAT slot address lies inside its main image's `SizeOfImage`. Main images are PE32+ except one PE32 on mem5 and one on mem6. No descriptor is bound. |
| IM2 | `_PEB.ImageBaseAddress` equals `_EPROCESS.SectionBaseAddress` for 75, 144, 67, 88 and 78 processes and differs for none. It does not read while the section base does for 4, 5, 3, 11 and 10. 4, 4, 1, 2 and 2 processes have neither a PEB nor a section base. |
| IM3 | Main images passed over because their headers do not read: 4, 51, 4, 34, 52; one on mem2 is not a PE image. Descriptor parts passed over: mem2 188 unread and 3 with reserved bits set, mem6 55, mem7 31. Rows with an unread library name 0, 317, 189, 210, 0; with an unread hint/name 0, 311, 64, 202, 0. |
| IM4 | Ordinal imports 653, 587, 256, 55, 0. Named from the mapped library 79, 58, 144, 32; from the ordinal table only 1, 0, 8, 4; unnamed 573, 529, 104, 19. Where the library named one, the ordinal table agrees for 58, 56, 83, 30 and has none for 21, 2, 61, 2; it never disagrees. |
| YM1 | Section views named ntdll.dll: 78, 149, 70, 95, 81 in 77, 147, 67, 92, 79 processes; the loader lists give 74, 125, 67, 72, 40. Views named kernel32.dll: 74, 144, 65, 90, 77; loader lists 73, 142, 66, 86, 76. More than one ntdll view in a process is the 32-bit copy of a WoW64 process or a System (PID 4) view. |
| YM2 | Wherever a view's headers read (ntdll 78, 138, 68, 61, 36), the header `SizeOfImage` fits inside the view. Of the ntdll views, 1, 1, 2, 1, 1 are PE32. Exports do not read in 1 of 78, 34 of 149, 2 of 70, 44 of 95 and 60 of 81 ntdll views tried. |
| YM3 | NtClose, NtCreateFile, LdrLoadDll, EtwEventWrite and RtlUserThreadStart resolve in all five; LdrpInitializeProcess, which ntdll does not export, resolves from the PDB in all but mem5, where no ntdll CodeView record reads in 70 views. kernel32's PDB is not in the offline cache on mem1, mem2, mem6 and mem7; its exports answer, and HeapAlloc is the forwarder `NTDLL.RtlAllocateHeap`. |
| YM4 | Asking each resolved non-forwarder address back gives the asked name: 9, 9, 8, 9, 9 process names and 6 kernel names (ntoskrnl from the kernel table, tcpip from its PDB) on each capture, none another name. |
| YM5 | The tcpip.sys export directory does not read on any capture (absent on mem1 and mem5, paged out on the others); `TcpCompartmentSet` and `PartitionTable` come from tcpip.pdb. `ntoskrnl.exe!PartitionTable` is missing on all five. |
| YM6 | The scan for a CodeView record finds tcpip.pdb (DAC097D9D8F30AC6467DB71184A8C2E5, F4CA288A1108EF44D23437E1E133B4A2, A577CBBD21BE43D3BA44C7CC864143BA, 11B241ADFEA742938BFD75329CFFE121 twice) and ntkrnlmp.pdb with the S55 GUIDs on all five; it finds an ntdll.pdb record in 47, 54, 0, 40 and 16 ntdll views. |

### windows.handle.list

#### Documentation

| # | Fact | Source |
|---|---|---|
| HD1 | "Kernel object handles are process specific." "The per-process limit on kernel handles is 2^24." "Kernel object handles include access rights that indicate the actions that can be granted or denied to a process." | Microsoft Learn, "Kernel Objects" (windows/win32/sysinfo/kernel-objects), dated 2018-05-31, accessed 2026-11-12. |
| HD2 | `ACCESS_MASK` is a DWORD: bits 0-15 specific rights, 16-23 standard rights (`DELETE` 16, `READ_CONTROL` 17, `WRITE_DAC` 18, `WRITE_OWNER` 19, `SYNCHRONIZE` 20), 24 `ACCESS_SYSTEM_SECURITY`, 25 `MAXIMUM_ALLOWED`, 26-27 reserved, 28-31 `GENERIC_ALL`, `_EXECUTE`, `_WRITE`, `_READ`. | Microsoft Learn, "ACCESS_MASK (Winnt.h)" (windows/win32/secauthz/access-mask), dated 2025-10-14, accessed 2026-11-12. |
| HD3 | 4-level paging translates 48-bit linear addresses; a canonical address has bits 63:47 equal; a 4 KB page is the paging granule. | Intel SDM Vol. 3A (253668-093US), H4.5; S55 D3. |
| HD4 | The object type of a header: its `TypeIndex` byte XOR the low byte of `ObHeaderCookie` XOR bits 15:8 of the header's address is the type's slot in `ObTypeIndexTable`, whose `_OBJECT_TYPE.Index` equals the slot; without the cookie the byte is the slot. | S31 4.5 steps 1 and 2, M1, M2, O4. |
| HD5 | Object names by type (namespace, file, key, process, thread) and the not-read rule. | S30 4.1 to 4.6. |

#### Kernel types

Read through the project's kernel tables by `petoolfacts -tool handlelist` for builds 26100 (mem1, GUID 0D960CE103763A6097E839406D8B369F; mem6 and mem7, 953A8DE880B0818C32DA2DEC1D79C2D9), 19045 (mem2, F57E740B088E5056E8AF0772F1CC5BEB) and 14393 (mem5, 3DFC5F7228304C26859E55E481700385).

| # | Fact |
|---|---|
| HT1 | `_EPROCESS.ObjectTable` (`_HANDLE_TABLE *`) at 0x300 on 26100, 0x570 on 19045, 0x418 on 14393. `_HANDLE_TABLE` is 0x80 bytes in all five: `NextHandleNeedingPool` (`unsigned int`) 0, `TableCode` (`unsigned long long`) 8. |
| HT2 | `_HANDLE_TABLE_ENTRY` is 16 bytes in all five, a union: `ObjectPointerBits` bits 20..63 and `Unlocked` bit 0 of the `unsigned long long` at 0; `GrantedAccessBits` bits 0..24 and `NoRightsUpgrade` bit 25 of the `unsigned int` at 8; `LeafHandleValue` (`_EXHANDLE`, 8 bytes) at 8. 44 stored bits and 4 implied zero bits make 48 bits, the 4-level linear address width (HD3). |
| HT3 | `_OBJECT_HEADER` is 0x38 bytes: `TypeIndex` (`unsigned char`) 0x18, `InfoMask` 0x1a, `Body` 0x30. |
| HT4 | `_OBJECT_TYPE` (0xe0 bytes on 26100, 0xd8 on the others): `Name` (`_UNICODE_STRING`) 0x10, `Index` (`unsigned char`) 0x28. The tables have the globals `ObTypeIndexTable` and `ObHeaderCookie`. |

#### Measurements

HM1 to HM8 come from `petoolfacts -tool handlelist` on 2026-11-12 over mem1_win11, mem2_win10, mem5_server2016, mem6_server2025 and mem7_server2025, in that order. The raw part walks every listed process's table with its own reads of HT1 to HT4 and does not use the tool.

| # | Measured |
|---|---|
| HM1 | Processes 83, 153, 71, 101, 90; `ObjectTable` null for 4, 4, 3, 8, 9; tables 79, 149, 68, 93, 81. No `ObjectTable` fails to read. |
| HM2 | `TableCode` low two bits: 0 for 30, 67, 28, 41, 32 tables and 1 for 49, 82, 40, 52, 49; never 2 or 3. With the low two bits cleared, `TableCode` is 4 KB aligned for every table but one on mem7 (PID 6792, `TableCode` 0x33003500620065, UTF-16 text). |
| HM3 | `NextHandleNeedingPool` is a multiple of 1024 for every table but the mem7 one, and equals 1024 times the number of entry pages walked for 79, 149, 67, 92 and 78 tables (the rest have a page that does not read). A page of 4096 / 16 = 256 entries thus spans 1024 handle values: four per entry. |
| HM4 | Of the entry pages that read (257, 322, 152, 209, 189), the first entry's word 0 is 0 and its word 1 (`LeafHandleValue`) equals the handle value of the page's first entry for 257, 322, 150, 209 and 189. The two others are on mem5, in the table of HM6. No first entry is in use except those two. |
| HM5 | Entries in use (`ObjectPointerBits` nonzero): 46,853, 57,560, 25,562, 40,072, 34,206 of 65,792, 82,432, 38,912, 53,504, 48,384 entries examined. Each decodes to a canonical upper-half header for all but 188 on mem5 (HM6). Their `TypeIndex` decodes (HD4) to a slot holding a named type for 43,353, 57,250, 25,170, 40,016 and 34,088; the header does not read for 1,472, 175, 341, 37, 71; the slot is empty for 2,028, 135, 51, 19, 47. Slots whose `_OBJECT_TYPE.Index` equals the slot: 75, 67, 58, 71, 71. |
| HM6 | Pointers in a level-1 top page at or past `NextHandleNeedingPool`: none, except one mem5 table (PID 5784, `NextHandleNeedingPool` 0x1400) with 452 such pointers; its 4 pointers below the ceiling name unmapped addresses (0x74536d4d03810000). The 372 in-use entries past the ceiling and the 220 entries with `Unlocked` clear are all in that table. |
| HM7 | Bits 25..31 of word 1 of in-use entries: only bit 25 (`NoRightsUpgrade`) is ever set, on 101, 321, 19, 152 and 134 entries, outside the mem5 table of HM6. |
| HM8 | Entry pages that do not read: 1, 6, 454, 6, 6; top pages that do not read: 0, 0, 0, 1, 3. Every one that is not in the HM6 table is in the pagefile. |

### windows.file.dump options

| # | Fact | Source |
|---|---|---|
| FD1 | Canonical form and the address mask by paging mode. | S55 4.3, D3, D4. |
| FD2 | A relative `FileName` was relative to a `RelatedFileObject` "only valid during the processing of the IRP_MJ_CREATE requests"; the file name a handle shows is the device's namespace path followed by `FileName`, or a relative `FileName` alone. | S30 4.2, D3. |
| FD3 | Options are typed; a value of the wrong type is an error; patterns are RE2. | `tools/options.go`, `tools/pattern.go` (project contract, plan section 4); owner decisions 2026-11-03 and COL-16. |

| # | Measured (`petoolfacts -tool filedump`, 2026-11-12, same five captures) |
|---|---|
| FM1 | Distinct file objects behind `File` handles: 7,882, 2,685, 1,589, 1,838, 1,700. Their handle-list names are full paths for 7,757, 2,663, 1,585, 1,831, 1,688; relative for 114, 9, 4, 2, 4; not read for 11, 13, 0, 5, 8. Of the full paths, 14, 30, 24, 20 and 17 do not start with `\Device\` (a device outside `\Device`, such as `\clfs`, or a nested one), so prefixing `\Device\` to a device's own name would misname them. |
| FM2 | Every one of those file object addresses translates through the kernel space, each to a distinct physical address. |
| FM3 | `windows.file.dump.filter` `\\ntdll\.dll$` with `ignore_case` tests 8,011, 4,162, 2,457, 2,897, 2,678 file objects (handles and file-backed VADs), keeps 4, 2, 2, 2, 2, writes 2 artefacts on each capture, and leaves out 125, 27, 6, 11 and 18 whose name is not a full path. |

### windows.library.compare

| # | Fact | Source |
|---|---|---|
| LD1 | `MEMORY_BASIC_INFORMATION.Type` `MEM_IMAGE`: "mapped into the view of an image section". | Microsoft Learn, "MEMORY_BASIC_INFORMATION (winnt.h)" (S24 D2). |
| LD2 | `PEB.Ldr` points to `PEB_LDR_DATA`, whose `InMemoryOrderModuleList` "contains the loaded modules for the process"; each item is an `LDR_DATA_TABLE_ENTRY`, whose `DllBase` is the module's base. | Microsoft Learn, "PEB structure", "PEB_LDR_DATA structure" (S56 D1 to D3). |
| LD3 | With `LOAD_LIBRARY_AS_IMAGE_RESOURCE` "the system maps the file into the process's virtual address space as an image file. However, the loader does not load the static imports or perform the other usual initialization steps." A module mapped as a data or image file this way is not made "visible to functions such as CreateToolhelp32Snapshot or EnumProcessModules". | Microsoft Learn, "LoadLibraryExA function (libloaderapi.h)", ms.date 2018-12-05, updated 2025-07-01, accessed 2026-11-12. |
| LT1 | `_PEB.Ldr`, the three `_PEB_LDR_DATA` list heads, the three `_LDR_DATA_TABLE_ENTRY` links and `DllBase`, and the 32-bit layout: S56 T1 to T4 and L1, read in the tables of builds 26100, 19045 and 14393. | S56. |
| LT2 | A VAD with `PrivateMemory` clear is a section view; `VadType` 2 is exactly where the control area has `Image` set (measured, S24 M11, O2). | S24. |

Measurements LM1 to LM7: `petoolfacts -tool librarycompare`, 2026-11-12, on mem1_win11, mem2_win10, mem5_server2016, mem6_server2025 and mem7_server2025, in that order. The raw half pairs the library list's records with the decoder's views directly; the tool half tallies the rows.

| # | Measured |
|---|---|
| LM1 | Processes 83, 153, 71, 101, 90. No VAD tree fails to read. VAD kinds image / mapped / private: 4,430 / 3,033 / 3,284; 8,315 / 5,533 / 7,935; 3,489 / 2,372 / 3,947; 4,859 / 3,949 / 5,285; 4,490 / 3,392 / 3,039. No VAD is of unknown kind. No two image views of a process start at the same address. |
| LM2 | The 2 bytes at an image view's start read `MZ` for 4,420, 4,946, 3,439, 2,156 and 706 views, read otherwise for 0, 13, 0, 0 and 1, and do not read for 10, 3,356, 50, 2,703 and 3,783. |
| LM3 | Loader records 4,351, 8,038, 3,524, 4,694 and 4,158. Records whose `DllBase` starts no image view: 0, 3, 42, 0 and 19; none of them lies inside an image view. They sit in processes whose VAD walk left nodes out (mem7: `WmiPrvSE.exe` 944, 18 records, 10 nodes left out; `svchost.exe` 1068, 1 record, 1 node) or whose tree gave no image view at all (mem5: `msedge.exe` 5136, 39 records); the one on mem7 at base 0 is the record S56 M5 names. |
| LM4 | Image views by the lists that hold their start: all three 4,276, 7,890, 3,408, 4,602, 4,057; load and memory order only 75, 144, 72, 91, 80; initialization order only 0, 0, 0, 0, 1; no list 79, 281, 9, 166, 352. Load order and memory order never disagree. |
| LM5 | Processes with image views and no loader record at all: 3, 4, 1, 4, 1 (`System` on all five; `Secure System` and `LsaIso.exe` on mem1 and mem2; `SearchApp.exe` on mem2 with 211 views; `fontdrvhost.exe`, `msdtc.exe` and `ssh-agent.exe` on mem6). Their views are 25, 235, 2, 79 and 3 of the no-list rows. |
| LM6 | The other no-list views, in processes with loader records (54, 46, 7, 87, 349), by file extension: `.dll` 40, 38, 6, 82, 340; `.winmd` 14, 7, 1, 4, 6; `.lex` 0, 1, 0, 0, 0; no extension 0, 0, 0, 1, 3. |
| LM7 | Rows marked 32-bit: 0, 43, 66, 27, 39. Processes whose WoW64 column is set but whose 32-bit lists gave no record: 3 on mem1 and 3 on mem6, all `msiexec.exe` with no native record either. The mapped file name does not read for 0, 3, 0, 3 and 14 rows. |

### windows.credential.find_truecrypt

| # | Fact | Source |
|---|---|---|
| TD1 | Section flags `IMAGE_SCN_MEM_EXECUTE` 0x20000000 ("can be executed as code") and `IMAGE_SCN_MEM_WRITE` 0x80000000 ("can be written to"). `VirtualSize` is "the total size of the section when loaded into memory"; if it is greater than `SizeOfRawData`, "the section is zero-padded". `SizeOfImage` is the size of the image as loaded. | Microsoft Learn, "PE Format", accessed 2026-11-12. |
| TD2 | File names on Windows: "Do not assume case sensitivity"; names that differ only in case are the same file to the file system by default. | Microsoft Learn, "Naming Files, Paths, and Namespaces", accessed 2026-11-12. |
| TD3 | The loaded kernel modules, their bases and `BaseDllName`: S55 4.1. The PE headers at a base: `extract.ReadHeaders` (S18). | S55, S18. |
| TD4 | No allowed source documents where or how the TrueCrypt driver keeps a passphrase. | Owner decision TO1. |

Measurements TM1 to TM4: `petoolfacts -tool credentialtruecrypt`, 2026-11-12, on the five captures in the order above. The raw half applies the tool's text rule (`FindCounted`) to the writable, non-executable sections of every loaded module: with no TrueCrypt driver present, what it finds is what the rule finds in memory that holds no passphrase.

| # | Measured |
|---|---|
| TM1 | Modules 195, 195, 142, 158, 165. No module is named `truecrypt.sys` or `veracrypt.sys`; the only names containing `crypt` are `symcryptk.dll` (mem1, mem6, mem7) and `filecrypt.sys` (all five). |
| TM2 | PE headers do not read for 0, 7, 6, 4 and 7 modules. Writable non-executable sections 264, 248, 172, 222, 223, holding 9,942,794, 6,013,145, 1,766,108, 7,826,615 and 7,767,498 bytes, of which 4,151,212, 26,404, 16,780, 4,351,301 and 4,292,360 do not read. No section is both writable and executable. |
| TM3 | Counted printable strings over those sections, by shortest length: 1: 167, 577, 233, 156, 154; 4: 2, 2, 0, 0, 0; 8: 2, 2, 0, 0, 0; 12: 0 on all five. At length 4 the hits are 8 to 15 bytes long, one each in `clipsp.sys` and `HTTP.sys` (mem1) and in `ntoskrnl.exe` and `clipsp.sys` (mem2). |
| TM4 | The tool gives no row and no error on all five. |

### windows.image.map_strings

| # | Fact | Source |
|---|---|---|
| GD1 | `strings -t d` writes each string "preceded by its byte offset from the start of the file" in the format `"%d %s"`; a string is a run of printable characters "terminated by a <newline> or NUL character". | POSIX.1-2024 (IEEE Std 1003.1-2024), `strings` utility, accessed 2026-11-12. |
| GD2 | A segmented image layer stores each physical run at a file offset after its own headers (`memory.Segment`: `PhysicalBase`, `FileOffset`, `Length`); a raw image is physical memory from offset 0. | The project's memory layers (crash dump, ELF core, LiME). |
| GD3 | The address-space listing gives each mapped run of a page-table root in virtual-address order, canonical, only where the image holds every byte, and leaves out a table that is one value repeated. | S53 (`layers.IntelTranslator.Mapping`). |
| GD4 | Each process's kernel page-table root maps its user half and the system half. | S25 (`processlist.KernelDirectoryTableBase`), S55 4.3. |

| # | Measured (`petoolfacts -tool imagestrings`, 2026-11-12; mem1_win11, mem2_win10, mem5_server2016, mem6_server2025, mem7_server2025) |
|---|---|
| GM1 | mem1, mem2 and mem5 are raw images (`FileMemoryReader`, no segments); mem6 and mem7 are crash dumps (`CrashDumpReader`) with segments. On each, the probe translated three virtual addresses (ntoskrnl's DOS stub text at the kernel base + 0x4e, and the same text in `lsass.exe` and `explorer.exe`), read `This program cannot be run in DOS mode` at the physical address, and wrote the file offset: the physical address on mem1, mem2 and mem5, the segment's file offset on mem6 and mem7. |
| GM2 | The tool gave each of the 15 lines the expected address: the kernel line its kernel address (mem2 a second kernel address as well) and no process address; each process line its process's user address and no kernel address. |
| GM3 | Offset 4096 holds physical memory on the raw images and lies in the dump header on mem6 and mem7, where the tool gives no address. A line without an offset is skipped and named in a diagnostic. |
| GM4 | Page tables that do not read: 1,596 on mem1 and 1,238 on mem7, none elsewhere. No process root failed to read. Run time 14.4, 18.3, 0.7, 12.8 and 12.7 s for 5 lines. |

### windows.image.read_crash_header

| # | Fact | Source |
|---|---|---|
| CD1 | `KeInitializeCrashDumpHeader` "supplies the header information the system requires for a crash dump file"; for `DumpType` "the only valid value is DUMP_TYPE_FULL". From Windows 8 it "always writes the base address of the system process page directory to the crash-dump header". | Microsoft Learn, "KeInitializeCrashDumpHeader function (ntddk.h)", ms.date 2018-04-30, accessed 2026-11-12. |
| CD2 | `KeQueryInterruptTime` returns "the current interrupt-time count in 100-nanosecond units", "the amount of time since the operating system was last started". `_KUSER_SHARED_DATA` sits at `KI_USER_SHARED_DATA` 0xFFFFF78000000000 on x64 and holds `InterruptTime` and `SystemTime`. | Microsoft Learn, "KeQueryInterruptTime function (wdm.h)", accessed 2026-11-12; WDK 10.0.28000.0 `km/wdm.h`. |
| CD3 | A `FILETIME` counts 100-nanosecond intervals since January 1, 1601 (UTC). | Microsoft Learn, "FILETIME structure (minwinbase.h)". |
| CD4 | The crash dump layer parses the 64-bit header and marks `DumpTypeIntact` false when the run array reaches `DumpType` at 0xF98; it opens only full dumps. | The project's crash dump layer (`memory/crashdump.go`). |

| # | Measured (`petoolfacts -tool imagecrashheader`, same five captures) |
|---|---|
| CM1 | mem1, mem2 and mem5 are not crash dumps: the tool returns `ErrNotCrashDump`. mem6 and mem7 are: version 15.26100, machine 0x8664, 4 processors, bug check 0x5454414D on both. mem6 has 309 runs, which overrun `DumpType`: the tool gives no dump type, time or comment, with its diagnostic. mem7 has 4 runs and dump type 1. |
| CM2 | mem7's comment field is "PAGE" 32 times, the fill the header's signature also uses: no comment was written. |
| CM3 | On mem7, header up time 12m10.5428888s and `_KUSER_SHARED_DATA.InterruptTime` 12m10.6033975s (read as 100 ns ticks) differ by 60.5087 ms, and header `SystemTime` and `_KUSER_SHARED_DATA.SystemTime` differ by the same 60.5087 ms: both header fields are the shared clock's 100 ns counts taken one moment earlier. |
| CM4 | `DirectoryTableBase` equals the session's kernel root (0x7D5000) on both, as CD1 says; `PsLoadedModuleList` and `PsActiveProcessHead` equal the symbol addresses of the kernel table. `KdDebuggerDataBlock` does not (0xFFFFE40B89004080 against 0xFFFFF804A79A1040 on mem6; 0xFFFF81012CD86080 against 0xFFFFF801A2651040 on mem7): the header holds another address, not the symbol. |

### windows.disk.scan_boot_records

| # | Fact | Source |
|---|---|---|
| BD1 | "The MBR contains a small amount of executable code called the master boot code, the disk signature, and the partition table for the disk. At the end of the MBR is a 2-byte structure called a signature word or end of sector marker, which is always set to 0x55AA." The disk signature is "a unique number at offset 0x01B8". The partition table is 64 bytes, "each partition table entry is 16 bytes long, with a maximum of four entries", at 0x1BE, 0x1CE, 0x1DE and 0x1EE. "When there are fewer than four partitions on a disk, the remaining partition table fields are set to the value 0." | Microsoft Learn (archived), "How Basic Disks and Volumes Work", ms.date 2009-10-08, accessed 2026-11-12. |
| BD2 | Entry fields: Boot Indicator (1 byte, legal values 00 "Do not use for booting" and 80 "Active partition"), Starting Head, Starting Sector (bits 0-5), Starting Cylinder (10 bits: the next byte and bits 6-7 of the sector byte), System ID, Ending Head, Ending Sector, Ending Cylinder, Relative Sectors (4 bytes, "the offset from the beginning of the disk to the beginning of the volume, counting by sectors"), Total Sectors (4 bytes). Numbers are little endian. | Same, "Partition Table Fields". |
| BD3 | "Only one primary partition on the disk can have this field set." Sector fields are 6 bits, "the enumeration of sectors starts at 1 (not 0, as for other fields)". The 32-bit Relative and Total Sectors allow partitions "up to 2^32 sectors". | Same. |
| BD4 | A GPT disk keeps a Protective MBR: one entry with System ID 0xEE and Boot Indicator 00 that "reserves the entire space of the disk"; Ending CHS fields set to FF when the end is too large. | Same, "GUID Partition Table". |
| BD5 | System ID values: 0x01 FAT12, 0x04 FAT16, 0x05 Extended, 0x06 BIGDOS FAT16, 0x07 Installable File System (NTFS), 0x0B FAT32, 0x0C FAT32 with INT 13h extensions, 0x0E BIGDOS FAT16 with INT 13h extensions, 0x0F Extended with INT 13h extensions, 0x12 EISA or OEM, 0x42 Dynamic volume, 0x84 power management hibernation, 0x86 and 0x87 Windows NT 4.0 multidisk FAT16 and NTFS, 0xA0 laptop hibernation, 0xDE Dell OEM, 0xFE IBM OEM, 0xEE GPT, 0xEF EFI System on an MBR disk. | Same, "System ID Values". |
| BD6 | The partition table is the same in an extended boot record. | Same. |
| BD7 | Code run in real-address mode uses 16-bit operand and address size by default. | Intel SDM Vol. 1 and Vol. 3A (253668-093US), real-address mode operation. |

| # | Measured (`petoolfacts -tool diskbootrecords`, same five captures; the raw half reads the layout of BD1 and BD2 itself and applies the rules of section 5 written again) |
|---|---|
| BM1 | Byte offsets ending in 0x55AA with 510 bytes before them: 4,271, 53,240, 7,650, 2,689, 6,583; of these, at a 512-byte boundary only 2, 39, 30, 9, 18. Records whose table every rule accepts: 9, 3, 4, 5, 5; at a 512-byte boundary only 0, 0, 0, 1, 1. Copies of one record recur at the same page offset (0x640 twice on mem2, 0x710 and 0xF10 twice on mem5), so they are buffers holding a record, not disk sectors in place. |
| BM2 | Accepted records: mem1 nine copies of one protective record (one entry 0xEE, Relative 1, Total 0xFFFFFFFF, zero boot code); mem2 two copies of a record with signature 0xAFB3AFB3, boot code and one active NTFS entry at sector 63, and a zero-code table of four entries (0x06 active, then three 0x07); mem5 two copies each of that same NTFS record and of the four-entry table with boot code; mem6 four protective records and one zero-code record whose only entry is type 0x55 at 85 with 1,431,655,680 sectors; mem7 the NTFS record, the four-entry table, two protective records and one record whose only entry is type 0xBB at 707,246,714 with 1,596,915,403 sectors. The 0x55 and 0xBB records have no documented System ID (BD5). |
| BM3 | The first rule each refused candidate breaks: boot indicator 3,344, 33,264, 6,815, 2,193, 6,221; unused entry not zero 647, 18,506, 484, 376, 206; CHS sector 0 112, 714, 147, 49, 45; past 2^32 sectors 88, 477, 98, 41, 69; no sectors 40, 147, 66, 15, 18; no entry in use 14, 13, 25, 5, 11; starts at sector 0 13, 88, 8, 3, 7; overlap 4, 28, 3, 2, 1; no capture has two active entries in a record that passes the earlier rules. |
| BM4 | The tool lists 9, 3, 4, 5, 5 records with 9, 6, 10, 5, 8 entries, each at an address the raw half accepted, and names the 4,262, 53,237, 7,646, 2,684 and 6,578 others in one diagnostic. With `full` it lists all 4,271, 53,240, 7,650, 2,689 and 6,583. No page fails to read. Run time 35, 38, 14, 17 and 12 s. |

## 4. Algorithm

### windows.pe.read_version

1. **Profile and option.** The profile must be Windows (`ErrNotWindows`); the extensive option is read as a boolean.
2. **Kernel rows.** For each module of `windows.module.list` with a readable base, in list order: read the PE headers through the S55 reader choice, set `SizeOfImage` from them, take data directory 2 and read the version with `pe.ReadVersion` over the image bounded by `SizeOfImage` (VD4). The product version's four 16-bit parts are `Major`, `Minor`, `Product`, `Build` (VD3). A module whose base does not read gives no row and is counted.
3. **Cached copies (extensive).** For kernel rows without a version whose name read, the wanted names are the base name and the path's last element, folded to lower case (ID3; S55 M4 shows base name and file differ for kdcom.dll). Physical memory is scanned in address order for the UTF-16LE key "VS_VERSION_INFO" plus NUL; the block starts 6 bytes before it (VD1). Its `wLength` bytes are read and parsed with `pe.ParseVersionInfo`, alignment taken from the physical address (VM4), and its tree is walked (VD1, VD2) for the OriginalFilename string. A block whose OriginalFilename folds to a wanted name gives that row its product version and `VersionPhysical` its address. The lowest address wins; names whose copies differ are reported (VM4). The agreement of VM5 is what makes a cached copy evidence of the loaded module's version.
4. **Process rows.** For each row of `windows.library.list` (pid applied), read the same way through the process's space only; a process whose space does not open gives no rows and is counted. A row with `BaseUnreadable` set (its `DllBase` did not read, S56 4.1 step 6) gives no row and is counted.
5. **Order.** Kernel modules in list order, then process modules in library list order.

### windows.pe.list_imports

1. **Layout.** `_EPROCESS.Peb` and `_PEB.ImageBaseAddress` are required (`ErrNoPEBTypes`); `_EPROCESS.SectionBaseAddress` is optional (IT1).
2. **Processes.** `any.process.list`, narrowed by `pid`.
3. **Main image base.** A PEB pointer of 0 means no user image: no rows, counted. Otherwise `ImageBaseAddress` read through the process space; when the PEB pointer or `ImageBaseAddress` does not read, or `ImageBaseAddress` is 0, the section base, counted (IM2: the two never differ).
4. **Directory.** Headers through the process space, data directory 1, `pe.ParseImports` over the image bounded by `SizeOfImage`, PE32 or PE32+ as the optional header says (ID1, ID2). No directory, a zero RVA or `pe.ErrNoImportDirectory`: no rows, counted.
5. **Rows.** One per import in descriptor order: library, function name or ordinal, `Bound` = the descriptor's time/date stamp is nonzero (ID1), `Address` = image base + the IAT slot RVA. A descriptor part the parser passed over is counted by cause.
6. **Ordinal names.** For an ordinal import whose library name read: the export of that ordinal (ID4) in the first library-list module of the same process with a nonzero `Base` (a row with `BaseUnreadable` set has `Base` 0) whose name equals the library without case (ID3) and whose width matches the importer (WoW64 for PE32), `FunctionFrom` `exports`; else the ordinal table, `table`; else no name. Each library mapping's exports are read once.

### windows.pe.resolve_symbols

1. **Request.** Module name trimmed and folded to lower case (ID3); exactly one of names or addresses; source `processes` or `kernel`.
2. **Instances.** Collected once, on first need, for all asked modules. `processes`: every process whose space opens, every section view whose file path has a separator; the module name is the path's last element, folded; the view's start and length are its base and size (YM2). With `loader_list`, the loader list rows with a base and a name; a row with `BaseUnreadable` set has `Base` 0 and is passed over. `kernel`: the modules of `windows.module.list` with a known range (S55 `Placed`), read through kernel space. Order: process list order, then view or list order (YM1).
3. **Asked keys.** Each module's asks keep the caller's order and repeats; a key is answered at most once, and stays answered.
4. **Kernel image.** For `ntoskrnl.exe` with source `kernel`, names come from the kernel table and addresses from its sorted address index first (YD3 does not apply: kernel table addresses are absolute).
5. **PDB.** Otherwise, when a PDB loader is given, for each instance in order until all keys are answered: read the CodeView record from the debug directory (YD2) through the instance's reader, load that fingerprint's table once (YD3); names give base + RVA; an address inside the instance's range gives the first name at its RVA in table order. A fingerprint that does not load is reported once; instances without a readable record are counted per module.
6. **Exports.** Then for each instance in order until all keys are answered: the first export of an asked name in table order, or the first named export at an asked address; forwarders keep their string (YD1). Instances whose exports do not read are counted per module.
7. **Results.** Found symbols in ask order with repeats; missing keys once each in first-ask order. An instance collection error is returned only when something stayed missing.
8. **Exports of one instance.** The reader is the instance's process space, or kernel memory for DTB 0, never the kernel tables for a process instance. The image is bounded by the instance size, or by the header `SizeOfImage` when the size is 0. When the directory fits `MaxBufferBytes`, it is read once and served from memory.
9. **CodeView scan (`FindPDBRecord`).** Pages of the range are read one by one; readable neighbours are searched as one run, so a record across a page boundary is found. A record is "RSDS", GUID, age, then a path whose NUL lies within `MAX_PATH` bytes (YD4); it matches when the path's last element equals the asked PDB name without case.
10. **Union (`CopyExports`).** Named, non-forwarder exports passing the caller's filter, one per name per base, sorted by address then name; the count of instances whose exports did not read.

### windows.handle.list

#### H4.1 Layout

1. Required: `_EPROCESS.ObjectTable`, `_HANDLE_TABLE.TableCode`, `_HANDLE_TABLE_ENTRY` with a size that divides a 4 KB page, `ObjectPointerBits` as a bit field of at most 60 bits, and `GrantedAccessBits`, both inside the entry (HT1, HT2). A missing one is `ErrNoHandleLayout` naming it.
2. Optional: `NextHandleNeedingPool` (the ceiling, H4.3), `LeafHandleValue` (the page check, H4.4), the type members and globals of HT3 and HT4 (H4.5).

#### H4.2 Table

1. Read `ObjectTable` as a pointer. Null: the process has no handle table and no rows, with no diagnostic (HM1).
2. Read `TableCode`. Its low two bits are the level, the rest the top page (HM2). A level above 2 is refused (`handlelist: handle table level not 0, 1 or 2`): with 512 pointers per page and 256 entries per leaf, level 2 holds 2^26 entries, above the 2^24 limit of HD1. A top page not 4 KB aligned is refused (`handlelist: handle table page is not page-aligned`, HM2). Either refusal gives a diagnostic and no rows.
3. Level 0: the top page is the one entry page. Level 1: it is a page of pointers to entry pages; pointer *i* covers handle values from *i* × 1024. Level 2: a page of pointers to level-1 pages, each covering 512 × 1024 values. Null pointers are skipped.

#### H4.3 Ceiling

1. The ceiling is `NextHandleNeedingPool` when it reads, is nonzero, is a multiple of the 1024 values a page spans, and does not exceed the limit (HM3). Otherwise it is the limit: `MaxTableEntries` × 4, capped at 2^24 × 4 (HD1).
2. A pointer whose first value is at or past `NextHandleNeedingPool` is not followed and is counted in one diagnostic per table: no intact table has one (HM6).
3. An entry at the limit stops the walk with a diagnostic naming the limit.

#### H4.4 Entries

1. Read each entry page whole. One that does not read is counted (HM8).
2. With `LeafHandleValue`, the page's first entry must hold the handle value of the page's first entry (HM4). A page that does not is not this table's page at this place: its entries are not listed and it is counted.
3. The first entry of each page is skipped: it is never in use (HM4).
4. An entry is in use when `ObjectPointerBits` is nonzero (HM5). Its handle value is 4 × (the page's first index + the entry's index) (HM3). Its object header is `ObjectPointerBits` shifted left 4, in canonical form at the 48-bit width the stored bits and the shift make (HT2, HD3). Its granted access is `GrantedAccessBits`: bits 0..24 of the access mask, the specific, standard and `ACCESS_SYSTEM_SECURITY` rights (HD2); bit 25 of the word is `NoRightsUpgrade`, not access (HT2, HM7).
5. `Unlocked` is not tested: every in-use entry of an intact table has it set (HM6), and a held lock is a passing state, not damage.

#### H4.5 Type

1. Read the header's `TypeIndex` byte and decode its slot (HD4). The cookie's low byte is read once per walker; a table without `ObHeaderCookie` uses the byte as the slot.
2. The slot's `ObTypeIndexTable` pointer must be nonzero and its `_OBJECT_TYPE.Index` must equal the slot (HM5); its `Name` is the type name. Slots are read once per walker.
3. A header that does not read, or a slot without such a type, leaves `TypeName` empty, `TypeIndex` the slot (0 when the header did not read), `NameUnreadable` set, and no name is attempted. One diagnostic per run counts them. A table without the type members or globals gives every row without a type, with one diagnostic.

#### H4.6 Name and order

1. Rows with a type take their name from S30 (HD5).
2. Rows are in process order, then handle value.
3. `FileObjectName` gives the S30 file form for a file object body, for tools that select file objects by that name.

### windows.file.dump options

1. **Address lists.** `virtaddr` and `physaddr` are unsigned lists. A key that is set but names no address is a type error (`ErrEmptyAddressList`): read as unset, it would carve every file object.
2. **Exclusions.** `filter` with either address option is `ErrFilterWithAddress`. `physaddr` without a physical layer is `ErrNoPhysicalMemory`.
3. **Notes.** `ignore_case` without `filter` gives a diagnostic. Addresses with a `pid` set give a diagnostic: given addresses are carved without walking processes.
4. **Virtual addresses.** Each is taken in canonical form (FD1). A value whose bits above the mask are neither all clear nor its sign extension gives a diagnostic naming the address bits.
5. **Once each.** A file object given twice, by the same or another spelling, is carved once, with a diagnostic naming the first spelling. A physical address the kernel maps at a given virtual address is dropped in its favour, with a diagnostic (FM2). Without translation both are carved, with a diagnostic. A physical address at or past the end of physical memory is not read, with a diagnostic.
6. **Filter.** The filter matches the name `windows.handle.list` shows for the file object (FD2, `handlelist.FileObjectName`), so a name read there selects the same object here. Only full paths are matched: a relative name lost its anchor (FD2), and a name that does not read cannot be matched. Those are left out and counted (FM3). One diagnostic says how many file objects of how many the filter kept, quoting the pattern without its case flag.

### windows.library.compare

1. The profile must be Windows (`ErrNotWindows`).
2. List the processes (S25) and keep those the PID set keeps.
3. List the loader records (S56 4.1). A record with `BaseUnreadable` set names no base and is left out of the index. Index the others by process (`_EPROCESS` address) and `DllBase`. A base held by several records takes the union of their lists, and is marked 32-bit when any of them came from the 32-bit lists (LT1). A failed library list fails the run: without it no membership means anything.
4. For each kept process, decode its VADs (S24). A tree that does not read is reported and the process skipped; in strict mode it fails the run.
5. Each VAD of kind `image` is an image view (LD1, LT2) and gives one row at its start: the image's base, where the loader record's `DllBase` points for a module the loader mapped (LD2, LM3). The row takes the lists of the records at that base, or none. A start already seen in the process is reported and the first view kept (LM1). VADs of kind `unknown` are counted and reported, not compared.
6. A process with image views and no loader record has every row marked `LoaderListsEmpty` and one diagnostic: the PEB or its lists did not read, or the process has no user-mode loader (LM5), so absence from the lists says nothing there.
7. A WoW64 process with native records and no 32-bit record is reported: its 32-bit images then show on no list.
8. Loader records whose `DllBase` starts no image view are counted per process, with the lowest base, in one diagnostic. Such a record names memory the loader did not map from an image section, or a view the VAD walk left out (LM3).
9. Rows: process list order, then base ascending.

### windows.credential.find_truecrypt

1. The profile must be Windows (`ErrNotWindows`). Read `truecrypt_min_length`; outside 1 to 128 it is `ErrMinLength`, a wrong type is the option type error.
2. List the kernel modules (S55). Keep each whose base name is `truecrypt.sys` ignoring case (TD2, TO2). A module whose name does not read cannot be ruled out; the count is reported once. A kept module without a readable base is reported and passed over.
3. Read the PE headers at the base (TD3). Unreadable headers are a diagnostic, or the error in strict mode.
4. Scan each section that is writable and not executable (TD1, TO4). Its span is `VirtualSize`, or `SizeOfRawData` when `VirtualSize` is 0, cut at `SizeOfImage`, and cut at `MaxRegionScanBytes` with a diagnostic. Read it page by page with holes as zeros (`extract.ReadPadded`); unread bytes are reported. Zeros cannot form a hit.
5. At each 4-byte aligned offset of the section, read a little-endian 32-bit length n. A hit is n from the minimum to 128, followed by n bytes from 0x20 to 0x7E and a NUL (TO3, TO5). The scan resumes at the first aligned offset after the NUL.
6. Each hit is a row at the virtual address of its length. Rows: module list order, then section order, then address.

### windows.image.map_strings

1. The profile must be Windows (`ErrNotWindows`), the file option set (`ErrNoFile`) and physical memory present (`ErrNoPhysicalMemory`).
2. **Lines.** Read the file line by line. A line ends at LF; a CR before it is dropped, since a listing written on Windows ends lines with CRLF. Empty lines are passed over. The empty test comes before the CR is dropped, so a line that holds only CR is not passed over: `ParseLine` drops the CR and rejects the empty rest as "no decimal offset" (GO6). A line longer than `MaxTextBytes` is rejected whole.
3. **Parse.** Optional blanks (space or tab), then decimal digits, then one blank, then the string (GD1). The string keeps every byte after that blank. Text that is valid UTF-8 is kept; otherwise each byte becomes the rune of its value (Latin-1), so no byte is lost (GO3). A line without digits, without the blank, with nothing after the blank, or whose offset does not fit 64 bits is rejected with its reason. Rejected lines are counted in one diagnostic that names the first ten with their reasons. More than `MaxRowsPerObject` accepted lines is an error.
4. **Physical address.** With segments, the offset is inside the segment whose file range holds it, and the physical address is that segment's base plus the distance into it; an offset in no segment (a header) holds no memory. Without segments, the offset is the physical address when it lies below the layer's size (GD2, GM1). Offsets that hold no memory are counted in a diagnostic and give rows with `InMemory` false.
5. **Kernel space.** List the runs of the session's kernel root with the session's paging mode (GD3). No kernel root is `ErrNoKernelRoot`; a kernel listing that fails is an error.
6. **Process spaces.** For each listed process that `pid` keeps, list the runs of its kernel page-table root (GD4), keeping only runs below the start of the upper half (S55 4.3): its system half is the kernel's and would repeat every kernel address once per process. A root that does not read, or a listing that fails, leaves the process out with a diagnostic; one more counts them.
7. **Match.** For each run, every wanted physical page inside it gives each of its strings the address `run virtual + (page − run physical) + offset in page`. Mappings come in space order (kernel, then processes in process-list order) and, within a space, in virtual-address order.
8. **Rows.** One per accepted line, in file order. `Result` joins the mappings, `kernel 0x<va>` or `pid <n> 0x<va>`, with `; `; empty when there are none.
9. Page tables that do not read are counted in one diagnostic, since strings on the pages they map lack those addresses.

### windows.image.read_crash_header

1. The physical layer must be the crash dump layer; otherwise `ErrNotCrashDump`.
2. Every field before the run array is given as the layer read it (CD4).
3. When `DumpTypeIntact` is false, the run array reaches `DumpType` and the fields after it: `DumpTypeKnown` is false, dump type, times and comment are not given, and one diagnostic names the run count (CM1).
4. Otherwise dump type 1 is named `full` (CD1); any other value is given by number (CO2). `SystemUpTime` is the field's count of 100 ns ticks (CD2, CM3), not given when it exceeds `time.Duration`. `SystemTime` is a `FILETIME` (CD3) through `util.FiletimeToTime`, not given when 0 or at or above 2^63.
5. The comment is the field's bytes up to the first NUL, invalid UTF-8 replaced. A comment that is only repeats of "PAGE" is no comment (CM2).
6. `Signature` is "PAGE", the signature the layer requires.

### windows.disk.scan_boot_records

1. Physical memory must be present (`ErrNoPhysicalMemory`).
2. **Scan.** Walk each mapped range in 16 MiB chunks. Each chunk is read with the 511 bytes before it, so a record that crosses a chunk end is seen whole and once: a marker found inside those 511 bytes either starts before them or was already seen. A chunk that does not read is read page by page; unread pages are counted once each, and a record any of whose bytes lie on one is counted and not decoded. Every byte offset is a candidate start, not only 512-byte boundaries (BM1).
3. **Candidate.** Each offset whose bytes 510 and 511 are 0x55 0xAA (BD1). Parse the four entries (BD2): the sector is bits 0-5 of its byte and the cylinder is bits 6-7 of that byte above the next byte.
4. **Table rules** (section 5), in order; the first broken rule is the record's problem. Without `full`, only records with no problem are listed, and one diagnostic counts the others.
5. **Record row.** Address, disk signature, MD5 of the boot code (bytes 0 to 0x1B7) and of the 512 bytes, the boot code bytes, and a listing of the boot code: decode with 16-bit operand and address size (BD7) from offset 0; a byte that does not decode is listed as `db 0x..` and passed over, so the listing covers every byte. Each line is the offset in four hex digits and the instruction. A listing longer than `MaxTextBytes` is cut at a line end and counted in a diagnostic.
6. **Entry rows.** One per entry whose System ID is not 0, in table order, with index 1 to 4, active flag, raw indicator, System ID and its name from BD5 (empty when BD5 has none), Relative and Total Sectors and the CHS fields.
7. **Order.** Physical address, each record followed by its entries.
8. After `MaxRowsPerObject` records the scan stops with a diagnostic. Unread pages give a diagnostic; in strict mode they then fail the run with `ErrUnreadMemory`.

## 5. Validity rules

### windows.pe.read_version

| Rule | Justification | On failure |
|---|---|---|
| Version from the image's own resource directory | VD1 to VD4 | Row kept, `VersionUnreadable`, cause counted |
| Read through the reader that maps the module | S55 4.6 step 3, M5 | Image reads fail; counted |
| Cached copy tied by OriginalFilename to base name or path file name | VD2, ID3, VM5 | No version |
| Lowest physical address wins | VM4 | Differing copies reported |
| Block alignment from its address | VD1, VM4 | Block not parsed |

### windows.pe.list_imports

| Rule | Justification | On failure |
|---|---|---|
| Main image from the PEB, else the section base | IM2 | Process passed over, counted |
| IAT slot = base + FirstThunk + index × width | ID1, ID2, IM1 | — |
| Ordinal named only from a same-width mapping of the library in the same process | ID2, ID4, IM4 | Ordinal table, then no name |
| Library names compare without case | ID3 | — |

### windows.pe.resolve_symbols

| Rule | Justification | On failure |
|---|---|---|
| PDB before exports | YM3: non-exported names | Exports answer |
| PDB address answered only inside the instance's range | YD3 | Next source |
| Process instances read only through their own space | 4 step 8 | Instance's exports fail, counted |
| First export of a name, first named export at an address | YD1, YM4 | — |
| Every process read regardless of pid | 4 step 2 | — |
| CodeView path NUL within `MAX_PATH` | YD4 | Record not taken |

### windows.handle.list

| Rule | Justification | On failure |
|---|---|---|
| Required layout members | HT1, HT2 | `ErrNoHandleLayout` |
| Level at most 2 | HD1, HM2 | Table refused, diagnostic |
| Top page 4 KB aligned | HM2 | Table refused, diagnostic |
| Entries below `NextHandleNeedingPool` when it is a page multiple | HM3, HM6 | Pointer not followed, counted |
| Entries below `MaxTableEntries` × 4 and 2^24 × 4 | HD1, Limits | Walk stops, diagnostic |
| Page's `LeafHandleValue` equals its first value | HM4 | Page not listed, counted |
| First entry of a page skipped | HM4 | — |
| In use when `ObjectPointerBits` nonzero | HM5 | Free |
| Granted access is bits 0..24 | HD2, HT2, HM7 | — |
| Type slot's `Index` equals the slot | HD4, HM5 | No type, flagged |

### windows.file.dump options

| Rule | Justification | On failure |
|---|---|---|
| Set address key names an address | FD3 | Option type error |
| Filter excludes addresses | 4 step 2 | `ErrFilterWithAddress` |
| Physical address needs the physical layer and lies inside it | 4 step 5 | `ErrNoPhysicalMemory`; diagnostic |
| Virtual address in canonical form | FD1 | Diagnostic when rewritten |
| One carve per file object | FM2 | Diagnostic |
| Filter on full handle-list names | FD2, FM1 | Left out, counted |

### windows.library.compare

| Rule | Justification | On failure |
|---|---|---|
| Image view is a VAD of kind `image` | LD1, LT2 | Not a row |
| Row base is the view's start | LD2, LM3 | — |
| Membership is the union of the records at the base | LT1 | — |
| One row per view start | LM1 | First kept, diagnostic |
| VADs of unknown kind are not compared | S24 4.5 | Diagnostic |
| No loader record in the process | LM5 | Rows flagged `LoaderListsEmpty`, diagnostic |
| WoW64 process without 32-bit records | LT1, LM7 | Diagnostic |
| Record without an image view | LD3, LM3 | Diagnostic |

### windows.credential.find_truecrypt

| Rule | Justification | On failure |
|---|---|---|
| Driver chosen by base name, case ignored | TD2, TO2 | Not scanned |
| Writable, non-executable sections only | TD1, TO4 | Not scanned |
| Section span from `VirtualSize`, else `SizeOfRawData`, within the image | TD1 | Cut |
| Length from the minimum to 128, 4-byte aligned | TO3, TO5, TM3 | No hit |
| Text bytes 0x20 to 0x7E, then a NUL | TO5, TM3 | No hit |
| Minimum length from 1 to 128 | TO3 | `ErrMinLength` |

### windows.image.map_strings

| Rule | Justification | On failure |
|---|---|---|
| Offset is decimal, then one blank, then a non-empty string | GD1 | Line rejected, counted |
| Line at most `MaxTextBytes` | Limits | Line rejected, counted |
| Offset inside a segment, or below the size of a raw image | GD2, GM1, GM3 | Row with `InMemory` false |
| Process mappings below the upper half only | GD4, S55 4.3 | Not listed for the process |
| Process kept by `pid` | Project PID set | Not mapped |

### windows.image.read_crash_header

| Rule | Justification | On failure |
|---|---|---|
| Physical layer is the crash dump layer | CD4 | `ErrNotCrashDump` |
| `DumpType` and later fields only when not overrun | CD4, CM1 | Not given, diagnostic |
| Up time within `time.Duration` | CD2 | Not given |
| Comment not the fill pattern | CM2 | Empty |

### windows.disk.scan_boot_records

| Rule | Justification | On failure |
|---|---|---|
| Bytes 510-511 are 0x55 0xAA | BD1 | Not a candidate |
| Every boot indicator 0x00 or 0x80 | BD2 | Problem `entry <n>: boot indicator 0x..` |
| An entry with System ID 0 is all zero | BD1 | `entry <n>: unused but not zero` |
| An entry in use has Total Sectors above 0 | BD2 | `entry <n>: no sectors` |
| An entry in use starts after sector 0, which holds the record | BD1, BD2 | `entry <n>: starts at the boot record` |
| Relative + Total Sectors at most 2^32 | BD3 | `entry <n>: runs past 2^32 sectors` |
| Starting and Ending Sector at least 1 | BD3 | `entry <n>: CHS sector 0` |
| No two entries in use overlap | BD2 | `entries <a> and <b> overlap` |
| At least one entry in use | BD1 | `no entry in use` |
| At most one active entry | BD3 | `<n> active entries` |

The protective record of BD4 passes every rule. System IDs are not checked against BD5 (BO4).

## 6. Failure modes

### windows.pe.read_version

| Case | Result |
|---|---|
| Not Windows | `windows.pe.read_version: "<os>": peversion: profile is not windows` |
| Extensive of the wrong type | `windows.pe.read_version: tools: option value of the wrong form: "windows.pe.read_version.extensive" is …; want …` |
| Module lists fail | `windows.pe.read_version: kernel modules: <err>` or `process modules: <err>` |
| Base unread, space unopened | `windows.pe.read_version: <n> kernel modules passed over: DllBase does not read`; `<n> process modules passed over: DllBase does not read`; `<n> process modules passed over: their process's address space does not open` |
| No version | `windows.pe.read_version: <n> kernel|process modules without a version: <cause>`, causes `headers do not read`, `not a PE image`, `no version resource`, `malformed version resource`, `resource bytes do not read` |
| Extensive without physical memory | `windows.pe.read_version: windows.pe.read_version.extensive set but there is no physical memory: <n> kernel modules not searched` |
| Extensive result | `windows.pe.read_version: <n> of <m> kernel modules without a mapped version resource matched a cached copy in physical memory`; `… cached version resources naming <name> hold different product versions: the lowest physical address is used` |

### windows.pe.list_imports

| Case | Result |
|---|---|
| Not Windows; types missing | `peimports: profile is not windows`; `peimports: symbol table lacks _EPROCESS.Peb or _PEB.ImageBaseAddress` |
| Process list fails | `windows.pe.list_imports: process list: <err>` |
| Counts | `windows.pe.list_imports: <n> processes passed over: their address space does not open` / `no PEB` / `main image base does not read`; `<n> processes whose PEB ImageBaseAddress does not read`; `<n> main images found through _EPROCESS.SectionBaseAddress`; `<n> main images passed over: <cause>`; `<n> main images have no import directory`; `<n> import directory parts passed over: <cause>`; `<n> import descriptors whose library name does not read: rows flagged`; `<n> imports whose hint/name entry does not read: rows flagged` |
| Library list fails | `windows.pe.list_imports: process modules not listed, ordinal imports named from the ordinal table only: <err>` |

### windows.pe.resolve_symbols

| Case | Result |
|---|---|
| Options | `pesymbols: no module named`, `… no symbol names or addresses given`, `… both symbol names and addresses given`, `"<v>": pesymbols: source is neither processes nor kernel`, option type errors; all prefixed `windows.pe.resolve_symbols: ` |
| Not Windows | `pesymbols: profile is not windows` |
| Instances not collected | `kernel modules: <err>`, `process modules: <err>`, `process list: <err>`, `mapped file names: <err>`, returned only when a key stayed missing |
| Per module | `windows.pe.resolve_symbols: <module>: exports do not read in <n> of <m> mappings tried: first: <module> at 0x<base> in pid <pid>: <err>`; `<module>: no CodeView record reads in <n> mappings, exports used: first: …`; `<module> in pid <pid>: PDB <name> <guid> age <age> not loaded, exports used: <err>` |
| Processes | `<n> processes passed over: their address space does not open`; `pid <n> (<name>): views not walked: <err>` |

### windows.handle.list

| Case | Result |
|---|---|
| Profile not Windows | `windows.handle.list: "<os>": handlelist: profile os is not windows` (`ErrNotWindows`) |
| Layout member missing | `windows.handle.list: handlelist: symbol table does not describe the handle table: <type>.<member>: …` |
| `ObjectTable` unread | `windows.handle.list: process <pid> at 0x<eprocess>: ObjectTable does not read, its handles are unknown: <err>` |
| `TableCode` unread | `windows.handle.list: handle table of process <pid> at 0x<table>: TableCode does not read, its handles are unknown: <err>` |
| Level or alignment refused | `… handle table of process <pid> at 0x<table>: TableCode 0x<code>: <sentinel>` |
| Pages unread | `… <n> of <m> entry pages and <p> of <q> pointer pages do not read, its handles are incomplete: <first>` |
| Pages misplaced | `… <n> of <m> entry pages do not start at the handle value of their place, their entries are not listed: <first>` |
| Past the ceiling | `… <n> page pointers at or past NextHandleNeedingPool 0x<v> are not followed` |
| Limit | `… stopped at MaxTableEntries (<n>), its rows may be a prefix`, or `… stopped at the per-process limit of 16777216 handles, its rows may be a prefix` when `MaxTableEntries` exceeds 2^24 |
| Types | `windows.handle.list: <n> handles hold an object header whose type does not resolve: listed without a type or name`; `windows.handle.list: object types not read, every handle is listed without a type: <err>` |
| Strict mode | After the rows: `windows.handle.list: strict mode: <n> handle tables: handlelist: a handle table was not read whole` (`ErrTableIncomplete`) |
| Names | S30 6 |

Sentinels: `ErrNotWindows`, `ErrNoHandleLayout`, `ErrTableIncomplete`, and the unexported level and alignment errors above.

### windows.file.dump options

| Case | Result |
|---|---|
| Empty address list | `option "<key>": tools: option value of the wrong form: filedump: an address option names no address` |
| Filter with an address | `windows.file.dump: windows.file.dump.filter with <key>: filedump: a filter and an address are mutually exclusive` |
| Physical without the layer | `windows.file.dump: windows.file.dump.physaddr: filedump: a physical address needs a physical memory layer` |
| Filter without device names | `ErrFilterNeedsDeviceNames` (S19, unchanged) |
| Notes | `windows.file.dump: windows.file.dump.ignore_case does nothing without windows.file.dump.filter`; `windows.file.dump: pid is not applied: given addresses are carved without walking processes`; `… <key> 0x<a> names file object 0x<f> again (given first as 0x<g>): carved once`; `… windows.file.dump.virtaddr 0x<a> is read as 0x<c>: the paging mode translates <n> address bits`; `… windows.file.dump.physaddr 0x<p> is where windows.file.dump.virtaddr 0x<v> lies: carved once, through the virtual address`; `… windows.file.dump.physaddr 0x<p> lies past the end of physical memory at 0x<end>: nothing read`; `… windows.file.dump.filter "<pattern>"[, ignoring case] keeps <k> of <n> file objects`; `… windows.file.dump.filter leaves out <n> file objects whose name does not read as a full device path` |

### windows.library.compare

| Case | Result |
|---|---|
| Not Windows | `librarycompare: profile is not windows` (`ErrNotWindows`) |
| Process or library list fails | `windows.library.compare: process list: <err>` or `…: loader lists: <err>` |
| VAD layout missing | `windows.library.compare: VAD layout: <err>` |
| VAD tree does not read | `windows.library.compare: process <pid> at 0x<eprocess>: VADs do not read, process not compared: <err>`; strict: `…: VADs do not read: <err>` |
| Repeated start, unknown kinds | `…: <n> image views start where an earlier one starts: the first is kept`; `…: <n> VADs of unknown kind are not compared: their flags do not read` |
| No loader record | `…: no loader list gave a record: its <n> image views are on no list` |
| WoW64 without 32-bit records | `…: WoW64 process whose 32-bit loader lists gave no record: its 32-bit images are on no list` |
| Records without a view | `…: <n> loader records have no image view at their DllBase, the lowest at 0x<base>` |

### windows.credential.find_truecrypt

| Case | Result |
|---|---|
| Not Windows | `credentialtruecrypt: profile is not windows` (`ErrNotWindows`) |
| Minimum length out of range | `windows.credential.find_truecrypt: truecrypt_min_length <n>: credentialtruecrypt: minimum length out of range: want 1 to 128` (`ErrMinLength`) |
| Module list fails | `windows.credential.find_truecrypt: module list: <err>` |
| Names unread | `…: <n> loaded modules have no readable name: any of them could be truecrypt.sys` |
| Base unread | `…: loader entry at 0x<entry>: <name> has no readable base: not scanned` |
| Headers unread | `…: truecrypt.sys at 0x<base>: PE headers do not read: <err>`; strict mode returns it |
| Section over the cap | `…: truecrypt.sys at 0x<base>: section "<name>" of <n> bytes is scanned to MaxRegionScanBytes <cap>` |
| Bytes unread | `…: section "<name>" at 0x<start>: <n> of <size> bytes do not read and are scanned as zero` |

### windows.image.map_strings

| Case | Result |
|---|---|
| Not Windows, no file, no physical memory, no kernel root | `windows.image.map_strings: …` with `ErrNotWindows`, `ErrNoFile`, `ErrNoPhysicalMemory`, `ErrNoKernelRoot` |
| Paging mode not known, kernel listing fails | Error `windows.image.map_strings: …` |
| File does not open or read | Error naming the file |
| More lines than `MaxRowsPerObject` | `ErrTooManyLines` |
| Rejected lines | `windows.image.map_strings: <n> strings file lines skipped: lines <n> (<reason>), …` |
| Offsets outside memory | `windows.image.map_strings: <n> strings lie at file offsets that hold no physical memory` |
| Process list fails | Diagnostic; only the kernel space is mapped |
| Process root or listing fails | `windows.image.map_strings: _EPROCESS at 0x<addr>: pid <n> page-table root does not read: left out: <err>`; `… pid <n> page tables at root 0x<root> do not list: left out: <err>`; a count |
| Page tables unread | `windows.image.map_strings: <n> page tables did not read: …` |

### windows.image.read_crash_header

| Case | Result |
|---|---|
| Not a crash dump | `windows.image.read_crash_header: imagecrashheader: the image is not a windows crash dump` |
| Run array overruns `DumpType` | Row without those fields; `windows.image.read_crash_header: crash dump header: <n> physical memory runs overrun DumpType and the fields after it: …` |

### windows.disk.scan_boot_records

| Case | Result |
|---|---|
| No physical memory | `ErrNoPhysicalMemory` |
| `full` of the wrong type | Option type error |
| Pages unread | `windows.disk.scan_boot_records: physical memory at 0x<first>: <n> pages did not read and were not scanned: <err>`; strict mode: `ErrUnreadMemory` after the scan |
| Records on unread pages | `windows.disk.scan_boot_records: <n> records end in 0x55AA but lie partly on pages that did not read: not decoded` |
| Refused tables, without `full` | `windows.disk.scan_boot_records: <n> records end in 0x55AA but their partition table breaks a rule: listed only with windows.disk.scan_boot_records.full` |
| Listing cut, record cap | `… <n> boot code listings cut at <n> bytes`; `… stopped at <n> records (MaxRowsPerObject) …` |

## 7. Result schema

### windows.pe.read_version

`peversion.Version`: `Kernel`, `PID`, `Process`, `Base`, `Name`, `NameUnreadable`, `SizeOfImage` (header, bytes; 0 when headers did not read), `Major`, `Minor`, `Product`, `Build` (product version parts; 0 when unread), `VersionUnreadable`, `VersionPhysical` (physical address of the cached `VS_VERSIONINFO` used; 0 when the version came from the image or is absent). Order: kernel list order, then library list order.

### windows.pe.list_imports

`peimports.Import`: `PID`, `Name` (process image name), `ImageBase`, `Library`, `LibraryUnreadable`, `Bound`, `ByOrdinal`, `Ordinal`, `Function` (empty when unnamed or unread), `FunctionUnreadable`, `FunctionFrom` (`exports`, `table` or empty; ordinal imports only), `Address` (IAT slot). Order: process list order, then descriptor and thunk order.

### windows.pe.resolve_symbols

`pesymbols.Result`: `Module` (folded), `Source`, `Symbols`, `Missing` (names) or `MissingAddresses`. `pesymbols.Symbol`: `Module`, `Name`, `Address`, `FoundInPID` (0 for kernel and kernel-table answers), `Forwarder`, `ForwarderUnreadable`. `pesymbols.Module`: `PID`, `ProcessName`, `DirectoryTableBase` (0 = kernel memory), `Name`, `Base`, `Size` (0 = take `SizeOfImage`). Order: ask order with repeats.

### windows.handle.list

`handlelist.Handle`: `PID`, `ProcessName`, `HandleValue` (a multiple of 4), `Object` (the `_OBJECT_HEADER` address; the body is at `Object` + `_OBJECT_HEADER.Body`), `GrantedAccess` (bits 0..24 of the access mask), `TypeIndex` (the decoded slot; 0 when the header did not read), `TypeName` (empty when the type did not resolve), `ObjectName` (S30), `NameUnreadable` (set when the name or the type did not resolve). Order: process order, then handle value.

Exports: `Name`, `OptionOffset`, `Handle`, `Run`, `RunAny`, `Walker`, `NewWalker`, `(*Walker).Process`, `(*Walker).Finish`, `FileObjectName`, `ErrNotWindows`, `ErrNoHandleLayout`, `ErrTableIncomplete`.

### windows.file.dump options

No row fields; the options select the S19 rows. Exports: `OptionVirtAddr`, `OptionPhysAddr`, `OptionFilter`, `OptionIgnoreCase`, `ErrFilterWithAddress`, `ErrNoPhysicalMemory`, `ErrFilterNeedsDeviceNames`, `ErrEmptyAddressList`.

### windows.library.compare

`librarycompare.Module`: `PID`, `Process`, `Base` (the image view's start), `InLoad`, `InMem`, `InInit` (a loader record at `Base` is on the in-load-order, in-memory-order or in-initialization-order list), `Wow64` (that record came from the 32-bit lists), `MappedPath` (the view's file name, empty when none read), `MappedPathUnreadable`, `LoaderListsEmpty`. Sort: process list order, then `Base`.

### windows.credential.find_truecrypt

`credentialtruecrypt.Passphrase`: `Offset` (virtual address of the 4-byte length), `Length` (bytes of text), `Password` (the text), `Section` (the PE section name). Sort: module list order, section order, address. `FindCounted` and `Counted` give the text rule to other callers.

### windows.image.map_strings

`imagestrings.Located`: `Line` (line number in the file), `String`, `FileOffset`, `PhysicalAddress` (0 when not in memory), `InMemory`, `Mappings` (`[]Mapping`: `Kernel`, `PID`, `Process`, `Address`), `Result` (text of the mappings). Order: file order. `PhysicalAddressWide` is removed: an offset that does not fit 64 bits is a rejected line (GO1).

### windows.image.read_crash_header

`imagecrashheader.Info`: `Signature`, `MajorVersion`, `MinorVersion`, `DirectoryTableBase`, `PfnDataBase`, `PsLoadedModuleList`, `PsActiveProcessHead`, `MachineImageType`, `NumberProcessors`, `BugCheckCode`, `KdDebuggerDataBlock`, `NumberOfRuns`, `NumberOfPages`, `DumpType` (`full`, a number, or empty), `DumpTypeKnown`, `SystemUpTime` (`time.Duration`) with `SystemUpTimeValid`, `SystemTime` (UTC) with `SystemTimeValid`, `Comment`. One row. Field names are the header's member names (CO1). New: `BugCheckCode`, `NumberOfRuns`, `NumberOfPages`, `DumpTypeKnown`. `UpTime` stays exported.

### windows.disk.scan_boot_records

`diskbootrecords.Row`, one per record (`Depth` 0) followed by one per entry in use (`Depth` 1). Record rows: `Offset` (physical address), `DiskSignature` (eight hex digits of the little-endian value), `BootcodeMD5`, `FullMBRMD5` (hex), `ValidTable`, `TableProblem` (empty when valid), `Disasm`, `Bootcode`. Entry rows: `Offset` (the record's), `PartitionIndex` (1 to 4), `Bootable`, `BootFlag`, `PartitionType` (BD5 name or empty), `PartitionTypeRaw`, `RelativeSectors`, `TotalSectors`, `StartingCylinder`, `StartingHead`, `StartingSector`, `EndingCylinder`, `EndingHead`, `EndingSector`. Renamed from 0.1.0 (BO5): `StartingLBA` to `RelativeSectors`, `SectorInSize` to `TotalSectors`, `StartingCHS` to `StartingHead`, `EndingCHS` to `EndingHead`. New: `TableProblem`.

## 8. Limits

### windows.pe.read_version

`pe.ReadVersion` limits (S18). A cached block is at most 65,535 bytes (`wLength`). The physical scan reads 4 MiB chunks, page by page when a chunk does not read whole.

### windows.pe.list_imports

`pe.ParseImports` limits (S18).

### windows.pe.resolve_symbols

`pe.ParseExports` limits; `MaxBufferBytes` for the directory cache; `MAX_PATH` for a CodeView path in the scan.

### windows.handle.list

- `MaxTableEntries`: entries per table; with HD1's 2^24, the ceiling when `NextHandleNeedingPool` is not usable.
- `MaxPathSteps`: S30 name walks.
- Pages are read 4 KB at a time; a table reads at most one top page, 512 middle pages and their entry pages below the ceiling.

### windows.file.dump options

None of their own; S19's `max_dump_size` and `MaxArtifactBytes` bound the carve.

### windows.library.compare

Only the caps of S56 and S24; the tool adds none. Rows are bounded by the VADs each walk returns.

### windows.credential.find_truecrypt

`MaxRegionScanBytes` per section: a header can declare any size, and the scan reads it whole. The 128-byte text cap bounds each candidate (TO3).

### windows.image.map_strings

- `MaxTextBytes`: the longest line read.
- `MaxRowsPerObject`: the most lines (rows) taken from one file.

### windows.image.read_crash_header

None: one fixed-size header.

### windows.disk.scan_boot_records

- `MaxRowsPerObject`: the most records listed.
- `MaxTextBytes`: the longest boot code listing.
- The chunk size (16 MiB) bounds one read, not the result.

## 9. Acceptance

### windows.pe.read_version

1. Synthetic fixtures (`tools/windows/peversion/s66_test.go`, on the shared process fixture plus a loader list at the S55 T1 offsets): the product version of a kernel module, a module with no resource and one with no image, with the cause counts; process modules through their own space and the pid option; a cached copy matched through the path's file name when the base name differs, with the lowest address taken and differing copies reported; the extensive option without physical memory; option type and profile refusals; the OriginalFilename walk with address alignment and truncation; the physical scan across a chunk boundary and not across a hole.
2. Fuzz target `FuzzOriginalFilename` (arbitrary block and base: no panic, no name without a match, no name longer than the block), 30 s on 2026-11-12: 4,660,762 executions, no failure.
3. On the captures: VM1 to VM6.

### windows.pe.list_imports

1. Synthetic fixtures (`tools/windows/peimports/s66_test.go`): rows in descriptor order with slot addresses across a descriptor's terminator and the `Bound` rule; ordinal names from the mapped library, from the table, and none; the section-base fallback and the no-PEB count; an unreadable hint/name flagged with the row kept; the pid option; an image without imports; the profile refusal. The tool has no parser of its own (`pe.ParseImports` is fuzzed in `pe`).
2. On the captures: IM1 to IM4.

### windows.pe.resolve_symbols

1. Synthetic fixtures (`tools/windows/pesymbols/s66_test.go`): ask order, repeats and missing once with a mixed-case module key; a second process answering what the first could not read, counted once; the PDB first, naming an unexported symbol, loaded once; a PDB that does not load reported once; a forwarder; addresses named by the PDB's first name, by exports, and not outside the mapping; the kernel table both ways; no kernel fallback for a process mapping; views and loader lists regardless of pid, and the loader_list type error; the union of `CopyExports`; `ReadRVAAt` bounds and short reads; the option rules and the module option; the CodeView scan across pages, after a hole, by file name without case, and inside the range only.
2. Fuzz target `FuzzFindPDBRecord` (arbitrary bytes and name: no panic; a match names the asked PDB with a 32-digit GUID), 30 s on 2026-11-12: 941,565 executions, no failure.
3. On the captures: YM1 to YM6.

### windows.handle.list

1. Synthetic fixtures (`tools/windows/handlelist/s66_fixture_test.go`, `handle_list_test.go`, on the 26100 offsets of HT1 to HT4): a level-0 table in value order with access and type through the cookie and `NoRightsUpgrade` left out; a page's first entry in use ignored; a level-1 table numbering pages by place, with a pointer past the ceiling counted; a level-2 table; level 3 and a misaligned `TableCode` refused, strict mode failing; a null `ObjectTable`; an unread page and a misplaced page costing only their entries; the `MaxTableEntries` stop; unresolved types (slot `Index` mismatch, empty slot, unread header); no cookie; the header's canonical form and the 25-bit access; each missing required member and a bitless `ObjectPointerBits`; a non-Windows profile; a visible NUL in a name; the registration. The S30 tests (`names_test.go`) run on the same package.
2. Fuzz target `FuzzHandleTable` (arbitrary top and entry pages under any level and `NextHandleNeedingPool`: values nonzero, multiples of 4, increasing, never a page's first entry; headers 16-byte aligned and canonical; access within 25 bits; untyped rows and only they flagged), 30 s on 2026-11-12: 811,934 executions, no failure. `FuzzKeyLevel` (S30): 30 s, no failure.
3. On the captures (`petoolfacts -tool handlelist`, 2026-11-12):

| Capture | Rows | Processes with rows | Type unresolved | Name not read | Name empty | Tables with a diagnostic |
|---|---|---|---|---|---|---|
| mem1_win11 | 46,853 | 76 | 3,500 | 3,563 | 28,275 | 1 (pagefile) |
| mem2_win10 | 57,560 | 146 | 310 | 328 | 43,081 | 6 (pagefile) |
| mem5_server2016 | 25,190 | 67 | 20 | 20 | 18,245 | 1 (HM6: 4 of 4 pages unread, 452 pointers past the ceiling) |
| mem6_server2025 | 40,072 | 88 | 56 | 64 | 30,073 | 7 (pagefile, one a top page) |
| mem7_server2025 | 34,206 | 77 | 118 | 139 | 25,601 | 9 (8 pagefile, PID 6792's `TableCode` refused) |

   - Rows equal the raw walk's in-use entries on every capture but mem5, where the 372 entries past the ceiling of HM6 are left out (25,562 − 372).
   - Type unresolved equals HM5's unread headers plus empty slots on every capture (1,472 + 2,028 on mem1).
   - Handle values ascend within every process.

### windows.file.dump options

1. Synthetic tests (`tools/windows/filedump/options_test.go`, on the S19 fixture): wrong-type and empty address lists; the filter with each address option; a physical address without the layer; the two notes; `ignore_case` folding and the filter report; once-each with a repeated, a masked, a non-canonical, a mapped physical, a repeated physical and an out-of-range physical address; the filter name for an absolute and a relative `FileName`.
2. No parser of its own: option values are parsed by `tools`, so no fuzz target is added.
3. On the captures: FM1 to FM3.

### windows.library.compare

1. Synthetic fixture (`internal/testsupport/s66_c_fixture.go`: the S43 VAD views and the S56 loader lists in one image): a row per image view with the lists of its base, a record cut from two lists, a view on no list, a private view giving no row, base order; a process without a PEB (`LoaderListsEmpty` and its diagnostic); a 32-bit record marking its view; a record without a view; the PID set; an unreadable VAD node (records reported without a view, strict failure); a non-Windows profile; registration.
2. Fuzz: `FuzzIndexRecords` (records indexed per process and base as the union of their lists, 32-bit counts exact), 30 s on 2026-11-12, 910,177 executions, no failure.
3. On the captures (LM1 to LM7): rows 4,430, 8,315, 3,489, 4,859, 4,490, equal to the image views; the tool's membership counts equal the raw pairing of LM4 on all five.

### windows.credential.find_truecrypt

1. Synthetic (hand-built module list and the mapped fixture PE, `.data` writable): a counted string found in `.data` and not in `.text`, a string under the minimum not found, the minimum option and its range and type, every copy of the driver scanned and no other driver, no driver giving no rows and no diagnostic, unreadable headers (diagnostic, strict error), an unread page scanned as zeros and reported, a non-Windows profile, the text rule's cases (terminator, control and high bytes, alignment, end of data, two in a row, over 128), registration.
2. Fuzz: `FuzzFindCounted` (each hit aligned, after the previous one, its count equal to its text length within range, printable, NUL-terminated), 30 s on 2026-11-12, 1,319,055 executions, no failure.
3. On the captures: no row and no error (TM4). The rule's yield on memory holding no passphrase is TM3.

### windows.image.map_strings

1. Synthetic tests (`tools/windows/imagestrings`, on the shared process fixture): the line grammar and each rejection reason; Latin-1 text; the line and row limits; one physical page mapped in the kernel and in two processes gives all three addresses in order; a process's system-half mapping is not listed; an offset past the image is not in memory; `pid` narrows the processes; a segmented layer maps an offset through its segment and gives no memory for a header offset; each refusal.
2. Fuzz: `FuzzParseLine` (ParseLine and ReadLines agree; accepted text is UTF-8 and non-empty), 30 s on 2026-11-12: 1,416,370 executions, no failure.
3. On the captures (GM1 to GM4) every probe line gets exactly its expected address.

### windows.image.read_crash_header

1. Synthetic tests: every field of a parsed header; an overrun header gives the fields before the run array and the diagnostic; dump type by number; the fill comment; invalid UTF-8; a raw image refused; up time in ticks and its ceiling.
2. Fuzz: `FuzzHeaderFields` (up time round-trips its ticks, the comment is UTF-8), 30 s: 572,972 executions, no failure.
3. On the captures: CM1 to CM4.

### windows.disk.scan_boot_records

1. Synthetic tests: a record and its entries; the CHS split; each table rule; the protective record; `full`; records across a chunk end at five offsets; an unread page counted, a torn record counted and strict failure; the record limit; the refusals; the real-mode listing and its cut.
2. Fuzz: `FuzzRecord` (an accepted table satisfies every rule; the listing covers the boot code), 30 s: 6,359,615 executions, no failure.
3. On the captures (BM1 to BM4) the tool's records are exactly those the raw half accepts.

## 10. Open points

### windows.pe.read_version

| # | Point | Closes with |
|---|---|---|
| VO1 | Owner decision: the `pid` option now narrows the process modules; before, it was not read. Kernel modules are listed whatever `pid` says, as in S55 O4. | Owner decision |
| VO2 | Owner decision: the extensive option now gives the product version of the cached copy, as the image path does, and records its physical address in the new field `VersionPhysical`; before, it gave the file version and no field said where it came from. | Owner decision on the row |
| VO3 | Owner decision (Q3): the other row field names are kept from 0.1.0. | Owner decision |
| VO4 | A cached copy is tied to a module only by name; two builds of one driver in file cache are told apart only by the "differing copies" diagnostic (VM4: 8 to 28 names per capture). VM5 shows no disagreement where both sources exist. | A capture with a driver update pending |
| VO5 | A module whose only cached copy is its `.mui` file (VM6: up to 9) gets no version: a `.mui` version resource describes the language file. | Owner decision |

### windows.pe.list_imports

| # | Point | Closes with |
|---|---|---|
| IO1 | Owner decision: an ordinal is no longer named from a mapping of the other width when no same-width mapping exists. | Owner decision |
| IO2 | `pe/peparse`'s ordinal table was generated by a measurement script that predates the rewrite; it is used as it is. IM4 shows it never disagrees with a mapped library. | Rebuild of the table from the captures' export directories |
| IO3 | Owner decision: the section-base fallback is new; it gives rows for 4, 5, 3, 11 and 10 processes whose PEB field does not read (IM2). | Owner decision |
| IO4 | Owner decision (Q3): row field names kept from 0.1.0. | Owner decision |

### windows.pe.resolve_symbols

| # | Point | Closes with |
|---|---|---|
| YO1 | The native and 32-bit ntdll.dll of a WoW64 process share one module key; the first instance that answers wins (YM1, YM2). | Owner decision on a width filter |
| YO2 | Owner decision: the `pid` option is not applied to instance collection, as before, so a name absent from a narrowed set is not reported as missing. | Owner decision |
| YO3 | Session-space drivers are read through kernel space only for source `kernel`; their exports do not read there (S55 M5). | A session reader in `CollectModules` |
| YO4 | The "RSDS" layout is read as `pe.ReadCodeView` reads it; the PE specification names the CodeView type but not the record. | A Microsoft source |
| YO5 | `FindPDBRecord` now matches a full build path by its file name, without case; before, the path had to be the bare name. | Owner decision |
| YO6 | Sentinel texts now start `pesymbols:` instead of the tool name; `ErrNotWindows` and `ErrUnknownSource` are new. | Owner decision (Q2) |

### windows.handle.list

| # | Point | Closes with |
|---|---|---|
| HO1 | Level 2 tables (more than 131,072 handle entries) follow the same geometry by HD1 and HT2 only; no capture has one (HM2). | A capture with a process holding over 131,072 handles |
| HO2 | Tables without `ObjectPointerBits` as a bit field (32-bit kernels, builds before the field) are refused with `ErrNoHandleLayout`; 0.1.0 read some of them. | Owner decision; a 32-bit or older capture |
| HO3 | Owner decision (Q3): the row field names are kept from 0.1.0; `Object` stays the header address, not the body. | Owner decision on field names |
| HO4 | Owner decision: a row whose type does not resolve is kept, flagged `NameUnreadable`, with no name attempted; before, its name was tried in the namespace form. On mem1 3,500 rows. | Owner decision on row values |
| HO5 | The level encoding in `TableCode`, the page span, the skipped first entry and the `LeafHandleValue` check rest on measurements HM2 to HM4 only; Microsoft documents none of them. | A Microsoft source |
| HO6 | Strict mode now fails a run in which a table was not read whole (pagefile pages included: every capture has such tables, HM8). | Owner decision |

### windows.file.dump options

| # | Point | Closes with |
|---|---|---|
| FO1 | Owner decision: the filter now matches the handle-list name (device namespace path, then `FileName`), not `\Device\` plus the device's own name plus `FileName`. The two differ for 14, 30, 24, 20 and 17 file objects (FM1); relative names are no longer matched (114 on mem1). | Owner decision on the filter text |
| FO2 | Owner decision: an address option set to an empty list is a type error with its own sentinel (`ErrEmptyAddressList`). | Owner decision |

### windows.library.compare

| # | Point | Closes with |
|---|---|---|
| LO1 | Owner decision (Q3): the 0.1.0 fields `InLoadBackward`, `InInitBackward` and `InMemBackward` are removed; S56 gives list membership without saying which walk direction found it. | Owner decision on row fields |
| LO2 | Owner decision: new fields `Wow64`, `MappedPathUnreadable` and `LoaderListsEmpty`. | Owner decision on row fields |
| LO3 | Owner decision: loader records without an image view give a diagnostic, not a row (LM3). A row of their own would show manually mapped modules. | Owner decision on rows |
| LO4 | Image views on no list in processes with records are mostly `.dll` and `.winmd` files (LM6), which LD3 explains as resource or image mappings; the tool does not tell them from a hidden module. | A measured rule that tells them apart |
| LO5 | `VadType` 2 meaning an image view is measured only (S24 O2). | S24 |
| LO6 | A private VAD (`VadS`) is not an image view. 4.5 gives rows only for image views, and LO3 makes a loader record without an image view a diagnostic, so a private VAD gives no row, whatever it holds. | Owner decision 2026-11-12 (follow-up M5): keep. |
| LO7 | A loader record with `BaseUnreadable` set (S56 O8) is left out of the base index (4 step 3). | Owner decision 2026-11-12 (follow-up D14): name the flag in S55 and S66. Done: 4 step 3 here, `windows.pe.read_version` 4 step 4 and section 6, `windows.pe.list_imports` 4 step 6, `windows.pe.resolve_symbols` 4 step 2, and S55 4.6 step 2; no code change. |

### windows.credential.find_truecrypt

| # | Point | Closes with |
|---|---|---|
| TO1 | Owner decision: no allowed source documents the driver's passphrase cache, and no capture holds the driver (TM1). Every rule of 4 rests on this choice, not on a source. The tool is kept. | A capture with the driver loaded and a known passphrase |
| TO2 | Owner decision: only `truecrypt.sys` is scanned; `veracrypt.sys` is not. | Owner decision, and a capture of either |
| TO3 | Owner decision: default minimum length 4 (0.1.0: 5) and the 128-byte text cap (0.1.0: 64). On the captures the minimum 4 and 8 give the same 2, 2, 0, 0, 0 hits (TM3). | A capture with the driver |
| TO4 | Owner decision: every writable non-executable section is scanned, not one named section. | A capture with the driver |
| TO5 | Owner decision: text is printable ASCII; a passphrase with other bytes is missed. | A capture with the driver |
| TO6 | Owner decision (Q3): new row field `Section`; `Offset` keeps its 0.1.0 name although it is a virtual address. | Owner decision on field names |

### windows.image.map_strings

| # | Point | Closes with |
|---|---|---|
| GO1 | Owner decision (Q3): `Located` gains `Line`, `FileOffset`, `InMemory` and `Mappings`; `PhysicalAddressWide` is removed; `Result` is now `kernel 0x…; pid <n> 0x…`, empty when unmapped, where 0.1.0 used other wording. | Owner decision on row fields |
| GO2 | Owner decision: only decimal offsets are read, as `strings -t d` writes; octal and hexadecimal listings (`-t o`, `-t x`) are rejected lines. | Owner decision |
| GO3 | Owner decision: non-UTF-8 text is read as Latin-1. | Owner decision |
| GO4 | Owner decision: more lines than `MaxRowsPerObject` (default 2^20) is an error, not a cut. | Owner decision on a limit |
| GO5 | Pages the layer's listing leaves out (a table of one repeated value, S53) give no address. | S53 |
| GO6 | `ReadLines` (`tools/windows/imagestrings/lines.go`) tests for an empty line before `ParseLine` drops the CR, so a line that holds only CR (an empty line of a CRLF listing) is a rejected line, "no decimal offset", where an empty LF line is passed over. Owner decision 2026-11-12: kept for v0.1.0; pass over a CR-only line as an empty line in v0.2.0. | v0.2.0 |

### windows.image.read_crash_header

| # | Point | Closes with |
|---|---|---|
| CO1 | Owner decision (Q3): field names are the header member names, kept from 0.1.0; four fields are new. | Owner decision |
| CO2 | The value of `DUMP_TYPE_FULL` (1) is not in the public WDK headers (`wdm.h` says `DUMP_TYPE` is defined in `ntiodump.h`); it rests on the crash dump layer and on mem7 (CM1). | A Microsoft source |
| CO3 | The header's `KdDebuggerDataBlock` is not the symbol's address on either dump (CM4); the field is given as read. | A Microsoft source or more dumps |
| CO4 | Only two crash dumps, both from one writer (bug check 0x5454414D), were measured; a dump written by the system after a real bug check was not. | A system-written dump |

### windows.disk.scan_boot_records

| # | Point | Closes with |
|---|---|---|
| BO1 | Owner decision: by default only records whose table passes section 5 are listed, and `full` lists every candidate; in 0.1.0 the option had another meaning. | Owner decision on the option |
| BO2 | Owner decision: MD5 for the boot code and record hashes, kept from 0.1.0; the disk signature as eight hex digits of its value. | Owner decision |
| BO3 | The listing gives offsets from the record start; the address firmware loads the record to is not in an allowed source. | A firmware specification |
| BO4 | System IDs are not a rule: two accepted records (mem6 0x55, mem7 0xBB) have undocumented IDs and look like chance matches (BM2), while real disks also use IDs that BD5 does not list. | Owner decision |
| BO5 | Owner decision (Q3): four fields renamed to the Microsoft Learn names; the rest kept from 0.1.0. | Owner decision |
| BO6 | Records are matched at every byte offset because every real record on the captures lies off a sector boundary (BM1). Extended boot records (BD6) are listed like any record, not followed. GPT headers are not read. | Owner decision |
| BO7 | Follow-up R3: with `full`, a record whose 440 bytes of boot code (0 to 0x1B7) are all zero (boot code MD5 5fb38429d5d77768867c76dcbdb35194) gives rows, with its entries, like any other candidate (4 step 4: `full` lists every candidate with its table problem). Owner decision 2026-11-12: keep; the tool is unchanged. | Closed: kept |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| VO1 | Narrow process modules only |
| VO2 | Product version plus VersionPhysical |
| VO3 | Keep 0.1.0 names |
| VO4 | Keep diagnostic until a capture shows it |
| VO5 | No version |
| IO1 | Leave unnamed |
| IO2 | Use as is for now |
| IO3 | Keep the fallback |
| IO4 | Keep 0.1.0 names |
| YO1 | Keep first answering instance |
| YO2 | Do not apply pid |
| YO3 | Defer to v0.2.0 |
| YO4 | Keep measured layout |
| YO5 | Match by file name, any case |
| YO6 | Yes, new prefix and sentinels |
| HO1 | Keep, await capture |
| HO2 | Refuse |
| HO3 | Keep names and header address |
| HO4 | Keep, flag, no name |
| HO5 | Keep measured rules |
| HO6 | Fail the run |
| FO1 | Match handle-list name |
| FO2 | Error ErrEmptyAddressList |
| LO1 | Remove them |
| LO2 | Add them |
| LO3 | Diagnostic only |
| LO4 | Defer to v0.2.0 |
| LO5 | Keep measured |
| LO6 | Keep |
| LO7 | Add to both specs |
| TO1 | Keep the tool |
| TO2 | truecrypt.sys only |
| TO3 | 4 and 128 |
| TO4 | Scan all such sections |
| TO5 | Printable ASCII only |
| TO6 | Add Section, keep Offset |
| GO1 | Yes, as specified |
| GO2 | Decimal only |
| GO3 | Latin-1 |
| GO4 | Error |
| GO5 | Keep, tied to S53 |
| CO1 | Keep names, add four |
| CO2 | Keep value 1 |
| CO3 | Give as read |
| CO4 | Provide a capture |
| BO1 | Valid by default, full lists all |
| BO2 | Keep MD5 and hex |
| BO3 | Record-relative offsets |
| BO4 | Not a rule |
| BO5 | Rename four, keep rest |
| BO6 | Yes, as specified |

## 11. Provenance

Written from Microsoft Learn (PE format, version resources, loader structures, handles and access masks, crash dump header routines, interrupt time, the master boot record and partition table), the WDK headers, the POSIX `strings` utility, the Intel SDM, the ntoskrnl and module PDB types read through the project's symbol tables, the shared specifications it names (S03, S18, S19, S24, S25, S30, S31, S32, S53, S55, S56), and the project's measurements. The previous implementations were read only for their exported names, their callers, the tool names and the option keys. Every rule rests on the sources and measurements above.
