# S72: PE image parsing

Version 1, 2026-11-12.

This specification covers package `pe` apart from the rebuild (S18): the headers, the reader of a mapped image, the export, import, debug and resource directories and the version resource. It also covers `pe/peparse`, the table that names ordinal imports when the exporting library's own directory cannot be read. Fact ids: `P` for the PE format specification, `V` for the version-resource pages, `X` for vendor architecture facts, `M` for measurements, `O` for open points. Measurements come from `peparsefacts` and `ordinalfacts`, run on 2026-11-12 on mem1_win11 (build 26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100).

## 1. Purpose

Most Windows tools start from a loaded image: a driver, a DLL or a process's main executable as the loader mapped it. They need its headers to find its sections and directories, its exports to find a function, its imports to see which functions it takes from where, its CodeView record to name and fetch its PDB, and its version resource to date it. This package reads those structures from the image as it lies in memory, where it differs from the file: every RVA is an offset from the load address, the import address table holds resolved addresses, and any page may be absent from the capture. Each parser says which parts it could not read instead of treating an absent page as an absent structure.

`pe/peparse` answers one further question. An import by ordinal carries no name. The name is in the exporting library's export directory, which the importing process may not have resident. The table records the names that captured builds of those libraries give their ordinals, kept only where the builds agree.

## 2. Inputs

| Input | Meaning |
|---|---|
| Image bytes | A buffer that starts at the image base (`ParseHeaders`), or a `ReadRVA` that reads `n` bytes at an RVA. `MappedReader` builds one from any `ReadAt(offset, size)` reader, a base and `SizeOfImage`. |
| Data directory | The `DataDirectory` entry the caller read with `Headers.DataDirectory` or `Headers.ReadDataDirectory`. |
| Limits | `MaxTableEntries` (export slots and names, import descriptors with lookup entries, resource entries), `MaxNameBytes` (every string), `MaxBufferBytes` (one export array). `ReadCodeView` takes no limits and uses the defaults of `limits.Default()`. |
| Ordinal table | Library name (ASCII case ignored), the importer's width (`PE32Plus`) and the ordinal. |

## 3. Facts from the sources

P facts are from Microsoft Learn, "PE Format" (learn.microsoft.com/windows/win32/debug/pe-format), page dated 2026-09-10, accessed 2026-11-12. V facts are from Microsoft Learn, "VS_VERSIONINFO structure" (learn.microsoft.com/windows/win32/menurc/vs-versioninfo, last updated 2020-12-11), "VS_FIXEDFILEINFO structure (verrsrc.h)" (learn.microsoft.com/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo, last updated 2021-04-02) and "Resource Types" (learn.microsoft.com/windows/win32/menurc/resource-types, last updated 2026-08-28), all accessed 2026-11-12.

| # | Fact | Source |
|---|---|---|
| P1 | "At location 0x3c, the stub has the file offset to the PE signature." The signature is "PE\0\0". | MS-DOS Stub, Signature |
| P2 | The COFF file header follows the signature: `Machine` 0 (2), `NumberOfSections` 2 (2), `TimeDateStamp` 4 (4), `PointerToSymbolTable` 8, `NumberOfSymbols` 12, `SizeOfOptionalHeader` 16 (2), `Characteristics` 18 (2); 20 bytes. "The Windows loader limits the number of sections to 96." | COFF File Header |
| P3 | Optional header `Magic` at 0: 0x10B is PE32, 0x20B is PE32+, 0x107 a ROM image. `AddressOfEntryPoint` at 16. PE32 has `BaseOfData` at 24, which PE32+ lacks. | Optional Header Standard Fields |
| P4 | Windows-specific fields, offset PE32/PE32+: `ImageBase` 28/24 (4/8 bytes), `SectionAlignment` 32, `FileAlignment` 36, `MajorOperatingSystemVersion` 40, `MinorOperatingSystemVersion` 42, `SizeOfImage` 56, `SizeOfHeaders` 60, `CheckSum` 64, `NumberOfRvaAndSizes` 92/108. | Optional Header Windows-Specific Fields |
| P5 | Data directories start at 96/112, 8 bytes each (`VirtualAddress`, `Size`), in the order Export, Import, Resource, Exception, Certificate, Base Relocation, Debug, … "the number of directories is not fixed. Before looking for a specific directory, check the NumberOfRvaAndSizes field." | Optional Header Data Directories |
| P6 | The section table "immediately follows the optional header", located by `SizeOfOptionalHeader`; `NumberOfSections` entries of 40 bytes. `Name` is "An 8-byte, null-padded UTF-8 encoded string. If the string is exactly 8 characters long, there is no terminating null"; `VirtualSize` 8, `VirtualAddress` 12, `SizeOfRawData` 16, `PointerToRawData` 20, `Characteristics` 36. | Section Table |
| P7 | The export directory table is 40 bytes: `Name RVA` 12, `Ordinal Base` 16, `Address Table Entries` 20, `Number of Name Pointers` 24, `Export Address Table RVA` 28, `Name Pointer RVA` 32, `Ordinal Table RVA` 36. | Export Directory Table |
| P8 | An export address table entry inside the export section "as defined by the address and length that are indicated in the optional header" is a forwarder RVA: "The pointer to a null-terminated ASCII string in the export section. This string must be within the range that is given by the export table data directory entry." | Export Address Table |
| P9 | "The export name pointer table and the export ordinal table form two parallel arrays"; the ordinal table is "an array of 16-bit unbiased indexes into the export address table"; the biased ordinal is the index plus `Ordinal Base`. "Every exported symbol has an ordinal value … Some, all, or none of the exported symbols can have export names." Names are null-terminated ASCII, sorted. | Export Name Pointer Table, Export Ordinal Table, Export Name Table |
| P10 | The import directory table is an array of 20-byte entries, `Import Lookup Table RVA` 0, `Time/Date Stamp` 4 ("zero until the image is bound"), `Forwarder Chain` 8, `Name RVA` 12, `Import Address Table RVA` 16. "The last directory entry is empty (filled with null values)." | Import Directory Table |
| P11 | An import lookup table entry is 32 bits (PE32) or 64 bits (PE32+); the last is zero. Bit 31/63 set: import by ordinal, the ordinal in bits 15-0, "Bits 30-15 or 62-15 must be 0". Clear: bits 30-0 are a hint/name table RVA, "For PE32+ bits 62-31 must be zero". The import address table's contents "are identical to the contents of the import lookup table until the image is bound." | Import Lookup Table |
| P12 | A hint/name entry is a 2-byte `Hint` and an ASCII name "terminated by a null byte"; the name is case sensitive. | Hint/Name Table |
| P13 | A debug directory entry is 28 bytes: `Type` 12, `SizeOfData` 16, `AddressOfRawData` 20 (the address when loaded), `PointerToRawData` 24. "The specified RVA can be zero if the debug information is not covered by a section header … and is not mapped." `IMAGE_DEBUG_TYPE_CODEVIEW` is 2, "The Visual C++ debug information." | Debug Directory, Debug Type |
| P14 | Resources form a tree; "By convention, however, Windows uses three levels: Type, Name, Language". A resource directory table is 16 bytes with `Number of Name Entries` at 12 and `Number of ID Entries` at 14; it is "immediately followed by" its 8-byte entries, "all the Name entries precede all the ID entries", sorted. | The .rsrc Section, Resource Directory Table |
| P15 | A directory entry's second field with "High bit 0" is the address of a Resource Data entry (a leaf); with "High bit 1. The lower 31 bits are the address of another resource directory table". "Offsets are relative to the address in the IMAGE_DIRECTORY_ENTRY_RESOURCE DataDirectory." A name entry's first field is "The offset of a string". | Resource Directory Entries |
| P16 | A Resource Data entry is 16 bytes: `Data RVA` 0, `Size` 4, `Codepage` 8, reserved 12. | Resource Data Entry |
| V1 | `RT_VERSION` is `MAKEINTRESOURCE(16)`. | Resource Types |
| V2 | `VS_VERSIONINFO` is `wLength`, `wValueLength`, `wType` (WORDs), `szKey` the Unicode string `L"VS_VERSION_INFO"` (16 WCHARs with its NUL), `Padding1` "as many zero words as necessary to align the Value member on a 32-bit boundary", then `Value`, a `VS_FIXEDFILEINFO`; "if wValueLength is zero, this member does not exist." | VS_VERSIONINFO |
| V3 | `VS_FIXEDFILEINFO` is 13 DWORDs: `dwSignature` "Contains the value 0xFEEF04BD", `dwStrucVersion`, `dwFileVersionMS`/`LS`, `dwProductVersionMS`/`LS`, `dwFileFlagsMask`, `dwFileFlags`, `dwFileOS`, `dwFileType`, `dwFileSubtype`, `dwFileDateMS`/`LS`: 52 bytes. The MS and LS halves together form "a 64-bit value used for numeric comparisons". | VS_FIXEDFILEINFO |
| X1 | x86-64 maps memory in 4 KiB pages; residency, and so what a capture holds, is decided per page. | Intel SDM Vol. 3A, 4.5 (4-level paging) |

### Measurements

`peparsefacts` reads every kernel module (through the S55 reader choice) and every image mapped in every process, once per address space and base: 841 kernel and 15,470 process images whose headers read. `ordinalfacts` reads the same process images.

| # | Measured |
|---|---|
| M1 | Every image is PE32+ with `SizeOfOptionalHeader` 240, except 40 WoW64 process images, PE32 with 224. `NumberOfRvaAndSizes` is 16 in all. No `e_lfanew` lies inside the 64-byte DOS header. The most sections in one image is 36. 14 process entries start without "MZ"; 9,289 entries (14 kernel) have headers that do not read. Every header was read through `extract.ReadHeaders`, which grows its buffer to each `TruncatedError.Need`. |
| M2 | Largest counts in one image: 14,103 export records, 131 import descriptors, 1,607 lookup entries in one descriptor, 40 version leaves, a PDB path of 171 bytes. All lie far below the default limits (`MaxTableEntries` 4,194,304, `MaxNameBytes` 4,096). |
| M3 | 14,148 export directories parse (140 kernel, 14,008 process); in 1,186 an array does not read, and in 2 (mem2, process) a count passes a limit. They give 5,663,626 named and 276,532 unnamed records, 254,318 forwarders, 235,861 names and 29,775 forwarders on pages that did not read. 1,721 images have address-table slots with RVA 0 and no name. No slot has more than one name, and no named slot has RVA 0. `Ordinal Base` is not 1 in 3,425 of the 14,148 (values 0 to 42,021). |
| M4 | 14,656 import directories parse; in 1,014 the first descriptor does not read. Walking to the all-zero descriptor while ignoring `Size`, it lies inside `Size` in 14,420 images, is not reached before an unread page in 234, and lies past `Size` in 2: mem5 kernel, all-zero descriptor at index 11,056 with `Size` 40, and mem2 process, index 318 with `Size` 680. Past `Size` those walks read unrelated bytes (nonzero time stamps, library names outside the image, reserved bits). Two descriptors have no lookup table. Of 44,038 ordinal imports none has bit 15 set; 7 lookup entries (mem2 process) set reserved bits. |
| M5 | Every kernel image has a CodeView entry; 840 of 841 RSDS records read, 1 is not RSDS. In process images 7,543 read, 7,921 lie on pages that did not read, 3 are not RSDS. In every RSDS record that read, the path's NUL lies inside `SizeOfData`: `SizeOfData` is 24 + path + 1 in all but 49, which are longer, and every path ends ".pdb". 49 images have two CodeView entries. |
| M6 | 10,847 of 10,848 named root resource entries have the high bit set; ID entries are in ascending order in every image. Every image with a version type has one leaf, except two with 39 and 40. All 11,517 version leaf RVAs are multiples of 4, so `Value` follows two bytes of `Padding1` at offset 40. In all 11,036 version resources whose first bytes read, `wType` is 0 and `wValueLength` 52. |
| M7 | Of 15,420 mapped images listed by `ordinalfacts`, 3,270 import by ordinal, from 79 libraries. 65 of them have an export directory in some capture; of the other 14, 13 are API-set names, which no mapped image carries. With the other width of each such library also read, 3,914 instances in 68 library-width pairs were parsed (288 export parses failed). No build gives one ordinal two names. Builds disagree widely for libraries whose named exports are numbered in name order: user32.dll 997 ordinals named differently, gdi32.dll 988, combase.dll 399. Others never disagree: oleaut32.dll, 425 names in 4 builds. The table below lists the 29 library-width tables kept, 25 libraries. |

| Library | Builds | Names agree | Differ | Named by one build only | Kept | Imported by ordinal | Of them named |
|---|---|---|---|---|---|---|---|
| appxdeploymentclient.dll (64-bit) | 3 | 82 | 22 | 22 | 60 | 5 | 5 |
| atl.dll (64-bit) | 2 | 54 | 0 | 0 | 54 | 11 | 11 |
| cabinet.dll (64-bit) | 3 | 26 | 0 | 0 | 26 | 14 | 14 |
| combase.dll (64-bit) | 4 | 145 | 399 | 77 | 68 | 131 | 41 |
| combase.dll (32-bit) | 2 | 224 | 237 | 136 | 88 | 41 | 39 |
| comctl32.dll (64-bit) | 6 | 75 | 78 | 4 | 71 | 28 | 27 |
| d2d1.dll (64-bit) | 4 | 13 | 0 | 0 | 13 | 6 | 6 |
| dcomp.dll (64-bit) | 4 | 12 | 11 | 5 | 7 | 16 | 1 |
| dwmapi.dll (64-bit) | 4 | 57 | 20 | 33 | 24 | 27 | 6 |
| gdi32.dll (64-bit) | 4 | 572 | 988 | 565 | 7 | 4 | 2 |
| gdi32.dll (32-bit) | 2 | 636 | 802 | 623 | 13 | 0 | 0 |
| lsasrv.dll (64-bit) | 4 | 62 | 269 | 60 | 2 | 34 | 2 |
| mmdevapi.dll (64-bit) | 4 | 7 | 3 | 4 | 3 | 21 | 1 |
| mscms.dll (64-bit) | 4 | 63 | 73 | 11 | 52 | 1 | 1 |
| oleaut32.dll (64-bit) | 4 | 425 | 0 | 0 | 425 | 197 | 197 |
| oleaut32.dll (32-bit) | 2 | 409 | 0 | 0 | 409 | 0 | 0 |
| propsys.dll (64-bit) | 4 | 4 | 220 | 0 | 4 | 5 | 2 |
| shcore.dll (64-bit) | 4 | 21 | 76 | 0 | 21 | 68 | 1 |
| shell32.dll (64-bit) | 4 | 146 | 339 | 6 | 140 | 181 | 81 |
| shlwapi.dll (64-bit) | 4 | 284 | 96 | 1 | 283 | 140 | 47 |
| tlscsp.dll (64-bit) | 2 | 10 | 0 | 0 | 10 | 5 | 5 |
| user32.dll (64-bit) | 4 | 46 | 997 | 3 | 43 | 80 | 13 |
| user32.dll (32-bit) | 3 | 91 | 943 | 86 | 5 | 2 | 1 |
| uxtheme.dll (64-bit) | 4 | 16 | 83 | 10 | 6 | 13 | 3 |
| vsstrace.dll (64-bit) | 3 | 15 | 0 | 0 | 15 | 11 | 11 |
| windows.storage.dll (64-bit) | 4 | 395 | 238 | 1 | 394 | 42 | 17 |
| winspool.drv (64-bit) | 4 | 18 | 180 | 0 | 18 | 5 | 2 |
| ws2_32.dll (64-bit) | 4 | 114 | 82 | 0 | 114 | 36 | 36 |
| wsnmp32.dll (64-bit) | 2 | 51 | 0 | 0 | 51 | 29 | 29 |

The table holds 2,426 ordinals. A build is one file header `TimeDateStamp`; mem6 and mem7 share theirs. "Imported by ordinal" counts the distinct ordinals the captures import in that width. Per library and build, the ordinals that carry a name:

| Library | Build (`TimeDateStamp`, file version) | Captures | Instances (export parse failed) | Slots | Named ordinals |
|---|---|---|---|---|---|
| appxdeploymentclient.dll (64-bit) | 0x2c02af8d 10.0.26100.1591 | mem6, mem7 | 6 (1) | 106 | 104: 2-15, 17-106 |
| appxdeploymentclient.dll (64-bit) | 0x584a7b20 10.0.14393.576 | mem5 | 1 (0) | 34 | 32: 2-15, 17-34 |
| appxdeploymentclient.dll (64-bit) | 0xd35563a3 10.0.19041.6456 | mem2 | 13 (0) | 84 | 82: 2-15, 17-84 |
| atl.dll (64-bit) | 0x57899ade version unread | mem5 | 4 (0) | 54 | 54: 10-63 |
| atl.dll (64-bit) | 0xf75e3099 version unread | mem2 | 1 (0) | 54 | 54: 10-63 |
| cabinet.dll (64-bit) | 0x2f2bcd44 5.0.1.1 | mem1, mem6, mem7 | 9 (0) | 26 | 26: 1-4, 10-14, 20-24, 30-35, 40-45 |
| cabinet.dll (64-bit) | 0x572fb1df 5.0.1.1 | mem2 | 6 (0) | 26 | 26: 1-4, 10-14, 20-24, 30-35, 40-45 |
| cabinet.dll (64-bit) | 0x578997ca 5.0.1.1 | mem5 | 5 (0) | 26 | 26: 1-4, 10-14, 20-24, 30-35, 40-45 |
| combase.dll (64-bit) | 0x089be9fd 10.0.19041.6456 | mem2 | 102 (7) | 591 | 457: 2-62, 72-78, 82-85, 89, 91, 94, 105-109, 113-119, 131-132, 144, 225-591 |
| combase.dll (64-bit) | 0x584a7796 10.0.14393.576 | mem5 | 55 (0) | 501 | 436: 2-62, 72-78, 82-85, 89, 94, 105-109, 113-119, 131-132, 144, 155-501 |
| combase.dll (64-bit) | 0xa251a592 10.0.26100.1591 | mem6, mem7 | 74 (9) | 601 | 461: 2-62, 72-78, 82-85, 89, 91, 94, 105-109, 113-119, 131-132, 144, 231-601 |
| combase.dll (64-bit) | 0xab922702 10.0.26100.8328 | mem1 | 67 (0) | 608 | 466: 2-62, 72-78, 82-85, 89, 91, 94, 105-109, 113-119, 131-132, 144, 233-608 |
| combase.dll (32-bit) | 0x584a76ba 10.0.14393.576 | mem5 | 1 (0) | 446 | 381: 2-62, 72-78, 82-85, 89, 94, 105-109, 113-119, 131-132, 144, 155-446 |
| combase.dll (32-bit) | 0xcdb5726d 10.0.26100.1742 | mem6 | 1 (0) | 525 | 405: 2-62, 72-78, 82-85, 89, 91, 94, 105-109, 113-119, 131-132, 144, 205-224, 231-525 |
| comctl32.dll (64-bit) | 0x14a79c81 version unread | mem1 | 2 (1) | 181 | 119: 2-70, 75-91, 152, 236, 320-340, 385-388, 400-401, 403, 410, 412-413 |
| comctl32.dll (64-bit) | 0x2c74016e version unread | mem1 | 5 (0) | 220 | 150: 2-17, 21-70, 75-102, 152, 200-210, 236, 320-340, 343-349, 380-381, 385-388, 394, 400-401, 403, 410-413, 423 |
| comctl32.dll (64-bit) | 0x5819bcf0 version unread | mem5 | 9 (0) | 217 | 148: 2-17, 20-70, 75-101, 152, 200-210, 236, 320-340, 343-348, 380-381, 385-388, 394, 400-401, 403, 410-413 |
| comctl32.dll (64-bit) | 0x6e70e083 6.10.19041.6456 | mem2 | 8 (1) | 218 | 148: 2-17, 21-70, 75-102, 152, 200-210, 236, 320-340, 343-348, 380-381, 385-388, 394, 400-401, 403, 410-413 |
| comctl32.dll (64-bit) | 0x91391835 version unread | mem6 | 1 (1) | 0 | 0:  |
| comctl32.dll (64-bit) | 0xb70dfba2 6.10.26100.1591 | mem6 | 3 (0) | 218 | 148: 2-17, 21-70, 75-102, 152, 200-210, 236, 320-340, 343-348, 380-381, 385-388, 394, 400-401, 403, 410-413 |
| d2d1.dll (64-bit) | 0x585a268a 10.0.14393.693 | mem5 | 7 (0) | 13 | 13: 1-13 |
| d2d1.dll (64-bit) | 0x88030962 10.0.19041.5794 | mem2 | 7 (0) | 13 | 13: 1-13 |
| d2d1.dll (64-bit) | 0xc0318d27 10.0.26100.8328 | mem1 | 9 (0) | 13 | 13: 1-13 |
| d2d1.dll (64-bit) | 0xeee64dcb 10.0.26100.1591 | mem6, mem7 | 8 (0) | 13 | 13: 1-13 |
| dcomp.dll (64-bit) | 0x0ee0be77 10.0.26100.1591 | mem6 | 5 (0) | 42 | 18: 1017-1018, 1020-1027, 1029-1030, 1100-1104, 2005 |
| dcomp.dll (64-bit) | 0x5789983d 10.0.14393.0 | mem5 | 7 (0) | 23 | 16: 1018, 1020-1027, 1029-1030, 1032, 1034-1037 |
| dcomp.dll (64-bit) | 0x84969877 10.0.19041.6157 | mem2 | 6 (1) | 32 | 12: 1017-1018, 1020-1027, 1029-1030 |
| dcomp.dll (64-bit) | 0xee86c6f4 10.0.26100.8328 | mem1 | 7 (0) | 42 | 18: 1017-1018, 1020-1027, 1029-1030, 1100-1104, 2005 |
| dwmapi.dll (64-bit) | 0x06dae957 10.0.19041.6157 | mem2 | 9 (0) | 99 | 44: 100-102, 111, 115-123, 125-131, 133-137, 143, 149, 156, 183-198 |
| dwmapi.dll (64-bit) | 0x57dacdba 10.0.14393.206 | mem5 | 15 (0) | 83 | 43: 100-102, 111, 115-123, 125-126, 128-130, 133, 135-137, 143, 149, 156, 165-182 |
| dwmapi.dll (64-bit) | 0xbd1c6bcf 10.0.26100.8328 | mem1 | 6 (0) | 113 | 44: 100-102, 111, 115-123, 125-131, 133-137, 143, 146, 149, 156, 183, 199-212 |
| dwmapi.dll (64-bit) | 0xd2051ec9 10.0.26100.1591 | mem6, mem7 | 5 (0) | 108 | 44: 100-102, 111, 115-123, 125-131, 133-137, 143, 146, 149, 156, 183, 194-207 |
| gdi32.dll (64-bit) | 0x12857ab6 10.0.26100.1150 | mem6, mem7 | 46 (4) | 1007 | 993: 1011-1012, 1014, 1017-2006 |
| gdi32.dll (64-bit) | 0x57dace36 10.0.14393.206 | mem5 | 54 (0) | 1572 | 1560: 1011-1012, 1014-2571 |
| gdi32.dll (64-bit) | 0x5cd2417b 10.0.26100.8328 | mem1 | 66 (0) | 1009 | 995: 1011-1012, 1014, 1017-2008 |
| gdi32.dll (64-bit) | 0x8fdf2fa3 10.0.19041.6157 | mem2 | 89 (9) | 987 | 973: 1011-1012, 1014, 1017-1985, 2000 |
| gdi32.dll (32-bit) | 0x57dad2ca 10.0.14393.206 | mem5 | 1 (0) | 1572 | 1260: 1011-1012, 1014-1827, 2000, 2129-2571 |
| gdi32.dll (32-bit) | 0x78b5626a 10.0.26100.1150 | mem6 | 1 (0) | 1007 | 993: 1011-1012, 1014, 1017-2006 |
| lsasrv.dll (64-bit) | 0x0600c443 version unread | mem7 | 1 (1) | 0 | 0:  |
| lsasrv.dll (64-bit) | 0x585a2650 10.0.14393.693 | mem5 | 1 (0) | 270 | 270: 1-270 |
| lsasrv.dll (64-bit) | 0xe29969d9 10.0.19041.6456 | mem2 | 1 (0) | 292 | 271: 1-271 |
| lsasrv.dll (64-bit) | 0xfcc179b3 10.0.26100.8328 | mem1 | 1 (0) | 331 | 292: 40-331 |
| mmdevapi.dll (64-bit) | 0x57899a5e 10.0.14393.0 | mem5 | 3 (0) | 32 | 5: 17, 30-33 |
| mmdevapi.dll (64-bit) | 0x5dbf1280 10.0.26100.1 | mem6 | 4 (0) | 37 | 5: 17, 35-38 |
| mmdevapi.dll (64-bit) | 0x77a1f607 10.0.19041.5915 | mem2 | 4 (1) | 35 | 5: 17, 33-36 |
| mmdevapi.dll (64-bit) | 0xd630f432 10.0.26100.8328 | mem1 | 4 (0) | 37 | 5: 17, 35-38 |
| mscms.dll (64-bit) | 0x272e9e0b 10.0.19041.5794 | mem2 | 1 (0) | 131 | 131: 1-106, 200-208, 210-219, 230-235 |
| mscms.dll (64-bit) | 0x369358f9 10.0.26100.1591 | mem6 | 2 (0) | 125 | 125: 1-106, 200-208, 230-236, 240, 250, 260 |
| mscms.dll (64-bit) | 0x578998fe 10.0.14393.0 | mem5 | 1 (0) | 108 | 108: 1-105, 200-202 |
| mscms.dll (64-bit) | 0xb4559d26 10.0.26100.8328 | mem1 | 1 (0) | 126 | 126: 1-106, 200-208, 230-236, 240, 250, 260, 270 |
| oleaut32.dll (64-bit) | 0x5819bf64 10.0.14393.447 | mem5 | 51 (7) | 425 | 425: 2-381, 401-402, 411-452, 500 |
| oleaut32.dll (64-bit) | 0x8c28766f 10.0.26100.8328 | mem1 | 52 (5) | 429 | 425: 2-381, 401-402, 411-452, 500 |
| oleaut32.dll (64-bit) | 0x90c1a1cf 10.0.26100.1150 | mem6, mem7 | 56 (8) | 429 | 425: 2-381, 401-402, 411-452, 500 |
| oleaut32.dll (64-bit) | 0xd42edff1 10.0.19041.3636 | mem2 | 76 (23) | 427 | 425: 2-381, 401-402, 411-452, 500 |
| oleaut32.dll (32-bit) | 0x5819c2b5 10.0.14393.447 | mem5 | 1 (0) | 409 | 409: 2-349, 360-379, 401-402, 411-448, 500 |
| oleaut32.dll (32-bit) | 0xed6eca80 10.0.26100.1 | mem6 | 1 (0) | 413 | 409: 2-349, 360-379, 401-402, 411-448, 500 |
| propsys.dll (64-bit) | 0x14f07495 7.0.19041.5794 | mem2 | 27 (1) | 267 | 223: 3-223, 435-436 |
| propsys.dll (64-bit) | 0x20cfe511 7.0.26100.1301 | mem6, mem7 | 14 (1) | 268 | 224: 3-224, 435-436 |
| propsys.dll (64-bit) | 0x578998ac 7.0.14393.0 | mem5 | 15 (0) | 263 | 223: 3-223, 435-436 |
| propsys.dll (64-bit) | 0x76025931 7.0.26100.8328 | mem1 | 21 (0) | 268 | 224: 3-224, 435-436 |
| shcore.dll (64-bit) | 0x4337d238 10.0.26100.1150 | mem6, mem7 | 37 (3) | 202 | 97: 2-97, 122 |
| shcore.dll (64-bit) | 0x57899893 10.0.14393.0 | mem5 | 38 (0) | 192 | 88: 2-88, 122 |
| shcore.dll (64-bit) | 0xcefe2122 10.0.26100.8328 | mem1 | 48 (0) | 202 | 97: 2-97, 122 |
| shcore.dll (64-bit) | 0xe8391836 10.0.19041.5794 | mem2 | 54 (1) | 201 | 97: 2-97, 122 |
| shell32.dll (64-bit) | 0x585a27b3 10.0.14393.693 | mem5 | 20 (15) | 836 | 485: 2-4, 6, 9-11, 13-14, 16-19, 21-25, 27-28, 41-43, 47, 49, 51, 59, 62-64, 66-68, 71-75, 77, 80-81, 83, 85, 88-90, 92, 98, 100, 102-103, 119, 125, 129, 131-139, 147, 149-150, 152-155, 157, 162, 164-165, 167-171, 173-174, 176, 178-180, 182-183, 189-193, 195-196, 199, 207-208, 226, 228-229, 231-232, 238-240, 245, 255-256, 263, 267-269, 272-519, 524, 526-620, 644-645, 652, 654, 680, 682, 685, 688-689, 701, 709, 716, 727, 730, 743, 747, 750, 846, 919-921, 925, 929, 931, 935-937, 941-942 |
| shell32.dll (64-bit) | 0x5e20c26c 10.0.26100.8328 | mem1 | 22 (15) | 843 | 479: 2-4, 6, 9-11, 13-14, 16-19, 21-25, 27-28, 41-43, 47, 49, 51, 59, 62-64, 66-68, 71-75, 77, 80-81, 83, 85, 88-90, 92, 98, 100, 102-103, 119, 125, 129, 131-139, 147, 149-150, 152-155, 157, 162, 164-165, 167-171, 173-174, 176, 178-180, 182-183, 189-193, 195-196, 199, 207-208, 226, 228-229, 231-232, 238-240, 245, 255-256, 263, 267-269, 272-519, 524, 526-614, 644-645, 652, 654, 680, 682, 685, 688-689, 701, 709, 716, 727, 730, 743, 747, 750, 846, 919-921, 925, 929, 931, 935-937, 941-942 |
| shell32.dll (64-bit) | 0x9ee39b73 10.0.19041.6456 | mem2 | 25 (2) | 833 | 477: 2-4, 6, 9-11, 13-14, 16-19, 21-25, 27-28, 41-43, 47, 49, 51, 59, 62-64, 66-68, 71-75, 77, 80-81, 83, 85, 88-90, 92, 98, 100, 102-103, 119, 125, 129, 131-139, 147, 149-150, 152-155, 157, 162, 164-165, 167-171, 173-174, 176, 178-180, 182-183, 189-193, 195-196, 199, 207-208, 226, 228-229, 231-232, 238-240, 245, 255-256, 263, 267-269, 272-519, 524, 526-612, 644-645, 652, 654, 680, 682, 685, 688-689, 701, 709, 716, 727, 730, 743, 747, 750, 846, 919-921, 925, 929, 931, 935-937, 941-942 |
| shell32.dll (64-bit) | 0xf524673a 10.0.26100.1591 | mem6, mem7 | 16 (5) | 842 | 478: 2-4, 6, 9-11, 13-14, 16-19, 21-25, 27-28, 41-43, 47, 49, 51, 59, 62-64, 66-68, 71-75, 77, 80-81, 83, 85, 88-90, 92, 98, 100, 102-103, 119, 125, 129, 131-139, 147, 149-150, 152-155, 157, 162, 164-165, 167-171, 173-174, 176, 178-180, 182-183, 189-193, 195-196, 199, 207-208, 226, 228-229, 231-232, 238-240, 245, 255-256, 263, 267-269, 272-519, 524, 526-613, 644-645, 652, 654, 680, 682, 685, 688-689, 701, 709, 716, 727, 730, 743, 747, 750, 846, 919-921, 925, 929, 931, 935-937, 941-942 |
| shlwapi.dll (64-bit) | 0x5789988d 10.0.14393.0 | mem5 | 26 (1) | 930 | 379: 1-2, 7-10, 12, 14-16, 29, 151-158, 163-164, 168-169, 172, 174, 176, 184-185, 191, 199, 203-204, 212-215, 217-219, 225, 236, 256, 270, 276, 278, 280-281, 345-346, 353-354, 377-378, 388, 432-433, 437, 446, 462, 467, 487, 512-513, 515, 553, 567-570, 579, 584-597, 607-610, 612, 615, 620, 622-625, 629-630, 649-930 |
| shlwapi.dll (64-bit) | 0x62436572 10.0.26100.8328 | mem1 | 31 (1) | 931 | 380: 1-2, 7-10, 12, 14-16, 29, 151-158, 163-164, 168-169, 172, 174, 176, 184-185, 191, 199, 203-204, 212-215, 217-219, 225, 236, 256, 270, 276, 278, 280-281, 345-346, 353-354, 377-378, 388, 432-433, 437, 446, 462, 467, 487, 512-513, 515, 553, 567-570, 579, 584-597, 607-610, 612, 615, 620, 622-625, 629-630, 649-931 |
| shlwapi.dll (64-bit) | 0x7ae35290 10.0.19041.6392 | mem2 | 36 (5) | 930 | 379: 1-2, 7-10, 12, 14-16, 29, 151-158, 163-164, 168-169, 172, 174, 176, 184-185, 191, 199, 203-204, 212-215, 217-219, 225, 236, 256, 270, 276, 278, 280-281, 345-346, 353-354, 377-378, 388, 432-433, 437, 446, 462, 467, 487, 512-513, 515, 553, 567-570, 579, 584-597, 607-610, 612, 615, 620, 622-625, 629-630, 649-930 |
| shlwapi.dll (64-bit) | 0x9a5ca5b7 10.0.26100.1591 | mem6, mem7 | 18 (1) | 930 | 379: 1-2, 7-10, 12, 14-16, 29, 151-158, 163-164, 168-169, 172, 174, 176, 184-185, 191, 199, 203-204, 212-215, 217-219, 225, 236, 256, 270, 276, 278, 280-281, 345-346, 353-354, 377-378, 388, 432-433, 437, 446, 462, 467, 487, 512-513, 515, 553, 567-570, 579, 584-597, 607-610, 612, 615, 620, 622-625, 629-630, 649-930 |
| tlscsp.dll (64-bit) | 0x513ab745 10.0.26100.4202 | mem1 | 1 (0) | 10 | 10: 1-10 |
| tlscsp.dll (64-bit) | 0x578997c3 10.0.14393.0 | mem5 | 1 (0) | 10 | 10: 1-10 |
| user32.dll (64-bit) | 0x45fed4a8 10.0.26100.1591 | mem6, mem7 | 55 (7) | 1194 | 1041: 1503-1549, 1553, 1555-2000, 2003-2004, 2006-2009, 2011-2505, 2521, 2528, 2542-2543, 2547, 2551, 2562, 2571, 2577, 2580, 2583, 2596, 2601, 2662-2668, 2671-2676, 2680-2695, 2800-2802, 2804 |
| user32.dll (64-bit) | 0x5094b343 10.0.19041.6456 | mem2 | 83 (1) | 1165 | 1005: 1503-1549, 1553, 1555-2000, 2003-2004, 2006-2009, 2011-2505, 2521, 2528, 2543, 2547, 2551, 2562, 2571, 2580, 2583, 2596 |
| user32.dll (64-bit) | 0x584a7939 10.0.14393.576 | mem5 | 54 (0) | 1061 | 951: 1503-1549, 1555-2000, 2003-2004, 2006-2009, 2011-2461, 2528 |
| user32.dll (64-bit) | 0x94089fa1 10.0.26100.8328 | mem1 | 66 (0) | 1205 | 1042: 1503-1549, 1553, 1555-2000, 2003-2004, 2006-2009, 2011-2505, 2521, 2528, 2542-2543, 2547, 2551, 2562, 2571, 2577, 2580, 2583, 2596, 2601, 2662-2668, 2671-2676, 2680-2694, 2800-2802, 2804, 2806, 2811 |
| user32.dll (32-bit) | 0x584a7a33 version unread | mem5 | 1 (0) | 1054 | 944: 1503-1549, 1555-2000, 2003-2004, 2006-2009, 2011-2454, 2528 |
| user32.dll (32-bit) | 0x7eac7a9d version unread | mem6 | 2 (0) | 1187 | 1034: 1503-1549, 1553, 1555-2000, 2003-2004, 2006-2009, 2011-2505, 2521, 2528, 2542-2543, 2551, 2571, 2662-2668, 2671-2676, 2680-2695, 2800-2802, 2804 |
| user32.dll (32-bit) | 0x933725ae version unread | mem2 | 1 (0) | 1158 | 619: 1503-1549, 1553, 1555-2000, 2003-2004, 2006-2009, 2011-2125, 2503, 2505, 2521, 2528 |
| uxtheme.dll (64-bit) | 0x57899875 10.0.14393.0 | mem5 | 21 (0) | 186 | 84: 5-6, 12, 37-42, 47, 51-59, 61, 70-71, 89, 95, 98, 114, 120-121, 131-186 |
| uxtheme.dll (64-bit) | 0x7b957925 10.0.26100.8328 | mem1 | 19 (0) | 199 | 85: 5-6, 12, 37-42, 47, 51-59, 61, 70-71, 89, 95, 98, 103, 114, 120-121, 129, 134, 146-199 |
| uxtheme.dll (64-bit) | 0xdc6190de 10.0.19041.5794 | mem2 | 17 (0) | 193 | 85: 5-6, 12, 37-42, 47, 51-59, 61, 70-71, 89, 95, 98, 103, 114, 120-121, 129, 134, 140-193 |
| uxtheme.dll (64-bit) | 0xf2d36d8b 10.0.26100.1591 | mem6 | 13 (0) | 197 | 85: 5-6, 12, 37-42, 47, 51-59, 61, 70-71, 89, 95, 98, 103, 114, 120-121, 129, 134, 144-197 |
| vsstrace.dll (64-bit) | 0x01aff7b1 10.0.26100.8328 | mem1 | 6 (0) | 15 | 15: 1-15 |
| vsstrace.dll (64-bit) | 0x57899afd 10.0.14393.0 | mem5 | 3 (0) | 15 | 15: 1-15 |
| vsstrace.dll (64-bit) | 0xf11f6fad 10.0.19041.3636 | mem2 | 4 (0) | 15 | 15: 1-15 |
| windows.storage.dll (64-bit) | 0x474d8b64 10.0.26100.1742 | mem6, mem7 | 14 (5) | 690 | 630: 2-76, 78-94, 96-171, 173-242, 245-263, 265-626, 644-645, 680, 846, 925, 938, 942-943, 945-947 |
| windows.storage.dll (64-bit) | 0x58258b70 10.0.14393.479 | mem5 | 24 (21) | 254 | 215: 2-94, 96-209, 245, 644-645, 680, 846, 925, 938, 942 |
| windows.storage.dll (64-bit) | 0x697ab702 10.0.26100.8328 | mem1 | 33 (3) | 691 | 631: 2-76, 78-94, 96-171, 173-242, 245-263, 265-627, 644-645, 680, 846, 925, 938, 942-943, 945-947 |
| windows.storage.dll (64-bit) | 0xe27225e8 10.0.19041.6456 | mem2 | 35 (20) | 290 | 243: 2-94, 96-235, 245, 644-645, 680, 846, 925, 938, 942-943, 945 |
| winspool.drv (64-bit) | 0x5789990f 10.0.14393.0 | mem5 | 4 (0) | 242 | 197: 101-204, 225, 232, 235-249, 263-337, 341 |
| winspool.drv (64-bit) | 0x98bbfba2 version unread | mem6 | 2 (0) | 257 | 198: 101-204, 225, 232, 235-249, 263-337, 341-342 |
| winspool.drv (64-bit) | 0xbcb69b94 version unread | mem2 | 2 (0) | 255 | 198: 101-204, 225, 232, 235-249, 263-337, 341-342 |
| winspool.drv (64-bit) | 0xd776274e 10.0.26100.8328 | mem1 | 3 (0) | 257 | 198: 101-204, 225, 232, 235-249, 263-337, 341-342 |
| ws2_32.dll (64-bit) | 0x1e872b67 10.0.26100.8328 | mem1 | 33 (0) | 196 | 196: 1-195, 500 |
| ws2_32.dll (64-bit) | 0x57dacda4 10.0.14393.206 | mem5 | 34 (0) | 195 | 195: 1-194, 500 |
| ws2_32.dll (64-bit) | 0x7a0d31bc 10.0.19041.3636 | mem2 | 56 (6) | 195 | 195: 1-194, 500 |
| ws2_32.dll (64-bit) | 0x9d63febb 10.0.26100.1591 | mem6, mem7 | 7 (0) | 196 | 196: 1-195, 500 |
| wsnmp32.dll (64-bit) | 0x57899b8b 10.0.14393.0 | mem5 | 1 (0) | 51 | 51: 100-109, 120, 200-206, 220-222, 291-293, 300-302, 320, 400-402, 500-504, 600-606, 900-906, 999 |
| wsnmp32.dll (64-bit) | 0x8e6fc6e6 10.0.26100.1150 | mem1 | 1 (0) | 51 | 51: 100-109, 120, 200-206, 220-222, 291-293, 300-302, 320, 400-402, 500-504, 600-606, 900-906, 999 |

## 4. Algorithm

### 4.1 Headers (`ParseHeaders`)

1. If the buffer holds at least 2 bytes and they are not "MZ", fail with `ErrNotPE`. A buffer shorter than 64 bytes is `TruncatedError{Need: 64}`.
2. `e_lfanew` is the DWORD at 0x3C (P1). The signature and file header need `e_lfanew + 24` bytes; fewer is `TruncatedError`. A signature other than "PE\0\0" is `ErrNoNTSignature`.
3. Decode the file header (P2). The optional header starts at `e_lfanew + 24`. Its magic must be 0x10B or 0x20B, else `ErrUnsupportedOptionalMagic` (P3; ROM images are not loaded by Windows and are not read).
4. `SizeOfOptionalHeader` must reach the data directories, 96 or 112 bytes, else `ErrShortOptionalHeader`: the fields of step 5 would otherwise be read from the section table (P4, P5, P6).
5. Decode the fields of P3 and P4 that `OptionalHeader` holds (not `BaseOfData` or `NumberOfRvaAndSizes`; 4.2 reads the latter), with `ImageBaseOffset` and `ImageBaseSize` giving where `ImageBase` lies (S18 rewrites it).
6. The section table starts at the optional header plus `SizeOfOptionalHeader` and ends at `HeaderSpan()`; a shorter buffer is `TruncatedError{Need: HeaderSpan()}`. Each 40-byte entry is decoded; `Name` keeps the raw bytes up to the first NUL, or all 8 (P6).

Every `TruncatedError` names the byte count the next step needs. A caller that reads more and calls again therefore progresses until the headers decode (M1). Section count is not capped at 96 (P2): headers in memory are read as they are, and `extract.ReadHeaders` bounds the span.

### 4.2 Data directories

An entry counts when its index is below `NumberOfRvaAndSizes` and its 8 bytes end inside `SizeOfOptionalHeader` (P5, P6); otherwise `ErrNoDataDirectory`. `DataDirectory` reads from a header buffer, `ReadDataDirectory` through a `ReadRVA`: the headers are mapped at RVA 0, so a header offset is its RVA.

### 4.3 Reading a mapped image

1. `MappedReader` refuses a read with negative length or one that ends past `SizeOfImage` (`ErrOutsideImage`); a failed or short read of the underlying reader is `ErrUnreadable`, wrapping the reader's error.
2. A string is read up to its NUL. It is read in pieces that end at 4 KiB page boundaries (X1), and a piece that fails is halved down to one byte, so a string that ends before an unread page, or before the end of the image, reads whole. No NUL within the limit is `ErrUnterminatedString`; a byte that does not read is that read's error.
3. Fixed arrays that are walked to a terminator (import descriptors and lookup tables) are read a page at a time; an entry that crosses a page boundary, or a page that does not read whole, is read on its own.

### 4.4 Exports (`ParseExports`)

1. `VirtualAddress` 0 is `ErrNoExportDirectory` (P5).
2. Read the 40-byte table (P7). `Address Table Entries` and `Number of Name Pointers` above `MaxTableEntries`, or a last ordinal `Ordinal Base + entries − 1` past 32 bits, are `ErrExportCountTooLarge`.
3. Read the address table, the name pointer table and the ordinal table whole. An array larger than `MaxBufferBytes` is `ErrExportCountTooLarge`; an array that does not read fails the parse with its read error. The arrays are the directory's skeleton: a list built with one missing would not say which exports it lacks (M3).
4. Attach each name to the slot its ordinal-table entry gives (P9). A slot index at or past `Address Table Entries` names nothing and the name is dropped.
5. For each slot in order: the ordinal is `Ordinal Base` plus the slot index (P9). A slot with RVA 0 and no name exports nothing and is left out (M3). An RVA inside `[VirtualAddress, VirtualAddress + Size)` is a forwarder (P8); its string is read with the limit `min(MaxNameBytes, directory end − RVA − 1)`, so it must end inside the directory. A forwarder string that does not read or is empty sets `ForwarderUnreadable`.
6. A slot with names gives one `Export` per name in name-table order (sorted, P9); a slot without gives one unnamed `Export`. A name that does not read sets `NameUnreadable` and leaves `Name` empty.

`LookupExport` returns `base + RVA` of the first export whose name equals the asked name byte for byte (P12: names are case sensitive) and that is neither a forwarder nor unread. A forwarder's RVA names a string, so it has no address in this image (P8).

### 4.5 Imports (`ParseImports`)

1. `VirtualAddress` 0 is `ErrNoImportDirectory`.
2. `Size` below 20 holds no descriptor: `ErrNoImportDirectory`. Read 20-byte descriptors until one is all zero (P10) or `Size` is used up. In M4 it lies inside `Size` in 14,420 of the 14,422 images where it was reached, and the two walks that went past `Size` read unrelated bytes; reaching `Size` without it is an `ErrImportLimit` problem. If the first descriptor does not read, the parse fails; a later one that does not read ends the list and is a problem.
3. Each descriptor's library name is read as a string (`LibraryErr` when it does not).
4. The lookup table is read when `Import Lookup Table RVA` is set, else the import address table (P11). In memory the address table holds resolved addresses; a descriptor that has only it is read anyway. For PE32+ its entries fail the reserved-bit rule of step 5; for PE32 a resolved address below 2 GB reads as a hint/name RVA past the image, and its `NameErr` wraps `ErrOutsideImage` (M4 counts two descriptors without a lookup table).
5. Each entry up to the zero one: bit 31/63 set is an ordinal import, the ordinal the low 16 bits, and bits 30-16 (62-16 for PE32+) must be zero. Bit 31/63 clear is a hint/name RVA, and for PE32+ bits 62-31 must be zero. A set reserved bit is `ErrReservedThunkBits` and ends that descriptor's walk (P11, O3). `SlotRVA` is the address-table RVA plus the entry index times the width.
6. A hint/name entry is the 2-byte hint and a string (P12); a failure sets `NameErr`.
7. `MaxTableEntries` is one budget for descriptors and lookup entries together. When it runs out, `ErrImportLimit` is a problem and the walk stops.

Problems are returned in `ImportTable.Problems`, each wrapping its sentinel, in the order met; the descriptors and imports read before a problem are kept.

### 4.6 CodeView record (`ReadCodeView`)

1. `VirtualAddress` 0 or `Size` 0 is `ErrNoDebugDirectory`. `Size` below 28 is `ErrBadDebugDirectory` (P13).
2. Walk the `Size / 28` entries in order. An entry that does not read ends the walk.
3. For each entry of type 2 (P13): `AddressOfRawData` 0 means not mapped. `SizeOfData` must exceed 24. The data starts "RSDS", then a 16-byte GUID, a 32-bit age and a NUL-terminated path that ends inside `SizeOfData` (O1, M5), at most `MaxNameBytes` long and not empty.
4. The first record that decodes is returned with `RVA = AddressOfRawData`. When none decodes, a read failure (`ErrUnreadable`, `ErrOutsideImage`) is returned before a malformed record, and `ErrNoCodeView` when there is neither: a page that did not read says nothing about what it held.

`PDBName` is the path after its last `\` or `/`.

### 4.7 Resources (`FindResources`)

1. `VirtualAddress` 0 is `ErrNoResourceDirectory`.
2. Read the root table and its entries (P14). Find the ID entry equal to the type; it must point at a subdirectory (P15), else `ErrNoResource`.
3. Read that table (the Name level). For each entry that points at a subdirectory, read the Language table; each of its entries that points at a data entry (high bit clear) gives a leaf: the 16-byte data entry (P16) with the Name and Language IDs of its path. A named entry's ID is its string offset with the high bit cleared, and `NameIsString` is set (P15, M6).
4. Leaves come in tree order: Name entries as stored (named first, then IDs ascending, P14), then Language entries as stored. Entries at a level where the convention puts none (a leaf at the Name level, a subdirectory at the Language level) are passed over (P14).
5. The root and Name tables must read. A Language table or data entry that does not read is passed over; if that leaves no leaf, its read error is returned, and `ErrNoResource` when the type has no leaf at all.
6. Every table counts its entries against `MaxTableEntries`; past it is `ErrResourceLimit`. The depth is fixed at three, so a table that points back up costs only its entries.

### 4.8 Version resource (`ParseVersionInfo`, `ReadVersion`)

1. `ParseVersionInfo(data, rva)`: `wLength`, `wValueLength`, `wType` (V2). `wLength` and the buffer must reach the end of `szKey`, which must be `L"VS_VERSION_INFO"` with its NUL, else `ErrBadVersionInfo`.
2. `wValueLength` 0 is `ErrNoFixedFileInfo` (V2).
3. `Value` starts after `szKey`, padded so that `rva + offset` is a multiple of 4 (V2): `rva` is the address the data was found at, so the padding matches the one the resource compiler wrote. `wValueLength` below 52, or `Value` ending past `wLength` or past the buffer, is `ErrBadVersionInfo`.
4. Decode the 13 DWORDs (V3); a signature other than 0xFEEF04BD is `ErrBadFixedFileInfoSignature`.
5. `ReadVersion` finds the `RT_VERSION` leaves (V1, 4.7) and reads, for each in order, only the bytes up to the end of `Value` (at most `Size`); the strings and variable children after it may lie on pages that did not read. The first leaf that decodes wins; when none does, the first leaf's error is returned.

`FileVersion` and `ProductVersion` split the MS and LS DWORDs into four 16-bit parts, high word first (V3).

### 4.9 Ordinal table (`pe/peparse`)

1. `OrdinalName(dll, pe32Plus, ordinal)` looks up the library name with ASCII letters folded to lower case in the table of the importer's width. 32-bit and 64-bit builds of one library number their exports apart (M7), so each width has its own table.
2. `HasOrdinalTable(dll)` is true when either width has a table for the library.
3. The table is generated by `ordinalfacts` from the captures:
   1. Every image mapped in every process is read, its import directory parsed, and each library imported by ordinal is recorded with the importer's width.
   2. Every mapped instance of those libraries, in either width, has its export directory parsed. Instances of one build, told apart by the file header's `TimeDateStamp`, are unioned, so a name lost to an unread page in one process is taken from another.
   3. An ordinal is kept when every build that names it gives it the same single name and at least two distinct builds name it (O4). A library is kept, in both widths, when at least one ordinal that the captures import from it by ordinal, in either width, is kept: a 32-bit importer of a library seen imported only by 64-bit images still gets its names.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| "MZ" at 0, "PE\0\0" at `e_lfanew` | P1 | `ErrNotPE`, `ErrNoNTSignature` |
| Magic PE32 or PE32+ | P3 | `ErrUnsupportedOptionalMagic` |
| `SizeOfOptionalHeader` reaches the directories | P4, P5, P6 | `ErrShortOptionalHeader` |
| Directory index below `NumberOfRvaAndSizes`, entry inside the optional header | P5, P6 | `ErrNoDataDirectory` |
| Reads inside `SizeOfImage` | P4 | `ErrOutsideImage` |
| Strings end with NUL within the limit | P8, P9, P12 | `ErrUnterminatedString`, the field flagged |
| Export counts within limits; ordinals fit 32 bits | Limits, P9 | `ErrExportCountTooLarge` |
| Export name's slot inside the address table | P9 | Name dropped |
| Forwarder string inside the export directory | P8 | `ForwarderUnreadable` |
| Import lookup reserved bits zero | P11 | `ErrReservedThunkBits`, descriptor ends |
| Descriptors within `Size`; descriptors and lookup entries within one budget | M4, Limits | `ErrImportLimit` |
| Debug directory holds a whole entry | P13 | `ErrBadDebugDirectory` |
| CodeView data "RSDS", path NUL inside `SizeOfData` | O1, M5 | Entry passed over |
| Resource leaves at the third level only | P14 | Entry passed over |
| `szKey` is `VS_VERSION_INFO`; `Value` 52 bytes inside `wLength` | V2, V3 | `ErrBadVersionInfo` |
| `dwSignature` 0xFEEF04BD | V3 | `ErrBadFixedFileInfoSignature` |
| Ordinal names agree across at least two builds | M7 | Ordinal left out of the table |

## 6. Failure modes

| Case | Result |
|---|---|
| Buffer too short for the headers | `*TruncatedError` with `Need`; `extract.ReadHeaders` reads more and retries |
| Page of a fixed structure unread | `ErrUnreadable` wrapping the reader's error, returned by the parser that needed it |
| Page of a string unread | The field's flag (`NameUnreadable`, `ForwarderUnreadable`, `LibraryErr`, `NameErr`) |
| Page of an import part unread | A problem in `ImportTable.Problems`; earlier parts kept |
| Resource subtree unread | Passed over; the read error only when no leaf remains |
| CodeView data unread | The read error, before `ErrNoCodeView` |
| Limits hit | `ErrExportCountTooLarge`, `ErrImportLimit`, `ErrResourceLimit` |
| Library or ordinal not in the table | `OrdinalName` returns `ok` false |

The package has no strict mode and writes no diagnostics; callers turn its sentinels into their own (S55, S66).

## 7. Result schema

| Type | Fields |
|---|---|
| `Headers` | `DOS` (`Magic`, `Lfanew`), `File` (`Machine`, `NumberOfSections`, `TimeDateStamp`, `SizeOfOptionalHeader`, `Characteristics`), `Optional` (`Magic`, `AddressOfEntryPoint`, `ImageBase`, `SectionAlignment`, `FileAlignment`, `MajorOperatingSystemVersion`, `MinorOperatingSystemVersion`, `SizeOfImage`, `SizeOfHeaders`, `CheckSum`, `PE32Plus`, `ImageBaseOffset`, `ImageBaseSize`), `Sections` (`Name`, `VirtualSize`, `VirtualAddress`, `SizeOfRawData`, `PointerToRawData`, `Characteristics`, `HeaderOffset`), `NTOffset`, `OptionalOffset`, `SectionTableOffset`; `HeaderSpan()` |
| `Export` | `Name`, `NameUnreadable` (new), `Ordinal` (biased), `RVA`, `Forwarder`, `ForwarderUnreadable`; `Address(base)` |
| `ImportTable` | `Descriptors` (P10 fields, `Library`, `LibraryErr`, `Imports`), `Problems` |
| `Import` | `ByOrdinal`, `Ordinal`, `Hint`, `Name`, `NameErr`, `SlotRVA`; `SlotAddress(base)` |
| `CodeView` | `GUID` (16 bytes as stored), `Age`, `PDBPath` (bytes as stored), `RVA`; `PDBName()` |
| `ResourceData` | `Name`, `NameIsString`, `Language`, `RVA`, `Size`, `CodePage` |
| `FixedFileInfo` | The 13 V3 DWORDs; `FileVersion()`, `ProductVersion()` |

Exports are in slot order, then name-table order; descriptors and imports in table order; resource leaves in tree order. Names and paths are the image's bytes, not decoded (O2).

Sentinel errors: `ErrNotPE`, `ErrNoNTSignature`, `ErrUnsupportedOptionalMagic`, `ErrShortOptionalHeader` (new), `ErrImageTooLarge`, `ErrSectionOutOfRange` (kept, no longer returned, O6), `ErrBadAlignment` (S18), `ErrNoDataDirectory`, `ErrOutsideImage`, `ErrUnreadable`, `ErrUnterminatedString`, `ErrNoExportDirectory`, `ErrExportCountTooLarge`, `ErrNoImportDirectory`, `ErrReservedThunkBits`, `ErrImportLimit`, `ErrNoDebugDirectory`, `ErrNoCodeView`, `ErrBadDebugDirectory`, `ErrNoResourceDirectory`, `ErrNoResource`, `ErrResourceLimit`, `ErrBadVersionInfo`, `ErrNoFixedFileInfo`, `ErrBadFixedFileInfoSignature`.

## 8. Limits

- `MaxTableEntries`: export slots and names each; import descriptors and lookup entries together; resource entries over the whole tree. M2 gives the largest counts met.
- `MaxNameBytes`: every string (export, forwarder, library, hint/name, PDB path).
- `MaxBufferBytes`: one export array.
- `ReadCodeView` has no `Limits` parameter and uses `limits.Default().MaxNameBytes` (O5).

## 9. Acceptance

1. Synthetic fixtures (`pe/*_test.go`):
   - Headers: PE32 and PE32+ decode to the values `debug/pe` reads from the same bytes; a buffer grown to each `TruncatedError.Need` reaches the full headers; each failure sentinel; an 8-byte section name; directory entries refused past `NumberOfRvaAndSizes` and past `SizeOfOptionalHeader`, and `ReadDataDirectory` agreeing with `DataDirectory`.
   - Reader: reads past `SizeOfImage`, negative, short and failed reads; strings that end before an unread page, cross a page boundary, end at the image end, meet the limit exactly or pass it.
   - Exports: biased ordinals in slot order, an empty slot left out, a slot with two names, a named slot with RVA 0, a forwarder; names and forwarders on an unread page flagged, not dropped; a name whose slot is past the table dropped; every limit, an ordinal past 32 bits, an unread directory and an array past the image; `LookupExport` exact and skipping forwarders.
   - Imports: PE32 and PE32+ by name and by ordinal, slot RVAs, a bound stamp, ordinal 0x8001; reserved bits in both widths ending the walk; an address table of resolved addresses refused, one still holding names read; unread names, library names and descriptors; the `Size` bound and a `Size` below one descriptor; the shared budget.
   - CodeView: the first RSDS in directory order after an NB10 entry; unread record and unread directory reported as unread; each failure of 4.6.
   - Resources and version: leaves in tree order with a named Name entry; absent type, no directory, limit; an unread subtree passed over and, alone, its error returned; `Value` at the padding the load address gives; each failure of 4.8; `ReadVersion` succeeding with every byte after `Value` unread.
   - Ordinal table: case folding, one table per width, an ordinal the builds name apart absent, a library outside the table absent, and every generated entry nonempty.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzParseHeaders` (8.26 million executions; a short buffer's `Need` passes its length, a parse has its section table inside the buffer and both directory readers agree), `FuzzParseExports` (43,171; no NUL in a name, a record is a forwarder exactly when its RVA is inside the directory, every ordinal inside `Ordinal Base + entries`), `FuzzParseImports` (2.72 million; descriptors within `Size` and the budget, slot RVAs in step, an ordinal import has no name), `FuzzReadCodeView` (3.63 million; a record starts "RSDS" at its RVA and has a nonempty path without NUL), `FuzzReadVersion` (150,583; a parse without leaves is an error, a version has the signature), `FuzzParseVersionInfo` (6.86 million; `Value` 32-bit aligned to the given address and inside the buffer). The first runs found a wrong invariant in the test (an export name may be empty) and an import walk whose cost grew with descriptors times entries, which led to the single budget of 4.5 step 7; no failure since.
3. On the captures (`peparsefacts`, 2026-11-12), M1 to M6 above, by capture:

| Capture | Images | Exports parsed / arrays unread | Imports parsed / first descriptor unread | Import problems | CodeView read / unread | Version read / unread |
|---|---|---|---|---|---|---|
| mem1 kernel | 195 | 64 / 0 | 182 / 11 | 0 | 195 / 0 | 10 / 182 |
| mem1 process | 4,341 | 4,180 / 90 | 4,231 / 27 | 460 | 2,425 / 1,915 | 3,744 / 566 |
| mem2 kernel | 192 | 7 / 60 | 185 / 6 | 0 | 192 / 0 | 10 / 179 |
| mem2 process | 4,809 | 4,081 / 538 | 3,948 / 564 | 9,439 | 2,182 / 2,624 | 3,113 / 1,630 |
| mem5 kernel | 142 | 49 / 1 | 140 / 2 | 4 | 141 / 0 | 7 / 132 |
| mem5 process | 3,472 | 3,285 / 109 | 3,321 / 3 | 0 | 1,799 / 1,672 | 2,798 / 659 |
| mem6 kernel | 154 | 10 / 51 | 150 / 2 | 11 | 154 / 0 | 8 / 143 |
| mem6 process | 2,128 | 1,887 / 177 | 1,802 / 257 | 8,290 | 882 / 1,246 | 1,032 / 1,090 |
| mem7 kernel | 158 | 10 / 49 | 152 / 4 | 0 | 158 / 0 | 8 / 147 |
| mem7 process | 720 | 575 / 111 | 545 / 138 | 4,347 | 255 / 464 | 303 / 417 |

Most kernel images export nothing, and the resource pages of most drivers did not read. Import problems are almost all pages that did not read.

4. The packages that use `pe` pass their tests unchanged, among them `extract`, `tools/windows/peimports` (whose fixture names ws2_32.dll ordinal 2 from the table), `pesymbols`, `peversion`, `pedump` and `credentialkerberoshook`.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | No Microsoft Learn page documents the CodeView "RSDS" record: the PE specification names type 2 only. The LLVM PDB documentation gives the PDB Stream's 32-bit `Age` and 128-bit GUID, which the record's 20 bytes after "RSDS" match in size; the layout used here is the one measured in M5. | A Microsoft source for the record |
| O2 | Export, import and library names are documented as ASCII and section names as UTF-8; PDB paths have no documented encoding. All are kept as the image's bytes. | Owner decision |
| O3 | P11 says bits 30-15 (62-15) of an ordinal entry must be zero, while it also puts the ordinal in bits 15-0. Bit 15 is taken as part of the ordinal and bits 30-16 (62-16) as reserved; in M4 no ordinal import sets bit 15, so the captures do not tell the readings apart. | A corrected specification |
| O4 | Owner decision: which ordinals the table keeps. Default: names that every build naming the ordinal agrees on, from at least two distinct builds (M7). The alternatives are any one build (more names, unchecked across builds), or only the ordinals the captures import. Libraries whose builds renumber their named exports (M7) lose most of their entries under the default. Owner decision 2026-11-12 (follow-up M6): keep the S72 bounds. Done: no change. | Owner decision |
| O5 | `ReadCodeView` takes no `Limits`; the path cap is the default `MaxNameBytes`. Adding a `Limits` parameter changes its signature, used by 14 callers (6 in the library, 8 in the measurement programs). | Owner decision |
| O6 | `ErrImageTooLarge` and `ErrSectionOutOfRange` are no longer returned by any function; they are kept so callers that test for them still compile. | Owner decision on removal |
| O7 | `HasOrdinalTable` now covers the libraries of M7 rather than a fixed three. It tells a caller whether a nameless ordinal import of a library can be named; no libvapour tool calls it. | Owner decision |
| O8 | Names for API-set libraries (`api-ms-win-…`) imported by ordinal cannot come from an export directory: no image of that name is mapped. They are not in the table. | Owner decision |
| O9 | No 32-bit image other than WoW64 user modules was measured. | A 32-bit capture (Q7) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep measured layout |
| O2 | Keep as bytes |
| O3 | Bit 15 is ordinal |
| O4 | Names agreed by at least two builds |
| O5 | Keep default cap |
| O6 | Keep |
| O7 | Cover M7 libraries |
| O8 | Left out |
| O9 | Provide a capture |

## 11. Provenance

Written from Microsoft Learn's PE Format specification, the Microsoft Learn version-resource and resource-type pages, the Intel SDM, the LLVM PDB documentation for the GUID and age fields, and the project's measurements. The ordinal table is generated from the captures by `ordinalfacts`. Every rule rests on the sources and measurements above.
