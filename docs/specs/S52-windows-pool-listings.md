# S52: Windows big-page allocations and the pool scan

Version 1, 2026-11-12.

## 1. Purpose

Pool allocations of a page or more carry no pool header, so a tag sweep of physical memory cannot find them. The kernel records each of them in a table of its own: the virtual address, the tag, the size and the kind of pool. Registry hives, large object tables and many driver buffers live there. An examiner wants that table as rows: every allocation still in use, and on request the slots whose allocation was freed but whose tag and size are still recorded.

The second tool sweeps physical memory for the tags of eight kinds of kernel allocation (processes, threads, files, mutants, drivers, symbolic links, atom tables and loaded-module entries) and reports each allocation the S31 scan accepts and the kind's body check confirms, with its kernel address and a name where the object carries one.

This specification defines both tools: `windows.pool.list_big` (package `poolbig`) and `windows.pool.scan` (package `poolscan`). The scan substrate (tag sweep, pool and object header checks, TypeIndex, copies, placement, object names) is S31's `scan` package and is not restated here.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | Virtual reads of the table, its globals, and name buffers. |
| Physical memory | The scan's address space (`physical_memory`). Required by `windows.pool.scan`. |
| Kernel frames | `layers.FrameMap` from `kernel_dtb` and `paging_mode`. Optional; without it the scan places no row at a kernel address and does not test TypeIndex (S31 4.5 step 3). |
| Symbol table | The types and globals of section 3, the S17 process and thread check members, S31's types. |
| Options | `windows.pool.list_big.tags` (a list of tags, or one string of comma-separated tags), `windows.pool.list_big.show_free` (bool), the retired `windows.pool.list_big.tag` (refused), `strict`. `windows.pool.scan` has none of its own. |
| Limits | `MaxTableEntries` (slots in the table), `MaxNameBytes` (name characters read), `Workers` (sweep goroutines). |

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | The tag is "a non-zero character literal of one to four characters"; each character must lie between 0x20 (space) and 0x7E (tilde). The value is stored in reverse (little-endian) order, so the first character is the lowest byte. A tag of 0 is invalid. | Microsoft Learn, "ExAllocatePool2 function (wdm.h)", dated 2020-05-12; "ExAllocatePoolWithTag function (wdm.h)", dated 2022-12-12; both accessed 2026-11-12. |
| D2 | A request of `PAGE_SIZE` or more gets a page-aligned buffer. A request below `PAGE_SIZE` lies within one page. When a request above `PAGE_SIZE` is not a multiple of it, the last page holds bytes that are not the caller's. | As D1. |
| D3 | `POOL_FLAGS` is a ULONG64. The low 32 bits are required flags. Defined values: `POOL_FLAG_USE_QUOTA` 0x1, `_UNINITIALIZED` 0x2, `_SESSION` 0x4, `_CACHE_ALIGNED` 0x8, `_RESERVED1` 0x10, `_RAISE_ON_FAILURE` 0x20, `_NON_PAGED` 0x40 (nonpaged, no-execute), `_NON_PAGED_EXECUTE` 0x80, `_PAGED` 0x100, `_RESERVED2` 0x200, `_RESERVED3` 0x400; `_SPECIAL_POOL` 0x100000000 is optional. `ExAllocatePool2` takes `POOL_FLAGS` and replaces `ExAllocatePoolWithTag`, which takes a `POOL_TYPE`. | Microsoft Learn, "POOL_FLAGS", dated 2020-06-16; "ExAllocatePool2 function (wdm.h)"; accessed 2026-11-12. |
| D4 | `POOL_TYPE` declares, in this order, `NonPagedPool`, `NonPagedPoolExecute` = `NonPagedPool`, `PagedPool`, `NonPagedPoolMustSucceed` = `NonPagedPool` + 2, `DontUseThisType`, `NonPagedPoolCacheAligned` = `NonPagedPool` + 4, `PagedPoolCacheAligned`, `NonPagedPoolCacheAlignedMustS` = `NonPagedPool` + 6, `MaxPoolType`, then `NonPagedPoolBase` = 0 and the `Base` forms of 2, 4 and 6, the session values 32 to 38, `NonPagedPoolNx` 512, `NonPagedPoolNxCacheAligned` 516, `NonPagedPoolSessionNx` 544. `NonPagedPoolExecute` is "an alternate name" for `NonPagedPool`; the `Base` names are "reserved for system use". | Microsoft Learn, "_POOL_TYPE (wdm.h)", dated 2018-04-30, accessed 2026-11-12. |
| D5 | Each component of an object's name begins with a backslash; objects are named relative to a parent. | Microsoft Learn, "Object Names", accessed 2026-11-12. |

### Kernel types

Read with `bigpoolfacts -types` on 2026-11-12 through the project's kernel tables: build 26100 (mem1, GUID 0D960CE103763A6097E839406D8B369F; mem6 and mem7, 953A8DE880B0818C32DA2DEC1D79C2D9), 19045 (mem2, F57E740B088E5056E8AF0772F1CC5BEB) and 14393 (mem5, 3DFC5F7228304C26859E55E481700385).

| # | Fact |
|---|---|
| T1 | 14393 and 19045: `_POOL_TRACKER_BIG_PAGES` is 24 bytes: `Va` (unsigned long long) 0, `Key` (unsigned int) 8, the bit fields `Pattern` 0:8, `PoolType` 8:12 and `SlushSize` 20:12 of the unsigned int at 0xc, `NumberOfBytes` (unsigned long long) 0x10. |
| T2 | 26100: 32 bytes. As T1, but bits 8:12 of the word at 0xc are `PoolFlags`, not `PoolType`, and `ProcessBilled` (`_EPROCESS *`) is at 0x18. |
| T3 | Every table has the globals `PoolBigPageTable` and `PoolBigPageTableSize` and none of `PoolBigPageTableHash`, `ExpPoolBigPageTable` or `ExpPoolBigPageTableSize`. The tables give the globals no type. |
| T4 | `_POOL_TYPE` in every table holds the D4 names and values; `NonPagedPool`, `NonPagedPoolBase` and `NonPagedPoolExecute` share 0, and each of 2, 4 and 6 has a plain and a `Base` name. |
| T5 | `_KLDR_DATA_TABLE_ENTRY.BaseDllName` and `_FILE_OBJECT.FileName` are `_UNICODE_STRING`s; `_CMHIVE.HiveList` is a `_LIST_ENTRY` on `CmpHiveListHead`. |

### Measurements

M1 to M9 come from `bigpoolfacts` on 2026-11-12 over mem1_win11, mem2_win10, mem5_server2016, mem6_server2025 and mem7_server2025. The ground truth for "in use" is the hive list: every `_CMHIVE` on `CmpHiveListHead` (24, 29, 19, 29, 24), walked with the S03 walker.

| # | Measured | mem1 | mem2 | mem5 | mem6 | mem7 |
|---|---|---|---|---|---|---|
| M1 | Table address, page offset | 0xffff9e03fc930000, 0 | 0xffff8b8887f20000, 0 | 0xffffab03a9603000, 0 | 0xffffe40b87090000, 0 | 0xffff810129090000, 0 |
| M1 | Slots (`PoolBigPageTableSize`; the upper dword of the 8 bytes there is 0) | 65,536 | 32,768 | 65,536 | 32,768 | 32,768 |
| M1 | Table bytes, all readable | 2 MiB | 768 KiB | 1.5 MiB | 1 MiB | 1 MiB |
| M2 | Slots with `Va` bit 0 clear | 8,073 | 8,312 | 23,452 | 6,699 | 6,793 |
| M2 | Slots with `Va` bit 0 set and a nonzero `Key` | 24,412 | 4,259 | 494 | 838 | 4,475 |
| M2 | Slots with `Key` 0 (every one has `Va` exactly 1) | 33,051 | 20,197 | 41,590 | 25,231 | 21,500 |
| M3 | Hives at the address of a bit-0-clear slot tagged `CM10` | 24 of 24 | 29 of 29 | 19 of 19 | 29 of 29 | 24 of 24 |
| M4 | Bit-0-clear addresses that do not translate | 306 | 3,109 | 344 | 3,051 | 3,856 |
| M4 | Bit-0-set slots whose address does not translate (the `Key` 0 slots, address 0, included) | 52,016 of 57,463 | 21,757 of 24,456 | 41,747 of 42,084 | 25,847 of 26,069 | 22,388 of 25,975 |
| M5 | `NumberOfBytes` of in-use slots | 4,096 to 2,101,248 | 4,096 to 3,145,728 | 4,096 to 3,145,728 | 4,096 to 3,145,728 | 4,096 to 3,145,728 |
| M5 | Of those, multiples of 4,096 | 6,455 | 7,015 | 22,453 | 5,467 | 5,681 |
| M6 | In-use translated allocations whose bytes 4 to 7 equal the tag (a pool header in front) | 1 of 7,767 | 0 of 5,203 | 11 of 23,108 | 0 of 3,648 | 0 of 2,937 |
| M7 | Distinct in-use tags | 241 | 225 | 186 | 211 | 212 |
| M7 | Most frequent in-use tags | `CM25` 2,568, `CM16` 746, `EtwB` 658, `MmSt` 572 | `CM25` 2,574, `MmSt` 778, `CM16` 547, `smWw` 512 | `CM31` 17,382, `CM25` 2,916, `MmSt` 900, `CMAl` 453 | `CM25` 3,454, `Gpbm` 560, `CM16` 473, `Obtb` 301 | `CM16` 3,971, `Gpbm` 391, `Obtb` 318, `MmSt` 272 |
| M7 | Most frequent freed tags | `CIcr` 17,510, `smWw` 1,209, `CM53` 592 | `smWw` 920, `fpRD` 545, `Mdl ` 264 | `MmSt` 201, `MmRe` 52, `NpFR` 46 | `MmSt` 293, `Gpbm` 158, `CM53` 92 | `CM53` 931, `WofD` 749, `MmSt` 542 |
| M8 | Nonzero keys with a byte outside 0x20 to 0x7e | 1 (`EP` and two zero bytes) | 1 (`HVD`, one zero byte) | 0 | 1 (`HVD`) | 1 (`HVD`) |
| M8 | Keys with bit 31 set; addresses not page aligned; duplicate in-use addresses | 0; 0; 0 | 0; 0; 0 | 0; 0; 0 | 0; 0; 0 | 0; 0; 0 |
| M9 | In-use pool kinds (section 4.3), with untranslated addresses | paged 6,315 (303), nonpaged 1,756 (3), nonpaged execute 2 (0) | paged 5,545 (2,787), nonpaged 2,767 (322) | paged 22,505 (343), nonpaged 947 (1) | paged 6,132 (3,051), nonpaged 562 (0), nonpaged execute 5 (0) | paged 5,976 (3,856), nonpaged 812 (0), nonpaged execute 5 (0) |
| M9 | In-use `PoolFlags` (26100) with not exactly one of 0x40, 0x80, 0x100 | 0 | | | 0 | 0 |
| M9 | In-use `PoolType` values (19045, 14393) | | 5: 2,628; 512: 2,472; 1: 2,445; 1025: 417; 1536: 263; 17: 54; 516, 524, 528, 532, 0, 9 | 5: 20,339; 1: 2,151; 512: 931; 17: 15; 516, 528, 0, 532, 524 | | |
| M9 | Freed slots keep a nonzero `NumberOfBytes` | all | all | all | all | all |

## 4. Algorithm

### 4.1 Locating the table (`windows.pool.list_big`)

1. Resolve `_POOL_TRACKER_BIG_PAGES` and its `Va` and `Key` (T1, T2). `NumberOfBytes`, `PoolType` and `PoolFlags` are used when present. Every member must end within the entry; the entry size is the stride.
2. Read the pointer at `PoolBigPageTable` (T3). It must be nonzero and a multiple of 4,096 (M1, D2).
3. Read 4 bytes at `PoolBigPageTableSize` as the slot count (M1: the upper dword is 0). It must be at least 1 and at most `MaxTableEntries`.

### 4.2 Reading the slots

1. The table is read in spans of 1 MiB of whole entries. A span that does not read is read again page by page; an entry is decoded only when every byte of it was read. Each run of unreadable pages is one diagnostic, or the error in strict mode.
2. An entry with `Key` 0 has never held an allocation (M2, D1: a tag is never 0) and gives no row.
3. Otherwise `Va` bit 0 is the freed mark (M2, M3, M4): the address is `Va` with bit 0 cleared, and `Freed` is the bit. Every measured in-use address is page aligned (M8, D2).
4. The tag is the four `Key` bytes from the lowest (D1). Trailing zero bytes are dropped, since a tag of fewer than four characters is stored with zeros after it (M8). Any other byte outside 0x20 to 0x7e is shown as `\xNN`. Spaces stay.
5. `Size` is `NumberOfBytes`: the requested size, not rounded to pages (M5, D2).

### 4.3 Pool kind

1. With `PoolType` (T1): the value's name from `_POOL_TYPE` when one matches exactly, choosing among shared values the shortest name (on T4's duplicates that is the one D4 declares first); otherwise the decimal value. `Pool` is `paged` for an odd value and `nonpaged` for an even one, the parity rule of S31 T5 applied to every value, modifiers included (M9: paged allocations account for nearly all the untranslated in-use addresses).
2. With `PoolFlags` (T2): the D3 names of the set bits joined by `|`, in bit order, with any unnamed bits as one hexadecimal remainder; 0 is `0x0`. `Pool` is `paged` for 0x100, `nonpaged` for 0x40 and `nonpaged_execute` for 0x80 when exactly one of the three is set (M9), and empty otherwise.
3. With neither member, both are empty.

### 4.4 Rows, filters and order

1. `ReadTable` returns every slot that holds or held an allocation, in slot order, unfiltered.
2. The tool hides freed slots unless `show_free` is set (owner decision on big pools: freed hidden by default).
3. With `tags`, a row is kept when its tag equals an item, or equals it once trailing spaces are dropped (the option trims each item, so `Mdl ` is given as `Mdl`). Tags compare case-sensitively: `fpRD` and `fprd` are distinct freed tags on mem2 (M7). An item longer than 4 bytes or with a byte outside 0x20 to 0x7e gets a diagnostic: it can match nothing.
4. Rows are sorted by address, then in-use before freed, then slot.

### 4.5 The pool scan (`windows.pool.scan`)

1. Refuse a non-Windows profile, a session without physical memory, and builds before Windows 8 (`RequirePoolScanBuild`, S31 O3).
2. Map the kernel frames once. Without them the scan runs unplaced, with a diagnostic.
3. Sweep physical memory once for all eight tags (S31 4.1).
4. Executive objects, with the S31 filters and the object layout resolved once:

| Kind | Filter | Body type tag (S31 4.5 step 5) | Body check | Name | Keeps a TypeIndex mismatch |
|---|---|---|---|---|---|
| Process | `Proc`, `_EPROCESS` | `Pcb.Header.Type` = 3 | S17 process check | `ImageFileName` | yes |
| Thread | `Thre`, `_ETHREAD` | `Tcb.Header.Type` = 6 | S17 thread check | none | yes |
| File | `File`, `_FILE_OBJECT` | `Type` = 5 | none | `FileName` | no |
| Mutant | `Muta`, `_KMUTANT` | `Header.Type` = 2 | none | object name (S31 4.10) | no |
| Driver | `Driv`, `_DRIVER_OBJECT` | `Type` = 4 | none | object name | no |
| Symbolic link | `Symb`, `_OBJECT_SYMBOLIC_LINK` | none | none | object name | no |

   A mismatch is kept only where the body check is structural (S17) and the body type tag resolved, since a freed object loses its TypeIndex first (S31 M2). A kind whose S17 check lacks its required members is not scanned, with a diagnostic.
5. Structures (no object header, S31 4.3): `AtmT` (`_RTL_ATOM_TABLE`, no name) and `MmLd` (the module entry type of S31 4.11, named by `BaseDllName`). A hit whose allocation would cross its page is refused (D2) and counted.
6. Hives (`CM10`) are not scanned: a `_CMHIVE` is larger than a pool header can size (S31 M10) and every measured hive is in the big-page table (M3).
7. Names: a counted string's descriptor is read from the body in physical memory and its characters from kernel memory, at most `MaxNameBytes`; trailing NULs are dropped and an embedded NUL is shown (`util.DecodeCountedUTF16LE`, which applies `util.CountedText`). Object names follow S31 4.10.
8. Each row gets its pool header's physical address, its kernel address (0 when the kernel maps no address of it), the physical pool address of the first other mapped copy (S31 4.7), the number of kernel mappings of its frame when frames are known, and `TypeIndexFailed`.
9. All rows are ordered by S31 4.9: placed rows by kernel address, then the rest by physical address.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Entry type has `Va` and `Key`, members within the entry | T1, T2 | `ErrNoTable` |
| `PoolBigPageTable` and `PoolBigPageTableSize` present | T3 | `ErrNoTable` |
| Table pointer nonzero and page aligned | M1, D2 | `ErrTableAddress` |
| 1 ≤ slots ≤ `MaxTableEntries` | M1 | `ErrTableSize` |
| `Key` nonzero | D1, M2 | slot counted as never used |
| `Va` bit 0 is the freed mark | M2, M3, M4 | not a rule: a reading |
| Process body passes S17 | S17 | refused (`BodyRejected`) |
| Thread body passes S17 | S17 | refused |
| Structure allocation within its page | D2 | refused, counted |

## 6. Failure modes

| Case | Result |
|---|---|
| No kernel reader, symbols or profile | `tools.ErrMissing…` |
| Profile not Windows | `<tool>: unsupported profile os "<os>"` |
| Retired option `windows.pool.list_big.tag` set | `ErrTagOptionRenamed` |
| `tags` not a string or string list, `show_free` not a bool or one of the words true, 1, yes, on, false, 0, no, off | `tools.ErrOptionType` |
| Table type or globals missing | `windows.pool.list_big: poolbig: symbol table has no big-page table: …` |
| Table pointer unreadable | `windows.pool.list_big: PoolBigPageTable at 0x<addr>: not readable: %w` |
| Table pointer null or off a page | `windows.pool.list_big: PoolBigPageTable at 0x<addr>: holds 0x<v>: poolbig: big-page table address not usable` |
| Slot count unreadable | `windows.pool.list_big: PoolBigPageTableSize at 0x<addr>: not readable: %w` |
| Slot count 0 or above the limit | `windows.pool.list_big: PoolBigPageTableSize at 0x<addr>: <n> slots, limit <max>: poolbig: big-page table size not usable` (`ErrTableSize`) |
| Table page unreadable | diagnostic `windows.pool.list_big: table entries at 0x<addr> (<n> bytes): not readable: %w`; the error in strict mode |
| `_POOL_TYPE` not in the table | diagnostic; `PoolType` shown as numbers |
| Scan without physical memory | `windows.pool.scan: no physical memory in the session` |
| Tag sweep fails | `windows.pool.scan: tag sweep: %w` |
| Object or pool header layout not resolved, or a kind's sweep fails | `windows.pool.scan: …: %w`; the tool fails |
| Build before Windows 8 | `tools.ErrPoolScanUnsupportedBuild` |
| No kernel frames | diagnostic; rows unplaced, TypeIndex untested |
| Type table unreadable | diagnostic per kind; judged on the body type tag |
| Kind's body type absent from the table | diagnostic; kind not scanned |

Messages: `poolbig: symbol table has no big-page table`, `poolbig: big-page table address not usable`, `poolbig: big-page table size not usable`, `poolbig: option "windows.pool.list_big.tag" is now "windows.pool.list_big.tags", a list of tags`.

## 7. Result schema

`poolbig.Allocation`:

| Field | Type | Meaning |
|---|---|---|
| `Address` | uint64 | Virtual address of the allocation (`Va` with bit 0 cleared). |
| `Tag` | string | 4.2 step 4. |
| `Size` | uint64 | `NumberOfBytes`, bytes; 0 when the table lacks it. |
| `Freed` | bool | `Va` bit 0. |
| `Pool` | `Pool` | `paged`, `nonpaged`, `nonpaged_execute`, or empty (4.3). |
| `PoolType` | string | 4.3 step 1; empty on tables with `PoolFlags`. |
| `PoolFlags` | string | 4.3 step 2; empty on tables with `PoolType`. |
| `Slot` | uint64 | Index in the table. |

Order: 4.4 step 4. Diagnostic per run: table address, slots, in use, freed, never used, not readable.

`poolscan.Allocation`:

| Field | Type | Meaning |
|---|---|---|
| `Type` | string | The body type: `_EPROCESS`, `_ETHREAD`, `_FILE_OBJECT`, `_KMUTANT`, `_DRIVER_OBJECT`, `_OBJECT_SYMBOLIC_LINK`, `_RTL_ATOM_TABLE`, or the module entry type. |
| `Tag` | string | The filter's tag. |
| `Physical` | uint64 | Physical address of the pool header. |
| `Address` | uint64 | Kernel virtual address of the pool header; 0 when unplaced. |
| `OtherCopyPhysical` | uint64 | Pool header of the first other mapped byte-identical copy; 0 when none. |
| `Name` | string | 4.5 step 4 and 5; empty when absent or unreadable. |
| `Mappings` | uint64 | Kernel mappings of the pool header's frame. |
| `MappingsKnown` | bool | Kernel frames were mapped. |
| `TypeIndexFailed` | bool | Kept with a TypeIndex that did not decode (4.5 step 4). |

Order: 4.5 step 9. Diagnostics: S31 `Describe` per object kind, accepted and refused counts per structure, and rows per type.

## 8. Limits

- `MaxTableEntries` (default 4,194,304) caps the slot count: the count is read from the image and is the walk's only bound. The measured tables hold 32,768 or 65,536.
- `MaxNameBytes` caps each name's characters.
- `Workers` sets the sweep's goroutines (S31 8).
- The big-page table is read in 1 MiB spans; a span costs one buffer of that size.

## 9. Acceptance

1. Synthetic fixtures, `tools/windows/poolbig/s52_fixture_test.go` with the T1 and T2 layouts: in-use, freed and never-used slots; `PoolType` names and kinds (shared values, modifiers, decimal fallback); `PoolFlags` names, remainders and kinds; tag text; the tag filter with trailing spaces and case; option errors; each table location rule; an unreadable table page losing only the entries that touch it, and strict mode; `ReadTable` in slot order; in-use before freed at one address.
2. `tools/windows/poolscan/s52_fixture_test.go` with S31's 26100 header layouts: one allocation of every kind with its name; an S17 failure, a wrong file `Type` and a paged-type filter mismatch refused; physical order without frames; kinds skipped without their check members; refusals; counted strings with an embedded NUL and a null buffer.
3. Fuzz targets, 30 s each on 2026-11-12: `FuzzTableRead` (any table bytes: at most one row per slot, `Key` nonzero, `Freed` and `Address` as `Va` gives them) 1.33 million executions; `FuzzCountedString` (any descriptor and characters: no panic, at most `MaxNameBytes` / 2 characters) 2.48 million executions.
4. On the captures, `bigpoolfacts -tool -scan`, 2026-11-12:

| | mem1 | mem2 | mem5 | mem6 | mem7 |
|---|---|---|---|---|---|
| `windows.pool.list_big` rows | 8,073 | 8,312 | 23,452 | 6,699 | 6,793 |
| with `show_free` | 32,485 | 12,571 | 23,946 | 7,537 | 11,268 |
| time | 30 ms | 18 ms | 33 ms | 8 ms | 12 ms |
| `windows.pool.scan` rows | 20,398 | 11,704 | 6,484 | 6,603 | 8,504 |
| `_EPROCESS` (kept with TypeIndex failed) | 88 (6) | 163 (10) | 71 (0) | 100 (0) | 104 (0) |
| `_ETHREAD` (kept) | 2,216 (1,074) | 2,294 (290) | 1,326 (9) | 1,345 (48) | 1,441 (10) |
| `_FILE_OBJECT` (named) | 16,850 (15,622) | 7,853 (5,570) | 4,250 (3,672) | 4,210 (3,622) | 5,922 (4,715) |
| `_KMUTANT` (named) | 632 (177) | 702 (330) | 362 (102) | 441 (211) | 489 (243) |
| `_DRIVER_OBJECT` (named) | 162 (161) | 157 (157) | 109 (109) | 124 (124) | 132 (131) |
| `_OBJECT_SYMBOLIC_LINK` (named) | 235 (231) | 324 (311) | 205 (188) | 213 (210) | 239 (230) |
| `_KLDR_DATA_TABLE_ENTRY` (named) | 206 (205) | 195 (195) | 142 (142) | 158 (158) | 166 (166) |
| `_RTL_ATOM_TABLE` | 9 | 16 | 19 | 12 | 11 |
| rows with a kernel address | 13,696 | 10,196 | 6,434 | 6,601 | 8,493 |
| time | 23.7 s | 11.0 s | 5.1 s | 2.1 s | 6.0 s |

   - Every process on `PsActiveProcessHead` that has a pool header is among the process rows (S31 9.3: 82, 153, 71, 100); the further rows are kept with a failed TypeIndex or are unlisted.
   - Every hive on `CmpHiveListHead` is a `CM10` row of `windows.pool.list_big` (M3).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | `Va` bit 0 as the freed mark, `Key` 0 as never used, and the 4-byte slot count rest on measurement (M1 to M4); no public document describes `_POOL_TRACKER_BIG_PAGES`. | Owner decision on measured rules |
| O2 | `PoolFlags` (T2) is read as the low 12 bits of `POOL_FLAGS` (D3) on the PDB member name and M9 alone. | Owner decision |
| O3 | The parity rule for `PoolType` values outside the enumeration (1025, 1536, 17, 9, 524 and others) extends S31 T5; the modifier bits have no public values. | Owner decision; a documented source for the modifiers |
| O4 | Row schema renamed (Q2): `BigPool` → `Allocation` with `Va` → `Address`, `Bytes` → `Size`, `Free` → `Freed`, new `Pool`, `PoolFlags`, `Slot`; `BytesUnreadable` and `PoolTypeUnreadable` removed (an entry decodes whole or not at all). Pool scan: `PoolTag` → `Tag`, `Offset` → `Physical`, `VirtualOffset` → `Address`, `OtherCopy` → `OtherCopyPhysical`; `Layer`, `HasName` and the `Layer` constant removed. `ListBigPools` → `ReadTable`, now in slot order. | Owner review (Q2) |
| O5 | The pool scan no longer sweeps `CM10` (4.5 step 6) and no longer requires a readable file name: file objects without one are rows with an empty `Name`. | Owner decision |
| O6 | Tags keep their spaces (`Mdl `) and show bytes outside 0x20 to 0x7e escaped; the trailing-space filter match follows from the option's trimming. | Owner decision |
| O7 | `ProcessBilled` (T2) is not reported. | Owner decision: add a billed-process column |
| O8 | The `Pool` kind on `PoolType` builds never says `nonpaged_execute`: D4 calls `NonPagedPool` executable but gives no rule for the other even values. | A documented source |
| O9 | x86 tables are covered only by the table-driven layouts; no 32-bit capture was measured. | A 32-bit capture (Q7) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept measured rules |
| O2 | Accept |
| O3 | Accept S31 T5 extension |
| O4 | Accept renames |
| O5 | Skip CM10, keep nameless files |
| O6 | Keep spaces, escape bytes |
| O7 | Do not report it |
| O8 | Leave as is |
| O9 | Defer to v0.2.0 |

## 11. Provenance

Written from Microsoft Learn's WDK documentation, the ntoskrnl types, enumerations and globals in the project's symbol tables, and the project's measurements with `bigpoolfacts`. Every rule rests on the sources and measurements above. Author: the S52 agent of the spec-first rewrite, 2026-11-12; reviewer: the owner.
