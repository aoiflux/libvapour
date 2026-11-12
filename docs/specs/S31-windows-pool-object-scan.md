# S31: Windows pool and object scanning

Version 1, 2026-11-12.

## 1. Purpose

A process, thread, file, mutant, driver or symbolic link that the kernel's lists no longer hold can still sit in kernel pool: freed, unlinked or hidden. The kernel tags every small pool allocation with four characters, and every executive object begins with an `_OBJECT_HEADER` that says how long its optional headers are and which type it has. An examiner wants every allocation in physical memory that carries a given tag and holds what the tag promises, with the kernel address it has (if any), whether a second physical copy of it exists, and why each other hit was refused.

This specification defines the tag sweep, the checks on a pool header, the placement of an object header behind it, the type tests, the handling of byte-identical copies, the placement of a hit at a kernel address, and the object-name reader the scans and other tools share. It is the `scan` package. The tools that call it (process, thread, file, mutant, driver, symbolic link and module scans, the pool scan with its atom table kind, the network scan, and the window-station and desktop scans) decide what a body must hold; this package decides where a body is and whether its headers allow it.

## 2. Inputs

| Input | Meaning |
|---|---|
| Physical memory | The scanned address space. Every scan reads it; a caller may pass another reader. |
| Kernel memory | The globals `ObTypeIndexTable`, `ObHeaderCookie` and `ObpInfoMaskToOffset`, the `_OBJECT_TYPE` objects, and name buffers. |
| Symbol table | The kernel types of section 3. |
| Residency | The kernel page tables' map from frames to the virtual addresses that map them (`layers.FrameMap`): `Contains`, `SecondAddressBytes`, `LowestAddresses`. Optional. |
| Filter | `PoolFilter`: tag, body type, page types, size and pool-index bounds, object type, and whether to skip the TypeIndex test. |
| Limits | `Workers` (sweep goroutines). The tools add `MaxPathSteps` and others for what they read. |

No option key belongs to this package.

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | The pool tag is "a non-zero character literal of one to four characters", "stored, and sometimes displayed, in reverse (little-endian) order". "Memory allocations of `PAGE_SIZE` or less are allocated within a page and do not cross page boundaries. Memory allocations of less than `PAGE_SIZE` are not necessarily page-aligned but are aligned to 8-byte boundaries in 32-bit systems and to 16-byte boundaries in 64-bit systems." "If NumberOfBytes is `PAGE_SIZE` or greater, a page-aligned buffer is allocated." | Microsoft Learn, "ExAllocatePool2 function (wdm.h)", dated 2020-05-12, accessed 2026-11-12. |
| D2 | "When an object is created, the object manager sets the object's reference count to one. Once that counter falls to zero, the object is freed." "Each routine that opens a handle increases both the object reference count and the object handle count by one." | Microsoft Learn, "Life Cycle of an Object", dated 2017-06-16, accessed 2026-11-12. |
| D3 | `FILE_OBJECT.Type`: "If the object is a file object, the value of this member is 5." | Microsoft Learn, "FILE_OBJECT (wdm.h)", dated 2023-08-17, accessed 2026-11-12. |
| D4 | "Named objects are organized into a hierarchy. Each object is named relative to a parent object. Each component of the object's name begins with a backslash character." | Microsoft Learn, "Object Names", dated 2017-06-16, accessed 2026-11-12. |
| D5 | A 4 KB page is the smallest page of 4-level and 5-level paging; bits 11:0 of a linear address are the offset in it. | Intel SDM Vol. 3A, chapter 5, "Paging". |

### Kernel types

Read through the project's kernel tables for builds 26100 (mem1, GUID 0D960CE1…; mem6, 953A8DE8…), 19045 (mem2, F57E740B…) and 14393 (mem5, 3DFC5F72…) with `poolfacts -types`. Every fact holds on all four unless it says otherwise.

| # | Fact |
|---|---|
| T1 | `_POOL_HEADER` is 16 bytes: `PreviousSize` bits 0..7 and `PoolIndex` bits 8..15 of the `unsigned short` at 0; `BlockSize` bits 0..7 and `PoolType` bits 8..15 of the `unsigned short` at 2; `PoolTag` (`unsigned int`) at 4; `ProcessBilled` at 8. |
| T2 | `_OBJECT_HEADER` is 56 bytes: `PointerCount` (`long long`) 0, `HandleCount` (`long long`) 8, `TypeIndex` (`unsigned char`) 0x18, `InfoMask` (`unsigned char`) 0x1a, `Body` 0x30. No table has `NameInfoOffset`. |
| T3 | Optional header sizes: `_OBJECT_HEADER_CREATOR_INFO` 32, `_NAME_INFO` 32 (`Directory` 0, `Name` 8, a `_UNICODE_STRING`), `_HANDLE_INFO` 16, `_QUOTA_INFO` 32, `_PROCESS_INFO` 16, `_AUDIT_INFO` 16, `_EXTENDED_INFO` 16, `_PADDING_INFO` 4 (`PaddingAmount`, `unsigned int`, at 0). No table has `_OBJECT_HEADER_HANDLE_REVOCATION_INFO`. |
| T4 | `_OBJECT_TYPE`: `Name` (`_UNICODE_STRING`) 0x10, `Index` (`unsigned char`) 0x28, `Key` (`unsigned int`) 0xc0, `TypeInfo` (`_OBJECT_TYPE_INITIALIZER`) 0x40. The initializer has `PoolType` (int) 0x24 and the bit flags `MaintainHandleCount` and `MaintainTypeList`. |
| T5 | Enumerations: `_KOBJECTS` has `MutantObject` 2, `ProcessObject` 3, `ThreadObject` 6. `_POOL_TYPE` has `NonPagedPool` 0, `PagedPool` 1, `NonPagedPoolMustSucceed` 2, `PagedPoolCacheAligned` 5, `NonPagedPoolSession` 32, `PagedPoolSession` 33, `NonPagedPoolNx` 512, `NonPagedPoolNxCacheAligned` 516, `NonPagedPoolSessionNx` 544, and others: every paged member is odd, every nonpaged member even. |
| T6 | `_DISPATCHER_HEADER.Type` is an `unsigned char` at 0 of `_KPROCESS.Header`, `_KTHREAD.Header` and `_KMUTANT.Header`; `_EPROCESS.Pcb` and `_ETHREAD.Tcb` are at 0. `_FILE_OBJECT.Type` and `_DRIVER_OBJECT.Type` are `short` at 0. |
| T7 | Globals in every table: `ObHeaderCookie`, `ObTypeIndexTable`, `ObpInfoMaskToOffset`, `ObpRootDirectoryObject`, `PsLoadedModuleList`. |

### Measurements

M1 to M12 come from `poolfacts` on 2026-11-12 over mem1_win11, mem2_win10, mem5_server2016 and mem6_server2025, run with `-table` on each capture's own kernel table. The ground-truth objects are the processes on `PsActiveProcessHead`, the threads on each process's `ThreadListHead` (S03 walker), the `_OBJECT_TYPE` objects of `ObTypeIndexTable`, the root directory, the drivers in `\Driver` and the devices on their `DeviceObject` chains whose `DriverObject` points back: 7,679 objects (1,602, 2,618, 1,707, 1,752). The handle census walks every process's handle table: 170,047 handles (46,853, 57,560, 25,562, 40,072).

| # | Measured |
|---|---|
| M1 | `ObTypeIndexTable`: slot 0 is null, slot 1 holds a value that is not a type (no name, `Index` 0), and every named type (75, 67, 58, 71) has `Index` equal to its slot. `Key` is the type's pool tag: `Proc`, `Thre`, `File`, `Muta`, `Driv`, `Symb`, `Wind`, `Desk`, `Devi`, `Dire`, `Key `, `ObjT` among them. |
| M2 | TypeIndex: for 7,662 of the 7,679 ground-truth objects the stored byte XOR the low byte of `ObHeaderCookie` XOR bits 15:8 of the header's virtual address is the type's slot. No other combination (the byte alone, with the cookie only, with the address only) holds for more than 111. The 17 exceptions are threads (5, 4, 1, 7) whose `PointerCount` is 0 or below: threads being freed. |
| M3 | Every object header is 16-byte aligned (7,679 ground truth, 28,197 objects behind handles). |
| M4 | `ObpInfoMaskToOffset` single-bit entries are 32, 32, 16, 32, 16, 16, 16, 4 for bits 0 to 7, the sizes of T3 in that order, and every one of the 256 entries is the sum of its bits' entries. Bit 1 is the name info: for every root directory entry (50, 61, 50, 63) the name info at header − `ObpInfoMaskToOffset[InfoMask & 3]` has `Directory` equal to the root. Bit 0 is set on every type object (`MaintainTypeList`), bit 2 on every object of a `MaintainHandleCount` type (13,994 objects behind handles). |
| M5 | Distance from the end of the pool header to the object header: `ObpInfoMaskToOffset[InfoMask & 0x7f]`, plus `PaddingAmount` when bit 7 is set, read 4 bytes in front of the other optional headers. It holds for 35,803 of the 35,805 objects whose pool header was found; the 2 others are freed threads on mem5 (`PoolType` 0). `PaddingAmount` is 0, 0x10, 0x20 or 0x30, and every padded body is 64-byte aligned. Re-measured on mem5 on 2026-11-12 (`poolfacts`): 0x10 on 336 padded objects, 0x20 on 743, 0x30 on 64, and one freed thread with 0xffffab03; none holds 0 (O9). |
| M6 | A pool header carrying the type's `Key` is found in front of 35,805 of the 35,876 ground-truth and handle-reached objects. Missing: 54 devices (11, 27, 7, 9 ground truth), whose optional headers start at a page boundary, so big-pool allocations (D1); 1 process on mem1 and 1 on mem6; and 15 objects behind mem1 handles (3 files, 2 keys, 1 mutant, 3 symbolic links, 3 directories, 2 types, 1 device) whose headers no longer hold objects (M8). No found tag has bit 31 set. |
| M7 | Every found pool header's `BlockSize` × 16 bytes holds the object's body, no allocation crosses its page, `PreviousSize` is 0 everywhere, and `PoolIndex` holds values from 0 to 253 (on threads, devices and drivers). `PoolType` is 2 for every object of a nonpaged type (initializer 512) and 3 for every one of a paged type (initializer 1), except 2 freed threads with 0. |
| M8 | `PointerCount` is positive, `HandleCount` not negative and not above `PointerCount` for every ground-truth object except the 17 freed threads (`PointerCount` ≤ 0), and for every object behind a handle except 12 on mem1 whose header no longer holds an object. |
| M9 | `_DRIVER_OBJECT.Type` is 4 for all 348 ground-truth drivers. `_FILE_OBJECT.Type` is 5 for 14,075 of the 14,078 file objects behind handles (3 on mem1 hold other values). |
| M10 | Every `PsLoadedModuleList` entry (195, 195, 142, 158) is preceded by a pool header tagged `MmLd` with `PoolType` 2. Hives (`CM10`) are never preceded by one on a 16-byte boundary: `_CMHIVE` is 4,824 bytes or more, past what `BlockSize` can size. |
| M11 | Census of physical memory (an independent sweep): hits of the object tags at header + 4 on a 16-byte header are 5 % to 37 % of all hits (`Proc` 4,005 of 77,751 on mem1). `PoolType` on the aligned hits takes most values from 0 to 255. Byte-identical allocations (the whole `BlockSize` × 16 bytes) occur in every capture: on mem1 13,423 groups of `File` hold 25,078 further copies, of which 102 the kernel also maps; on mem6 71 groups hold 82. |
| M12 | The kernel maps few of the copies of M11 (0 % to 1.6 %), and of every group at most a few frames: copies are stale frames of one allocation, not distinct objects. Objects hold pointers into themselves (list heads), so two live objects never match byte for byte. |

## 4. Algorithm

### 4.1 Tag sweep

1. The reader's mapped ranges (`memory.MappedRanges`) are cut into 1 MiB chunks. Each chunk is read with the longest tag's length less one byte past its end, so a tag across an edge is found once, in the chunk where it starts.
2. A chunk that does not read is read again page by page; pages that do not read are skipped. This keeps a sparse image's holes from hiding the pages around them.
3. Every occurrence of every distinct tag is reported at the address of its first byte, at any alignment: the alignment rule belongs to the pool header check (4.2). Results are sorted by address, then tag.
4. `Workers` goroutines read chunks in parallel; the result does not depend on their number.

### 4.2 Pool header check

For a hit at address *t* and a filter whose tag it is, the header is at *t* − `PoolTag` offset (T1).

1. **Alignment.** The header must be a multiple of 16 bytes (8 on a 32-bit table) (D1, M3).
2. **Read.** The table decodes `BlockSize`, `PoolType` and `PoolIndex` (T1); a header that does not read is refused.
3. **Page type.** `PoolType` 0 is free, odd is paged, nonzero even is nonpaged (T5, M7). The filter's page types must include it; a filter naming none admits every one.
4. **Size.** `BlockSize` × 16 must be at least the minimum (4.4 step 1; for a structure, the pool header plus the body type's size), and at most `MaxSize` when the filter sets one.
5. **Pool index.** Within `MinIndex`..`MaxIndex` when `MaxIndex` is set. No built-in filter sets it: `PoolIndex` carries values with no measured meaning (M7).
6. **Page.** The allocation must end within its page (D1, M7); one that does not is page-crossing.

### 4.3 Structure scan

1. Each hit is offered to the filters with its tag, in the order given. The first whose checks pass and whose decoder accepts the body (the header's end) takes it: one allocation is one structure.
2. A hit no filter takes because it crosses its page is reported among `PageCrossingHits` with its header, for the caller to judge.
3. Copies (4.7), placement (4.8) and order (4.9) follow.

### 4.4 Object header placement

1. **Minimum.** The allocation must hold the pool header, the object header up to `Body`, and the body type's size (or `MinSize`, if larger).
2. **Positions.** Candidate object headers lie at the pool header's end plus *d*, for *d* = 0, 16, 32, … up to the reach: the longest optional header length plus 48, the largest padding below a 64-byte line (M4, M5). A position is tried only while the object header, `Body` offset and body fit in the allocation.
3. **Geometry.** At each position, read `InfoMask`. The optional length is `ObpInfoMaskToOffset[InfoMask & 0x7f]` from kernel memory when the identity carries the table, otherwise the sum of the T3 sizes for the set bits 0 to 6 (M4). With bit 7, `PaddingAmount` is read 4 bytes in front of that length; it counts the padding info's own 4 bytes (M4, M5), so it must be at least the padding info's size and below 64; it is added. The position fits only when the result equals *d* (M5). A table without `InfoMask` tries every position up to 240 and requires only that `NameInfoOffset`, when present, does not exceed *d* (O3).
4. **Counts.** `PointerCount` must not be negative; `HandleCount` must not be negative and not above `PointerCount` (D2, M8). A freed object, with both 0, passes.
5. **Type.** Then 4.5. Among the positions that pass everything, one whose TypeIndex decodes wins over one that could not be tested, which wins over a kept mismatch; among equals the nearest whose name reads (4.10: present, readable and not empty) wins, else the nearest. A nearer header can be bytes inside a farther object's optional headers that happen to pass (O10). Names are read only when the caller gives the scan a kernel reader (`ObjectLayout.PreferringNamed`); the symbolic link scan does (S69 4.2). More than one winner of the same rank is counted (`MultiValid`).

### 4.5 Type tests

1. **TypeIndex.** At resolution, the filter's object type is found in `ObTypeIndexTable` by its `_OBJECT_TYPE.Name`, and its `Index` must equal its slot (M1). The low byte of `ObHeaderCookie` is read once.
2. For a header at physical address *p*, the residency gives the values of virtual address bits 15:8 under which the kernel maps *p*'s frame (bits 15:12 from each mapping's page, bits 11:8 from *p*). The test passes for the page keys under which stored byte XOR cookie XOR that value equals the slot (M2). A table without `ObHeaderCookie` compares the stored byte to the slot directly (O4).
3. A frame the kernel does not map, or no residency, leaves TypeIndex untested: a freed page is what the scan exists to find, and the body type tag still decides.
4. A failed test refuses the position, unless the caller keeps mismatches and the body type tag is resolved and passes: then it is kept and flagged `TypeIndexFailed`, since a freed object can lose its header's TypeIndex while its body still matches (M2).
5. **Body type tag.** `TypeTag` reads the member a chain of members names, at the width the table gives (T6), and compares it with the expected value: `ProcessObject` 3, `ThreadObject` 6, `MutantObject` 2 (T5), file 5 (D3, M9), driver 4 (M9). An unresolved tag accepts every body, and the tools say so.
6. **Body.** The caller's decoder judges the body last.

### 4.6 Object identity resolution

`ResolveObjectIdentity` reads `ObpInfoMaskToOffset` (256 bytes; entry 0 must be 0) and then the TypeIndex test unless the filter skips it or names no object type. An `ObpInfoMaskToOffset` that is missing or does not read is not an error: the type sizes serve (4.4 step 3). A type table that does not read, a type not in it, or an `ObHeaderCookie` that does not read is an error returned with the partial identity, so the caller can scan on the body type tag and say why. A table without the `ObHeaderCookie` symbol is not an error (4.5 step 2).

### 4.7 Copies

1. Accepted allocations are grouped by the SHA-256 of their whole `BlockSize` × 16 bytes. An allocation whose bytes do not read is alone (M11, M12).
2. In a group with mapped copies (`Residency.Contains`), each mapped copy is reported; its `Copies` lists the others with their mapped flag, and `OtherMapped` the other mapped copies' pool addresses in ascending order. Unmapped copies are withheld and counted (`DuplicateCopies`); the further mapped copies are counted (`MappedCopies`).
3. In a group with none mapped, or with no residency, the lowest physical address is reported and the rest withheld.
4. `ReportingEveryCopy` turns grouping off.

### 4.8 Placement

Each reported row asks the residency for the lowest kernel virtual address of its pool header, restricted to the page keys under which its TypeIndex decoded (any key when untested). A found address sets `Place.Virtual`, `VirtualPool` and `VirtualBody` (pool address plus the body's distance; the allocation is within its page, D1).

### 4.9 Order

Rows with a kernel address come first by `VirtualPool`, then the rest by physical pool address; ties keep physical order. This is the owner's decision that pool scans report in virtual-address order.

### 4.10 Object names

`ObjectNamer` finds `_OBJECT_HEADER_NAME_INFO` at header − `ObpInfoMaskToOffset[InfoMask & 3]` when bit 1 is set (M4), or at header − `NameInfoOffset` on a table without `InfoMask` (O3). The name's descriptor is read with the header's reader, its characters from kernel memory. NULs at the end of the counted name are its terminator and are dropped; a NUL inside it is data and shows as `␀` (U+2400), as in the handle list (S30 4.1 step 2, O6), so a suffix after a NUL cannot hide. `NameInfo` gives the name info's address, for callers that walk `Directory` (S30).

### 4.11 Module entry type

`ModuleEntryType` is `_KLDR_DATA_TABLE_ENTRY` when the table has it, else `_LDR_DATA_TABLE_ENTRY`; `ModuleFilterFor` puts it in the `MmLd` filter (M10).

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Header 16-byte aligned (8 on x86) | D1, M3 | `Rejected.Alignment` |
| Header reads | | `Rejected.Unreadable` |
| Page type in the filter (0 free, odd paged, even nonpaged) | T5, M7 | `Rejected.PageType` |
| `BlockSize` × 16 ≥ minimum, ≤ `MaxSize` | D1, M7 | `Rejected.Size` |
| `PoolIndex` in range when bounded | caller's | `Rejected.Index` |
| Allocation within its page | D1, M7 | `PageCrossing` (structures: `PageCrossingHits`) |
| No position fits in the allocation | 4.4 | `BlockSizeBounded` |
| Optional headers place the header at *d* | M4, M5 | `InfoMaskRejected` |
| `PaddingAmount` below 64 | M5 | `InfoMaskRejected` |
| `PointerCount` ≥ 0, 0 ≤ `HandleCount` ≤ `PointerCount` | D2, M8 | `PointerCountRejected` |
| TypeIndex decodes to the slot under a mapped address | M1, M2 | `TypeIndexRejected`, or kept as `TypeIndexFailed` |
| Body type tag | T5, T6, D3, M9 | `TypeTagRejected` |
| Caller's body check | the tool's spec | `BodyRejected` |
| Byte-identical copy of a reported allocation | M11, M12 | `DuplicateCopies` |

A hit refused at several positions is counted once, at the furthest stage any position reached.

## 6. Failure modes

| Case | Result |
|---|---|
| No reader | `ErrNilReader` |
| Table lacks `_POOL_HEADER`, `PoolTag`, `BlockSize` or `PoolType` | `ErrNoPoolHeader` |
| Table lacks `_OBJECT_HEADER.Body` | `ErrNoObjectHeader` |
| Filter body type not in the table | `ErrStructureUndescribed`, wrapped as `pool tag "<tag>": …` |
| `ObTypeIndexTable`, `_OBJECT_TYPE.Name` or `ObHeaderCookie` unreadable | `ErrNoTypeTable`; scans continue on the body type tag |
| Object type not in the type table | `ErrTypeNotListed`; as above |
| Residency query fails | `place "<tag>" objects: …` (object scans), `place pool allocations: …` (structure scans) |
| Unreadable chunk or page | skipped (4.1) |

Messages: `scan: no memory to scan`, `scan: symbol table has no _POOL_HEADER`, `scan: symbol table has no _OBJECT_HEADER`, `scan: pool filter body type not in symbols`, `scan: kernel object type table not readable`, `scan: object type not in the kernel type table`, `scan: object name not readable`.

## 7. Result schema

`Placed[T]`: `Row` (the decoder's), `Place` (`Pool`, `Body` physical; `Virtual`, `VirtualPool`, `VirtualBody`; `PoolAddress` and `BodyAddress` give the virtual address or 0), `Copies` (`Pool`, `Mapped`), `OtherMapped` (pool addresses; `OtherMappedPool`, `OtherMappedBody`), `TypeIndexFailed`. `Rows` drops the placement.

`ObjectScanStats`: `TagHits`, `Rejected` (`Size`, `PageType`, `Index`, `Alignment`, `Unreadable`; the last two new), `HeaderUnreadable`, `PageCrossing`, `BlockSizeBounded`, `PointerCountRejected`, `InfoMaskRejected`, `TypeIndexRejected`, `TypeIndexAccepted`, `TypeIndexFailed`, `TypeTagRejected`, `BodyRejected` (new), `DuplicateCopies`, `MappedCopies`, `PastPage` (always 0: page-crossing allocations are refused first), `MultiValid`, `Accepted`. `Describe` lists the accepted count and each nonzero counter, for example `100 accepted, 1 of another TypeIndex`.

`ScanStats`: `TagHits`, `Passed`, `Rejected`, `PageCrossing`, `PageCrossingHits`, `DuplicateCopies`, `MappedCopies`, `Accepted`.

Order: 4.9.

## 8. Limits

- `Workers`: sweep goroutines (4.1). The sweep holds one 1 MiB chunk per worker.
- The object header reach is at most 208 bytes on the measured builds (4.4); no Limits field caps it.

## 9. Acceptance

1. Synthetic fixtures (`scan/s31_fixture_test.go`, build 26100 layouts of T1 to T4): the sweep across chunk edges and holes; every pool header rule; each optional header shape; a `PaddingAmount` below the padding info refused; a nearer unnamed header and a farther named one in one allocation; a freed allocation; each geometry, count and type rule; a kept and flagged mismatch; an unmapped frame; the kernel mask table over type sizes; copies mapped once, twice and never; virtual-address order; the type slot by name and `Index`; an identity without the type table; first-filter structure scans with page-crossing hits; names; `Unaccounted`; `Describe`.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzSweepTags` (every hit is the tag's bytes, in order, and no hit of a hole-free buffer is missed) and `FuzzObjectScan` (an arbitrary page behind a `Proc` tag: no panic, and every accepted header sits where its `InfoMask` places it): 5.81 million and 2.63 million executions.
3. On the captures, `poolfacts -scan` with every body accepted, 2026-11-12 (accepted; TypeIndex accepted / kept flagged when mismatches are kept; withheld copies):

| Tag | mem1_win11 | mem2_win10 | mem5_server2016 | mem6_server2025 |
|---|---|---|---|---|
| `Proc` | 88; 82/6; 67 | 163; 153/10; 52 | 71; 71/0; 64 | 100; 100/0; 0 |
| `Thre` | 2,263; 1,186/1,074; 2,078 | 2,294; 2,004/290; 550 | 1,326; 1,317/9; 1,327 | 1,357; 1,308/49; 0 |
| `File` | 20,847; 10,399/7,651; 23,078 | 16,427; 6,394/10,033; 3,648 | 4,942; 4,220/722; 4,478 | 4,921; 4,210/711; 0 |
| `Muta` | 989; 389/600; 653 | 856; 664/192; 170 | 365; 359/6; 375 | 528; 441/87; 0 |
| `Driv` | 162; 162/0; 186 | 157; 157/0; 11 | 111; 109/2; 67 | 124; 124/0; 0 |
| `Symb` | 235; 231/0; 251 | 324; 313/0; 99 | 205; 188/0; 165 | 213; 211/0; 0 |
| `AtmT` | 9; 10 | 16; 5 | 19; 22 | 12; 0 |
| `MmLd` | 206; 221 | 195; 6 | 142; 69 | 158; 0 |
| `CM10` | 0 | 0 | 0 | 0 |

   - Every ground-truth process with a pool header is found: 82 of 83, 153, 71, 100 of 101 (M6).
   - Sweep of 9 tags: 352,970 hits in 9.1 s on mem1 (10.9 GB), 133,152 in 1.1 s on mem6.
   - `windows.pool.scan` rows: 19,125, 9,184, 5,898, 5,967; with a kernel address 12,034, 8,509, 5,852, 5,965.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Byte-identical copies are withheld behind the mapped or lowest copy (4.7). On mem1 that withholds 23,078 `File` allocations. | Owner decision: keep withholding (default), or report each copy flagged |
| O2 | `PageType` parity, the `PaddingAmount` bound of 64, the optional header bit order and the TypeIndex XOR rest on the PDB enums and types plus measurement; no public document states them. | Owner decision on measured rules |
| O3 | Tables without `InfoMask` (before Windows 8) are covered only by the one-byte reach of `NameInfoOffset` and by the namer; no such capture was measured, and the pool scan tools refuse those builds. | A pre-Windows 8 capture |
| O4 | A table without `ObHeaderCookie` compares the stored TypeIndex directly; every measured build has the cookie. | A Windows 8 or 8.1 capture |
| O5 | Big-pool allocations (no pool header; devices M6, hives M10) are outside a tag scan. | The big-page table tool's own spec |
| O6 | `ObjectNamer` ends a name at its first NUL, as its callers' tests require; the handle list keeps a NUL visible (S30). Owner decision 2026-11-12: show NUL in the namer too. Done: 4.10; `ObjectNamer` decodes with `util.DecodeCountedUTF16LE` (`scan/names.go`); tests `TestObjectNames` (`scan/s31_scan_test.go`) and `TestANameIsJudgedPastAnInnerNUL` (`tools/windows/objectmutants`); no other caller's test depended on the cut. Measured 2026-11-12 on the five Windows captures with every caller (handle list, file, driver, mutant, link and pool scans, device tree, GUI): row counts unchanged; mem2, mem5 and mem6 give identical rows; mem1 shows the hidden suffix of one stale driver object name (1 row each in `windows.driver.scan` and `windows.pool.scan`, 4 in `windows.device.tree`); mem7 shows it for 6 stale mutant names in `windows.pool.scan`, and one `windows.object.scan_mutants` name read before as `df` is now flagged `NameUnreadable`, its suffix holding a backslash (S69 4.1 step 4). | Owner decision on one rule |
| O7 | New exports: `ObjectNamer.NameInfo`, `ObjectScanStats.BodyRejected`, `HeaderRejections.Alignment` and `.Unreadable`, `ErrNilReader`, `ErrNoPoolHeader`, `ErrNoObjectHeader`, `ErrNoTypeTable`, `ErrTypeNotListed`. `Place.BodyAddress` and `PoolAddress` return 0 for an unplaced row. | Owner review (Q2) |
| O8 | x86 tables (8-byte granularity, 4-byte pointers) are covered by the table-driven layouts only; no 32-bit capture was measured. | A 32-bit capture (Q7) |
| O9 | 4.4 step 3 accepted `PaddingAmount` 0 with `InfoMask` bit 7: one registry-data false positive on mem5, while every valid padded object holds 16, 32 or 48 (M5). Owner decision 2026-11-12: require at least 4, drop the zero fixture. Done: 4.4 step 3 requires at least the padding info's size, 4 bytes on every measured build (M4) (`scan/objectlayout.go`); the "padding of zero" shape is gone from `TestAProcessBehindEachOptionalHeaderShapeIsFound` and `TestAPaddingAmountBelowThePaddingInfoIsRefused` refuses it (`scan/s31_scan_test.go`). A private real-image test of the located objects passes on mem5, and on mem1, mem2 and mem7. | Closed |
| O10 | 4.4 step 5 took the nearest of equal positions. On mem2 the link `\Sessions\1\AppContainerNamedObjects\S-1-15-2-…\Session` (body 0xffff9d016983df10, `InfoMask` 0xa) was reported 64 bytes nearer, at a position whose `InfoMask` 0 has no name and whose target reads empty: the one directory link of 313 the scan missed (S69 9). Owner decision 2026-11-12: prefer the nearest position whose name reads. Done: 4.4 step 5; `ObjectLayout.PreferringNamed` (new export), `scan/objects.go`, `scan/objectlayout.go`, `scan/placement.go`; `objectlinks` opts in; test `TestANamedHeaderWinsOverANearerUnnamedOne`. Measured with `objectscanfacts -tool -list` on 2026-11-12: link rows 231, 315, 190, 211, 234 on mem1, mem2, mem5, mem6, mem7 (unchanged); directory links found 231 of 231, 313 of 313, 188 of 188, 210 of 210, 230 of 230. The other object scans do not opt in and are unchanged. | Closed |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep withholding copies |
| O2 | Keep the measured rules |
| O3 | Defer; builds are refused |
| O4 | Defer; every measured build has it |
| O5 | Leave to the big-page tool |
| O6 | Show NUL in namer too |
| O7 | Accept the new exports |
| O8 | Defer; table-driven layouts only |
| O9 | Require at least 4 (2026-11-12) |
| O10 | Prefer the nearest position whose name reads (2026-11-12) |

## 11. Provenance

Written from Microsoft Learn's WDK documentation, the Intel SDM, the ntoskrnl types and enumerations in the project's symbol tables, and the project's measurements with `poolfacts`. Every rule rests on the sources and measurements above.
