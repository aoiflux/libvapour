# S19: Windows file objects, section caches and cache views

Version 1, 2026-11-12.

## 1. Purpose

A file that a process opened or mapped may still be in memory after the process stopped using it. Windows keeps a stream's bytes in up to three caches: a data section and an image section, each described by a control area whose subsections list prototype PTEs, and the cache manager's shared cache map, whose views map the data section into system space. An examiner wants each cached copy as a file, placed at the file offsets the bytes came from, with the holes marked.

Every pointer on the way comes from the image and can be stale: a freed control area, a cache map reused for another file, a subsection list that runs into pool. Written without checks, such a pointer puts another file's bytes under this file's name. This specification defines the checks on file objects, control areas, subsections and shared cache maps, the extent each cache gives, and the device filter that keeps file objects of devices without files out.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | Kernel virtual reads. |
| Physical memory | Required for the two section caches: prototype PTEs give frames. |
| Symbol table | The kernel types of section 3 and the globals `CcVacbArrays` and `CcVacbArraysHighestUsedIndex`. |
| File objects | From each process's handle table (`File` handles; the body follows `_OBJECT_HEADER.Body`) and from its file-backed VADs (`_MMVAD.Subsection` → `ControlArea` → `FilePointer`), or the addresses given in `windows.file.dump.virtaddr` and `windows.file.dump.physaddr`. |
| Options | `windows.file.dump.virtaddr`, `.physaddr`, `.filter`, `.ignore_case`, `pid`, `output_dir`, `max_dump_size`. |
| Limits | `MaxListEntries` (subsections per control area), `MaxTableEntries` (VACB arrays and VACBs per array), `MaxArtifactBytes` (default dump ceiling). |

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | `FILE_OBJECT.Type` "indicate[s] that the object is a file object. If the object is a file object, the value of this member is 5." `Size` "specifies the size, in bytes, of the file object". `DeviceObject` is "the device object on which the file is opened"; `SectionObjectPointer` points to the file's section object pointers; for file system drivers `FsContext` "must point to a FSRTL_ADVANCED_FCB_HEADER". `FileName` is a `UNICODE_STRING`. | Microsoft Learn, "FILE_OBJECT (wdm.h)", dated 2023-08-17, accessed 2026-11-12. |
| D2 | `SECTION_OBJECT_POINTERS` has `DataSectionObject` (a `CONTROL_AREA` for the data stream), `SharedCacheMap` (a `SHARED_CACHE_MAP` that tracks views mapped to the data stream) and `ImageSectionObject` (a `CONTROL_AREA` for the executable image). "There is a one-to-one relationship between a SECTION_OBJECT_POINTERS structure and a file stream … the SectionObjectPointer member for all file objects must point to the same SECTION_OBJECT_POINTERS structure." | Microsoft Learn, "SECTION_OBJECT_POINTERS (wdm.h)", dated 2022-12-16, accessed 2026-11-12. |
| D3 | `DEVICE_OBJECT.DeviceType` holds the device type. Values include `FILE_DEVICE_CD_ROM` 0x02, `_CD_ROM_FILE_SYSTEM` 0x03, `_DISK` 0x07, `_DISK_FILE_SYSTEM` 0x08, `_NAMED_PIPE` 0x11, `_NETWORK` 0x12, `_NETWORK_FILE_SYSTEM` 0x14, `_VIRTUAL_DISK` 0x24, `_DVD` 0x33, `_DFS_FILE_SYSTEM` 0x35, `_DFS_VOLUME` 0x36. "The FILE_DEVICE_DISK specification covers disk partitions and any object that appears as a disk." Values 32768 to 65535 are for third parties. | Microsoft Learn, "Specifying Device Types", dated 2025-02-21, accessed 2026-11-12. |
| D4 | "The cache manager manages files in the system in 256 KB-aligned views. (The cache manager's view size is specified by the system-defined constant VACB_MAPPING_GRANULARITY, which is set to 256 KB in ntifs.h.)" | Microsoft Learn, "CcMapData function (ntifs.h)", accessed 2026-11-12. |

### Kernel types

Read through the project's kernel tables for builds 26100 (mem1, mem6; GUIDs 0D960CE1…, 953A8DE8…), 19045 (mem2; F57E740B…) and 14393 (mem5; 3DFC5F72…), with `filefacts -types`.

| # | Fact |
|---|---|
| T1 | `_FILE_OBJECT` is 216 bytes in all four: `Type` (short) 0, `Size` (short) 2, `DeviceObject` 8, `FsContext` 0x18, `SectionObjectPointer` 0x28, `FileName` 0x58. `_SECTION_OBJECT_POINTERS`: `DataSectionObject` 0, `SharedCacheMap` 8, `ImageSectionObject` 0x10. `_DEVICE_OBJECT.DeviceType` (unsigned int) 0x48. `_FSRTL_ADVANCED_FCB_HEADER.FileSize` (`_LARGE_INTEGER`) 0x20. |
| T2 | `_CONTROL_AREA` is 128 bytes: `Segment` 0, `u` 0x38 (an unnamed union the tables do not expand), `FilePointer` 0x40 (`_EX_FAST_REF`). `_EX_FAST_REF.RefCnt` is bits 0..3. `_MMSECTION_FLAGS` (4 bytes): `BeingDeleted` bit 0, `Image` bit 5, `File` bit 7 in all four. |
| T3 | `_SEGMENT`: `ControlArea` 0, `TotalNumberOfPtes` (unsigned int) 8, `SizeOfSegment` (unsigned long long) 0x18. |
| T4 | `_SUBSECTION` is 56 bytes: `ControlArea` 0, `SubsectionBase` 8, `NextSubsection` 0x10, flags at 0x20, `StartingSector` (unsigned int) 0x24, `NumberOfFullSectors` 0x28, `PtesInSubsection` 0x2c, `UnusedPtes` at 0x34 (30 bits on 26100 and 19045, 31 on 14393). On 26100 the flags member is `SubsectionFlags` (`_MMSUBSECTION_FLAGS`); on 19045 and 14393 it is an unnamed union `u` at the same offset. `_MMSUBSECTION_FLAGS`: `StartingSector4132` 10 bits and `SectorEndOffset` 12 bits (bits 6 and 20 of a 32-bit word on 26100; bit 6 of the first and bit 4 of the second 16-bit word on 19045 and 14393). `_MSUBSECTION` begins with the `_SUBSECTION` as `Core`. |
| T5 | `_MMPTE` is 8 bytes. `_MMPTE_HARDWARE`: `Valid` bit 0, `PageFrameNumber` from bit 12 (40 bits on 26100, 36 on the others). `_MMPTE_TRANSITION`: `Valid` bit 0, `Prototype` bit 10, `Transition` bit 11, `PageFrameNumber` from bit 12. `_MMPTE_SUBSECTION` has `Prototype` at bit 10. |
| T6 | `_SHARED_CACHE_MAP` is 616 bytes on 26100, 552 on 19045, 528 on 14393: `NodeTypeCode` (short) 0, `NodeByteSize` (short) 2, `FileSize` 8, `SectionSize` 0x20, `ValidDataLength` 0x28 (all `_LARGE_INTEGER`), `InitialVacbs` 0x38, `Vacbs` 0x58, `FileObjectFastRef` 0x60 (`_EX_FAST_REF`). |
| T7 | `_VACB` is 40 bytes: `BaseAddress` 0, `SharedCacheMap` 8, `Overlay` 0x10 (unnamed union), `ArrayHead` 0x20 (`_VACB_ARRAY_HEADER *`). `_VACB_ARRAY_HEADER` is 16 bytes: `VacbArrayIndex` 0, `MappingCount` 4, `HighestMappedIndex` 8, `Reserved` 12. All four tables have `CcVacbArrays` and `CcVacbArraysHighestUsedIndex`. |

### Measurements

M1 to M9 come from `filefacts` on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393) and mem6_server2025 (26100). The census takes every file object a `File` handle or a file-backed VAD leads to: 17,530 in all (8,012, 4,162, 2,459, 2,897), with 2,964 data control areas, 4,286 image control areas and 1,122 shared cache maps reached through their section object pointers.

| # | Measured |
|---|---|
| M1 | 17,523 file objects have `Type` 5 and `Size` 216; 3 on mem1 have other values and 4 do not read. Every file object with a nonzero cache pointer is on a device of type 0x07, 0x08 or 0x14 (7,536 in all; 0x14 only on mem1, 1,230). No other device type ever has one. |
| M2 | The first subsection follows its control area: `ControlArea` at control area + 128 points back for 2,261 of 2,284 data and 4,248 of 4,271 image control areas that read. |
| M3 | Among the control areas whose subsections walk: `Segment.ControlArea` points back for all but 32 (10, 2, 21, 1 per capture). `File` is set, and `Image` matches the pointer the area came from, for every one. `FilePointer` is null only where `BeingDeleted` is set (171 in all, 156 on mem1), and names a file object of another stream (a different `SectionObjectPointer`) in 13 on mem5. |
| M4 | Image subsections: for every image whose header page reads, there is one subsection for the headers and one per PE section (3,471 images). For all 24,805 sections, `StartingSector` × 0x200 equals `PointerToRawData` and `NumberOfFullSectors` × 0x200 + `SectorEndOffset` equals `SizeOfRawData`; the header subsection starts at sector 0 and its extent equals `SizeOfHeaders`. Each section's prototype PTEs start at the header subsection's array plus 8 × (RVA / 0x1000). |
| M5 | Data subsections: every later subsection's `StartingSector` × 0x1000 equals the bytes of the subsections before it (943 subsections). `NumberOfFullSectors` × 0x1000 + `SectorEndOffset`, in pages, equals `PtesInSubsection` − `UnusedPtes` wherever `UnusedPtes` ≤ `PtesInSubsection` (3,158 subsections); on mem5, 43 subsections carry an `UnusedPtes` above `PtesInSubsection`. The summed extent equals `SizeOfSegment` in 2,229 of 2,257 data control areas with a readable file size. |
| M6 | Data extents run past the file: the `FsContext` header `FileSize` is below the extent in 1,114 data control areas. Where the stream has a shared cache map, the data extent equals the map's `SectionSize` (1,114 of 1,120) and the map's `FileSize` equals the `FsContext` header's (1,113 of 1,120). |
| M7 | Shared cache maps: 1,121 of 1,122 have `NodeTypeCode` 0x2FF and `NodeByteSize` equal to the type's size; the other (mem5) has neither. In every valid map `0 ≤ FileSize ≤ SectionSize`, `SectionSize` is a multiple of 256 KB, and `FileObjectFastRef` names a file object of the same stream. |
| M8 | VACB arrays: `CcVacbArraysHighestUsedIndex` is 0 or 1; every array pointer leads to a header whose `VacbArrayIndex` is its position, followed by 3,276 VACBs whose `ArrayHead` is that header. 4,979 VACBs have both a base and a map. Every such base is 256 KB-aligned, and the first 8 bytes of `Overlay`, below bit 18, have bits only in 15:0 (6 VACBs) — rounded down to 256 KB they are a multiple of the view size. |
| M9 | For the 1,088 maps of at most 32 MB whose per-map `Vacbs` index reads with every entry pointing back, the views from the VACB arrays are exactly the index's: entry *i* has offset *i* × 256 KB. On mem2, 5 index entries point to VACBs of other maps. |
| M10 | Header pages of image sections that are resident but do not parse as PE: 56, 20, 13 and 0 per capture, mostly from transition PTEs. The page-frame database's `PteAddress` does not separate them cleanly from good pages (mem2: 42 good pages fail it, mem1: 41 bad pages pass it). |

## 4. Algorithm

### 4.1 File objects

1. Collect owners: per process kept by `pid`, its `File` handles, then its file-backed VADs (only `_MMVAD`; a short VAD has no `Subsection`). Or the given addresses, as `windows.file.dump` options define them. Each owner is taken once by address.
2. **File object check.** `Type` must be 5 and `Size` the size of `_FILE_OBJECT` (D1, T1, M1). `DeviceObject` must be nonzero and its `DeviceType` must read (D1, D3).
3. **Device filter.** The device type must be one that holds files: `CD_ROM`, `CD_ROM_FILE_SYSTEM`, `DISK`, `DISK_FILE_SYSTEM`, `NETWORK_FILE_SYSTEM`, `VIRTUAL_DISK`, `DVD`, `DFS_FILE_SYSTEM`, `DFS_VOLUME` (D3). The three measured types are 0x07, 0x08 and 0x14 (M1); the others are admitted by name (O1).
4. Read `SectionObjectPointer`. Null means nothing is cached. A stream is carved once: a second file object with the same `SectionObjectPointer` is the same stream (D2) and is skipped.
5. Read the three cache pointers (D2).
6. **File size.** The shared cache map's `FileSize` when the map passes 4.4; otherwise the `FsContext` header's `FileSize` when it reads and is above 0 (D1, M6, O9); otherwise unknown. An empty file has no cached page, so a header size of 0 bounds nothing.

### 4.2 Control area check

For a control area reached through `DataSectionObject` (data) or `ImageSectionObject` (image):

1. `Segment` must be nonzero and its `ControlArea` must be this control area (T3, M3).
2. In the section flags at `u`: `File` must be set and `Image` must be set exactly for an image control area (T2, M3). `BeingDeleted` does not refuse the control area: it is copied to the row (`BeingDeleted`) and the area is carved, since its pages may still be the file's (O2).
3. `FilePointer`, with the `RefCnt` bits cleared (T2), must name a file object whose `SectionObjectPointer` is the one the control area came from (D2, M3). A null pointer fails, except with `BeingDeleted` set: M3 finds a null pointer only there, so it is the delete's own clearing, and the control area still came from this stream's `SectionObjectPointer` (O2). A nonzero pointer to another stream refuses a control area being deleted too.

### 4.3 Subsection walk and extents

1. **Unit.** 0x200 bytes for an image control area, 0x1000 for a data one (M4, M5).
2. **Budget.** `Segment.TotalNumberOfPtes`, when the table has it.
3. Start at control area + size of `_CONTROL_AREA` (M2). For each subsection, until `NextSubsection` is 0:
   1. Stop if it was seen before or the count passes `MaxListEntries` (cut).
   2. `ControlArea` must be this control area. On the first subsection a mismatch is `ErrNoSubsections`; later it cuts the list.
   3. Read `SubsectionBase`, `PtesInSubsection`, `StartingSector`, `NumberOfFullSectors`, `StartingSector4132` and `SectorEndOffset` (T4).
   4. **Extent.** File offset = (`StartingSector` | `StartingSector4132` << 32) × unit. Bytes = `NumberOfFullSectors` × unit + `SectorEndOffset`. File pages = bytes rounded up to 0x1000 (M4, M5). `UnusedPtes` is not read (M5).
   5. `SectorEndOffset` must be below the unit, the file pages must not exceed `PtesInSubsection`, and the PTE array must not pass the top of the address space; else the list is cut (`ErrExtent`).
   6. The file pages are charged to the budget; more than is left cuts the list (`ErrBudget`).
   7. For each of the first file-page entries of the PTE array: valid → frame; `Prototype` clear and `Transition` set → frame (T5); anything else is not resident. A page whose entry does not read loses the rest of that PTE page too. Page *i* lands at file offset + *i* × 0x1000 and holds min(0x1000, bytes − *i* × 0x1000) bytes.
4. A cut returns the pages before it with the error; the tool carves them and says so.
5. A VAD view (`AvailablePagesFromVAD`) starts in the subsection whose array holds the VAD's `FirstPrototypePte` and takes the VAD's page count of entries from there across subsections; only file pages yield output.

### 4.4 Shared cache map check and views

1. `NodeTypeCode` must be 0x2FF and `NodeByteSize` the size of `_SHARED_CACHE_MAP` (M7).
2. `FileSize` and `SectionSize` must not be negative, `FileSize ≤ SectionSize`, and `SectionSize` a multiple of 256 KB (D4, M7).
3. `FileObjectFastRef`, `RefCnt` bits cleared, must name a file object of the same stream (M7).
4. **Views.** Once per run, walk the VACB arrays: for *i* from 0 to `CcVacbArraysHighestUsedIndex` (bounded by `MaxTableEntries`), header = `CcVacbArrays[i]`; its `VacbArrayIndex` must be *i*. The VACBs follow the header at its size, 40 bytes apart, while `ArrayHead` is the header (M8). A VACB with a nonzero base and map is a view of that map at offset = the first 8 bytes of `Overlay` rounded down to 256 KB (D4, M8). The arrays give the views of every map without the per-map index (M9).
5. For one map: a view at or past `FileSize` is ignored; a view whose base is not 256 KB-aligned, or whose offset repeats, is dropped and counted. Each view holds min(256 KB, `FileSize` − offset) bytes, read from kernel memory at its base.

### 4.5 Artefacts

1. Each cache that passes its check becomes one artefact; each that fails becomes a row with `Skipped` set to the reason. The section caches read physical memory; the cache map reads kernel memory.
2. Pieces at or past the file size are left out and the last is cut at it. Pieces past the dump ceiling (`max_dump_size` when set and below `MaxArtifactBytes`, else `MaxArtifactBytes`) are withheld and listed.
3. The file is written through `extract`. Its length is the file size when known (capped at the ceiling), else the end of the last piece. Holes are listed in `Gaps`.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| `Type` 5, `Size` = size of `_FILE_OBJECT` | D1, T1, M1 | `ErrNotFileObject` |
| File object and its device read | D1 | `ErrFileUnread`, `ErrDeviceUnread` |
| Device type holds files | D3, M1 | `ErrNoFiles` |
| One carve per `SectionObjectPointer` | D2 | Later file objects skipped |
| Segment points back | T3, M3 | `ErrSegment` |
| `File` set, `Image` matches the pointer | T2, D2, M3 | `ErrSectionFlags` |
| `BeingDeleted` | T2, M3, O2 | Carved; row flag `BeingDeleted` |
| `FilePointer` names a file object of this stream, or is null with `BeingDeleted` set | D2, M3, O2 | `ErrOtherStream` |
| First subsection points back | M2 | `ErrNoSubsections` |
| Later subsections point back, no cycle | M2 | List cut (`ErrListCut`) |
| Extent fits the PTE array; end offset below the unit | M4, M5 | List cut (`ErrExtent`) |
| File pages within `TotalNumberOfPtes` | T3, M5 | List cut (`ErrBudget`) |
| Map node type and size | M7 | `ErrCacheMapNode` |
| `0 ≤ FileSize ≤ SectionSize`, `SectionSize` a 256 KB multiple | D4, M7 | `ErrCacheMapSizes` |
| `FileObjectFastRef` names a file object of this stream | M7 | `ErrOtherStream` |
| VACB array index matches its position | M8 | Array skipped, counted |
| View base 256 KB-aligned, offset unique | D4, M8 | View dropped, counted |

## 6. Failure modes

| Case | Result |
|---|---|
| Table lacks a member of 4.1 or 4.2 | `ErrLayout`; the run fails |
| Table lacks the size of `_CONTROL_AREA`, or `_SUBSECTION.SubsectionBase`, `PtesInSubsection`, `NextSubsection`, `StartingSector` or `ControlArea` | The subsection resolver is not built; the run fails |
| Table lacks another member of 4.3 | `subsection.ErrWalkFields` on each section cache row |
| Table lacks a member or global of 4.4 | `ErrCacheLayout`; diagnostic `windows.file.dump: shared cache maps not read: …`; no cache map rows |
| VACB arrays do not read | Diagnostic; cache map rows carve nothing |
| A rejected file object found by enumeration | Counted: `windows.file.dump: <n> not carved: file object: <reason>` |
| A rejected given address | `windows.file.dump: windows.file.dump.virtaddr 0x<addr> not carved: file object: <reason>` |
| A rejected cache | Row with `Skipped` = the reason; counted as above for enumeration |
| A cut list | Pages before the cut written; diagnostic `windows.file.dump: <cache> at 0x<addr>: pages after the cut are not carved: <error>`; in strict mode the run returns the rows and the error |
| No physical memory | Section cache rows skipped |
| Dump ceiling | `Withheld` set; diagnostic names the first withheld offset |

## 7. Result schema

`windows.file.dump` row (`filedump.Artifact`): `FileObject`, `MemoryObject` (control area or map), `FileObjectPhysical`, `Cache` (`DataSectionObject`, `ImageSectionObject`, `SharedCacheMap`), `BeingDeleted` (new, 4.2 step 2: the control area's flag, false for cache map rows), `Name`, `NameUnreadable`, `PID`, `Process`, `FileName` (S00 name: kind `file`, scope `kernel` or `phys`, the file object and cache addresses, labels view and name, extension `bin`), `FileSize` and `FileSizeKnown` (new, 4.1 step 6), `Size`, `Captured` (bytes read), `Gaps`, `Withheld`, `Pages` (pieces written), `Skipped`. Rows come in owner order, then data, image, cache map per stream.

Data artefacts hold the file's bytes at their offsets. Image artefacts hold the file layout: each PE section's raw data at its `PointerToRawData` (M4), with the relocations the memory manager applied. Bytes the image never maps (the attribute certificate) are holes.

`subsection.AvailablePage` is unchanged in shape: `PageSize` is now the file bytes in the page, below 0x1000 for the last page of an extent.

## 8. Limits

- `MaxListEntries`: subsections per control area. The value comes from the run's `Limits`, which each tool passes with `Resolver.SetLimits`. A resolver that never receives them uses the default limits.
- `MaxTableEntries`: VACB arrays, and VACBs per array.
- `MaxArtifactBytes`, or `max_dump_size` when it is lower: bytes written per artefact.

## 9. Acceptance

1. Synthetic fixtures (`subsection/subsection_test.go`, `tools/windows/filedump/file_dump_test.go`, on the 26100 layouts of T1 to T7 in `internal/testsupport/s19_fixture.go`): data and image extents, high sector bits, partial last pages, transition and subsection PTEs, every cut and refusal of 4.3, an unreadable PTE page, a VAD view across subsections, a header file size of 0 read as unknown, every file object, control area and cache map rule, a control area being deleted carved and flagged with its `FilePointer` null and refused with a pointer to another stream, a stream reached twice, view filtering, the file-size bound, the dump ceiling and a physical file object address.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzWalkSubsections` (arbitrary control area, segment, subsections and PTEs; no panic, page sizes 1 to 0x1000, file offsets multiples of the unit, no more pages than `TotalNumberOfPtes`): 760,201 executions. `FuzzCacheViews` (arbitrary VACBs and map sizes; every view aligned, inside the file, at increasing offsets): 1.32 million executions.
3. On the captures, `filefacts -tool` with a 64 MiB ceiling, 2026-11-12; mem5 rerun after the w12 sweep:

| Capture | Rows | Data written (complete) | Image written (complete) | Map written (complete) | Rejected file objects: no files on device | Rejected caches |
|---|---|---|---|---|---|---|
| mem1_win11 | 2,064 | 429 (255) | 1,120 (196) | 201 (129) | 762 | 90 segment |
| mem2_win10 | 2,307 | 421 (120) | 1,269 (0) | 180 (46) | 1,176 | 4 segment |
| mem5_server2016 | 1,581 | 460 (272) | 784 (148) | 249 (127) | 742 | 23 segment, 8 other stream |
| mem6_server2025 | 1,762 | 430 (149) | 854 (3) | 105 (30) | 819 | 1 segment |

   - Control areas being deleted (O2; mem1 and mem2 rerun on 2026-11-12, mem5 and mem6 have none): mem1 154 (75 data, 79 image), mem2 1 (data), every one with a null `FilePointer`, as M3 says. 34 mem1 image artefacts are written (8 complete); the other 45 image and all 76 data control areas carve nothing (nothing resident, or no page reads). Of the 34, 12 parse with `debug/pe`, 14 have a captured header page that does not parse and 8 have none captured; the 12 hold 27 sections, all inside the artefact. The other columns are unchanged by O2.
   - Every page present in both the data section artefact and the cache map artefact of a stream is identical: 20,614 pages, none differ.
   - Image artefacts whose header page was captured parse with `debug/pe`: 3,482 of 3,517; the 35 others have header pages that are not PE (M10). Their 24,661 sections lie inside the artefact, apart from 30 sections past the 64 MiB ceiling.
   - Where a stream has both, the image artefact's headers equal the data artefact's except for `ImageBase` in 104 streams, are equal in 8 and differ elsewhere in 7.
   - Artefacts that start with `MZ` parse with `debug/pe`: 407 of 424 data section artefacts, 28 of 28 cache map artefacts.
   - Lists cut: 1 on mem1 at the budget, 3 on mem5 at a subsection of another control area.
   - Ten mem5 artefacts could not be read back on the measuring host: its antivirus quarantined them.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The device filter admits six types no capture measured (CD-ROM, CD-ROM file system, virtual disk, DVD, DFS file system, DFS volume) by their documented names. | Owner decision; a capture with a mounted ISO or a DFS share |
| O2 | `BeingDeleted` control areas are rejected (171, M3). Their pages may still be file pages. Owner decision 2026-11-12: Carve them with a flag. Done: `Artifact.BeingDeleted`, 4.2 steps 2 and 3, section 5, 7, 9.1 and 9.3; `ErrBeingDeleted` removed (`tools/windows/filedump/file_dump.go`, `file_dump_test.go`). Every such control area measured has a null `FilePointer` (M3), which step 3 refuses, so the decision is applied with a null pointer accepted for a control area being deleted only; a pointer to another stream still refuses it. Owner decision 2026-11-12 (follow-up D10): accept a null `FilePointer` only when `BeingDeleted` is set, as measured in all 154 mem1 cases. Done: no change. | Owner decision: carve them flagged instead |
| O3 | Image section prototype pages carry relocations; the image artefact is not the file on disk. Where the data section also has a page, the data copy is the file's. | Owner decision: merge the two copies, or keep them separate (default) |
| O4 | Header pages that are resident but not PE (M10) are written as found. A page-frame-database check was measured and does not separate them. | A source for the transition-page lifecycle |
| O5 | 0x2FF (`NodeTypeCode`), the 0x200 and 0x1000 sector units, the first-subsection placement and the VACB array layout rest on measurements only; no public source states them. | Owner decision on measured constants |
| O6 | The tables do not expand the unnamed unions `_CONTROL_AREA.u`, `_SUBSECTION.u` and `_VACB.Overlay`; their members' placement is measured (M3 to M5, M8). | A symbol-table change that keeps union members |
| O7 | x86 kernels (4-byte PTEs and pointers) are covered only by the table-driven layouts; no 32-bit capture was measured. | A 32-bit capture (Q7) |
| O8 | The mem5 counts of 9.3 differed slightly from the w12 run. | Owner decision 2026-11-12 (follow-up D11): refresh to the w12 measurements. Done: `filefacts -tool` rerun on mem5; rows 1,583 to 1,581, rejected caches 24 segment and 1 map node to 23 segment and none; every other mem5 count unchanged. |
| O9 | The `FsContext` header can read a `FileSize` of 0 for a file whose caches hold pages. Probe (follow-up Mem-M9, `filefacts -owners 11172 -ca`, mem1, 2026-11-12): file object 0xffff9e040114c3a0 (cabinet.dll, device type 0x14) has `FileSize`, `ValidDataLength` and `AllocationSize` 0 in its `FsContext` header, while its image control area 0xffff9e04006e9ba0 has a valid header page and its data control area 0xffff9e0401e08cc0 is set; 4.1 step 6 took 0 as the file size and cut every piece, so both rows were `nothing resident`. It is the only one of the 309 file objects with a cache on device type 0x14 that pid 11172 reaches with a size of 0. | Owner decision 2026-11-12 (follow-up Mem-M9): run the dump tests once per image. Bug, fixed: 4.1 step 6 takes the header size only when it is above 0; `fcbFileSize` in `tools/windows/filedump/file_dump.go`, test `TestAZeroFileSizeInTheFileHeaderIsUnknown`. The cabinet.dll image artefact is now written on mem1. `filefacts -tool` rerun on mem1 after the fix: data written 428 (254 complete) to 429 (255), image 1,116 (193) to 1,120 (196), the mem1 row of 9.3 updated; one image section (WMIsvc.dll `.reloc`) now lies past the end of an artefact whose size is unknown (4.5 step 3). The other figures of 9.3 are from before the fix. |
| O10 | Follow-up Mem-M9: `windows.file.dump` run on mem1 (pid 11172) and mem2 (pid 3804), with and without filters. Not bugs; these rules shape the artefacts: (a) 4.5 step 3: an artefact runs to the file size, not to its last piece; (b) 4.4 step 5 and 4.5 step 2: no page or view is written past the file size; (c) 4.3 step 7: a prototype page past an extent's end is not written, so it never covers the next section's file offsets. Measured on xmllite.dll (control area 0xffff9e0400b48ba0): the `.data` subsection holds 0x1000 file bytes and 2 prototype PTEs, the second in transition; file offset 0x3d000 holds `.pdata`, whose PTE there is not resident. On AudioSes.dll the `RT_BSS` subsection has 0 file bytes at sector 0 and 1 PTE in transition; none of it is written over the header page; (d) 4.1 step 4: a stream that several file objects reach is carved once; (e) rows follow the section 7 order. Every data section cache that passes the checks of 4.1 and 4.2 is carved. Owner decision 2026-11-12 (follow-up N4): keep carving them. Done: no code change. | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Admit them by documented names |
| O2 | Carve them with a flag |
| O3 | Keep them separate |
| O4 | Write as found |
| O5 | Accept the measured constants |
| O6 | Defer to v0.2.0 |
| O7 | Ship as written, mark untested |
| O8 | Refresh to w12 measurements |
| O9 | Follow-up Mem-M9: probed, fixed |
| O10 | Follow-up Mem-M9: rules confirmed; follow-up N4: carve every data cache that passes the checks |

## 11. Provenance

Written from Microsoft Learn's WDK documentation, the ntoskrnl types in the project's symbol tables, and the project's measurements. Every rule rests on the sources and measurements above.
