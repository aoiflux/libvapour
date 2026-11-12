# S42: NTFS file record segments found in physical memory

Version 1, 2026-11-12.

## 1. Purpose

NTFS describes every file in file record segments of the master file table. The file system reads them through the cache and copies them into its own buffers, so live and freed copies sit in physical memory long after the volume is gone. A record carries the file's times, its names and the directories that hold them, and, for small files, the data itself. An examiner wants each copy that is still a well-formed record: its $STANDARD_INFORMATION and $FILE_NAME times for a timeline, its named resident data streams, and its unnamed resident data.

Physical memory also holds the four letters "FILE" in other data, and records that were overwritten in part or are in the middle of a write. This specification defines how a record is found, how its update sequence array is applied, the checks that make it a record, and how its attributes are read, from Microsoft's published NTFS structures and, where those are silent, from measurements on the captures.

## 2. Inputs

| Input | Meaning |
|---|---|
| Physical memory | `tools.OptionPhysicalMemory`. Required; without it every tool fails with `ErrNoPhysicalMemory`. |
| Profile | Must be Windows; otherwise `ErrNotWindows`. |
| Symbol table | Not read. NTFS on-disk structures are not in the kernel's types. |
| Options | None of their own. `strict` and `diagnostics` as for every tool. |
| Limits | `MaxMatchesPerChunk` (signatures parsed per 1 MiB scan window). |

## 3. Facts from the sources

### Documentation

All Microsoft Learn pages accessed 2026-11-12. The eight NTFS structure pages carry `ms.date` 2018-05-31 and "last updated 2021-01-06"; each says it "is valid only for major version 3 and minor version 0 or 1".

| # | Fact | Source |
|---|---|---|
| D1 | `MULTI_SECTOR_HEADER` is `UCHAR Signature[4]`, `USHORT UpdateSequenceArrayOffset`, `USHORT UpdateSequenceArraySize` (8 bytes). The offset is "from the start of this structure. The update sequence array must end before the last USHORT value in the first sector." The size is "the size of the update sequence array, in bytes". The array "consists of an array of n USHORT values, where n is the size of the structure being protected divided by the sequence number stride" (512). "The first word contains the update sequence number … Next are the n saved USHORT values." Before a write "the last word in each sequence number stride is saved to its respective position in the sequence number array, then it is overwritten with the next update sequence number. After the write, or whenever the structure is read, the saved word … is restored." Before restoring, "all the sequence numbers at the end of each stride are compared with the actual sequence number … If any of these comparisons are not equal, then a failed multisector transfer has been detected." Space to reserve: "(size of structure / 512 + 1) * sizeof(USHORT)". | "MULTI_SECTOR_HEADER structure", learn.microsoft.com/windows/win32/devnotes/multi-sector-header |
| D2 | `FILE_RECORD_SEGMENT_HEADER`: `MULTI_SECTOR_HEADER MultiSectorHeader` (signature always "FILE"), `ULONGLONG Reserved1`, `USHORT SequenceNumber` ("incremented each time that a file record segment is freed; it is 0 if the segment is not used"), `USHORT Reserved2`, `USHORT FirstAttributeOffset`, `USHORT Flags` (`FILE_RECORD_SEGMENT_IN_USE` 0x0001, `FILE_FILE_NAME_INDEX_PRESENT` 0x0002), `ULONG Reserved3[2]`, `FILE_REFERENCE BaseFileRecordSegment` (0 for a base record), `USHORT Reserved4`, `UPDATE_SEQUENCE_ARRAY UpdateSequenceArray`. With natural alignment the members sit at 0, 8, 0x10, 0x12, 0x14, 0x16, 0x18, 0x20, 0x28 and 0x2A. | "FILE_RECORD_SEGMENT_HEADER structure", …/devnotes/file-record-segment-header |
| D3 | `ATTRIBUTE_RECORD_HEADER`: `TypeCode` (ULONG) 0, `RecordLength` (ULONG) 4 ("always rounded to the nearest quadword boundary"), `FormCode` (UCHAR) 8 (`RESIDENT_FORM` 0, `NONRESIDENT_FORM` 1), `NameLength` (UCHAR, characters) 9, `NameOffset` (USHORT, from the start of the attribute record) 0xA, `Flags` 0xC, `Instance` 0xE, then the form union at 0x10. Resident: `ValueLength` (ULONG) 0x10, `ValueOffset` (USHORT, from the start of the record) 0x14, `Reserved[2]`; the value "immediately follows the attribute record header" (0x18 bytes). Nonresident: `LowestVcn`, `HighestVcn`, `MappingPairsOffset`, `Reserved[6]`, `AllocatedLength`, `FileSize`, `ValidDataLength`, `TotalAllocated` (0x48 bytes). "Attribute records are always aligned on a quadword boundary." Type codes: `$STANDARD_INFORMATION` 0x10, `$ATTRIBUTE_LIST` 0x20, `$FILE_NAME` 0x30, `$OBJECT_ID` 0x40, `$VOLUME_NAME` 0x60, `$VOLUME_INFORMATION` 0x70, `$DATA` 0x80, `$INDEX_ROOT` 0x90, `$INDEX_ALLOCATION` 0xA0, `$BITMAP` 0xB0, `$REPARSE_POINT` 0xC0. | "ATTRIBUTE_RECORD_HEADER structure", …/devnotes/attribute-record-header |
| D4 | `STANDARD_INFORMATION` is `UCHAR Reserved[0x30]`, `ULONG OwnerId`, `ULONG SecurityId`; the attribute "is present in every base file record and must be resident". | "STANDARD_INFORMATION structure", …/devnotes/standard-information |
| D5 | `FILE_NAME` is `FILE_REFERENCE ParentDirectory`, `UCHAR Reserved[0x38]`, `UCHAR FileNameLength` (characters), `UCHAR Flags` (`FILE_NAME_NTFS` 0x01, `FILE_NAME_DOS` 0x02), `WCHAR FileName[1]`: offsets 0, 8, 0x40, 0x41, 0x42. "A file has one file name attribute for every directory it is entered into." | "FILE_NAME structure", …/devnotes/file-name |
| D6 | `MFT_SEGMENT_REFERENCE` (= `FILE_REFERENCE`) is `ULONG SegmentNumberLowPart`, `USHORT SegmentNumberHighPart`, `USHORT SequenceNumber`. | "MFT_SEGMENT_REFERENCE structure", …/devnotes/mft-segment-reference |
| D7 | "Each file record segment starts with a file record segment header … followed by one or more attributes … The attribute list is terminated with 0xFFFFFFFF ($END)." Segment 0 is `$MFT`, 5 the root directory. | "Master File Table", …/devnotes/master-file-table |
| D8 | A FILETIME is "a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC)". "NTFS records times on disk in UTC." "The NTFS file system delays updates to the last access time for a file by up to 1 hour"; "the last write time is not fully updated until all handles that are used for writing are closed." | "FILETIME structure (minwinbase.h)", ms.date 2018-12-05; "File Times", ms.date 2018-05-31 |
| D9 | The four file times are `CreationTime`, `LastAccessTime`, `LastWriteTime`, `ChangeTime`, next to `FileAttributes` (`FILE_ATTRIBUTE_*` flags). | "FILE_BASIC_INFORMATION (wdm.h)", ms.date 2021-05-18 |
| D10 | `FILE_ATTRIBUTE_*` values, among them `READONLY` 0x1, `HIDDEN` 0x2, `SYSTEM` 0x4, `DIRECTORY` 0x10, `ARCHIVE` 0x20, `SPARSE_FILE` 0x200, `REPARSE_POINT` 0x400, `COMPRESSED` 0x800, `OFFLINE` 0x1000, `NOT_CONTENT_INDEXED` 0x2000, `EA` 0x40000. | "File Attribute Constants (WinNT.h)", ms.date 2025-09-23 |
| D11 | A stream's full name is "filename:stream name:stream type"; "the default data stream is unnamed". Directories "can have named data streams". Stream types include `$EA`, `$EA_INFORMATION` and `$LOGGED_UTILITY_STREAM`, without codes. | "File Streams (Local File Systems)", ms.date 2025-07-08; [MS-FSCC] "NTFS Streams", last updated 2025-11-21 |
| D12 | NTFS attribute names include `$SECURITY_DESCRIPTOR`, `$EA`, `$EA_INFORMATION`, `$LOGGED_UTILITY_STREAM`, without codes. | [MS-FSCC] "NTFS Attribute Types", last updated 2023-09-20 |
| D13 | `BytesPerFileRecordSegment` is a per-volume value returned by `FSCTL_GET_NTFS_VOLUME_DATA`. | "NTFS_VOLUME_DATA_BUFFER structure (winioctl.h)", ms.date 2018-12-05 |

### Measurements

M1 to M13 come from `mftfacts` on 2026-11-12 over mem1_win11 (Windows 11, 26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100). The script parses the bytes itself, independently of the tool. "Accepted" means a candidate whose header passes and whose attribute walk (4.3) reaches the end marker. Columns are mem1, mem2, mem5, mem6, mem7.

| # | Measured | mem1 | mem2 | mem5 | mem6 | mem7 |
|---|---|---|---|---|---|---|
| M1 | "FILE" anywhere in physical memory | 45,545 | 44,697 | 28,766 | 16,189 | 20,642 |
| | "BAAD" anywhere | 91 | 56 | 85 | 33 | 45 |
| | accepted | 36,724 | 39,282 | 20,574 | 10,897 | 14,303 |
| | accepted at a multiple of 8 | all | all | all | all | all |
| | accepted at a multiple of 1024 | 35,010 | 39,213 | 20,403 | 10,669 | 14,244 |
| | most "FILE" in one MiB | 352 | 395 | 256 | 132 | 154 |
| M2 | update sequence array inside the first sector: array offset 0x30 and size field 3 | 38,424 of 38,424 | 40,598 of 40,599 | 20,895 of 20,895 | 11,369 of 11,369 | 15,215 of 15,215 |
| | accepted records 1024 bytes long; dword at 0x1C equals 1024 | all; all | all; all but 1 | all; all | all; all | all; all but 1 |
| M3 | raw tail census of candidates whose array fits: every tail holds the number ("protected") | 1,005 | 1,105 | 19 | 4 | 170 |
| | no tail holds it ("restored") | 35,766 | 39,379 | 20,840 | 11,337 | 15,034 |
| | some tails hold it, others not | 1,653 | 115 | 36 | 28 | 11 |
| | of those, the tail that does not hold it lies past the used bytes | 1,650 | 65 | 36 | 26 | 10 |
| M4 | accepted: first attribute at 0x38 | all | all | all | all | all |
| | dword at 0x18 equals end marker offset + 8 | all | all but 6 | all | all | all but 1 |
| M5 | dword at 0x2C of the accepted record 1024 bytes on is one more | 27,552 of 27,840 | 29,319 of 29,578 | 15,325 of 15,475 | 8,005 of 8,044 | 10,714 of 10,753 |
| | accepted records whose dword at 0x2C is 0 name `$MFT`; 5 name `.` | 3; 1 | 1; 2 | 5 (and 7 unnamed); 3 | 1; 1 | 1; 1 |
| | word at 0x2A when the array is at 0x30 | 0 in all | 0 in all | 0 in all | 0 in all | 0 in all |
| M6 | type codes in accepted records outside the D3 table | 0x50, 0xD0, 0xE0 | 0x50, 0xD0, 0xE0, 0x100 | same | same | same |
| | type codes non-decreasing within each accepted record | all | all | all | all | all |
| | shortest nonresident attribute record | 0x48 | 0x48 | 0x48 | 0x48 | 0x48 |
| M7 | `$STANDARD_INFORMATION` value length 72 / 48 | 36,710 / 13 | 31,205 / 3 | 20,430 / 19 | 10,329 / 1 | 13,793 / 1 |
| | `$FILE_NAME` flags (0, 1, 2, 3); other values | 36,072, 0, 0, 28; none | 11,995, 25,814, 23,328, 6,607; none | 13,969, 12,037, 12,039, 7,321; none | 7,766, 6,272, 6,270, 2,882; none | 6,779, 8,819, 8,831, 3,317; none |
| | `$FILE_NAME` value length is 0x42 + 2 × `FileNameLength`, rounded up to 8 | all | all but 4 | all | all | all |
| M8 | each of the four quadwords at 0, 8, 0x10, 0x18 of `$STANDARD_INFORMATION` decodes to 1980..2049 (per slot) | 36,723 of 36,723 | 31,205 to 31,207 of 31,208 | all | 10,329 to 10,330 of 10,330 | all |
| | the same at 8, 0x10, 0x18, 0x20 of `$FILE_NAME` (first per record) | 36,095 to 36,096 of 36,096 | 37,433 to 37,434 of 37,434 | all | all | all |
| | slot 1 later than slot 2 | 57 of 36,723 | 45 of 31,205 | 49 of 20,449 | 53 of 10,329 | 310 of 13,794 |
| | slot 0 later than slot 2 | 387 | 82 | 99 | 181 | 117 |
| | slot 0 later than slot 1 | 20,446 | 11,369 | 948 | 1,031 | 1,322 |
| | slot within 7 days of the capture's latest time (slots 0, 1, 2, 3) | 10,968, 13,277, 15,908, 35,684 | 5,903, 4,476, 10,398, 14,339 | 1,055, 1,822, 1,957, 1,537 | 2,524, 2,704, 3,489, 2,877 | 1,442, 2,257, 2,416, 2,272 |
| M9 | mem7 ground truth: the capture file `mem7_server2025.mem`, created at 19:09:32 UTC by the acquisition (its own log), has three record copies, all four slots 2026-10-29T19:09:32.4008404Z | | | | | 3 |
| M10 | dword at 0x20 of `$STANDARD_INFORMATION`: bit 0x40000 set with `$EA` (0xE0) in the record / bit without `$EA` / `$EA` without bit | 4,149 / 0 / 0 | 3,547 / 1,160 / 0 | 799 / 0 / 2 | 3,452 / 28 / 0 | 3,735 / 44 / 0 |
| | bit 0x400 with `$REPARSE_POINT` / bit alone / attribute alone | 31,077 / 0 / 0 | 691 / 134 / 0 | 52 / 0 / 0 | 93 / 0 / 0 | 6 / 21 / 0 |
| M11 | flag 0x0002 set and `$INDEX_ROOT` (0x90) present / flag alone / attribute alone | 5,341 / 0 / 9 | 8,532 / 65 / 10 | 3,730 / 1 / 13 | 2,514 / 4 / 4 | 4,206 / 2 / 4 |
| M12 | copies per (dword at 0x2C, sequence number): 1 / 2-3 / more | 7,183 / 8,762 / 1,938 | 22,705 / 6,562 / 465 | 2,452 / 6,761 / 320 | 10,730 / 79 / 1 | 14,149 / 74 / 1 |
| | accepted records with both `$STANDARD_INFORMATION` and `$FILE_NAME` times | 36,096 | 31,094 | 20,437 | 10,329 | 13,794 |
| | with only one / neither | 627 / 1 | 6,454 / 1,734 | 107 / 30 | 540 / 28 | 414 / 95 |
| | resident `$DATA` unnamed / named | 1,029 / 16 | 3,418 / 12 | 1,298 / 39 | 684 / 5 | 762 / 4 |
| M13 | word at 0x12 equals the number of `$FILE_NAME` attributes in the record, DOS names counted, in base records without `$ATTRIBUTE_LIST` | 36,718 of 36,718 | 29,392 of 29,393 | 20,398 of 20,398 | 9,989 of 9,989 | 13,473 of 13,473 |
| | the same in base records with `$ATTRIBUTE_LIST` / in extension records, whose other names lie in other records | 3 of 3 / 3 of 3 | 40 of 1,814 / 74 of 8,075 | 10 of 58 / 23 of 118 | 10 of 341 / 14 of 567 | 8 of 321 / 9 of 509 |
| | the same counting only names that are not `FILE_NAME_DOS` alone (base, in use, no `$ATTRIBUTE_LIST`) | 36,717 of 36,717 | 9,516 of 29,306 | 8,433 of 20,387 | 4,240 of 9,937 | 4,609 of 12,213 |
| | records with rows (`mftfacts -tool`): dword at 0x1C 1024; dword at 0x18 a multiple of 8 no larger than it | all; all | all but 1 (2,623,407,104); all | all; all | all; all | all; all |

## 4. Algorithm

### 4.1 Finding candidates

1. Scan physical memory in 1 MiB windows that overlap by 4095 bytes, so a record of up to 4096 bytes is whole in the window where it starts (`memory.ScanWindows`).
2. Every "FILE" (D2) at a physical address that is a multiple of 8 (M1) is a candidate. At most `MaxMatchesPerChunk` candidates per window are parsed.

### 4.2 Header and update sequence array

1. **Array placement.** `UpdateSequenceArrayOffset` must be even, at least 0x2A (the array member's offset, D2), and the array (offset + 2 × size field) must end before the last word of the first 512 bytes (D1).
2. **Record size.** The size field counts words: the sequence number and one saved word per 512-byte stride (D1's n + 1, M2). Size = (field − 1) × 512, from 1024 to 4096 bytes. The volume's record size is not in memory (D13); every accepted record measured is 1024 (M2).
3. The record bytes are copied; the image is never changed.
4. **Restore (D1).** For each stride, its tail word is compared with the update sequence number and with its saved word. A tail equal to both says nothing. A tail equal to the number is replaced by the saved word and marked held; any other tail is marked not held.
5. The header gives `SequenceNumber` (0x10), `Flags` (0x16) and `BaseFileRecordSegment` (0x20) (D2, D6), and three values Learn leaves reserved, reported as read and not checked (O9): the link count, the word at 0x12 (`Reserved2`), which counts the record's `$FILE_NAME` attributes, DOS names included (M13), so it is not the hard-link count Windows reports; the bytes in use, the dword at 0x18, which ends at the end marker's quadword (M4); and the bytes allocated, the dword at 0x1C, the record size (M2) (`Reserved3`). When the array is at 0x30 or later, the dword at 0x2C is the record's segment number (M5); otherwise the number is unknown.

### 4.3 Attribute walk

1. Start at `FirstAttributeOffset`, which must be a multiple of 8 (D3), at or past the end of the update sequence array, and inside the record.
2. For each attribute record:
   1. A type code of 0xFFFFFFFF is the end marker (D7). The used bytes end at the end of its quadword (D3, M4).
   2. Type codes must not decrease (M6).
   3. `FormCode` must be 0 or 1 (D3).
   4. `RecordLength` must be a multiple of 8, at least 0x18 for resident and 0x48 for nonresident form (D3, M6), and inside the record.
   5. A name of `NameLength` characters at `NameOffset` must end inside the attribute record (D3).
   6. A resident value must start at or after 0x18 and end inside the attribute record (D3).
   7. The next attribute record starts `RecordLength` bytes on.
3. The record is accepted only when the end marker is reached inside it.

### 4.4 Fixup form

Only strides whose tail lies inside the used bytes count (M3): past the end marker a stride holds no attribute bytes, and in 1,787 of 1,843 records with mixed tails that is the stride that differs.

| Form | Rule |
|---|---|
| `protected` | Every counted stride held the number. The record is in its written form; the restore made it whole. |
| `restored` | No counted stride held the number. The record is in its read form: the tails are its own bytes and the saved words may be stale. |
| `torn` | Some counted strides held the number and others did not: D1's failed multisector transfer. The record is kept and marked (O3). |

### 4.5 Attributes read

1. `$STANDARD_INFORMATION` (0x10): must be resident (D4) and its value at least 0x30 bytes (D4's reserved block, M7). Quadwords 0, 8, 0x10 and 0x18 are `CreationTime`, `LastWriteTime`, `ChangeTime` and `LastAccessTime` (D9 names, M8 order and type); the dword at 0x20 is `FileAttributes` (D10, M10).
2. `$FILE_NAME` (0x30): must be resident and its value at least 0x42 bytes (D5). `ParentDirectory` at 0 (D5, D6); the name of `FileNameLength` UTF-16 characters at 0x42 must end inside the value; `Flags` may hold only `FILE_NAME_NTFS` and `FILE_NAME_DOS` (D5, M7). Quadwords 8, 0x10, 0x18, 0x20 are the same four times (M8).
3. An attribute that fails 1 or 2 gives no row and is counted; the record's other attributes still count.
4. **Record name.** The first `$FILE_NAME` whose flags hold `FILE_NAME_NTFS`; else the first with neither flag; else the first. A short (`FILE_NAME_DOS` only) name is the last choice because it is the 8.3 alias of a long one (D5, D11).
5. **Resident data.** A resident `$DATA` (0x80) with a name is a named stream (D11); without a name it is the file's default stream. Nonresident data gives no row.
6. **Time.** A FILETIME of 0 is absent (the zero `time.Time`); any other value is converted from 100-nanosecond intervals since 1601-01-01 UTC (D8) to UTC.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Signature "FILE" at a multiple of 8 | D2, M1 | Not a candidate |
| Array even, at or past 0x2A, ending before the last word of the first sector | D1, D2 | `errArray` |
| Record 1024 to 4096 bytes from the size field | D1, M2 | `errSize` |
| Whole record readable in the window | 4.1 | `errTruncated` |
| First attribute quadword-aligned, after the array, inside the record | D2, D3 | `errFirstAttribute` |
| Type codes non-decreasing | M6 | `errTypeOrder` |
| Form code 0 or 1 | D3 | `errForm` |
| Record length a quadword multiple, at least the form's header, inside the record | D3, M6 | `errAttributeSize` |
| Name inside the attribute record | D3 | `errAttributeName` |
| Resident value between the header and the attribute record end | D3 | `errValue` |
| End marker inside the record | D7 | `errNoEnd` |
| Counted strides agree | D1, M3 | Kept, `Fixup` = `torn`, counted |
| `$STANDARD_INFORMATION` resident, value ≥ 0x30 | D4, M7 | `errStandardForm`, `errStandardShort`; attribute counted |
| `$FILE_NAME` resident, value ≥ 0x42, name inside it, known flags only | D5, M7 | `errNameForm`, `errNameShort`, `errNameLength`, `errNameFlags`; attribute counted |

## 6. Failure modes

| Case | Result |
|---|---|
| No physical memory | `<tool>: ntfsrecord: no physical memory` (`ErrNoPhysicalMemory`) |
| Profile not Windows | `<tool>: ntfsrecord: profile is not windows` (`ErrNotWindows`) |
| Census | Diagnostic `<tool>: <n> FILE signatures at 8-byte multiples, <m> parsed as file record segments` |
| Rejected candidates | One diagnostic per reason: `<tool>: <n> candidate records rejected, first at 0x<addr>: <reason>` |
| Torn records | `<tool>: <n> records kept with fixup torn, first at 0x<addr>: <reason>` |
| Attributes not read | `<tool>: <n> attributes not read, first in the record at 0x<addr>: <reason>` |
| `MaxMatchesPerChunk` hit | `<tool>: <n> windows over MaxMatchesPerChunk (<cap>), first signature dropped at 0x<addr>`; the rest of that window is not parsed |
| Unreadable windows | `<tool>: physical memory not fully scanned: <coverage>`; in strict mode the rows found and the error are returned |

## 7. Result schema

Every row embeds `RecordHeader`: `RecordPhysical` (physical address of the record), `SegmentNumber` and `SegmentNumberKnown` (4.2 step 5), `SequenceNumber`, `LinkCount` (the word at 0x12: the number of `$FILE_NAME` attributes the record holds, DOS names included (M13), so a single link whose 8.3 name is a `FILE_NAME_DOS` attribute of its own counts 2; it is not the hard-link count Windows reports), `BytesInUse`, `BytesAllocated` (4.2 step 5, as read), `BaseSegmentNumber` (48-bit segment of `BaseFileRecordSegment`, 0 for a base record), `Flags` (raw), `InUse` (`FILE_RECORD_SEGMENT_IN_USE`), `NameIndexPresent` (`FILE_FILE_NAME_INDEX_PRESENT`, set on directories: M11), `Fixup` (`protected`, `restored`, `torn`). `AttributeOffset` is the attribute record's offset inside the record.

| Tool | Row | One row per | Fields |
|---|---|---|---|
| `windows.ntfs.scan_records` | `Row` | readable `$STANDARD_INFORMATION` or `$FILE_NAME` | `AttributeType` (`$STANDARD_INFORMATION` or `$FILE_NAME`), `FileAttributes` (`$STANDARD_INFORMATION` only), `ParentSegmentNumber`, `ParentSequenceNumber`, `Namespace` (`$FILE_NAME` only: `FILE_NAME_NTFS`, `FILE_NAME_DOS`, `FILE_NAME_NTFS\|FILE_NAME_DOS`, `neither`), `Name` and `NameKnown` (the attribute's own name for `$FILE_NAME`, the record name of 4.5 step 4 for `$STANDARD_INFORMATION`), `CreationTime`, `LastWriteTime`, `ChangeTime`, `LastAccessTime` (UTC, zero when absent) |
| `windows.ntfs.scan_streams` | `StreamRow` | named resident `$DATA` | `Name`, `NameKnown` (record name), `StreamName`, `Value` (the whole value) |
| `windows.ntfs.scan_resident_data` | `DataRow` | unnamed resident `$DATA` | `Name`, `NameKnown`, `Value` |

Rows come in physical order of their records, then attribute order within the record. Every copy of a record is a row of its own (M12).

## 8. Limits

- `MaxMatchesPerChunk`: candidates parsed per 1 MiB window. The most measured is 395 (M1); the default is far above it.
- The record size is capped at 4096 bytes, one page, which bounds every copy and the window overlap.

## 9. Acceptance

1. Synthetic fixtures (`tools/windows/ntfsrecord/s42_fixture_test.go`, used by `record_test.go` and `ntfs_scan_records_test.go`), built from the D1 to D6 layouts: a record in restored and protected form; the fixup forms of 4.4, including a lost stride past the used bytes and a torn record; every rejection of section 5; the `$STANDARD_INFORMATION` and `$FILE_NAME` fields, namespaces and rejections; the record name choice; FILETIME conversion; a segment number only with the array at 0x30; the link count and the two dwords as written; the window scan with an unaligned copy, a record across a window edge, a truncated record, the `MaxMatchesPerChunk` cap and an unreadable window in lenient and strict mode; the three tools' rows and diagnostics.
2. Fuzz target `FuzzParseRecord` (arbitrary bytes; no panic; attributes quadword-aligned, increasing, with non-decreasing type codes; a fixup form of 4.4; the record name known exactly when a `$FILE_NAME` reads; the link count and the two dwords equal the bytes at 0x12, 0x18 and 0x1C), 30 s on 2026-11-12: 121,204 executions with `-fuzzminimizetime=1s`, then 62,710 with the default minimisation time on the grown corpus (minimising new 1 KiB inputs takes most of a default run). Rerun with the header-dword check after O9, `-fuzzminimizetime=1s`: 2,535,279 executions, no failure.
3. On the captures, `mftfacts -tool`, 2026-11-12:

| Capture | Candidates | Records | `windows.ntfs.scan_records` rows ($STANDARD_INFORMATION / $FILE_NAME) | Records with both times | `protected` / `restored` / `torn` (records with rows) | `scan_streams` rows | `scan_resident_data` rows |
|---|---|---|---|---|---|---|---|
| mem1_win11 | 39,076 | 36,724 | 72,823 (36,723 / 36,100) | 36,096 | 2,387 / 34,336 / 0 | 16 | 1,029 |
| mem2_win10 | 41,161 | 39,282 | 98,952 (31,208 / 67,744) | 31,094 | 797 / 36,751 / 0 | 12 | 3,418 |
| mem5_server2016 | 22,028 | 20,574 | 65,815 (20,449 / 45,366) | 20,437 | 29 / 20,515 / 0 | 39 | 1,298 |
| mem6_server2025 | 12,173 | 10,897 | 33,520 (10,330 / 23,190) | 10,329 | 4 / 10,865 / 0 | 5 | 684 |
| mem7_server2025 | 16,113 | 14,303 | 41,540 (13,794 / 27,746) | 13,794 | 113 / 14,095 / 0 | 4 | 762 |

   - The tool's record counts equal the measure script's independent counts (M1) on every capture.
   - Rejections by rule, mem1 / mem2 / mem5 / mem6 / mem7: array 629 / 558 / 1,127 / 804 / 897; size 23 / 5 / 6 / 0 / 1; first attribute 428 / 235 / 146 / 258 / 83; type order 472 / 307 / 4 / 5 / 51; form 267 / 446 / 29 / 26 / 65; record length 183 / 128 / 10 / 4 / 34; name 0 / 34 / 0 / 0 / 0; value 350 / 166 / 132 / 179 / 679; no end marker 0 in all.
   - Attributes not read: 2 nonresident `$FILE_NAME` on mem2, none elsewhere.
   - Stream names seen: `$Config`, `$Info`, `$Max`, `$SRAT`, `SmartScreen`, `Win32App_1`, `Zone.Identifier`.
   - mem7: the three copies of the capture file's record give `Name` `mem7_server2025.mem` and `CreationTime` 2026-10-29T19:09:32.4008404Z, within 0.14 s of the logged start (M9).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | D1 calls `UpdateSequenceArraySize` a size in bytes; every record measured holds 3 for 1024 bytes, which is a count of words (M2). The rule follows the measurement. | Owner decision; a 4096-byte-record volume (4Kn disk) capture |
| O2 | Learn leaves the bytes of `$STANDARD_INFORMATION` before 0x30 and of `$FILE_NAME` from 8 to 0x40 reserved (D4, D5). The four FILETIME slots, their order (creation, last write, change, last access) and `FileAttributes` at 0x20 rest on M8 to M10 only: slot 2 is at least slots 0 and 1 in over 99 % of records, slot 0 is later than slot 1 in copied and installed files, slot 3 is the most recent where access updates run, and bit 0x40000 (`FILE_ATTRIBUTE_EA`) follows `$EA`. The mem7 ground truth fixes the epoch and UTC but has four equal slots. | Owner decision; a capture of a volume with files given four distinct times by `SetFileInformationByHandle` |
| O3 | Torn records are kept and marked, not rejected; none were seen once only counted strides decide (4.4). | Owner decision: reject instead |
| O4 | The segment number at 0x2C (array at 0x30), the 8-byte alignment of copies, the first attribute at 0x38, non-decreasing type codes and the 0x48 nonresident minimum rest on measurement (M1, M4 to M6); Learn's header ends at 0x2A. | A primary source for NTFS 3.1's header |
| O5 | Type codes 0x50, 0xD0, 0xE0 and 0x100 appear in accepted records (M6). MS-FSCC names `$SECURITY_DESCRIPTOR`, `$EA_INFORMATION`, `$EA` and `$LOGGED_UTILITY_STREAM` (D11, D12) without codes, so the rows do not name them; they give no rows. | Owner decision: a source pairing names and codes |
| O6 | "BAAD" (M1) is not a documented signature and is not parsed. | A primary source for it |
| O7 | Every copy is reported (M12: up to more than three per record on mem1, mem2 and mem5). Folding copies by segment and sequence number would lose the differences between them. | Owner decision |
| O8 | Row field and type names are new (owner question Q2): `RecordPhysical`, `SegmentNumber`, `SegmentNumberKnown`, `BaseSegmentNumber`, `Flags`, `InUse`, `NameIndexPresent`, `Fixup`, `AttributeOffset` (now inside the record), `AttributeType` (now with `$`), `FileAttributes`, `ParentSegmentNumber`, `ParentSequenceNumber`, `Namespace`, `Name`, `NameKnown`, `CreationTime`, `LastWriteTime`, `ChangeTime`, `LastAccessTime`, `StreamName`, `Value`; `StreamRow` and `DataRow`; `NameStreams`. The registered names `windows.ntfs.scan_records`, `windows.ntfs.scan_streams` and `windows.ntfs.scan_resident_data` are kept; there are no option keys. | Owner decision (Q2) |
| O9 | Link count (Learn's `Reserved2`) and the bytes-in-use and allocated dwords (`Reserved3`) are not reported; M2 and M4 show the latter two agree with the record size and the end marker. Owner decision 2026-11-12: Add as measured fields. Done: `RecordHeader.LinkCount`, `BytesInUse`, `BytesAllocated` (4.2 step 5, section 7; `tools/windows/ntfsrecord/record.go`, `ntfs_scan_records.go`, fixture, row test and fuzz check). Re-measured with `mftfacts` on the five Windows captures (M13): the link count is the number of `$FILE_NAME` attributes in the record, DOS names included, so it equals Windows' link count only where no 8.3 names exist (mem1). Owner decision 2026-11-12 (follow-up D12): keep the name, state the meaning in S42. Done: section 7 says what `LinkCount` counts. | Owner decision: add them as measured fields |
| O10 | Follow-up R4: a record whose attribute walk (4.3) breaks before the quadword its own bytes in use (dword 0x18) give for the end marker reaches no end marker, so 4.3 step 3 rejects the record whole and none of its attributes gives a row. Owner decision 2026-11-12: measure before deciding. Result: a spec choice, not a miss. `mftfacts -explain` on mem1, mem2, mem5 and mem7 shows four kinds of break: a `RecordLength` that does not fit, a value past its attribute record, a form code above 1, or a name past its attribute record. Sample, attribute and record: mem5 0x1008ef8 in 0x1008ec0, 0x27393f48 in 0x27393e38, 0x5f629fe0 in 0x5f629fa8, 0xa7c07fe0 in 0xa7c07fa8, 0xcd185f58 in 0xcd185ec0; mem2 0x92e038, 0x1a9e1098, 0x3c825038, 0x4fc89038, 0x7a44f038 (each in the record at its page start); mem1 0x15e6f80 in 0x15e6f48, 0x224fc098, 0x2fed5fa8 in 0x2fed5f70, 0x8a7f7038, 0xb6219098; mem7 0x2413038, 0x14fcf838 in 0x14fcf800, 0x1dfeb438 in 0x1dfeb400 (form code), 0x307d8098, 0x4fba8098. | Closed: rule kept |
| O11 | Follow-up R5: how `Value` (hex) and name cells of `scan_resident_data`, `scan_streams` and `scan_records` are rendered. Owner decision 2026-11-12: map each render back to the capture's bytes. Result: (a) a stride tail is shown as 4.2 step 4 restores it, not as stored; (b) a record is named by its first long name (4.5 step 4); (c) a name shows its whole `FileNameLength`, NULs included (4.5 step 2); (d) the 8.3 alias, as before. No tool output changed. | Closed |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Count of words, as measured |
| O2 | Keep the measured layout |
| O3 | Keep and mark |
| O4 | Keep the measured layout |
| O5 | Unnamed, no rows |
| O6 | Do not parse |
| O7 | Report every copy |
| O8 | Accept the new names |
| O9 | Add as measured fields |

## 11. Provenance

Written from Microsoft Learn's NTFS structure pages, the Win32 and WDK documentation of file times, attributes and streams, [MS-FSCC], and the project's own measurements. Every rule rests on the sources and measurements above.
