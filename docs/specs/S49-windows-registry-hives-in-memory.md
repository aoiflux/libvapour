# S49: Windows registry hives in memory

Version 1, 2026-11-12.

## 1. Purpose

Windows loads each registry hive into memory and keeps it there while it is mounted. The memory copy holds the hive's stable storage, which is the content of its file, and its volatile storage, which holds keys that exist only in memory and never reach the file. A capture can therefore show keys and values that the hive files on disk do not hold, or no longer hold.

An examiner wants three things: the list of loaded hives with the file each came from and the place it is mounted; the keys and values of any hive, read through the same cell map the kernel uses; and a hive file rebuilt from memory for offline tools. Many other tools in this project read the registry through this package: SAM, LSA secrets, cached logons, services, autostart entries, scheduled tasks, UserAssist, the compatibility cache and the timeline.

This specification defines how the hives are found, how a cell index is turned into an address, how each cell kind is decoded, the checks each cell must pass, and how a hive is written to a file.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory and symbol table | The `CmpHiveListHead` and `CmpRegistryProcess` symbols and the registry types of section 3, from the kernel PDB through the project's symbol tables (`symbols/autoload`). |
| Registry process memory | The address space of the Registry process (4.2), through `tools.Context.ProcessSpace`. |
| Process list | S25 `processlist.Run`, without the PID filter, to find the Registry process. |
| Pool scan | `registryhivescan.Run`, which finds `_CMHIVE` allocations by pool tag; used by the gathering functions (4.7). |
| Options | `windows.registry.list_hives.name` (string, a hive filter, 4.7 step 5); `output_dir` and `max_dump_size` for `windows.registry.dump_hives`; `strict`. |
| Limits | `MaxListEntries` (hive list walk, subkeys and values per key), `MaxNameBytes` (hive path strings), `MaxBufferBytes` (bytes of one cell or one value), `MaxArtifactBytes` through `DumpLimit` (hive file size). |

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | Value types: `REG_NONE` 0, `REG_SZ` 1, `REG_EXPAND_SZ` 2, `REG_BINARY` 3, `REG_DWORD` 4 (also `REG_DWORD_LITTLE_ENDIAN`), `REG_DWORD_BIG_ENDIAN` 5, `REG_LINK` 6, `REG_MULTI_SZ` 7, `REG_QWORD` 11 (also `REG_QWORD_LITTLE_ENDIAN`). | Microsoft Learn, [MS-RRP] 2.2.5 "RVALENT", updated 2024-04-23, accessed 2026-11-12. |
| D2 | `REG_RESOURCE_LIST` is 0x00000008, "A device driver resource list". | Microsoft Learn, [MS-RPRN] "Registry Type Values", updated 2025-08-11, accessed 2026-11-12. |
| D3 | `REG_SZ` and `REG_EXPAND_SZ` are null-terminated strings; `REG_LINK` is "A null-terminated Unicode string that contains the target path of a symbolic link"; `REG_MULTI_SZ` is "A sequence of null-terminated strings, terminated by an empty string (`\0`)", and "it's not possible to include a zero-length string in the sequence". A stored string "might not have been stored with the proper terminating null characters". `REG_DWORD_BIG_ENDIAN` stores the highest byte first. | Microsoft Learn, "Registry value types", dated 2023-02-08, updated 2025-03-11, accessed 2026-11-12. |
| D4 | Size limits: key name 255 characters; value name 16,383 characters; value data "Available memory (latest format) 1 MB (standard format)"; "A registry tree can be 512 levels deep." | Microsoft Learn, "Registry element size limits", dated 2022-07-22, accessed 2026-11-12. |
| D5 | "Key names are not case sensitive. Key names cannot include the backslash character (\\), but any other printable character can be used. Value names and data can include the backslash character." "The name of each subkey is unique with respect to the key that is immediately above it." | Microsoft Learn, "Structure of the Registry", dated 2018-05-31, updated 2025-04-15, accessed 2026-11-12. |
| D6 | A key has at most "one unnamed value"; a NULL or empty value name sets "the key's unnamed or default value". | Microsoft Learn, "RegSetValueExW function (winreg.h)", updated 2025-07-01, accessed 2026-11-12. |
| D7 | A hive is "a logical group of keys, subkeys, and values in the registry that has a set of supporting files"; the standard hives' files are `System`, `Sam`, `Security`, `Software`, `Default` and `Ntuser.dat`. Files have a standard and a latest format. | Microsoft Learn, "Registry Hives", dated 2018-05-31, accessed 2026-11-12. |
| D8 | User space is 0x00000000 through 0x7FFFFFFF for a 32-bit process and 0x000'00000000 through 0x7FFF'FFFFFFFF for a 64-bit process on 64-bit Windows; kernel-mode code shares one system space. | Microsoft Learn, "Virtual Address Spaces", dated 2024-06-28, accessed 2026-11-12. |

### Kernel PDB types

Read through the project's symbol tables (`hivefacts -types`) for ntkrnlmp.pdb 0D960CE103763A6097E839406D8B369F-1 (mem1, 26100), F57E740B088E5056E8AF0772F1CC5BEB-1 (mem2, 19045), 3DFC5F7228304C26859E55E481700385-1 (mem5, 14393) and 953A8DE880B0818C32DA2DEC1D79C2D9-1 (mem6 and mem7, 26100).

| # | Fact |
|---|---|
| P1 | `_CMHIVE` begins with `Hive` (`_HHIVE`, +0) and has `HiveList` (`_LIST_ENTRY`; +0x648 on 26100, +0x640 on 19045, +0xaa8 on 14393), `FileFullPath`, `FileUserName` and `HiveRootPath` (`_UNICODE_STRING`; +0x720, +0x730, +0x740 on 26100; +0x718, +0x728, +0x738 on 19045; +0xbb0, +0xbc0, +0xbd0 on 14393) and `RootKcb` (`*_CM_KEY_CONTROL_BLOCK`; +0xb78, +0xb70, +0x1008). `_CM_KEY_CONTROL_BLOCK.KeyCell` is an `unsigned int`. |
| P2 | `_HHIVE` has `Signature` (`unsigned int`, +0), `BaseBlock` (`*_HBASE_BLOCK`, +0x40) and `Storage` (`[2]_DUAL`; +0x118 on 26100, +0x110 on 19045, +0x578 on 14393). `_DUAL` (0x278 bytes) has `Length` (`unsigned int`, +0), `Map` (`*_HMAP_DIRECTORY`, +8) and `SmallDir` (`*_HMAP_TABLE`, +0x10). |
| P3 | `_HMAP_DIRECTORY` is `Directory`, `[1024]*_HMAP_TABLE`. `_HMAP_TABLE` is `Table`, `[512]_HMAP_ENTRY`. `_HMAP_ENTRY` has `BlockOffset` (`unsigned long long`, +0) and `PermanentBinAddress` (`unsigned long long`, +8); it is 0x18 bytes on 26100 and 19045 and 0x28 bytes on 14393, which adds `TemporaryBinAddress` (+0x10) and moves `MemAlloc` from +0x10 to +0x20. |
| P4 | `_HBASE_BLOCK` is 0x1000 bytes with `Signature` (+0), `Sequence1`, `Sequence2`, `TimeStamp`, `Major` (+0x14), `Minor` (+0x18), `Type`, `Format`, `RootCell` (+0x24), `Length` (+0x28), `Cluster`, `FileName` (`[64]unsigned char`, +0x30) and `CheckSum` (+0x1fc). |
| P5 | `_HBIN` (0x20 bytes) has `Signature` (+0), `FileOffset` (+4), `Size` (+8) and `TimeStamp` (+0x14) on 19045 and 14393. The 26100 tables have no `_HBIN`. |
| P6 | `_CM_KEY_NODE` (identical on all three builds): `Signature` `unsigned short` +0, `Flags` `unsigned short` +2, `LastWriteTime` `_LARGE_INTEGER` +4, `Parent` +0x10, `SubKeyCounts` `[2]unsigned int` +0x14, `SubKeyLists` `[2]unsigned int` +0x1c, `ValueList` `_CHILD_LIST` +0x24 (`Count` +0, `List` +4), `Security` +0x2c, `Class` +0x30, `NameLength` `unsigned short` +0x48, `ClassLength` `unsigned short` +0x4a, `Name` `[1]wchar_t` +0x4c. |
| P7 | `_CM_KEY_VALUE` (all builds): `Signature` `unsigned short` +0, `NameLength` `unsigned short` +2, `DataLength` `unsigned int` +4, `Data` `unsigned int` +8, `Type` `unsigned int` +0xc, `Flags` `unsigned short` +0x10, `Name` `[1]wchar_t` +0x14. |
| P8 | `_CM_KEY_INDEX` (all builds): `Signature` `unsigned short` +0, `Count` `unsigned short` +2, `List` `[1]unsigned int` +4. `_CM_INDEX` is 8 bytes with `Cell` +0 and a hash or name hint at +4. `_CM_BIG_DATA`: `Signature` +0, `Count` `unsigned short` +2, `List` `unsigned int` +4. |
| P9 | `CmpHiveListHead` and `CmpRegistryProcess` are kernel symbols on 26100 and 19045; 14393 has `CmpHiveListHead` and no `CmpRegistryProcess`. |

### Measurements

M1 to M15 come from `hivefacts` on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100). `-hives` walks the hives with its own raw reads and no use of this package; `-tool` runs this package's reader.

| # | Measured |
|---|---|
| M1 | `CmpHiveListHead` walks to 24, 29, 19, 29 and 24 `_CMHIVE` entries (mem1, mem2, mem5, mem6, mem7), every one with `_HHIVE.Signature` 0xbee0bee0. On mem7 a 25th entry, which its forward neighbour and the head's `Blink` both name, has `Flink` and `Blink` 0, as an entry being unlinked would; the S03 recovering walk stops before it in both directions and reports it, and the pool scan does not find its hive either (24 allocations). |
| M2 | `FileFullPath` is empty on every hive of every capture. `FileUserName` holds the file path (`\SystemRoot\System32\Config\SOFTWARE`, `\??\C:\Users\…\ntuser.dat`, `\Device\HarddiskVolume1\EFI\Microsoft\Boot\BCD`) except for the master hive, SYSTEM and HARDWARE, which have none. `HiveRootPath` holds the mount point (`\REGISTRY\MACHINE\SYSTEM`, `\REGISTRY\USER\S-1-5-…`, `\REGISTRY\A\{…}`), empty only for the master hive. |
| M3 | `CmpRegistryProcess` holds a kernel handle value (0xffffffff80000060, 0xffffffff8000005c, 0xffffffff80000054, 0xffffffff80000054), not a pointer. One process named `Registry` exists on each of the four captures that have the symbol, with parent process ID 4 (PIDs 276, 128, 124, 124); mem5 has neither. |
| M4 | Bin addresses: SYSTEM's and HARDWARE's bins are kernel addresses; on 19045 and 26100 the bins of SOFTWARE, user hives and application hives are user addresses (for example 0x25d82c41000 on mem2), which read only through the Registry process. On mem5 every bin is a kernel address. |
| M5 | Map shape: `Storage[i].Map` points at a directory whose slot *d* holds the table for blocks 512·*d* to 512·*d*+511. When a storage has at most 512 blocks, `Map` points at that storage's own `SmallDir` member (for example hive+0x120 on 19045, `Storage` +0x110 plus `SmallDir` +0x10), so `SmallDir` is directory slot 0; this holds on every such storage measured. SOFTWARE on mem2 uses 39 table slots. |
| M6 | `PermanentBinAddress` carries flags in its low four bits: values 0x0 to 0x5 and 0x8 to 0xd occur (mem1 21,919 entries: 0x1 17,860, 0x9 3,310, 0x0 589, 0x8 389, others under 50 each). With the low four bits cleared it is the address of a bin header beginning `hbin` (mem1 17,861 of 17,938 readable headers; mem5 22,660 of 22,660). `BlockOffset` is the block's offset in its bin: the bin's `FileOffset` equals the block's storage offset less `BlockOffset` in 17,838 of 17,938 (mem1), 9,777 of 10,177 (mem2), 22,628 of 22,660 (mem5), 7,851 of 7,857 (mem6) and 4,407 of 4,516 (mem7) readable headers. A cell's address is therefore the bin address plus `BlockOffset` plus the cell index's offset in the block. |
| M7 | Cell size word: the 4 bytes at the cell address are a negative 32-bit size whose magnitude includes the word, for 1,064,883 stable and 1,875 volatile cells reached on mem1 (341 and 8 positive), and for every cell on mem5 (1,666,775 and 1,423). The root key cell is 0x20 in every base block and every `RootKcb.KeyCell` that reads (all five captures), the first cell after a 0x20-byte bin header. |
| M8 | Signatures (two ASCII bytes at +0): key cells `nk`; values `vk`; subkey lists `lf` (140, 3,484, 1,247, 321, 289), `lh` (70,807, 37,078, 96,952, 24,622, 11,842) and `ri` (24, 11, 23, 11, 11), every `ri` entry leading to `lf` or `lh`, never to `ri`. No `li` list is found on any capture. A list with any other signature appears on mem1 (5), mem2 (1) and mem7 (23) and leads to cells that are not key nodes: on mem2 one such list in SYSTEM made a naive walk report 2,000,000 keys. Key cells reached that are not `nk`: 23, 0, 18, 0, 7; on mem1 and mem5 they are `lk` cells under the master hive's `\REGISTRY\A`. |
| M9 | Key flags: every key has 0x20 except 1, 4 and 4 keys on mem5, mem6 and mem7 (flags 0); 0x20 keys decode as one byte per character and the others as UTF-16LE. The flag 0x4 occurs on hive root keys only (flags 0x2c: 22, 21, 19, 27, 13 keys, one per readable root), never on another key. `Parent` names the parent cell in all keys reached but one on mem7. Value names are one byte per character when `Flags` bit 0x1 is set (272,289 of 367,848 values on mem1) and UTF-16LE otherwise. |
| M10 | `DataLength` with bit 31 set holds the data in `Data` itself; the remaining length is 0 to 4 in every such value (mem1 lengths 0, 1, 2, 3, 4). |
| M11 | Data cells: every data cell whose capacity is below its value's length begins `db` (23, 17, 21, 12, 12 values), and no data cell that holds its length begins `db` (210,602, 138,345, 343,034, 93,097, 41,574). Big-data values run from 16,414 to 189,652 bytes; non-big values reach 123,164 bytes in one cell. Every big-data segment cell has capacity 16,348; in every non-last segment that reads, bytes 16,344 to 16,347 are zero while bytes 16,340 to 16,343 of string values are text (mem5, 21 values): each segment holds 16,344 bytes of data. |
| M12 | Volatile storage: lists named by `SubKeyLists[1]` have cell index bit 31 set and those named by `SubKeyLists[0]` have it clear, in every key reached. |
| M13 | Paging: of the cells the raw walk reached, stable storage reads 1,064,883 (46,428 unreadable) on mem1, 629,711 (72,300 unreadable, 3,061 without a map entry) on mem2, 1,666,775 (none unreadable) on mem5, 421,168 (64,836; 187) on mem6 and 211,612 (63,059; 1,014) on mem7. The base block does not read on 0, 10, 0, 9 and 11 hives; `RootKcb` gives the root for 5, 7 and 8 of those, and the first-cell rule of 4.4 for 4, 2 and 3. Some user-address pages are prototype pages that the Registry process layer does not resolve. |
| M14 | With bin header checking on (4.3 step 6), the reader reaches 185,481 of 189,968 keys on mem1, 67,860 of 102,750 on mem2, all 305,637 on mem5, 65,993 of 71,418 on mem6 and 27,089 of 44,907 on mem7: the header page is often out of memory while the cell pages are in. |
| M15 | `_HMAP_ENTRY` is 0x18 bytes on 19045 (`BlockOffset` +0, `PermanentBinAddress` +8), so table slot 170 lies at table +0xFF0 and ends 8 bytes into the table's next page. With raw reads of the whole entry, 2,246 and 1,711 stable map entries do not read on mem2 and mem6 (none on mem1 and mem5; 6,681 on mem7); in 2 of them on each of mem2 and mem6, all in SOFTWARE, the two members read and only the bytes past them are on a page out of memory. On mem2 SOFTWARE (`_CMHIVE` 0xffff9d01669cd000) block 0x48aa000 is one: its table page 0xffff9d0166d7b000 is valid and the next page's entry is a software entry. |

## 4. Algorithm

### 4.1 Layout

1. Read the members of P1 to P8 from the symbol table. A missing member is `ErrLayout`, except these, which a reader can do without: `_CMHIVE.Hive` (+0 on every build, P1), `HiveList` (needed only by 4.7, which then fails with `ErrLayout`), `FileFullPath`, `FileUserName` and `HiveRootPath` (left out of 4.7 step 3), `RootKcb` and `KeyCell` (4.4 skips that source), `_CM_KEY_NODE.Parent` (the parent check of 4.5 step 4 is skipped), `Class` and `ClassLength` (no class data) and `_CM_BIG_DATA` (big-data values are unreadable). With no `_HBIN` type the bin header members are taken at +0 (`Signature`) and +4 (`FileOffset`) with a 0x20-byte header, as P5 gives them on 19045 and 14393 and as M6 and M7 measure them on 26100.
2. The cell index shape comes from the array lengths: `Storage` gives the storage count, `Directory` the directory slots, `Table` the table slots and the size of `_HBASE_BLOCK` the block size. Each must be a power of two, the storage count must be 2, and the four widths must fill 32 bits (1 + 10 + 9 + 12 on every capture). Otherwise `ErrLayout`.
3. The pointer size must be 4 or 8.

### 4.2 Cell reader

1. A cell at a user address (D8) is read through the Registry process; any other through kernel memory.
2. When `CmpRegistryProcess` is absent (P9), bins are in kernel memory (M4) and the kernel-only reader is used.
3. Otherwise list processes (S25) and take the first named `Registry` whose `InheritedFromUniqueProcessId` is 4 (M3); its space reads user addresses. No such process, or a space that does not build, gives the kernel-only reader and a diagnostic. `CmpRegistryProcess` is not followed: it holds a handle (M3).

### 4.3 Translating a cell index

1. Bit 31 picks the storage (stable 0, volatile 1; M12). The offset is the remaining 31 bits; an offset at or past `Storage[s].Length` is `ErrCellOutside`.
2. Split the offset into directory slot, table slot and offset in block (4.1 step 2).
3. Read the table pointer from `Map` + slot × pointer size (M5); a pointer that does not read or is null is `ErrCellUnmapped`.
4. Read the `BlockOffset` and `PermanentBinAddress` members of the `_HMAP_ENTRY`, not the whole entry: an entry can end on a page that is out of memory past those members (M15). Clear the low four bits of `PermanentBinAddress` (M6). A zero bin is `ErrCellUnmapped`.
5. The cell address is bin + `BlockOffset` + offset in block (M6).
6. Bin header checking, off by default (M14): the header at the bin address must begin `hbin`, and for stable storage its `FileOffset` must equal the block's storage offset less `BlockOffset` (M6). Otherwise `ErrBinHeader`.
7. Directory pointers and map entries are cached per hive layer.

### 4.4 Root cell

1. The base block (`_HHIVE.BaseBlock`, one block, signature `regf` 0x66676572 measured in every readable base block) gives `RootCell`.
2. When it does not read: `_CMHIVE.RootKcb` → `KeyCell` (M7, M13).
3. When neither reads: cell 0x20, the first cell after the bin header (M7), if it decodes as a key node with flag 0x4 (M9). This use is reported.
4. Otherwise `ErrNoRootCell`.

### 4.5 Reading cells

1. Read the size word (M7). A word that does not read is `ErrCellUnreadable`; a non-negative word `ErrCellFree`; a magnitude under 4 `ErrCellSize`. The capacity is the magnitude less 4.
2. Read the cell body page by page up to what the caller needs, the capacity and `MaxBufferBytes`. A page that does not read leaves the members on it unread; it does not fail the cell.
3. **Key node.** The signature must be `nk` (M8). `LastWriteTime`, the subkey counts and lists, the value count and list, the class and the name are each read only when their bytes read; otherwise `LastWriteUnreadable`, `SubkeysUnreadable`, `ValuesUnreadable` or `NameUnreadable` is set. The name is `NameLength` bytes: one byte per character when `Flags` has 0x20, else UTF-16LE (M9). A name of more than 255 characters (D4), an odd UTF-16 byte count or a backslash (D5) is not taken: `NameUnreadable`.
4. **Subkeys.** For each storage whose count is not zero, read the list named in `SubKeyLists`. `lf` and `lh` lists hold `_CM_INDEX` entries (P8); `ri` lists hold cell indexes of `lf` or `lh` lists (M8). Any other signature, a nested `ri`, an entry that does not read, a key cell that fails 4.5 step 3, a key whose `Parent` is not the listing key (M9) or a repeated entry leaves the list incomplete. Fewer keys than `SubKeyCounts` says leaves it incomplete. More than `MaxListEntries` keys cuts it. Keys come in list order.
5. **Values.** Read `Count` cell indexes from the value list (at most `MaxListEntries`). Each must be a `vk` cell (M8). `Type` and `DataLength` set `TypeUnreadable` and `LengthUnreadable` when they do not read. The name is `NameLength` bytes, one byte per character when `Flags` has 0x1, else UTF-16LE (M9); more than 16,383 characters (D4) is `NameUnreadable`; a zero length is the unnamed value (D6), named `(Default)`. A value that fails is left out and the list marked incomplete.
6. **Value data.** Bit 31 of `DataLength` set: the data is the first *n* bytes of `Data` read little-endian, *n* ≤ 4 (M10); more is unreadable. Otherwise `Data` is a cell index. A cell whose capacity holds the length is the data (M11). A cell that does not must begin `db`: its `Count` segments listed at `List` each give 16,344 bytes, the last the remainder (M11). The data stops at the first byte that does not read, at a segment that does not read or is too small, or at `MaxBufferBytes`; a value whose data is shorter than its length is unreadable.
7. **Class data.** `ClassLength` bytes of the cell named by `Class`; none when any byte does not read.

### 4.6 Data text

1. `REG_SZ`, `REG_EXPAND_SZ`, `REG_LINK`: UTF-16LE up to the first NUL (D3).
2. `REG_MULTI_SZ`: the strings up to the first empty one (D3), joined by a line feed.
3. `REG_DWORD` with exactly 4 bytes, `REG_DWORD_BIG_ENDIAN` with exactly 4 bytes read big-endian (D3), `REG_QWORD` with exactly 8 bytes: `0x` and lower-case hexadecimal.
4. Every other type, and the numeric types at any other size: the bytes as two-digit lower-case hexadecimal separated by spaces.

### 4.7 Hive list and selection (`windows.registry.list_hives`)

1. Walk `CmpHiveListHead` with the S03 recovering walker (`MaxListEntries`, strict mode, diagnostics) (M1). No symbol is `ErrNoHiveList`.
2. Each entry less `_CMHIVE.HiveList` is a hive. A hive whose signature is not 0xbee0bee0 (M1) or whose stable length and map do not read is reported and skipped; strict mode fails the run.
3. `FileFullPath` is the first non-empty of `_CMHIVE.FileFullPath`, `FileUserName` and `HiveRootPath` (M2), each read up to `MaxNameBytes`; `Name` is its last path component; `RegistryPath` is `HiveRootPath`. Sizes are the two storage lengths; `RootCell` comes from 4.4 without its report.
4. Rows are in list order, which is load order: a boot-time hive comes before a later copy with the same name.
5. With the name option, select (step 6) on it.
6. **Selection.** A hive whose `Name`, last `FileFullPath` component or last `RegistryPath` component equals the filter ignoring case (D5) is an exact match. Exact matches win; otherwise hives whose `FileFullPath`, `Name` or `RegistryPath` contains the filter ignoring case.
7. **Gathering.** List hives, then append hives the pool scan finds that the list does not hold, merged by address. Opening by name or substring prefers listed hives and falls back to scan-only hives (a scan-only hive may be unloaded). Several listed hives with one name are reported and the first that opens is used.

### 4.8 Keys by path

1. Resolve the root (4.4), then each backslash-separated component in turn (empty components skipped) among the subkeys of 4.5 step 4, ignoring case (D5).
2. A component not found in a complete list is `ErrKeyNotFound`. Not found in an incomplete list, or with a subkey whose name did not read, is `ErrKeyUnreadable`: the key may exist.
3. Values by name follow the same rule; value names are compared ignoring case (O4).
4. The current control set is `ControlSet` and the three-digit `Select\Current` DWORD (1 to 999); when it does not read, `ControlSet001` is returned with read false, and the reporting form says so.

### 4.9 Hive file (`windows.registry.dump_hives`)

1. Without `output_dir`, `ErrNoOutputDir`.
2. For each listed hive, after the name option of 4.7 step 5: the file is the base block (one block) followed by the stable storage, 0 to `Storage[0].Length` (D7: the file is the stable content; the volatile storage is not written). The size must not exceed `DumpLimit`; a larger hive is refused whole and reported.
3. Stable storage is read block by block through 4.3; a block that does not translate and any page that does not read are written as zeros and recorded as gaps at their file offsets. A base block that does not read is written as zeros and flagged.
4. The file name is the S00 hive name from `FileFullPath` and the `_CMHIVE` address; files are created with `extract.CreateNew`.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| `_HHIVE.Signature` 0xbee0bee0 | M1 | Hive skipped (`ErrNotHive`) |
| Map shape fills 32 bits with powers of two | P2, P3, P4 | `ErrLayout` |
| Cell offset below the storage length | P2, M13 | `ErrCellOutside` |
| Directory slot and map entry read, bin non-zero | M5, M6 | `ErrCellUnmapped` |
| Size word negative, magnitude at least 4 | M7 | `ErrCellFree`, `ErrCellSize` |
| Signatures `nk`, `vk`, `lf`, `lh`, `ri`, `db` where expected | M8, M11 | `ErrCellSignature`; lists incomplete |
| `ri` entries are not `ri` | M8 | List incomplete |
| Subkey `Parent` is the listing key | M9 | Key left out; list incomplete |
| Key name ≤ 255 characters, no backslash | D4, D5 | `NameUnreadable` |
| Value name ≤ 16,383 characters | D4 | `NameUnreadable` |
| Resident data ≤ 4 bytes | M10 | Value unreadable |
| Short data cell begins `db`; 16,344 bytes per segment | M11 | Value unreadable |
| Root fallback cell has flag 0x4 | M7, M9 | `ErrNoRootCell` |
| Bin header `hbin` and `FileOffset` (opt-in) | M6, M14 | `ErrBinHeader` |

## 6. Failure modes

| Case | Result |
|---|---|
| Registry types missing | `ErrLayout` |
| No `CmpHiveListHead` | `ErrNoHiveList` |
| Hive list head does not read | S03 error; the tool fails |
| Hive list broken | S03 recovering walk; diagnostic; strict mode fails |
| Hive signature or storage does not read | Diagnostic `windows.registry.list_hives: hive at 0x<addr>: not opened: <error>`; strict mode fails |
| No Registry process on a build that has one | Diagnostic; user-address cells fail with `ErrUserCellNoSpace` |
| Root cell not readable | `ErrNoRootCell`; `OpenKey` returns `ErrKeyUnreadable` |
| Cell unreadable, free, outside or unmapped | The member, key or value is marked unreadable or left out; lists incomplete |
| `Select\Current` not readable | `ControlSet001`, read false; diagnostic from `CurrentControlSet` |
| Hive over the dump limit, file not created | Row with `Skipped`; diagnostic `windows.registry.dump_hives: hive at 0x<addr>: not saved: <reason>` |
| No `output_dir` | `ErrNoOutputDir` |

## 7. Result schema

`windows.registry.list_hives` returns `[]registryhive.Hive`:

| Field | Type | Meaning |
|---|---|---|
| `Name` | string | Last component of `FileFullPath` |
| `Address` | uint64 | `_CMHIVE` address |
| `FileFullPath` | string | 4.7 step 3 |
| `RegistryPath` | string | `HiveRootPath`, the mount point (new) |
| `RootCell` | uint32 | 0 when it does not read |
| `StableSize`, `VolatileSize` | uint64 | Storage lengths in bytes |

`windows.registry.dump_hives` returns `[]registryhive.DumpedHive`: the `Hive` fields and `FileName`, `Size` (bytes of the file), `Captured` (bytes read), `Gaps` (file offsets written as zeros), `Skipped` (reason, empty when written) and `BaseBlockUnreadable`.

The reading API returns `KeyNode` (`CellIndex`, `Address` of the size word, `Name`, `LastWrite` as a FILETIME, and the `…Unreadable` flags of 4.5 step 3) and `Value` (`Name`, `Type`, `Data` text of 4.6, `Raw` bytes read, `Length` declared, `TypeUnreadable`, `LengthUnreadable`, `NameUnreadable`; `Unreadable()` is true when the length did not read or `Raw` is shorter than `Length`).

## 8. Limits

- `MaxListEntries`: hive list entries, subkeys per key, values per key.
- `MaxNameBytes`: bytes of each hive path string.
- `MaxBufferBytes`: bytes of one cell body and of one value's data (D4 leaves values bounded only by memory).
- `DumpLimit` (`max_dump_size`, else `MaxArtifactBytes`): bytes of one hive file.

## 9. Acceptance

1. Synthetic fixtures (`tools/windows/registryhive/s49_fixture_test.go`, used by `hive_test.go`, `list_test.go` and `dump_test.go`) build hives in a sparse address space with the 26100 layout: translation through directory, table and entry with flag bits, outside and unmapped cells, free cells, bin header checking; key names in both encodings, overlong names and backslashes, members on a missing page; `lf`, `lh` and `ri` lists, a nested `ri`, an unknown list signature, a wrong parent, a repeated entry, a count mismatch, the entry cap; resident, cell and big-data values with a missing segment; the unnamed value; data text for every type of 4.6; the three root sources; `OpenKey` errors; the control set; the hive list with paths, a bad signature, the filter and strict mode; selection; the hive file with gaps, an unreadable base block, a map entry whose bytes past its two members are out of memory, the size limit and no output directory; the user-address reader.
2. Fuzz targets, 30 s each on 2026-11-12, in `fuzz_test.go`: `FuzzDecodeKey`, `FuzzDecodeValue`, `FuzzDecodeIndex` (arbitrary cell bytes and missing pages; decoding never panics and never reads past the cell) and `FuzzHiveWalk` (arbitrary stable storage bytes behind a valid map; the walk ends and no key appears twice in one subkey list). Executions: 3.36 million, 1.19 million, 322,000 and 283,000.
3. On the captures, `hivefacts -tool -bins -dumpdir` on 2026-11-12:

| Capture | Hives listed | Keys | Values | Subkey lists incomplete | Values unreadable | Root by base, `RootKcb`, first cell, none | Hive files written (without base block) | Bytes captured of written |
|---|---|---|---|---|---|---|---|---|
| mem1_win11 | 24 | 189,968 | 368,409 | 9,838 | 422 | 24, 0, 0, 0 | 24 (0) | 70,328,320 of 87,945,216 |
| mem2_win10 | 29 | 102,800 | 227,762 | 5,333 | 540 | 19, 5, 4, 1 | 29 (10) | 38,117,376 of 103,890,944 |
| mem5_server2016 | 19 | 305,637 | 543,807 | 3 | 0 | 19, 0, 0, 0 | 19 (0) | 92,602,368 of 92,733,440 |
| mem6_server2025 | 29 | 71,418 | 167,482 | 1,073 | 552 | 20, 7, 2, 0 | 29 (9) | 30,347,264 of 99,880,960 |
| mem7_server2025 | 24 | 44,907 | 80,774 | 2,602 | 423 | 13, 8, 3, 0 | 24 (11) | 16,433,152 of 101,335,040 |

   - On mem5, where every cell reads, the reader reaches the same 305,637 keys as the independent raw walk (M8 counts) and 543,807 values.
   - The pool scan adds no hive to the list on any capture (gathered rows equal listed rows).
   - SYSTEM's current control set reads as `ControlSet001` on mem1, mem5, mem6 and mem7; on mem2 the `Current` value cell is out of memory and the fallback is reported.
   - Key names that are not printable: 1, 2, 2, 1, 1. Non-ASCII key names: 0, 0, 1, 4, 4. Key names not readable: 3, 13, 0, 11, 8; value names not readable: 1, 7, 0, 4, 2.
   - A second run after the last code change gives the same counts. The mem2 row was measured again on 2026-11-12 after the M15 change (50 keys, 46 values and one 4,096-byte block more, all in SOFTWARE); mem6, whose two such blocks do not read, is unchanged.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The signatures, the size word, the bin flag mask, the key and value name flags, the resident-data bit, the 16,344-byte segment, the root flag 0x4 and the 26100 bin header members rest on measurements only (M6 to M11); the PDBs give no constants for them. | Owner decision on measured constants |
| O2 | `li` lists are not accepted: no capture holds one (M8) and no type names the signature. A hive with them would report its subkey lists as incomplete. | A capture with `li` lists |
| O3 | Free cells (M7: 341 and 8 on mem1, 672 on mem7) reached through a list are not trusted and leave the list incomplete. Some may be keys deleted after the list was written. | Owner decision: show them as deleted keys |
| O4 | Value names are compared ignoring case. Learn states this for key names (D5) only. | A Learn page, or owner decision |
| O5 | The unnamed value is named `(Default)` for the callers that look it up; D6 gives it no name. | Owner decision (Q2) |
| O6 | `RegistryPath` is a new row field; `FileFullPath` falls back to the mount point when the kernel records no file path, so SYSTEM and HARDWARE show `\REGISTRY\MACHINE\…` there. | Owner decision (Q2) |
| O7 | Data text is new wording (4.6): numbers in hexadecimal, multi-strings joined by line feeds, other data as spaced hexadecimal. | Owner decision (Q2) |
| O8 | User-address hive pages that are prototype pages do not read through the Registry process layer (M13), so some application hives show no keys. | The layer's prototype page support |
| O9 | 32-bit kernels are not measured; the reader follows the PDB widths and D8 and is untested on one. | A 32-bit capture (Q7) |
| O10 | Bin header checking stays off by default: on four captures it loses 2 % to 40 % of keys (M14). | Owner decision |
| O11 | Follow-up R1: on mem2 one SOFTWARE page of the hive file, file offset 0x48ab000, was zeros. Owner decision 2026-11-12: probe before release. Result: a library bug. The page is storage block 0x48aa000; its map entry is table slot 170, whose last 8 bytes (past `PermanentBinAddress`) lie on a page out of memory, and the reader read the whole entry (M15). Done: 4.3 step 4 reads the two members only (`tools/windows/registryhive/cellmap.go`); fixture `TestAMapEntryNeedsOnlyItsBlockOffsetAndBinAddress` in `dump_test.go`; `hivefacts -block` traces one block from map entry to frame and `-hives` counts such entries; section 9 mem2 row measured again. | Closed |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep the measured constants |
| O2 | Keep refusing |
| O3 | Keep untrusted; list incomplete |
| O4 | Ignore case |
| O5 | Name it (Default) |
| O6 | Accept both |
| O7 | Accept the new wording |
| O8 | Defer to v0.2.0 |
| O9 | Defer |
| O10 | Off by default |

## 11. Provenance

Written from the captures' ntkrnlmp.pdb types read through the project's symbol tables, Microsoft Learn's registry pages and the project's measurements. Every rule rests on the sources and measurements above.
