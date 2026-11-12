# S41: Windows application compatibility cache in kernel memory

Version 1, 2026-11-12.

## 1. Purpose

Windows keeps a cache of the programs it has checked for application compatibility fixes. The cache lives in the kernel driver `ahcache.sys`, and the driver saves it to the SYSTEM hive value `CurrentControlSet\Control\Session Manager\AppCompatCache` when the cache is written out, typically at shutdown. An entry names a program by its path (or, for a packaged application, by a package key), and holds the last-write time of the program's file as the driver saw it, and the driver's own data about the program. An examiner wants the entries as they stand in memory: programs added since the value was last written are only there, and the order of the list tells which programs were used most recently.

`windows.execution.list_compat_cache` lists every entry of the in-memory cache with its key, file last-write time, position in the most-recently-used order and data bytes. It does not judge an entry.

No type information describes the driver's own structures. This specification defines them from the code of the routines that read and write the cache, disassembled from each capture's `ahcache.sys`, and checks each offset against the registry value of the same capture, decoded independently by the measurement script.

## 2. Inputs

| Input | Use |
|---|---|
| Kernel memory | The cache structures of section 3.3. |
| Kernel symbol table | `_RTL_AVL_TABLE`, `_RTL_BALANCED_LINKS`, `_LIST_ENTRY` and `_UNICODE_STRING` (T1 to T3). |
| Loaded modules | `windows.module.list`, unfiltered by PID, for the base of `ahcache.sys`. |
| `ahcache.sys` symbol table | Loaded through `tools.Context.LoadPDB` from the CodeView record of the driver image in memory; supplies the public `AhcCacheHandle` (P1). |
| Options | `strict` and `diagnostics` only. The tool has no option of its own. |
| Limits | `MaxListEntries` (list walk), `MaxTableEntries` (tree walk), `MaxNameBytes` (key), `MaxBufferBytes` (data). |

The image is untrusted. Every pointer and count can hold any value.

## 3. Facts from the sources

### 3.1 Documentation

All Microsoft Learn pages accessed 2026-11-12.

| # | Fact | Source |
|---|---|---|
| D1 | `RtlInitializeGenericTableAvl(Table, CompareRoutine, AllocateRoutine, FreeRoutine, TableContext)`: for each new element the AllocateRoutine "is called to allocate memory for caller-supplied data plus some additional memory for use by the Rtl...GenericTableAvl routines"; "caller-supplied routines must not access the first sizeof(RTL_BALANCED_LINKS) bytes of any element". The CompareRoutine returns GenericLessThan, GenericGreaterThan or GenericEqual. The initialised table "should be considered opaque". | "RtlInitializeGenericTableAvl function (ntddk.h)", ms.date 2025-11-13 |
| D2 | `RtlLookupElementGenericTableAvl(Table, Buffer)` "returns a pointer to the user data that is associated with the matching element". | "RtlLookupElementGenericTableAvl function (ntddk.h)", ms.date 2023-01-10 |
| D3 | `LIST_ENTRY { Flink; Blink; }`: in an entry, Flink points to the next entry or to the list header; in the header, Flink points to the first entry and Blink to the last, or to the header itself when the list is empty. | "LIST_ENTRY (ntdef.h)", ms.date 2018-12-05 |
| D4 | `UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; }`: Length is the length in bytes of the string, MaximumLength the length in bytes of Buffer; a trailing NUL is not counted. | "_UNICODE_STRING (ntdef.h)", ms.date 2018-04-30 |
| D5 | `NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)`; class `FileBasicInformation` (4) returns a `FILE_BASIC_INFORMATION`. | "NtQueryInformationFile function (ntifs.h)", ms.date 2021-09-27; "FILE_INFORMATION_CLASS (wdm.h)", ms.date 2024-02-06 |
| D6 | `FILE_BASIC_INFORMATION { LARGE_INTEGER CreationTime; LARGE_INTEGER LastAccessTime; LARGE_INTEGER LastWriteTime; LARGE_INTEGER ChangeTime; ULONG FileAttributes; }`; LastWriteTime "specifies the time that the file was last written to", in 100-nanosecond intervals since 1601. With 8-byte members the structure is 0x28 bytes and LastWriteTime is at 0x10. | "FILE_BASIC_INFORMATION (wdm.h)", ms.date 2021-05-18 |
| D7 | A FILETIME counts 100-nanosecond intervals since January 1, 1601 (UTC). | "FILETIME (minwinbase.h)", ms.date 2018-12-05 |

### 3.2 Symbol tables

| # | Fact | Source |
|---|---|---|
| T1 | `_RTL_AVL_TABLE` (size 0x68): `BalancedRoot` at 0 (an `_RTL_BALANCED_LINKS`), `NumberGenericTableElements` at 0x2c (32-bit), `CompareRoutine` 0x48, `AllocateRoutine` 0x50, `FreeRoutine` 0x58, `TableContext` 0x60. | ntoskrnl PDB types in all four kernel tables (ntkrnlmp GUIDs 0D960CE1, F57E740B, 3DFC5F72, 953A8DE8), printed by `shimcachefacts -cache` |
| T2 | `_RTL_BALANCED_LINKS` (size 0x20): `Parent` 0, `LeftChild` 8, `RightChild` 0x10, `Balance` 0x18. | As T1 |
| T3 | `_UNICODE_STRING` (size 0x10): `Length` 0, `MaximumLength` 2, `Buffer` 8. `_LIST_ENTRY`: `Flink` 0, `Blink` 8. | As T1 |
| P1 | Every `ahcache.sys` PDB has the public `AhcCacheHandle` (a data symbol) and the routines `AhcCacheLoad`, `AhcCacheSave`, `AhcStoreInsert`, `AhcpStoreInsertAvlEntry`, `AhcpAVLTableCompare`, `AhcStorePromote`, `AhcStoreLoad`, `AhcStoreSave`, `AhcpStoreKeySave`, `AhcpCacheEntrySave`, `AhcpCacheEntryLoad`, `AhcpCacheEntryCopy`, `AhcpCacheEntryAcquire`, `AhcpCacheEntryUpdate`, `AhcCacheReadRegistry`. The PDBs carry no types. | `ahcache.pdb` GUIDs 90B1FCD5510B007B1ABDE32585EBA47B (mem1, 26100), 15896A5F39BD54F95039FB5313EC16FA (mem2, 19045), 95F67F1313C34ADAA271E53B6A2D1C11 (mem5, 14393), 222F1121EFFF7604B7E6FABEF6C8D114 (mem6 and mem7, 26100), loaded with `shimcachefacts -publics` and `-types` |

### 3.3 Code

Read with `shimcachefacts -code`, which disassembles a public's bytes from the capture through the project's `disasm` package. A routine whose pages are not resident cannot be read; the table names the builds on which each fact was read. `C` is the cache object, `S` the store, `E` an element's user data, `X` an entry's data object.

| # | Fact | Read on |
|---|---|---|
| C1 | `AhcCacheReadRegistry` loads the pointer held at `AhcCacheHandle` and passes it as the first argument to `AhcCacheLoad`. | 14393, 26100 |
| C2 | `AhcCacheLoad(C, stream)` and `AhcCacheSave(C, stream)` take `[C+0]` as the lock (passed to `ExEnterCriticalRegionAndAcquireResourceExclusive`) and pass `[C+8]` to `AhcStoreLoad` or `AhcStoreSave`. So `C+8` points to the store `S`. | C+0/C+8: 14393, 26100 |
| C3 | `AhcStoreInsert(S, ...)` calls `RtlNumberGenericTableElementsAvl(S)`: the store begins with its `RTL_AVL_TABLE`. It then inserts the new element at the head of the `LIST_ENTRY` at `S+0x68` (new Flink = old first entry, new Blink = `S+0x68`). The element's own `LIST_ENTRY` is at `E+0`. It compares the element count with the 64-bit value at `S+0x78`. | 19045, 26100 |
| C4 | `AhcpStoreInsertAvlEntry` builds a 0x30-byte search buffer with the key's `UNICODE_STRING` at +0x18, calls `RtlLookupElementGenericTableAvl`, then `RtlInsertElementGenericTableAvl` with size 0x30. On the returned user data `E` (D2) it clears the 32-bit word at `E+0x10`, copies the key into `E+0x18`, and stores the entry's data object at `E+0x28`. | 19045, 26100 |
| C5 | `AhcpAVLTableCompare` compares the two `UNICODE_STRING`s at +0x18 of its arguments with `RtlCompareUnicodeString(..., CaseInSensitive = TRUE)`. | 19045, 26100 |
| C6 | `AhcStorePromote(S, key)` looks the element up, unlinks it and links it again at the head of `S+0x68`. | 26100 |
| C7 | `AhcStoreLoad(S, stream)` reads records of a 32-bit signature `0x73743031`, a 32-bit CRC compared with `RtlComputeCrc32` over the payload, and a 32-bit payload length; it stops when the element count reaches `[S+0x78]`; it links each new element at the tail of `S+0x68`. | 14393 |
| C8 | `AhcStoreSave(S, stream)` walks `S+0x68` from Flink. For each element it writes the 12-byte record header, calls `AhcpStoreKeySave(E+0x18, stream)`, then calls the store's save routine with `[E+0x28]`, and back-fills the header with `0x73743031`, the CRC32 of the payload and its length. | 26100; first page on 19045 (`S+0x68`) |
| C9 | `AhcpStoreKeySave` writes the key's 16-bit `Length` and then `Length` bytes of `Buffer`. | 26100 |
| C10 | `AhcpCacheEntrySave(X, stream)` writes the 64-bit `[X+8]`, the 32-bit `[X+0x10]`, then `[X+0x10]` bytes from the pointer `[X+0x18]`. `AhcpCacheEntryLoad` clears a 0x20-byte object and reads the same three fields back into `X+8`, `X+0x10` and a new buffer at `X+0x18`. `AhcpCacheEntryCopy` copies the same three fields. | Save: 26100; Load: 14393; Copy: 19045 |
| C11 | `AhcpCacheEntryAcquire` calls `ZwQueryInformationFile(handle, iosb, buffer, 0x28, 4)` (D5, D6), directly on 14393 and through `AslFileGetTime` on 26100, takes the 64-bit value at buffer+0x10, compares it with `[X+8]` of the element found by `RtlLookupElementGenericTableAvl`, and on 26100 stores it in `X+8` when they differ. It adds to the 32-bit word at `E+0x10` with a locked add or increment, and later decrements it. It passes `[X+0]` to `AhcLockAcquireSharedWait`. | 14393, 26100 |
| C12 | `AhcpCacheEntryUpdate` walks the data buffer as items of a 32-bit tag, a 32-bit size and the bytes, each item rounded up to 4 bytes, and replaces the item with the requested tag. | 26100 |

### 3.4 Measurements

M1 to M9 come from `shimcachefacts -cache -entries -scan`, run on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 and mem7_server2025 (26100). The script decodes the registry value on its own from C7 to C10, and walks memory with the offsets under test.

| # | Measured |
|---|---|
| M1 | `AhcCacheHandle` holds a pool pointer `C` on all five; `[C+8]` is `S`; `[S+0x78]` is 1024 on all five. |
| M2 | Tree: walking every node reachable from `BalancedRoot.RightChild` (T1, T2) reaches `NumberGenericTableElements` nodes on mem2 (811), mem5 (256), mem6 (237) and mem7 (272); mem1 has 141 elements and 139 reachable nodes, with 2 children whose `Parent` is not the node above. `BalancedRoot.LeftChild` is 0 on all five. |
| M3 | List: the `S+0x68` list walks whole on mem2, mem5, mem6 and mem7 with as many entries as the tree has nodes, and every entry is a tree node + 0x20 (the size of `_RTL_BALANCED_LINKS`, D1). On mem1 the forward walk stops after 1 entry and the backward walk after 123 (a null link each way); 123 of the 124 entries are tree nodes + 0x20. |
| M4 | Registry value, decoded by the script: on mem1 a 52-byte header and 139 records; on mem5 a 48-byte header and 256 records; every record's CRC32 (IEEE polynomial) matches and the records end exactly at the value's end. On mem2, mem6 and mem7 the value (205,386, 51,240 and 66,610 bytes) is not resident. |
| M5 | Entries matched by key between memory and the value: mem5 256 of 256, with the same file time (256), the same data bytes (256) and the same position in the list as in the value (256). mem1 123 of 124, same time 122, same data 118; 16 records of the value have no entry in memory. |
| M6 | Records with a valid CRC32 found anywhere in physical memory: mem1 146 (122 entries matched by key, 121 with the same time, 117 also the same data), mem2 16 (16, 16, 16), mem5 252 (251, 251, 251), mem6 and mem7 none. |
| M7 | Keys: 811 entries on mem2, of which 26 keys and 11 data buffers do not read; 3 keys on mem7 do not read; all others read. The file time `[X+8]` is 0 on exactly the entries whose key is a tab-separated package identity starting `0000000` (49, 248, 15, 66 and 73 readable entries) and on 14 mem2 entries whose key does not read; it is nonzero on every other entry. |
| M8 | `[E+0x10]` is 0 on all 1,700 entries. `[X+0]` is a nonzero pool pointer on all 1,700. |
| M9 | Data buffer sizes (bytes:count): mem1 12:1 24:10 36:45 60:4 72:57 84:3 124:1 136:3; mem2 12 to 592 in 18 sizes; mem5 12 to 604 in 18 sizes; mem6 24 to 604 in 14 sizes; mem7 24 to 604 in 16 sizes. Every readable buffer decodes end to end as C12 items except one on mem7. Tags seen: 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200 (in every buffer), 0x400, 0x800, 0x2000, 0x014C0001, 0x86640001. |
| M10 | The tool, run with `shimcachefacts -tool` (and `-cache -tool` for the registry comparison): mem1 140 rows (124 on the list, of which 1 placed from the head and 123 from the tail; 139 in the tree; 16 only in the tree; 1 only on the list), mem2 811, mem5 256, mem6 237, mem7 272 rows, all on both list and tree. mem1's two misparented nodes (M2) are the two list entries where the walks stop (M3); both have a null data pointer. Against the registry value: mem1 137 of 139 records have a row (14 of them only in the tree), same time 136, same data 129; mem5 256 of 256, same time 256, same data 256. Keys unread: mem2 26, mem7 3; data unread: mem1 2, mem2 11. |

### 3.5 Layout

From C1 to C12 and T1 to T3; confirmed by M1 to M9 on 14393, 19045 and 26100.

| # | Object | Offset | Member | Evidence |
|---|---|---|---|---|
| L1 | `AhcCacheHandle` | 0 | pointer to `C` | C1, M1 |
| L2 | `C` | 0x08 | pointer to `S` | C2, M1 |
| L3 | `S` | 0 | `RTL_AVL_TABLE` (T1) | C3, M2 |
| L4 | `S` | 0x68 | `LIST_ENTRY` head, most recent first | C3, C6, C7, C8, M3, M5 |
| L5 | `E` | 0 | the element's `LIST_ENTRY` | C3, M3 |
| L6 | `E` | 0x18 | key, `UNICODE_STRING` | C4, C5, C9, M5 |
| L7 | `E` | 0x28 | pointer to `X` | C4, C8 |
| L8 | `X` | 0x08 | file last-write time, FILETIME | C10, C11, D6, M5, M6 |
| L9 | `X` | 0x10 | data size, 32-bit | C10, M5, M9 |
| L10 | `X` | 0x18 | pointer to the data bytes | C10, M5 |
| L11 | tree node | 0x20 | the element's user data `E` (node + size of `_RTL_BALANCED_LINKS`) | D1, D2, M3 |

`C+0`, `S+0x78`, `S+0x80` to `S+0xa8` (pointers into `ahcache.sys`), `E+0x10` and `X+0` are not emitted (section 10).

## 4. Algorithm

1. Refuse a kernel whose pointer size is not 8 (`ErrNot64Bit`): every layout was measured on x64.
2. Find `ahcache.sys` in the module list by base name, case folded. Not found: `ErrNoDriver`.
3. Read the driver's PE headers at its base, its debug directory and CodeView record, and load its symbol table with `LoadPDB`. Look up `AhcCacheHandle` (P1). Any failure: `ErrNoSymbols` wrapping the cause.
4. Read `C` at `AhcCacheHandle` (L1), then `S` at `C+8` (L2). Either unreadable or null: `ErrCacheUnread`.
5. Walk the tree (L3, T1, T2): from `S + BalancedRoot` take `RightChild`, then every `LeftChild` and `RightChild`, depth first, each node once, at most `MaxTableEntries` nodes. Record each node's user data `node + sizeof(_RTL_BALANCED_LINKS)` (L11). A node that does not read, or a child whose `Parent` is not the node above, is reported and the walk carries on with the other nodes.
6. Walk the list at `S+0x68` (L4, L5) with `winkernel.ListWalker.WalkRecovering` (S03), at most `MaxListEntries`. Entries reached forward are numbered from the head; entries reached backward are numbered from the tail.
7. One row per user data address found by step 5 or step 6. Read `E+0x18` (L6) as the key, `E+0x28` (L7) as `X`, then `X+8`, `X+0x10` and `X+0x18` (L8 to L10) and the data bytes.
8. Order: list entries reached forward by position from the head; then those reached backward from the one nearest the head to the tail; then entries found only in the tree, by key (case folded), then address.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Kernel pointer size 8 | Section 3 measured on x64 only | `ErrNot64Bit` |
| `AhcCacheHandle` lies inside the driver's `SizeOfImage` | P1 (a data symbol of the image) | `ErrNoSymbols` |
| `C` and `S` read and are not null | L1, L2 | `ErrCacheUnread` |
| `NumberGenericTableElements` reads | T1 | `ErrCacheUnread` |
| A tree node reads | T2 | Diagnostic; the node and the nodes below it are not reached |
| A child's `Parent` is the node above | D1 (the table's own links), M2 | Diagnostic; the child is still walked |
| Tree node count at most `MaxTableEntries` | 8 | Diagnostic and `ErrLimit` in strict mode; the walk stops |
| List links | S03 | `winkernel` diagnostics; in strict mode the walk error |
| Key `Length` even and not above `MaximumLength` | D4 | `KeyUnreadable` |
| Key `Length` at most `MaxNameBytes` | 8 | `KeyUnreadable` and diagnostic |
| Element, data object or key buffer reads | L6 to L10 | `KeyUnreadable` or `DataUnreadable` |
| Data size at most `MaxBufferBytes` | 8 | `DataUnreadable` and diagnostic |

The tree and the list are compared: the number of rows found in the tree but not on the list, on the list but not in the tree, and the nodes reached against `NumberGenericTableElements`, are reported in one diagnostic when they disagree (M3, M10: an update in progress at capture time leaves such entries).

## 6. Failure modes

| Case | Result |
|---|---|
| Profile not Windows | Run error `windows.execution.list_compat_cache: unsupported profile os "<os>"` |
| Not x64 | Run error `windows.execution.list_compat_cache: executioncompatcachememory: kernel is not 64-bit` |
| Module list fails | Run error `windows.execution.list_compat_cache: loaded modules: ...` |
| No `ahcache.sys` | Run error wrapping `ErrNoDriver` |
| No CodeView record, PDB not loaded, no `AhcCacheHandle` | Run error wrapping `ErrNoSymbols` |
| `C`, `S` or the element count do not read | Run error wrapping `ErrCacheUnread` |
| Table lacks a `_RTL_AVL_TABLE` or `_RTL_BALANCED_LINKS` member of T1 or T2 | Run error wrapping `ErrTypeMissing` |
| Tree node unreadable or misparented | Diagnostic `windows.execution.list_compat_cache: tree node at 0x<addr>: links do not read: <err>` or `windows.execution.list_compat_cache: tree node at 0x<addr>: Parent is 0x<p>, not the node above, 0x<q>` |
| Tree past `MaxTableEntries` | Diagnostic; in strict mode the run returns the rows and `ErrLimit` |
| List broken | `winkernel` diagnostic; in strict mode the run returns no rows and the walk error |
| Tree and list disagree, or the tree reaches fewer or more nodes than `NumberGenericTableElements` | Diagnostic `windows.execution.list_compat_cache: cache at 0x<S>: <n> entries only in the tree, <m> only in the list, <r> tree nodes reached of <c> counted` |
| Key or data unreadable | Row flag; diagnostic `windows.execution.list_compat_cache: entry at 0x<E>: key not read: <err>`, `data not read: <err>` or `element does not read: <err>` (both flags); in strict mode the run returns all rows and the first such error |

## 7. Result schema

One `executioncompatcachememory.CacheEntry` per element:

| Field | Type | Meaning |
|---|---|---|
| `Position` | int | 0-based place from the list head, most recently used first; -1 when not reached from the head |
| `PositionFromTail` | int | 0-based place from the list tail; -1 when not reached from the tail and the walk from the head did not complete |
| `InList`, `InTable` | bool | Reached on the list (L4); reached in the tree (L3) |
| `Key` | string | L6, verbatim; a file path or a package identity |
| `KeyUnreadable` | bool | L6 did not read or failed section 5 |
| `FileLastWrite` | time.Time (UTC) | L8 (D6, D7); zero when 0, unreadable, or out of FILETIME range |
| `DataSize` | uint32 | L9 |
| `Data` | []byte | L10, the bytes the driver saves after the time in the registry record (C10, M5) |
| `DataUnreadable` | bool | L7, L9 or L10 did not read, or the size is above `MaxBufferBytes` |
| `Address` | uint64 | `E`, the element's user data |

Sort: section 4 step 8.

## 8. Limits

- `MaxListEntries`: the list walk. The store caps itself at `[S+0x78]` = 1024 entries (C3, C7, M1); the default is far above.
- `MaxTableEntries`: the tree walk; same reason.
- `MaxNameBytes`: the key. Keys measured are paths and package identities well under 1 KB.
- `MaxBufferBytes`: one entry's data. The largest measured is 604 bytes (M9).

## 9. Acceptance

1. Synthetic fixtures (`tools/windows/executioncompatcachememory/s41_fixture_test.go`, from L1 to L11; tests in `cache_test.go`): a whole cache of three entries in list and tree, most recent first, with both positions; a package key with no file time; an empty data buffer; an empty cache; a broken list (forward and backward parts and a tree-only entry) with its diagnostic and the strict-mode error; a list entry outside the tree; a misparented and an unreadable tree node; a key of odd length; unreadable key and data; data above `MaxBufferBytes`; a key above `MaxNameBytes`; the tree limit in normal and strict mode; a null store, an unreadable handle and missing tree types; a 32-bit kernel; another profile; the handle found through the driver's CodeView record and a symbol loader, and each way that fails (no driver, no loader, load failure, no `AhcCacheHandle`).
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzDecodeElement` (no panic; only package errors; no ill-formed key accepted) 1.72 million executions; `FuzzDecodeEntryData` (no panic; only `ErrShort`, and only for short input) 2.80 million; `FuzzCacheWalk` (the store and first element overwritten by the input: no panic, rows within the limits, every row's address unique) 1.90 million.
3. On the captures (M10): 140 rows on mem1 with the disagreement diagnostic, 811, 256, 237 and 272 on the others, with no run error.
4. The registry and physical-memory cross-checks of M5 and M6.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Data items (C12): the tags seen (M9) are not tied to any documented property, so `Data` is emitted as bytes and not decoded. | A document or a controlled capture that sets each item |
| O2 | The value header (M4: 52 bytes on 26100, 48 on 14393; `AhcCheckForChange` writes 0x34 at its start and increments the word at +0x10 after a servicing clear) is on disk only and not emitted. | Owner decision |
| O3 | `[S+0x78]` (1024 on all captures, compared with the element count by C3 and C7) is the store's capacity by its use; not emitted. `S+0x80` to `S+0xa8` hold pointers into `ahcache.sys` (statistics and the store's allocate, free, copy, save and load routines by their targets); not emitted. | Owner decision |
| O4 | `E+0x10` is a reference count by its use in C11 and 0 on all captures (M8); `X+0` is passed as a lock (C11). Neither is emitted. | Owner decision |
| O5 | Keys that are package identities (M7) are not split into their tab-separated parts: no document names the parts. | A document of the package key |
| O6 | Builds other than 14393, 19045 and 26100 are not refused: the walk's checks (tree membership, list links, key validity) are relied on instead. The layout of other builds was not measured. | Captures of other builds |
| O7 | Row and field names are new: `CacheEntry` replaces `Entry`; `Key` replaces `Path`, `FileLastWrite` (a time) replaces `LastModified` (a string); `Order` and `Recovered` are gone; `PositionFromTail`, `InList`, `InTable`, `DataSize`, `Data`, `DataUnreadable` and `Address` are new. | Owner decision (Q2) |
| O8 | The measurement script reads the registry value with the IEEE CRC32; that `RtlComputeCrc32` uses it is measured (M4: every record matches), not documented. The tool does not compute it. | None needed for the tool |
| O9 | Private member names in this layout (the store, element and data objects) are the specification's own (Q3). | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Emit bytes, not decoded |
| O2 | Do not emit |
| O3 | Do not emit |
| O4 | Do not emit |
| O5 | Keep unsplit |
| O6 | Do not refuse; rely on checks |
| O7 | Accept the new names |
| O8 | No change needed |
| O9 | Keep the names |

## 11. Provenance

Author: the project, 2026-11-12. Sources: the Microsoft Learn pages of 3.1, accessed 2026-11-12; the ntoskrnl and `ahcache.sys` PDBs of the captures through the project's symbol tables (BuilderVersion 10); disassembly of each capture's `ahcache.sys` routines through the project's `disasm` package; the SYSTEM hive of each capture through the project's `registryhive` reader; the project's measurements with `shimcachefacts` on the five captures of 3.4. Every rule rests on the sources and measurements above.
