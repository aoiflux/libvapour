# S24: Windows memory protection and VAD walk

Version 1, 2026-11-12.

## 1. Purpose

Windows describes each reserved range of a process's user space with a virtual address descriptor (VAD). The VADs of a process form a balanced binary tree rooted at `_EPROCESS.VadRoot`. An examiner wants each range with its protection, whether it is private memory, an image view or another section view, the file behind a view, and its commit charge. The memory tree tool shows the tree's links. The page listing tool shows every page that the process's page tables map.

A capture taken from a running system can catch a tree in mid-change, and a link can point into freed pool. Followed blindly, such a link adds ranges that the process does not have. This specification defines a bounded walk of the tree, the checks that keep links the kernel did not make out of the result, the address arithmetic per build, the mapping from the VAD's protection index to the documented `PAGE_*` constants, and the diagnostics.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | Kernel virtual reads: the `_EPROCESS`, the tree nodes, the kernel globals of 3.2. |
| Physical memory | Only for the page listing (4.9). |
| Symbol table | The kernel types and globals of section 3. |
| Processes | From `any.process.list`, kept by the `pid` option. |
| Options | `pid`, `strict`, `diagnostics`, `any.memory.list.address` (4.10), `paging_mode` (4.9). |
| Limits | `MaxListEntries`: tree nodes per process (8). |

## 3. Facts from the sources

### 3.1 Documentation

| # | Fact | Source |
|---|---|---|
| D1 | Memory protection constants: `PAGE_NOACCESS` 0x01, `PAGE_READONLY` 0x02, `PAGE_READWRITE` 0x04, `PAGE_WRITECOPY` 0x08, `PAGE_EXECUTE` 0x10, `PAGE_EXECUTE_READ` 0x20, `PAGE_EXECUTE_READWRITE` 0x40, `PAGE_EXECUTE_WRITECOPY` 0x80, `PAGE_TARGETS_INVALID` and `PAGE_TARGETS_NO_UPDATE` 0x40000000. "You must specify one of the following values." The modifiers `PAGE_GUARD` 0x100, `PAGE_NOCACHE` 0x200 and `PAGE_WRITECOMBINE` 0x400 "can be used in addition to the options provided in the previous table". The enclave constants are listed without values. | Microsoft Learn, "Memory Protection Constants (WinNT.h)", dated 2022-05-18, accessed 2026-11-12. |
| D2 | `MEMORY_BASIC_INFORMATION.Type`: `MEM_IMAGE` "mapped into the view of an image section", `MEM_MAPPED` "mapped into the view of a section", `MEM_PRIVATE` "private (that is, not shared by other processes)". | Microsoft Learn, "MEMORY_BASIC_INFORMATION (winnt.h)", dated 2018-12-05, accessed 2026-11-12. |
| D3 | A 64-bit process has user space within 0x000'00000000 through 0x7FFF'FFFFFFFF. In 32-bit Windows the lower 2 GB is user space, and a boot option can raise it to 3 GB. Pages are "typically 4 kilobytes". | Microsoft Learn, "Virtual Address Spaces" (Windows drivers), dated 2024-06-28, accessed 2026-11-12. |
| D4 | A 4-KByte page maps through the low 12 bits of the linear address as the page offset; bits 47:12 (or 56:12 with 5-level paging) select the page. | Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 3A, "Paging" chapter. |

### 3.2 Kernel types

Read through the project's kernel tables for builds 26100 (mem1, mem6; GUIDs 0D960CE1…, 953A8DE8…), 19045 (mem2; F57E740B…) and 14393 (mem5; 3DFC5F72…), with `vadfacts -types`.

| # | Fact |
|---|---|
| T1 | `_EPROCESS.VadRoot` is an `_RTL_AVL_TREE` at 0x558 (26100), 0x7D8 (19045), 0x620 (14393); `VadCount` (unsigned long long) follows 0x10 later. `_RTL_AVL_TREE` is 8 bytes: `Root` (`_RTL_BALANCED_NODE *`) at 0. |
| T2 | `_RTL_BALANCED_NODE` is 24 bytes: `Left` 0, `Right` 8 (also `Children[2]` at 0), `ParentValue` (unsigned long long) 0x10, overlaid by `Balance` (bits 0..1) and `Red` (bit 0). |
| T3 | `_MMVAD_SHORT` is 64 bytes: `VadNode` (`_RTL_BALANCED_NODE`) 0, `StartingVpn` 0x18 and `EndingVpn` 0x1C (unsigned int), `StartingVpnHigh` 0x20, `EndingVpnHigh` 0x21 and `CommitChargeHigh` 0x22 (unsigned char), `u` 0x30. On 26100 `CommitCharge` (unsigned int) is a member at 0x34; on 19045 and 14393 an unnamed union `u1` is at 0x34. The tables do not expand `u` or `u1`. |
| T4 | `_MMVAD` is 136 bytes: `Core` (`_MMVAD_SHORT`) 0, `Subsection` (`_SUBSECTION *`) 0x48, `FileObject` 0x80. |
| T5 | `_MMVAD_FLAGS` is 4 bytes: `Protection` 5 bits at bit 7 (26100, 19045) or 3 (14393); `PrivateMemory` 1 bit at bit 21 (26100), 20 (19045) or 15 (14393); `VadType` 3 bits at bit 4 (26100, 19045) or 0 (14393). `_MMVAD_FLAGS1` (19045, 14393) has `CommitCharge` bits 0..30 and `MemCommit` bit 31; 26100 has no `_MMVAD_FLAGS1`. |
| T6 | 26100 and 19045 have `_MM_PRIVATE_VAD_FLAGS`, whose bit at the `PrivateMemory` position is named `PrivateMemoryAlwaysSet`, and `_MM_SHARED_VAD_FLAGS`, whose bit there is `PrivateMemoryAlwaysClear` and which alone has `PrivateFixup`. 14393 has neither. |
| T7 | No table has an enumeration for `VadType` (no `_MI_VAD_TYPE`). |
| T8 | `_POOL_HEADER` is 16 bytes with `PoolTag` (unsigned int) at 4 in all four. |
| T9 | Every table has the globals `MmProtectToValue` and `MmHighestUserAddress`; neither carries a type. |
| T10 | `_SUBSECTION.ControlArea` 0, `_CONTROL_AREA.FilePointer` (`_EX_FAST_REF`) 0x40, `_MMSECTION_FLAGS.File` bit 7 and `Image` bit 5 in `_CONTROL_AREA.u`, `_FILE_OBJECT.FileName` (`_UNICODE_STRING`) 0x58 (S19 T1, T2, T4). |

### 3.3 Measurements

M1 to M12 come from `vadfacts` on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393) and mem6_server2025 (26100). The script walks each process's tree from `VadRoot.Root` through `Left` and `Right`, visiting each node once, and applies the rules of 4.2 to see what each one removes. The four captures hold 408 processes, 19 with an empty tree.

| # | Measured |
|---|---|
| M1 | `MmHighestUserAddress` holds 0x7FFF'FFFEFFFF on all four. |
| M2 | `MmProtectToValue` holds 32 unsigned 32-bit values (2 to the `Protection` bit width) identical on all four: index *i* = *b* + 8 × *m* gives base *b* in {`NOACCESS`, `READONLY`, `EXECUTE`, `EXECUTE_READ`, `READWRITE`, `WRITECOPY`, `EXECUTE_READWRITE`, `EXECUTE_WRITECOPY`} and modifier *m* in {none, `NOCACHE`, `GUARD`, `WRITECOMBINE`}, except that base 0 gives 0x01 whatever the modifier. The words after entry 31 differ per build and are not protections. |
| M3 | Nodes reached: 10,748, 21,801, 9,829 and 14,095. Nodes kept by 4.2: 10,747, 21,783, 9,808 and 14,093. Removed: out of order 1, 13, 18 and 2; inverted 0, 5, 3 and 0; reached twice 0, 8, 4 and 5; above user space or unreadable 0 (every node above `MmHighestUserAddress` is already out of order). |
| M4 | Every kept node has a pool tag that starts with `Vad` (`Vad `, `VadS`, `VadF`, `VadE`, `VadI`, `Vadl`). Of the removed nodes, every inverted one and 5 out-of-order ones do not; the other out-of-order ones do. A walk without the rules of 4.2 reaches 10,748, 21,824, 10,906 and 14,102 nodes, 1,149 more than the rules keep; 0, 18, 1,017 and 9 of them have a tag that does not start with `Vad` (for example `Thre`, `MmSe`, `SeTl`, `Muta`). |
| M5 | The kept ranges never overlap. In start order, 2,321, 7,510, 3,673 and 4,431 neighbours touch (the next `StartingVpn` is the previous `EndingVpn` + 1); the rest leave a gap. |
| M6 | Kept trees are at most 13 high (largest tree 1,936 nodes), never higher than the largest height an AVL tree of their node count can have (4.2 step 2). |
| M7 | `Balance` is 0, 1 or 3 and equals the right-minus-left subtree height (0, +1, −1 as a 2-bit signed value) in 10,701 of 10,748, 21,670 of 21,824, 9,772 of 10,053 and 14,045 of 14,102 nodes reached; it is 2 in 3 nodes. |
| M8 | `ParentValue` with the `Balance` bits cleared is not the node above in 25, 43, 20 and 28 kept nodes, all tagged `Vad`; the kept tree holds them in order and in bounds. |
| M9 | `StartingVpnHigh` and `EndingVpnHigh` of kept nodes are 0 to 7. `VadCount` equals the kept count in 61 of 79, 122 of 149, 55 of 68 and 79 of 93 non-empty trees. |
| M10 | Protection indexes of kept nodes: 1, 4, 5, 6, 7 and 24 on all four, 28 (`READWRITE`\|`WRITECOMBINE`) on mem1 only. |
| M11 | `PrivateMemory` is clear in exactly the kept nodes tagged `Vad ` or `VadI` (7,463, 13,848, 5,861, 8,808); every one of them has a nonzero `Subsection`. Kept nodes with `PrivateMemory` set are tagged `VadS`, `VadF`, `VadE` or `Vadl`. Through `Subsection` → `ControlArea` → `u`, `Image` is set exactly where `VadType` is 2 (4,430, 8,315, 3,489, 4,859) and never where it is 0. `VadType` values in kept nodes: 0, 1 (`Vadl`, private), 2 (shared) and 4 (`VadS`, private). |
| M12 | Section views whose control area has `File` set and a readable file name: 5,715, 10,226, 4,352 and 6,591. `_MMVAD.FileObject` never equals that control area's `FilePointer`. Commit charge, read as the low member with `CommitChargeHigh` above its bits: within the page count for every shared node; for private nodes, 2^35 − 2 in 10 (mem1) and 843 (mem2), above the page count in 68 (mem5), 2 (mem6) and 1 (mem2), within it elsewhere. |

## 4. Algorithm

### 4.1 Layout

Resolved once per run from the symbol table.

1. **Required.** `_EPROCESS.VadRoot`, `_RTL_AVL_TREE.Root`, `_RTL_BALANCED_NODE.Left` and `.Right`, `_MMVAD_SHORT.StartingVpn` and `.EndingVpn` (T1 to T3). Without one, the walk fails with `ErrVADLayout`.
2. **Node.** The tree node is at the VAD's address plus `_MMVAD_SHORT.VadNode` (T3); a table without the member puts it at the VAD's start (O6).
3. **High bytes.** `StartingVpnHigh` and `EndingVpnHigh` are used when the table has both (T3).
4. **Flags.** Each of `Protection`, `PrivateMemory` and `VadType` is a member of `_MMVAD_SHORT` when the table names it there; otherwise it is the `_MMVAD_FLAGS` bit field inside the word at `_MMVAD_SHORT.u` (T3, T5, O1). A bit field whose word width the table does not give is read as a word of the size of `_MMVAD_FLAGS`, or 4 bytes (T5).
5. **Commit.** `_MMVAD_SHORT.CommitCharge` when named; otherwise `_MMVAD_FLAGS1.CommitCharge` inside the word at `_MMVAD_SHORT.u1` (T3, T5). `CommitChargeHigh` when present.
6. **Parent.** `_RTL_BALANCED_NODE.ParentValue` with the bits of `Balance` and `Red` cleared (T2).
7. **Pool tag.** At the VAD's address minus (size of `_POOL_HEADER` − offset of `PoolTag`), 12 on all four (T8). A table without `_POOL_HEADER` uses 12 when pointers are 8 bytes and reads no tag otherwise (O5).
8. **Globals.** `MmHighestUserAddress` and `MmProtectToValue` (T9), read once per run (4.2, 4.4).

### 4.2 Tree walk

Per process:

1. Read the pointer at `_EPROCESS` + `VadRoot` + `Root`. Unreadable: the process's tree is not read. Zero: the tree is empty.
2. **Height bound.** An AVL tree of height *h* has at least *N*(*h*) nodes, *N*(1) = 1, *N*(2) = 2, *N*(*h*) = *N*(*h*−1) + *N*(*h*−2) + 1, since a node's subtrees differ in height by at most one (M7). The bound is the largest *h* with *N*(*h*) ≤ `MaxListEntries`: 28 for the default 2^20.
3. Walk depth first from the root, each pending node carrying its depth and the VPN interval its ancestors allow (initially unbounded). For each node:
   1. A node already reached is left out (`ErrVADReachedTwice`); its subtree was walked once.
   2. `Left`, `Right` and the range (4.3) must read (`ErrVADUnread`).
   3. Start VPN ≤ end VPN (`ErrVADInverted`).
   4. Start VPN above the interval's lower bound and end VPN below its upper bound (`ErrVADOutOfOrder`): the tree is ordered by address and its ranges do not overlap (M3, M5).
   5. End address ≤ the highest user address (`ErrVADAboveUserSpace`). That is `MmHighestUserAddress` when it reads and holds a nonzero value no larger than the documented top of user space: 0x7FFF'FFFFFFFF for 8-byte pointers, 0xBFFF'FFFF for 4-byte ones (D3, M1). Otherwise it is that documented top.
   6. A node failing 2 to 5 is left out with its subtree.
   7. A kept node deeper than the bound of step 2 ends the walk: the tree is refused with `ErrVADTreeTooDeep`.
   8. More kept nodes than `MaxListEntries` ends the walk (`ErrVADBudget`); the nodes kept so far are the result.
   9. Otherwise the node is kept. Its left child is pending with the upper bound set to its start VPN, its right child with the lower bound set to its end VPN.
4. The kept nodes are sorted by start address. The interval rule makes this their in-order sequence.
5. The walk cannot loop: a node is never inside the interval of its own subtree, and step 3.1 drops a node reached a second time.

### 4.3 Address arithmetic

1. VPN = low member + (high byte << (8 × width of the low member)), the high byte only when 4.1 step 3 applies (T3). On the measured builds a VPN has 40 bits.
2. Start = start VPN × 0x1000; End = end VPN × 0x1000 + 0xFFF. The page is 4 KB (D3, D4); `EndingVpn` is the last page of the range (M5).

### 4.4 Protection

1. The index is the `Protection` field (4.1 step 4).
2. The table is `MmProtectToValue`: 2^(bit width of `Protection`) unsigned 32-bit values (M2). It is read once per run. The value is the table entry at the index.
3. **Name** (`ProtectionName`). The documented constants of D1 whose bits are set, in ascending order of value, joined by `|`; bits no constant names follow as one hexadecimal part (`0x…`). Zero is `0x0`.
4. The protection is `unknown` (`ProtectionUnknown`) when the flags do not read, the table lacks the field, or `MmProtectToValue` is absent or does not read.
5. **Parsing.** `Win32Protection` turns a name back into its value: each `|` part is a D1 name, with or without the `PAGE_` prefix, or a hexadecimal part. An empty or unknown part makes the name unknown.

### 4.5 Kind

1. `PrivateMemory` set: `private` (D2 `MEM_PRIVATE`).
2. `PrivateMemory` clear: a section view (T6, M11). `VadType` 2: `image` (D2 `MEM_IMAGE`, M11, O2). Otherwise, or without `VadType` in the table: `mapped` (D2 `MEM_MAPPED`).
3. `PrivateMemory` not in the table or the flags do not read: `unknown`.

### 4.6 Section view and file name

1. A VAD is a section view (`VAD.IsMMVAD`) when its `PrivateMemory` is known (in the table and read) and clear (T6, M11). When it is not known, the pool tag decides: `Vad ` or `VadI` (M11, O3).
2. Only a section view's `_MMVAD.Subsection` is read: it lies past the end of an `_MMVAD_SHORT` (T3, T4).
3. `Subsection` → `_SUBSECTION.ControlArea`. When the table has `_CONTROL_AREA.u` and `_MMSECTION_FLAGS.File`, `File` must be set; a pagefile-backed section has no file (T10, M11).
4. `_CONTROL_AREA.FilePointer` with the `_EX_FAST_REF.RefCnt` bits cleared (4 bits on 8-byte pointers and 3 on 4-byte ones when the table lacks `_EX_FAST_REF`; S19 T2, O4) is the file object. Zero: no file.
5. `_FILE_OBJECT.FileName` is read as a `UNICODE_STRING` of at most 65,535 bytes. A name that does not read leaves the path unreadable; an empty name gives no path.
6. **File state (O8).** Each row is in exactly one of three states. *No file* (`NoFile`): `PrivateMemory` read and set; or, without `PrivateMemory` in the table, a pool tag that reads and is neither `Vad ` nor `VadI`; or a section view whose control area reads with `File` clear, or whose `FilePointer` reads as zero. *Named*: the name read; `Path` holds it, empty when the name is empty. *Unreadable* (`PathUnreadable`): any other row, that is, a read of the chain above failed, or the file-name layout is absent, so the row may map a file whose name is not known. `MappedFile.NoFile` carries the same no-file state for other tools.

### 4.7 Commit charge

Low member + (`CommitChargeHigh` << the low member's bit width, 32 on 26100 and 31 on 19045 and 14393) (T3, T5). Reported as read (M12, O7).

### 4.8 Rows

1. **`any.memory.list` (Windows).** For each process kept by `pid`, in process-list order, one `Mapping` per kept VAD, in start order (7).
2. **Memory tree.** `TreeWalker.Walk` gives one `TreeNode` per kept VAD with its raw `Left` and `Right` and its parent (4.1 step 6), in start order. It needs `ParentValue`.
3. **`ProcessVADs`** gives `VAD` values for other tools, in start order, without reading protections.

### 4.9 Page listing (`any.memory.list_pages`)

1. Windows only. For each process kept by `pid`, the root is `_EPROCESS.Pcb` + `_KPROCESS.DirectoryTableBase`, which maps both halves of the address space.
2. The process's page tables are walked in the paging mode the session chose (`paging_mode`; S04) through physical memory, giving runs of mapped pages.
3. Each run is a `PageRun`; `FileOffset` is the sum of the sizes of the runs before it in that process, the offset the run would have in a file of the process's mapped pages laid end to end.
4. Unreadable and repeated tables and pages outside the image are counted over the run and reported once.

### 4.10 Address filter

`any.memory.list.address` (an unsigned integer) keeps the rows whose range holds the address; a diagnostic says how many of how many. It needs a Windows profile.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Each node once | 4.2 step 5 | `ErrVADReachedTwice`; node left out |
| Links and range read | T2, T3 | `ErrVADUnread`; node and subtree left out |
| Start VPN ≤ end VPN | T3, M3 | `ErrVADInverted`; node and subtree left out |
| Range inside the interval its ancestors allow | M3, M4, M5 | `ErrVADOutOfOrder`; node and subtree left out |
| End ≤ highest user address | D3, M1 | `ErrVADAboveUserSpace`; node and subtree left out |
| Depth ≤ AVL height for `MaxListEntries` nodes | M6, M7 | `ErrVADTreeTooDeep`; tree refused |
| At most `MaxListEntries` nodes | 8 | `ErrVADBudget`; walk ends |
| Protection index inside `MmProtectToValue` | M2 | protection `unknown` |
| `Subsection` read only for a section view | T3, T4, T6, M11 | no file name |
| Control area `File` set | T10, M11 | no file name |

## 6. Failure modes

| Case | Result |
|---|---|
| Table lacks a required member (4.1 step 1) | `ErrVADLayout`; the run fails |
| `VadRoot` does not read | `<tool>: pid <pid> _EPROCESS at 0x<addr>: VAD tree not read: <error>`; the process has no rows. Strict mode: the run fails |
| Nodes left out | `<tool>: pid <pid> _EPROCESS at 0x<addr>: <n> VAD tree nodes left out: <count> <reason>, …`. Strict mode: the first one fails the run |
| Tree too deep | The process's tree is refused with `ErrVADTreeTooDeep`, reported as above |
| Flags do not read | `<tool>: pid <pid> VAD at 0x<addr>: flags not read: <error>`; protection and kind `unknown`. Strict mode: the run fails |
| `MmProtectToValue` absent or unread | `<tool>: MmProtectToValue: not read, VAD protections unknown: <error>`, once |
| `MmHighestUserAddress` in the table but unread, zero or above the documented top | `<tool>: MmHighestUserAddress at 0x<addr>: not read, user space taken to end at 0x<limit>: <error>` (or `holds 0x<value>, user space taken to end at 0x<limit>`), once per walk setup |
| File name layout absent | `<tool>: VAD file names not read: layout: <error>`, once; no paths |
| A kept node's `ParentValue` does not read (memory tree) | `<tool>: pid <pid> _EPROCESS at 0x<addr>: <n> VAD parent links not read, shown as 0` |
| Page-listing root does not read | `<tool>: pid <pid> _EPROCESS at 0x<addr>: pages not listed: <error>`; strict mode: the run fails |
| Page listing on another OS | Error naming `any.memory.list` for Linux ranges |
| Page tables unreadable | `<tool>: <n> page tables unreadable, <n> filled with one repeated entry, <n> pages outside the image; their ranges are left out` |

## 7. Result schema

`Mapping` (Windows; the Linux fields `PageOffset`, `Inode`, `Major`, `Minor` stay zero): `PID`, `Process`, `DirectoryTableBase` (the process list's), `VadAddress` (the VAD's address), `Start`, `End` (inclusive), `Protection` (4.4), `Type` (`private`, `image`, `mapped`, `unknown`, exported as `KindPrivate`, `KindImage`, `KindMapped`, `KindUnknown`; 4.5), `PrivateMemory` and `PrivateMemoryKnown`, `CommitCharge` (pages) and `CommitChargeKnown`, `Path`, `PathUnreadable` and `NoFile` (4.6 step 6: never both set; `NoFile` stays false on Linux rows, whose naming is S39's), `Parent` and `ParentUnreadable`, `Tag` (four printable ASCII bytes, else empty). Sorted by process-list order, then `Start`.

`TreeNode`: `Base`, `Parent`, `Left`, `Right`, `Start`, `End`, `Tag`, in `Start` order. `VAD`: `Base`, `Start`, `End`, `PrivateMemory`, `PrivateMemoryKnown`, `Tag`, in `Start` order. `PageRun`: `PID`, `Virtual`, `Physical`, `Size`, `FileOffset`, in walk order. `MappedFile`: `ControlArea`, `FileObject`, `Path`, `NameUnreadable`, `NoFile`.

## 8. Limits

`MaxListEntries` bounds the kept nodes of one tree (default 2^20, far above the largest measured tree of 1,936, M6) and sets the height bound of 4.2 step 2.

## 9. Acceptance

1. Synthetic fixtures (`tools/any/memoryranges/*_test.go`, on the 26100 layout of T1 to T5 and the shared process fixture): every rule of 4.2 including a node reached twice and a refused deep tree, high bytes, the protection table and names, every kind, a section view's file name with and without `File`, a short VAD that names no file, the three file states (no file for private VADs, `File` clear and a zero `FilePointer`; unreadable for unread flags, an unread control area and an unread name), the commit charge with its high byte, unreadable flags, strict mode, the page listing and the address filter.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzVADTree` (up to eight nodes with arbitrary ranges, flags and links, including links into the middle of nodes; no panic, kept ranges ordered, disjoint, page-aligned, below the user limit, each node once, at most the budget, every protection parses, `NoFile` and `PathUnreadable` never both set and neither with a path): 783,230 executions; rerun with the file-state checks after O8, 538,922 executions, no failure. `FuzzProtectionName` (any value renders and parses back to itself): 2,706,674 executions.
3. On the captures, `vadfacts -tool`, 2026-11-12, rerun after the w12 sweep (page runs and pages outside the image refreshed; every other count unchanged):

| Capture | `any.memory.list` rows (image, mapped, private) | Named | Protection unknown | Processes with nodes left out | `windows.memory.tree` rows | Page runs (MiB mapped) |
|---|---|---|---|---|---|---|
| mem1_win11 | 10,747 (4,430, 3,033, 3,284) | 5,711 | 0 | 1 | 10,747 | 38,330,323 (172,808) |
| mem2_win10 | 21,783 (8,315, 5,533, 7,935) | 10,166 | 0 | 10 | 21,783 | 13,687,445 (83,994) |
| mem5_server2016 | 9,808 (3,489, 2,372, 3,947) | 4,352 | 0 | 9 | 9,808 | 5,688,692 (33,230) |
| mem6_server2025 | 14,093 (4,859, 3,949, 5,285) | 6,587 | 0 | 5 | 14,093 | 31,923,393 (137,830) |

   - The rows equal the kept nodes of M3 on every capture, and every row's tag starts with `Vad`.
   - Named rows are the section views of M12 whose name buffer also reads; 4, 60, 0 and 4 have a nonzero name length but a buffer that does not read.
   - File states after O8 (`vadfacts -tool`, 2026-11-12), mem1 / mem2 / mem5 / mem6: no file 5,032 / 11,551 / 5,455 / 7,497 (every private row, 3,284 / 7,935 / 3,947 / 5,285, and section views without a file, 1,748 / 3,616 / 1,508 / 2,212, all `mapped`); unreadable 0 / 60 / 0 / 4 (`mapped` 0 / 57 / 0 / 1, `image` 0 / 3 / 0 / 3); a name that reads but is empty 4 / 6 / 1 / 5, all `mapped`. Named, empty, no-file and unreadable rows add up to the row count on all four.
   - Protections seen: `NOACCESS`, `READONLY`, `READWRITE`, `WRITECOPY`, `EXECUTE_READWRITE`, `EXECUTE_WRITECOPY`, and `READWRITE|WRITECOMBINE` (460, mem1 only), as M10 predicts.
   - Page runs walk each process's kernel root, so system space is counted once per process. The listing reports page tables unreadable (1,577, 0, 0, 0), filled with one repeated entry (365,952, 478,737, 2,020, 444,301) and pages outside the image (54,103, 40,939, 20,365, 66,155).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The tables do not expand `_MMVAD_SHORT.u` and `.u1`; that `u` holds `_MMVAD_FLAGS` and `u1` `_MMVAD_FLAGS1` rests on M11 and M12. | A symbol-table change that keeps union members |
| O2 | `VadType` has no enumeration in the tables (T7); 2 meaning an image view is measured (M11). Other values are not named. | Owner decision on measured constants |
| O3 | The pool-tag fallback for tables without `PrivateMemory` and the tag offset rest on measurements (M4, M11). | Owner decision |
| O4 | x86 kernels (4-byte pointers, no high bytes): the fast-reference mask, the tag offset and the 3 GB user limit are not measured. | A 32-bit capture (Q7) |
| O5 | The pool tag is read but is not a rule; the interval rule removes every node whose tag does not start with `Vad` (M4). | Owner decision |
| O6 | A table without `VadNode` (builds before the measured ones) is walked with the node at the VAD's start. | A capture of such a build |
| O7 | Private commit charges of 2^35 − 2, and others above the page count (M12), are reported as read; their meaning is not documented. Owner decision 2026-11-12 (follow-up M3): report the raw value; measure on the lab VM later. Done: no change needed; 4.7 reports the raw sum and the code holds no sentinel constant (`tools/any/memoryranges/vadflags.go`). Remains: a lab VM measurement of what writes 2^35 − 2. | A source for the value, or a lab VM measurement |
| O8 | `PathUnreadable` is true for rows with no file at all, kept from 0.1.0 for callers; a separate "no file" state would be clearer. Row field names are owner question Q2. Owner decision 2026-11-12: Add a separate no-file state. Done: `Mapping.NoFile` and `MappedFile.NoFile` (names from this specification, Q2); `PathUnreadable` now means a file may be mapped but its name did not read (4.6 step 6, section 7, 9.3; `tools/any/memoryranges/listing.go`, `sectionfile.go`, `vadrows.go` and tests). Callers fixed: `examples/memory` prints N/A for no file and the unreadable mark otherwise. | Owner decision |
| O9 | `VadCount` differs from the kept count in 18 % of trees (M9), mostly by smear; it is not checked. A diagnostic would flag an unlinked VAD and many smeared trees alike. | Owner decision |
| O10 | `ParentValue` disagrees with the tree in M8's nodes; it is reported as read, not checked. | Owner decision |
| O11 | Rows stay in start order (4.2 step 4, 4.8). | Owner decision 2026-11-12 (follow-up M1): confirm start order. Done: no change. |
| O12 | A node left out by 4.2 step 3 takes its subtree with it, and the left-out nodes are not listed. A process whose tree lost nodes is reported once, with the count left out per reason (section 6), not node by node. | Owner decision 2026-11-12 (follow-up M2): accept per-process counts. Done: no change. |
| O13 | The page-run counts of 9.3 differed slightly from the w12 run. | Owner decision 2026-11-12 (follow-up D11): refresh to the w12 measurements. Done: `vadfacts -tool` rerun on the four captures; page runs on mem1, mem2 and mem5 and pages outside the image on the same three changed (9.3); every other count unchanged. |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Defer to v0.2.0 |
| O2 | Accept measured value, name only image |
| O3 | Accept the measured fallback |
| O4 | Ship as written, mark untested |
| O5 | Interval rule removes non-Vad tags |
| O6 | Keep node-at-start walk |
| O7 | Report as read |
| O8 | Add a separate no-file state |
| O9 | Do not check |
| O10 | Report as read |
| O11 | Confirm start order |
| O12 | Accept per-process counts |
| O13 | Refresh to w12 measurements |

## 11. Provenance

Written from Microsoft Learn's Win32 and driver documentation, the Intel SDM, the ntoskrnl types in the project's symbol tables, and the project's measurements. Every rule rests on the sources and measurements above.
