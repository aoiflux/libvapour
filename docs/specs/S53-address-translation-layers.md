# S53: Address translation layers

Version 1, 2026-11-12.

## 1. Purpose

Every reader of kernel or process memory in a session goes through one translator: the processor's page-table walk, done in software over the captured physical memory. An examiner needs that walk to give the bytes the processor would have read, to say why an address gives none (never mapped, paged out, demand-zero, behind a prototype entry, or a table the capture lacks), and to list or map what a page-table root maps. A Windows session also has to find that root without the processor's registers, and the kernel's virtual base without the debugger's help.

This specification covers the four paging modes and their entry formats, the Windows meanings of not-present entries as far as the kernel's own `_MMPTE` types state them, the Linux frame field, the page-table entry cache, the virtual reader, the address-space listing, the physical frame map, the System process scan that gives the kernel root, and the four ways the kernel base is found. Paging-mode detection is S04; VMCOREINFO, which gives the Linux root, is S05.

## 2. Inputs

| Input | Meaning |
|---|---|
| Physical | The image's physical address space. Where it lists segments, only their bytes are held (`memory.MappedRanges`). |
| CR3 | A page-table root as a CR3 value: the System process's `DirectoryTableBase`, a process's, or the Linux root from VMCOREINFO (S05). |
| Mode | One of four presets, or a Linux mode derived from one (section 4.1). The zero value is 4-level paging. |
| Symbol table | Windows only: the kernel's `_EPROCESS`, `_KPROCESS`, `_LIST_ENTRY`, `_MMPTE_SOFTWARE` and `_MI_HARDWARE_STATE` types and the `PsActiveProcessHead` symbol. |
| Pagefiles | Optional readers by pagefile number, used only when `CheckPagefilePTELayout` accepts the kernel (4.3). |
| Limits | `PTECacheEntries` (entry cache), `MaxImageBytes` (frame map storage), `MaxListEntries` (process-list walk). |

## 3. Facts from the sources

### 3.1 Architecture

Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 3A, order number 253668-093US. In this edition paging is chapter 5 (chapter 4 in editions before the HLAT additions). S04 section 3 holds facts A1 to A15 and is not repeated here.

| # | Fact | Source |
|---|---|---|
| P1 | 4-level paging takes bits 47:39, 38:30, 29:21 and 20:12 of a linear address as indexes into the PML4 table, the page-directory-pointer table, the page directory and the page table, 512 8-byte entries each. 5-level paging adds bits 56:48 for the PML5 table. | 5.5.4 |
| P2 | A PTE (Table 5-20): P bit 0, R/W 1, U/S 2, PWT 3, PCD 4, A 5, D 6, PAT 7, G 8, physical address bits M−1:12, protection key 62:59, XD 63. | Table 5-20 |
| P3 | A PDE with PS (bit 7) = 1 maps a 2-MByte page from bits M−1:21; bit 12 is PAT; bits 20:13 are reserved. A PDPTE with PS = 1 maps a 1-GByte page from bits M−1:30; bit 12 is PAT; bits 29:13 are reserved. With PS = 0 an entry references the next table at bits M−1:12. | Tables 5-16 to 5-19 |
| P4 | PAE paging: CR3 bits 31:5 locate four PDPTEs; bits 31:30 of the address pick the PDPTE, 29:21 the PDE, 20:12 the PTE. A PDE with PS = 1 maps a 2-MByte page. | 5.4.1, 5.4.2, Tables 5-8 to 5-11 |
| P5 | 32-bit paging: bits 31:22 pick one of 1,024 4-byte PDEs, bits 21:12 a PTE. A PDE with PS = 1 maps a 4-MByte page: bits 31:22 are address bits 31:22 and bits M−20:13 are address bits M−1:32, with M at most 40 (PSE-36). | 5.3, Table 5-4 |
| P6 | "If a paging-structure entry's P flag (bit 0) is 0 or if the entry sets any reserved bit, the entry is used neither to reference another paging-structure entry nor to map a page." | 5.3, 5.4.2, 5.5.4 |
| P7 | Two entries that hold one address make the processor use one table for two address ranges, and a root entry that holds the root's own address is used "as a PML4E, a PDPTE, a PDE, and a PTE". | 5.10.3.3 |
| P8 | A 4-level address is canonical when bits 63:47 are all equal; a 5-level one when bits 63:56 are. | 4.5 (S04 A14) |

AMD64 Architecture Programmer's Manual, Volume 2: System Programming, publication 24593, revision 3.46 (October 2026), chapter 5, fetched from docs.amd.com on 2026-11-12. S04 section 3.1 holds its reserved-bit facts A16 to A20.

| # | Fact | Source |
|---|---|---|
| P9 | Long mode takes bits 56:48 (5-level only), 47:39, 38:30, 29:21 and 20:12 as indexes into 512-entry tables of 8-byte entries, as P1. A PTE has P 0, R/W 1, U/S 2, PWT 3, PCD 4, A 5, D 6, PAT 7, G 8, the physical-page base in bits 51:12, the protection key in 62:59 and NX in 63, as P2. A PDE with PS = 1 maps a 2-MByte page from bits 51:21 and a PDPTE with PS = 1 a 1-GByte page from bits 51:30, with PAT at bit 12 and the bits between reserved, as P3. PS is MBZ in PML5Es and PML4Es, so neither maps a page. | APM 5.3.3 to 5.3.5, Figures 5-19 to 5-23, 5-29, 5-34; 5.4.1 "Page Size (PS) Bit", "Page-Attribute Table (PAT) Bit" |
| P10 | Legacy PAE: bits 31:30 pick one of four PDPTEs, 29:21 the PDE, 20:12 the PTE; a PDE with PS = 1 maps a 2-MByte page, as P4. Non-PAE: a PDE with PS = 1 maps a 4-MByte page with address bits 31:22 in bits 31:22 and address bits 39:32 in bits 20:13, the same field as P5 with M at its largest, 40. | APM 5.2.2, 5.2.3, Figures 5-8, 5-9, 5-13 |
| P11 | With Secure Memory Encryption the C-bit, whose position CPUID gives and which "may be a physical address bit (e.g., address bit 47)", marks an encrypted page in an entry of any level, and the physical address width may shrink while it is enabled. | APM 7.10.1, 7.10.4 |

### 3.2 Windows kernel types

Read through the project's symbol tables for the captures' own kernels with `pagetablefacts`: build 26100 (mem1, mem6, mem7), 19045 (mem2), 14393 (mem5).

| # | Fact |
|---|---|
| W1 | `_MMPTE_HARDWARE`: Valid 0, Dirty1 1, Owner 2, WriteThrough 3, CacheDisable 4, Accessed 5, Dirty 6, LargePage 7, Global 8, CopyOnWrite 9, Write 11, NoExecute 63 on all three builds. `PageFrameNumber` is bits 47:12 on 14393 and 19045 (bits 51:48 `reserved1` or `ReservedForHardware`) and bits 51:12 on 26100. A `LargePage` member, which only an entry above the leaf can use, makes the type the format of directory entries too. |
| W2 | `_MMPTE_TRANSITION`: Valid 0, Protection 9:5, Prototype 10, Transition 11, `PageFrameNumber` 47:12 (14393, 19045) or 51:12 (26100). |
| W3 | `_MMPTE_SOFTWARE`: Valid 0, Protection 9:5, Prototype 10, Transition 11, `PageFileHigh` 63:32 on all three builds. `PageFileLow` is bits 4:1 on 14393 and bits 15:12 on 19045 and 26100, where bits 4:1 are `PageFileReserved`, `PageFileAllocated`, `ColdPage` and `SwizzleBit`. |
| W4 | `_MMPTE_PROTOTYPE`: Valid 0, Prototype 10, `ProtoAddress` 63:16 on all builds, declared `long long`, so signed (`guifacts -prototype`, 2026-11-12, on all five Windows captures). Bit 11 is `Combined` on 19045 and 26100 and part of `Protection` (15:11) on 14393. `_MMPTE_SUBSECTION`: Prototype 10, `SubsectionAddress` 63:16. |
| W5 | `_MI_HARDWARE_STATE.InvalidPteMask` exists (offset 0xC0) on 19045 and 26100, not on 14393. |
| W6 | `_KPROCESS.DirectoryTableBase` is at 0x28 and `_EPROCESS.Pcb` at 0 on all builds. `_EPROCESS.UniqueProcessId`, `ActiveProcessLinks` and `ImageFileName` are at 0x2E8, 0x2F0, 0x450 (14393), 0x440, 0x448, 0x5A8 (19045) and 0x1D0, 0x1D8, 0x338 (26100). |
| W7 | No build's table has `_KDDEBUGGER_DATA64` or `_DBGKD_DEBUG_DATA_HEADER64`. Every build has the symbols `KdDebuggerDataBlock` and `KdpDataBlockEncoded`. |

### 3.3 Microsoft Learn

| # | Fact | Source |
|---|---|---|
| L1 | "At location 0x3c, the stub has the file offset to the PE signature." The COFF header's fields end at offset 20; `SizeOfOptionalHeader` is at 16. The optional header's `Magic` is 0x10B (PE32) or 0x20B (PE32+); data directories start at 96 or 112, and `NumberOfRvaAndSizes` is at 92 or 108: "the number of directories is not fixed. Before looking for a specific directory, check the NumberOfRvaAndSizes field." Debug is the seventh, at 144 or 160. "The SizeOfOptionalHeader field in the COFF header must be used to validate that a probe into the file for a particular data directory does not go beyond SizeOfOptionalHeader." `ImageBase` "must be a multiple of 64 K". | "PE Format", accessed 2026-11-12 |
| L2 | A debug directory entry is `Characteristics` 0, `TimeDateStamp` 4, `MajorVersion` 8, `MinorVersion` 10, `Type` 12, `SizeOfData` 16, `AddressOfRawData` 20 ("the address of the debug data when loaded, relative to the image base"), `PointerToRawData` 24: 28 bytes. `IMAGE_DEBUG_TYPE_CODEVIEW` is 2. The RSDS record is S32 F20 and S47 B6. | "PE Format", Debug Directory (Image Only), Debug Type |
| L3 | `DEBUG_DATA_KernBase` "returns the base address of the kernel image"; `DEBUG_DATA_PsActiveProcessHeadAddr` "the address of the kernel variable PsActiveProcessHead". | "IDebugDataSpaces::ReadDebuggerData (dbgeng.h)", accessed 2026-11-12 |
| L4 | The debugger data block is found by `KDBG_TAG` ("specified in wdbgexts.h"), and its size includes the header. The tag's value and the block's layout are not given. | "GetDebuggerData macro (wdbgexts.h)", accessed 2026-11-12 |

### 3.4 Linux

Checked at v4.19, v6.1, v6.4, v6.14 and v6.17.

| # | Fact | Source |
|---|---|---|
| X1 | `_PAGE_BIT_PRESENT` 0, `_PAGE_BIT_RW` 1, `_PAGE_BIT_USER` 2, `_PAGE_BIT_ACCESSED` 5, `_PAGE_BIT_DIRTY` 6, `_PAGE_BIT_PSE` 7 (`_PAGE_BIT_PAT` 7 on 4-KByte pages, `_PAGE_BIT_PAT_LARGE` 12), `_PAGE_BIT_GLOBAL` 8, `_PAGE_BIT_NX` 63, all tags. | `arch/x86/include/asm/pgtable_types.h` |
| X2 | "If _PAGE_BIT_PRESENT is clear": `_PAGE_BIT_PROTNONE` is `_PAGE_BIT_GLOBAL`, "if the user mapped it with PROT_NONE; pte_present gives true". A swap entry keeps its type in the top 5 bits and its offset above `_PAGE_BIT_PROTNONE`, inverted. | `pgtable_types.h`; `arch/x86/include/asm/pgtable_64.h` (`SWP_TYPE_BITS`, `__swp_offset`), v4.19, v6.17 |
| X3 | A not-present entry that is not zero has its frame inverted (`__pte_needs_invert`, `protnone_mask`). | `arch/x86/include/asm/pgtable-invert.h`, v4.19, v6.17 |
| X4 | `PTE_PFN_MASK` is `PHYSICAL_PAGE_MASK`, `PAGE_MASK & __PHYSICAL_MASK`; `__PHYSICAL_MASK` is `physical_mask` under `CONFIG_DYNAMIC_PHYSICAL_MASK`, else `(1 << __PHYSICAL_MASK_SHIFT) − 1`, and `__PHYSICAL_MASK_SHIFT` is 52 on x86-64. | `pgtable_types.h`, `page_types.h`, `page_64_types.h`, all tags |
| X5 | SME setup clears the encryption bit from the physical mask: `physical_mask &= ~sme_me_mask`. | `arch/x86/mm/mem_encrypt_identity.c` (v4.19, v6.1, v6.14); `arch/x86/boot/startup/sme.c` (v6.17) |
| X6 | `MAX_PHYSMEM_BITS` is 52 with 5-level paging and 46 without, on x86-64. VMCOREINFO carries it, and `sme_mask` (S05 K10). | `arch/x86/include/asm/sparsemem.h`, all tags |

### 3.5 Measurements

`pagetablefacts` on all seven captures, 2026-11-12. Process roots: the first six processes of `PsActiveProcessHead` with a root of their own.

- **M1 System process.** Exactly one 8-aligned record per Windows capture has `UniqueProcessId` 4 and `ImageFileName` "System" followed by NUL. Each has a root with bits 11:0 clear and below the image size, upper-half entries in its root (mem1 53, mem2 50, mem5 20, mem6 54, mem7 54), one root entry pointing at the root itself, and `ActiveProcessLinks` both in the upper half. Its `Blink` is `PsActiveProcessHead` (verified base + RVA) on all five.
- **M2 Self-map index.** The root entry that points at the root is 264 (mem1), 479 (mem2), 483 (mem5), 493 (mem6), 494 (mem7). The Linux roots have none.
- **M3 Frame width.** No present or transition entry reached from the kernel root sets any of bits 51:45 on mem2, mem5, mem6, mem7 or the Linux captures. On mem1, 316 present and 116 transition entries do; every one names a frame past the image's end, as do 128 transition frames even within bits 44:12 (M3a).
- **M4 Leaves.** Entries at the leaf level of the kernel root, by kind, and what `Translate` gives (table 9.1). Every present leaf and every transition leaf translates; every prototype leaf faults as prototype, every software leaf with bits 63:32 set as in-pagefile, every other non-zero software leaf with Protection set as demand-zero, and the rest as not mapped.
- **M5 Swizzled entries.** On mem2 (19045), 261,894 of the 361,721 software leaves with bits 63:32 set have bits 31:0 all zero, the shape an empty entry takes when XORed with a mask confined to bits 63:32 (W5).
- **M6 One-value tables.** Tables below the root whose 512 entries are one value: 3,119 (mem2), 27 (mem5), 4,399 (mem6), 4,407 (mem7), 4,409 (mem1), and one each on mem3 and mem4. On mem6 and mem7, 4,356 of them repeat one present, global, no-execute entry for a single frame, so each maps that frame 512 times.
- **M7 Debugger data block.** At `KdDebuggerDataBlock` the bytes are encoded on all five captures (no "KDBG" at +0x10). A physical scan for "KDBG" finds a block whose 64-bit value at tag+8 is the verified kernel base on mem6 and mem7 only (M7a, section 9.2).
- **M8 Kernel base.** Results and times of the four methods, table 9.2.
- **M9 Entry cache.** Translating the first 200,000 leaves (mem5: all 168,511) of the kernel root reads 4 entries per address without the cache and 1.0 with 8,192 entries (table 9.1).
- **M10 Listing and frame map.** Table 9.3.
- **M11 Linux.** Both Linux roots are 4-level (VMCOREINFO and S04 agree), `MAX_PHYSMEM_BITS` 46, `sme_mask` 0. mem4 has 418 not-present non-zero leaf entries in its kernel tables; mem3 none.

## 4. Algorithm

### 4.1 Modes

| Preset | Name | Levels (index bits, leaf-capable) | Entry | Root (CR3 bits) | Frame field | Not-present entries |
|---|---|---|---|---|---|---|
| `ModeX64` | x64 | 9, 9 (1 GiB), 9 (2 MiB), 9 | 8 bytes | 51:12 | 51:12 | Windows meanings (4.3) |
| `ModeLA57` | la57 | 9, 9, 9 (1 GiB), 9 (2 MiB), 9 | 8 bytes | 51:12 | 51:12 | Windows meanings |
| `ModeX86PAE` | x86pae | 2, 9 (2 MiB), 9 | 8 bytes | 31:5 | 51:12 | none |
| `ModeX86NonPAE` | x86 | 10 (4 MiB), 10 | 4 bytes | 31:12 | 31:12, PSE-36 for 4 MiB | none |

The frame field is the architecture's widest (A5, A6, P2, P3; AMD P9, P10), which is also the 26100 `PageFrameNumber` (W1, W2). On the older builds the bits above 47 are reserved or unused (W1, W2) and no measured entry sets them (M3). The zero `PagingMode` is `ModeX64`.

The x64 and LA57 presets do not remove the SME C-bit (P11). Its position comes from CPUID (APM 7.10.4), which a capture does not record, and a Windows image carries no other record of it, so an entry of an encrypted page on an AMD host with SME active is read with the C-bit as an address bit and names a frame the image may not hold. Only `LinuxMode` removes it, from VMCOREINFO's `sme_mask` (X5).

`LinuxMode(mode, physicalBits, encryptionMask)` names the mode `linux-<name>`, gives not-present entries no meaning (X2, X3: swap entries, `PROT_NONE` pages and inverted frames are all not-present), and for the 8-byte 64-bit modes sets the frame and root fields to bits `physicalBits−1`:12, or 51:12 when `physicalBits` is not in 13 to 51, less `encryptionMask` (X4, X5, X6). The 32-bit presets keep their fields.

`PagingModeByName` knows the four preset names only.

### 4.2 Walk

For a virtual address, from the root (CR3 & root field), at each level read the entry the address's index selects (P1, P4, P5), through the cache when one is enabled:

1. The entry cannot be read: fault `PageNotCaptured`, with the span of the entry that named the table (zero at the root).
2. Present, at the leaf: the page is the frame field plus bits 11:0 of the address.
3. Present, PS = 1 at a leaf-capable level: the page is the frame field with the bits below the page size cleared, plus the address bits below it (P3). For 32-bit paging the frame is bits 31:22 and bits 20:13 as 39:32 (P5).
4. Present otherwise: the next table is the frame field.
5. Not present, in a mode without Windows meanings: fault `PageInvalid`, with the entry's span above the leaf.
6. Not present, Windows meanings, Prototype 0 and Transition 1 (W2): at the leaf the page is the frame field; above it the next table is the frame field whatever bit 7 is, since bit 7 is inside Protection.
7. Not present, Windows meanings, at the leaf, otherwise: decode as 4.3.
8. Not present above the leaf otherwise: fault `PageInvalid` with the span.

Reserved bits are not tested. A present entry the processor would refuse (P6) is read through its address field. M3 and table 9.1 found no such entry on six captures; the mem1 entries of M3 name frames past the image, which then fail to read (O2).

`LeafEntry` returns the entry that ended the walk at the leaf level, or a large-page entry, whatever it holds; a walk that ends above the leaf returns its fault.

### 4.3 Windows not-present leaves

The `_MMPTE` members are told apart by Prototype (bit 10) first, since `_MMPTE_PROTOTYPE` uses bit 11 for `Combined` or `Protection` (W4), then by Transition (bit 11, W2), and an entry with both clear is `_MMPTE_SOFTWARE` (W3):

| Entry | Fault | Fields |
|---|---|---|
| Prototype 1 | `PagePrototype` | none: the processor never follows a prototype entry; `subsection` resolves it (S19) |
| `PageFileHigh` (63:32) non-zero | `PageInPagefile` | number = bits 4:1, offset = `PageFileHigh` × 4096 |
| Protection (9:5) non-zero | `PageDemandZero` | none |
| otherwise | `PageInvalid` | none |

The number and offset are the pre-17134 layout (W3). `CheckPagefilePTELayout` accepts a kernel only when its table declares `PageFileLow` as bits 4:1 and `PageFileHigh` as 63:32, and has neither `_MMPTE_SOFTWARE.SwizzleBit` nor `_MI_HARDWARE_STATE.InvalidPteMask` (W3, W5, M5). Of the captures, only 14393 (mem5) passes.

`ResolveProtoPTE` decodes the entry a prototype pointer leads to. That entry is read by the memory manager, not the processor, so a valid entry gives its frame first; then a transition entry its frame; then the table above.

`PrototypeEntryAddress` gives the address of the entry a prototype leaf names: `ProtoAddress` sign-extended from its top bit (W4), for an entry with Valid clear and Prototype set; any other entry names none. On mem7 every kernel prototype leaf of `win32kbase.sys`, `win32kfull.sys` and `win32k.sys` (956 entries) names an 8-byte-aligned system-space address that reads, and the one for `win32kbase.sys`'s header page names a transition entry whose frame holds the image's PE header (S57 M10). The translator still faults such a page as prototype; following the entry is the caller's choice.

### 4.4 Virtual reader

`VirtualMemoryLayer.ReadAt` splits a read at 4-KByte page boundaries, translates each page and reads it from Physical. A read whose last byte would wrap past 2^64 fails with `memory.ErrOutOfBounds`, a length above the platform's `int` with `memory.ErrSizeOverflow`. The result grows page by page past `MaxReadPrealloc` (1 MiB), because the length is often a value read from the image. A page whose fault is `PageInPagefile` is read from the pagefile of that number when one was supplied; otherwise the fault is the read's error. `Size` is Physical's size. `IsDirty` is bit 6 of a present leaf entry only (P2; in a not-present Windows entry bit 6 is Protection, W2, W3).

`NewProcessLayer` enables the cache only when Physical is an immutable snapshot (`memory.IsImmutableSnapshot`): an entry cached by its physical address is stale on live memory.

### 4.5 Entry cache

Up to `PTECacheEntries` entries (the limit's default when zero), keyed by the entry's physical address. A full cache evicts by second chance: a hand passes the slots in turn, clearing a slot's used mark or evicting the first slot without one. One lock guards it, since one process layer serves many readers.

### 4.6 Address-space listing

`IntelTranslator.Mapping` visits every entry of the root and the tables below it in index order, which is virtual-address order, and applies 4.2 steps 2 to 6. Each page is offered to a run; a page joins the open run when it follows it in both spaces and does not start the upper half; otherwise the run is emitted, with a canonical address (P8), and a new one opens. A page that the held ranges do not hold whole is counted in `UncapturedPages` and not listed. A table below the root that does not read is counted once in `UnreadableTables`. A table whose entries are all one value is not visited (M6): zero, it maps nothing; otherwise it is counted once in `RepeatedTables`. A root whose entries are all one value is an error. The walk follows the self-map (P7) as the processor would; its depth is bounded by the mode's levels. The callback's error ends the listing.

### 4.7 Frame map

`MapFrames` walks level by level. Each level's tables are visited once each, with the number of paths that reach them from the root and the lowest address prefix among those paths (P7: a table two entries name serves two ranges). A table already visited at a shallower level is visited again at this one; the entries that lead to such a table are counted in `RecursiveEntries`, and the table's counts (`Tables`, `UnreadableTables`, `RepeatedTables`) are made only on its first visit. Unreadable and one-value tables are skipped as in 4.6; an unreadable or one-value root is an error.

For each 4-KByte leaf the map records, per captured frame, the set of values of address bits 15:12 (the page keys, from the entry's index), and adds the table's path count to the frame's mappings. For each large page held whole it records the page with its paths and its lowest address; a large page held in part is counted once in `PartialLargePages` and not recorded. Storage is one 16-bit key set per frame of the held ranges, refused when they hold more frames than `MaxImageBytes` allows.

- `Contains(pa)`: the frame is held and a leaf or a large page maps it.
- `Len`: frames held that any leaf or large page maps.
- `Mappings(pa)`: the paths of every leaf and large page that map it.
- `SecondAddressBytes(pa)`: for each page key k, the byte `k << 4 | (pa >> 8 & 0xF)`, ascending; a large page gives the key of the frame's own bits 15:12, since a large page is aligned alike in both spaces.
- `LowestAddresses(queries)`: for each physical address and key set (`AnyPageKey` is all 16), the lowest canonical address that maps it through a leaf whose key is in the set, or through a large page whose frame key is. Leaf tables are read again for this; a leaf table that no longer reads is an error.

### 4.8 System process and kernel root

`FindKernelBootstrap` takes the member offsets from the table (W6) and scans the held ranges in 4-MiB windows that overlap by the record's span, at 8-byte steps (the records' measured alignment, M1, and an `_EPROCESS` holds 8-byte members). A candidate has `UniqueProcessId` 4 and `ImageFileName` "System" with its NUL (M1). It is accepted when its `DirectoryTableBase`, read as CR3 (bits 11:0 are flags or PCID, A5):

- sets none of bits 60:52 (A5),
- has a non-zero root below the image size (A13),
- has a readable root with at least one present entry among 256 to 511 (A14, A15),

and its `ActiveProcessLinks.Flink` is in the upper half (A15). The first accepted record in physical order is returned with its Flink and, when the table has `_LIST_ENTRY.Blink`, its Blink.

### 4.9 Kernel base

Every method except the debugger data block (step 3) reads the kernel through a translator in the mode S04 detects for the root, 4-level when undecided. Such a method accepts a candidate base when it is page-aligned, in the upper half, and its first two bytes read "MZ". `FindKernelBaseFromKDBG` takes no CR3 and reads nothing at the candidate: it accepts any page-aligned upper-half value (O12). The caller verifies the build from the CodeView record (`ImageCodeViews`). Page alignment, not 64-KiB alignment (L1), because mem5's kernel loads at 0xFFFFF80145019000 (table 9.2).

1. **List head** (`FindKernelBaseFromListHead`): the System process's Blink less the image-relative RVA of `PsActiveProcessHead` (L3, M1).
2. **Process list** (`FindKernelBaseByProcessListAnchor`): from the System process's Flink, each entry less the RVA is tried, then its Flink is followed, up to `MaxListEntries` entries. The walk ends with an error when an entry returns to the start, points at itself, leaves the upper half or does not read.
3. **Debugger data block** (`FindKernelBaseFromKDBG`): a physical scan at 8-byte steps for "KDBG" 16 bytes into a block, a 32-bit size after it of at least 32 bytes and at most a page, and a 64-bit base after that which is a candidate (M7, L4). The first page-aligned upper-half base is returned; no "MZ" is read at it (O12). Encoded blocks are not decoded (O4).
4. **Image scan** (`FindKernelImageBase`): every page start in the upper half of the address-space listing (4.6) whose physical bytes start "MZ" and whose CodeView record names the requested PDB, compared by its last path component, without case.

### 4.10 CodeView records

`ImageCodeViews` reads the first page of the image: "MZ", the PE signature at the offset at 0x3C, which with the COFF header must lie in the page, the optional header's magic, and the Debug directory, whose entry must lie inside `SizeOfOptionalHeader` (L1) and whose index, 6, must be below `NumberOfRvaAndSizes` at optional header offset 92 (PE32) or 108 (PE32+) (L1, O6). Every image measured declares 16 directories (S72 M1), so no capture's result changes. It reads up to one page of the debug directory and, for each 28-byte entry of type 2 (L2), up to 284 bytes at `AddressOfRawData`: "RSDS", the GUID, the age and a path ended by NUL within the 260 bytes after the age, so 1 to 259 bytes (S47 B6, B8). Each record that decodes is returned, in directory order.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| A table is read from Physical whole. | A13; a capture holds RAM. | `PageNotCaptured` with the span (walk); counted (listing, map). |
| A not-present entry carries Windows meanings only in the x64 presets. | W1–W4 measured on x64 builds only; X2, X3 for Linux. | Fault `PageInvalid`. |
| Prototype is tested before Transition. | W4. | — |
| A pagefile is read only for a kernel with the pre-17134 software layout and no swizzle. | W3, W5, M5. | The session leaves pagefiles closed; reads fault `PageInPagefile`. |
| A one-value table below the root is not listed or mapped. | M6. | Counted in `RepeatedTables`. |
| A System candidate's root is a loadable CR3 that maps the upper half; its Flink is in the upper half. | A5, A13, A14, A15, M1. | The candidate is skipped. |
| A kernel base is page-aligned, upper-half and starts "MZ". The debugger data block method tests only page alignment and the upper half (O12). | A15, M8 (table 9.2). | The method fails. |
| A debug directory entry lies inside `SizeOfOptionalHeader`. | L1. | `ImageCodeViews` fails. |
| `NumberOfRvaAndSizes` above 6, the Debug directory's index. | L1, O6. | `ImageCodeViews` fails. |

## 6. Failure modes

Leaf errors and sentinels (all `layers: ...`):

- `ErrPageInvalid` "page not mapped"; `ErrPageDemandZero` "page is demand-zero and was never written"; `ErrPageInPagefile` "page is in a pagefile that was not supplied"; `ErrPageNotCaptured` "page table not in the capture"; `ErrPagePrototype` "page is reached through a prototype entry". `UnmappedPageError` unwraps to its kind's sentinel; its text is `layers: virtual address 0x<va>: <kind>`, the kinds being "not mapped", "demand-zero", "in pagefile", "table not captured", "prototype".
- Listing and frame map: `layers: address-space listing: no physical layer`, `layers: frame map: no physical layer`, `layers: page-table root at 0x<root>: page table not in the capture` (wrapping `ErrPageNotCaptured`), `...: every entry is one value`, `layers: frame map: the image holds more than <n> frames, the MaxImageBytes limit`, `layers: page table at 0x<t>: ...` (a leaf table that no longer reads).
- System scan: `layers: system process scan: no symbol table`; `layers: system process scan: <type>.<member>: <err>`; `...: no System process in the <n>-byte image`; `...: no System process in the readable part of the image: <coverage>`.
- Kernel base: `layers: kernel base from the list head: ...`, `layers: kernel base from the process list: entry at 0x<e>: ...`, `layers: kernel base from the process list: no head in the first <n> entries`, `layers: kernel base from the debugger data block: none in the image` (or `...: none in the readable part of the image: <coverage>`), `layers: kernel image scan: ...`, ending `no image in the kernel half names <pdb>` when the listing completed.
- CodeView: `layers: image at 0x<base>: <what>`.

No limit is silent: the frame map refuses an image over `MaxImageBytes`, and the list walk says it stopped at `MaxListEntries`.

## 7. Result schema

Unchanged exported API. `MappedRun{Virtual, Physical, Size}` in bytes, ascending `Virtual`, canonical. `MappingStats{Tables, UnreadableTables, RepeatedTables, UncapturedPages}`. `FrameMap` counters `Tables`, `UnreadableTables`, `RecursiveEntries`, `RepeatedTables`, `PartialLargePages`. `UnmappedPageError{VirtualAddress, Kind, PageFileNumber, PageFileOffset, Span}`; `Span` is zero at the leaf. `KernelBootstrap{CR3, ListFlink, ListBlink}`; `ListBlink` is zero without `_LIST_ENTRY.Blink`. `CodeViewRecord{PDBPath, GUID, Age}`. `LowestAddress{Virtual, Mapped}`; `Virtual` is zero when not mapped.

## 8. Limits

- `PTECacheEntries`: cache capacity; measured hit rate in M9.
- `MaxImageBytes`: frame-map storage, 2 bytes per held frame.
- `MaxListEntries`: process-list walk.
- `MaxReadPrealloc` 1 MiB: the most a read allocates before its pages are known to read.
- One page each for headers and the debug directory, 260 bytes of PDB path (S47 B8).

## 9. Acceptance

Synthetic fixtures (`layers` tests): every mode's walk, 2-MiB, 1-GiB and PSE-36 4-MiB pages with their PAT and reserved bits dropped, CR3 flag bits, spans of misses at each level, a table outside the image, each Windows leaf kind and its pagefile fields, a transition directory entry with bit 7 set, a prototype directory entry not followed, prototype entry addresses (sign extension, present and transition entries naming none), Linux frame masks and present-only reading, `LeafEntry` above and at the leaf, cache read counts and eviction, reads across pages, wrap and size errors, bounded allocation of a failing huge read, pagefile reads, `IsDirty`, the cache gate, listing order, joins, the canonical gap, uncaptured pages, one-value tables, the callback's error, a 32-bit listing, the frame map's queries, the self-map, partial large pages, the storage limit, the System scan's rules and holes, the four base methods, and CodeView parsing and refusals. Fuzz targets, 30 s each: `FuzzTranslate` (a translation keeps the page offset, stays inside the frame field and has a leaf entry), `FuzzFrameMap` (the map and the listing fail together; every listed page translates, is in the map, and its lowest address is at most its listed one), `FuzzImageCodeViews` (no panic; paths are 1 to 260 bytes without NUL).

### 9.1 Kernel root leaves and translation (M4, M9)

| Capture | Present | Transition | Prototype | In pagefile | Demand-zero | Not mapped | 2 MiB | Reads per address, no cache / cache |
|---|---|---|---|---|---|---|---|---|
| mem1_win11 | 179,502 | 6,162 | 416,927 | 23,118 | 8,704 | 10 | 35 | 4.00 / 1.00 |
| mem2_win10 | 87,824 | 319 | 133,267 | 361,721 | 1,252 | 1 | 73 | 4.00 / 1.00 |
| mem5_server2016 | 89,700 | 494 | 74,621 | 3,536 | 126 | 3 | 31 | 4.00 / 1.00 |
| mem6_server2025 | 71,847 | 410 | 443,155 | 11,578 | 2,568 | 0 | 18 | 4.00 / 1.00 |
| mem7_server2025 | 78,838 | 654 | 486,013 | 13,798 | 1,865 | 2 | 19 | 4.00 / 1.00 |
| mem3_ubuntu24 | 39,964 | — | — | — | — | 0 | 1,023 | 3.98 / 1.00 |
| mem4_fedora40 | 58,696 | — | — | — | — | 418 | 994 | 3.98 / 1.00 |

Every present and transition leaf translated, every other kind faulted as its row says. The six process roots per Windows capture give the same: no leaf translated or faulted otherwise. On Linux "Not mapped" counts non-zero not-present leaves, which a Linux mode does not read. With the cache, reads per address are 1.002 to 1.003 on every capture; Linux's 2-MiB direct map makes the uncached figure under 4. The mem1 present leaves include the 11 entries with reserved bits set and the 316 whose frames lie past the image (M3): they translate, and reading their frames fails.

### 9.2 Kernel base methods (M8)

The verified base is the one whose CodeView record names the loaded kernel. Times on the measuring host.

| Capture | Verified base | List head | Process list | Debugger data block | Image scan |
|---|---|---|---|---|---|
| mem1_win11 | 0xFFFFF8037D130000 | found | found | none (6.3 s) | found (2.1 s) |
| mem2_win10 | 0xFFFFF80563400000 | found | an entry's Flink is 0 | none (7.8 s) | found (1.0 s) |
| mem5_server2016 | 0xFFFFF80145019000 | found | found | none (2.6 s) | found (0.5 s) |
| mem6_server2025 | 0xFFFFF804A6BA0000 | found | found | found (4.6 s) | found (2.2 s) |
| mem7_server2025 | 0xFFFFF801A1850000 | found | an entry's Flink is 0x8067 | found (1.5 s) | found (2.6 s) |

List head and process list take under 20 ms. Every base a method returned was the verified base.

M7a, the debugger data blocks the scan finds: mem6 has two, at physical 0x6D11D080 and 0x6D1E1080, mem7 one at 0x25AD8080; each has a `_LIST_ENTRY` of two equal kernel addresses at +0, "KDBG" at +0x10, size 0x3A0 at +0x14 and the verified base at +0x18. Of all "KDBG" byte strings in the images (mem6 76, mem7 51, mem2 25), no other is followed by the base.

### 9.3 Listing and frame map (M10)

Kernel root; the listing counts a table each time the self-map leads to it again, the frame map once.

| Capture | Runs | Listed MiB | Tables | Unreadable | One-value | Uncaptured pages | Frames | Map tables | Recursive | Partial large |
|---|---|---|---|---|---|---|---|---|---|---|
| mem1_win11 | 457,267 | 2,053.8 | 2,640 | 19 | 4,409 | 477 | 194,260 | 1,895 | 1 | 0 |
| mem2_win10 | 82,880 | 519.6 | 1,620 | 0 | 3,119 | 258 | 118,915 | 1,539 | 1 | 0 |
| mem5_server2016 | 71,682 | 426.1 | 474 | 0 | 27 | 258 | 98,485 | 415 | 1 | 0 |
| mem6_server2025 | 311,322 | 1,344.9 | 2,157 | 0 | 4,399 | 655 | 80,219 | 1,566 | 1 | 0 |
| mem7_server2025 | 320,112 | 1,380.4 | 2,289 | 0 | 4,407 | 655 | 89,373 | 1,698 | 1 | 0 |
| mem3_ubuntu24 | 5,763 | 2,141.5 | 118 | 0 | 1 | 183 | 510,698 | 118 | 0 | 3 |
| mem4_fedora40 | 6,748 | 2,204.7 | 162 | 0 | 1 | 159 | 522,568 | 162 | 0 | 2 |

Both take at most 0.4 s per root. `FindKernelBootstrap` stops at the first accepted record: 0.2 s (mem7) to 7.8 s (mem2, whose record is at 4.1 GiB). Reading every window takes 2.4 s (mem5) to 16.9 s (mem1, 10 GiB).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Result field names, kind names and messages are this specification's; the old `PageErrorKind.String` texts ("pagefile-backed", "invalid") and sentinel texts changed. | Owner decision (Q2) |
| O2 | Reserved bits are not tested: a present entry the processor refuses (P6) is read through its address field. The processor-faithful rule (fault) changes no measured translation on six captures. | Owner decision: fault on reserved bits, or read through (default) |
| O3 | `PageFileHigh` zero is read as "no pagefile page" and Protection non-zero then as demand-zero; no public source states either. On 19045 and 26100 swizzled entries (M5) are not unswizzled, so their kind can be "in pagefile" for an empty entry. | A capture with its pagefile; `MiState.Hardware.InvalidPteMask` read from the image |
| O4 | The debugger data block layout (tag at +0x10, size at +0x14, base at +0x18) is measured (M7), not documented (L4); encoded blocks are not decoded. | Owner decision on a measured layout |
| O5 | AMD APM Volume 2 was not fetched; the entry formats are Intel's. | The APM, Volume 2, chapter 5. Owner decision 2026-11-12: fetch and check now. Done: revision 3.46 (October 2026), chapter 5 read (P9 to P11, S04 A16 to A20). Every index field, leaf level, frame field, PAT position and PSE address field of section 4.1 and 4.2 matches AMD's, so no code or test changed here; the PAE PDPTE difference is in S04 (A16). Remains: an AMD host with SME active (P11) would set the C-bit inside the frame field of the x64 presets, which read it as an address bit; `LinuxMode` removes it through `sme_mask` (X5). No Windows capture shows that pattern (M3), and a Windows image gives no C-bit position. Owner decision 2026-11-12 (follow-up D2): accept, and document that the C-bit cannot be removed in the x64 Windows presets, because its position comes from CPUID (APM 7.10.4), which a capture does not hold. Done: 4.1 states it; no code change. |
| O6 | `NumberOfRvaAndSizes` is not consulted (L1 says to); the project's own fixtures omit it. Owner decision 2026-11-12: Consult it. Done: `ImageCodeViews` refuses an image whose count leaves out the Debug directory (4.10, section 5; `layers/codeview.go`); the fixtures now write 16 (`layers/codeview_test.go`, `symbols/autoload/s75_fixture_test.go`, `s76_fixture_test.go`), with refusals for 0 and 6 directories and acceptance of 7. The `pe` package already consulted it (S72 P5). | Owner decision |
| O7 | The x86 presets give not-present entries no Windows meaning: no 32-bit kernel was measured. | A 32-bit capture (Q7) |
| O8 | Linux `PROT_NONE` pages are resident but not present (X2) and are not read. | Owner decision: read them with the frame un-inverted (X3) |
| O9 | The scan's "System" name and PID 4 are measured on five captures (M1), not documented. | Owner decision on measured constants |
| O10 | S04 leaves mem1 undecided (an all-ones PDE refutes the 4-level reading), so mem1 is read as 4-level by default. | S04 |
| O11 | A kernel page behind a prototype leaf faults; only the GUI tools follow the entry, for `win32kbase.sys`'s header (S57 4.1). Owner decision 2026-11-12 (follow-up D13): read that header through the prototype entry before release. Done: `PrototypeEntryAddress` (4.3; `layers/windows_entries.go`, test `TestAPrototypeEntryNamesItsTargetSignExtended`); `Translate` is unchanged. Remains: the entry's 48 bits cannot hold a 5-level address, and no 5-level capture has a kernel prototype leaf. | Owner decision |
| O12 | `FindKernelBaseFromKDBG` (`layers/kernelbase.go`) takes no CR3 and does not read "MZ" at its candidate: it returns the first page-aligned upper-half base a block holds. The session's CodeView check (S76) is then the only test of that base; outside strict mode an unconfirmed base is still used, with a note. Owner decision 2026-11-12: kept for v0.1.0; read "MZ" at the candidate through a translator in v0.2.0. | v0.2.0 |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept |
| O2 | Read through |
| O3 | Defer to v0.2.0 |
| O4 | Accept measured layout |
| O5 | Fetch and check now |
| O6 | Consult it |
| O7 | Defer to v0.2.0 |
| O8 | Do not read them |
| O9 | Accept measured constants |
| O10 | Keep 4-level default |

## 11. Provenance

Written from the Intel SDM, the AMD APM Volume 2 (revision 3.46), Microsoft Learn's PE Format and debugger pages, the Linux headers at the tags named, the ntoskrnl types in the project's symbol tables, and the project's measurements. Every rule rests on the sources and measurements above.
