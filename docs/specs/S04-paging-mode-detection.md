# S04: Paging-mode detection

Version 1, 2026-11-11.

## 1. Purpose

A Windows session finds the kernel's page-table root (the System process's directory table base) but no control registers. The processor that wrote the image chose one of four paging modes from CR0.PG, CR4.PAE, IA32_EFER.LME and CR4.LA57, and each mode reads the same table bytes differently. This specification decides the mode from the tables themselves, using only rules the processor enforces, and says when the evidence does not decide.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Physical | memory reader | The image's physical address space. Its size is the end of the highest captured byte. |
| Root | unsigned 64-bit | The candidate CR3 value: a page-table root that may carry the flag and PCID bits of CR3. |
| Pointer width | 4 or 8 bytes | The kernel's pointer size, from the symbol table the session has already matched to the image. |

## 3. Constraints from the architecture

All references are to the Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 3A, order number 253668-093US (September 2026). In this edition paging is chapter 5.

| # | Constraint | Source |
|---|---|---|
| A1 | 32-bit paging: CR0.PG = 1, CR4.PAE = 0. PAE paging: CR0.PG = 1, CR4.PAE = 1, IA32_EFER.LME = 0. 4-level paging: also IA32_EFER.LME = 1 and CR4.LA57 = 0. 5-level paging: CR4.LA57 = 1. | 5.3, 5.4, 5.5 |
| A2 | 32-bit and PAE paging translate 32-bit linear addresses. 4-level and 5-level paging run only in IA-32e mode, whose linear addresses are 64 bits wide. A kernel with 4-byte pointers therefore uses 32-bit or PAE paging. A kernel with 8-byte pointers uses 4-level or 5-level paging. | 5.1.1, Table 5-1 |
| A3 | 32-bit paging: CR3 bits 31:12 locate a 4-KByte page directory of 1024 4-byte entries. Bits 11:0 are flags or ignored. | Table 5-3 |
| A4 | PAE paging: CR3 bits 31:5 locate a 32-byte page-directory-pointer table of four 8-byte PDPTEs. Bits 4:0 are ignored. The table therefore lies below 4 GBytes. | Table 5-7, 5.4.1 |
| A5 | 4-level and 5-level paging: CR3 bits M-1:12 locate the 4-KByte root table of 512 8-byte entries. Bits 11:0 are flags or the PCID. Bits 60:M and 63 are reserved. | Tables 5-12, 5-13 |
| A6 | MAXPHYADDR (M) is at most 52. With PSE-36, the M of a 32-bit 4-MByte page is at most 40. | 5.1.4; Table 5-4 note 2 |
| A7 | A present entry with a reserved bit set causes a page fault with the RSVD flag. Reserved bits are not checked in an entry whose P flag is 0. | 5.7, error-code flag RSVD |
| A8 | A present PDPTE with a reserved bit set makes the MOV to CR3 fault (#GP), so the PDPTEs that CR3 names were loadable. PDPTE bits 2:1, 8:5 and 63:M are reserved. | 5.4.1, Table 5-8 |
| A9 | PAE PDE: bits 62:M are reserved. When PS = 1 (2-MByte page), bits 20:13 are also reserved. | Tables 5-9, 5-10 |
| A10 | 32-bit PDE with PS = 1 (4-MByte page): bits 21:M-19 are reserved. With M at most 40 (A6), bit 21 is always reserved. A PDE with PS = 0 has no reserved bits. | Tables 5-4, 5-5 |
| A11 | PML5E and PML4E: bit 7 (PS) is reserved. Bits 51:M are reserved. | Tables 5-14, 5-15 |
| A12 | A PDPTE with PS = 1 maps a 1-GByte page, and bits 29:13 are reserved. A PDE with PS = 1 maps a 2-MByte page, and bits 20:13 are reserved. Entries that reference a table reserve only bits 51:M. | Tables 5-16 to 5-19 |
| A13 | Every paging structure is located by a physical address. The processor reads it from memory, so it lies in RAM. | 5.2 |
| A14 | A linear address is canonical for 4-level paging if bits 63:47 are identical, and for 5-level paging if bits 63:56 are identical. The upper half of the address space is the half with bit 47 (or 56) set. Root entries 256 to 511 map it. | 4.5 |
| A15 | Windows and Linux kernels with 8-byte pointers run in the upper canonical half. 32-bit kernels run with linear-address bit 31 set: PDPTEs 2 and 3, PDEs 512 to 1023. | Linux `Documentation/arch/x86/x86_64/mm.rst` and `arch/x86/Kconfig` (`PAGE_OFFSET` defaults, v6.17); the project's measurement on the lab Windows images (the kernel image and the self-map sit above 0xFFFF800000000000). |

### 3.1 AMD

References are to the AMD64 Architecture Programmer's Manual, Volume 2: System Programming, publication 24593, revision 3.46 (October 2026), chapter 5, "Page Translation and Protection", fetched from docs.amd.com on 2026-11-12.

| # | Constraint | Source |
|---|---|---|
| A16 | Recent AMD processors in native mode do not load the four PAE PDPTEs at MOV to CR3. They read and check each one when a walk uses it, and a reserved bit then faults with #PF at that point. So only the PDPTEs a kernel's walks pass through are known to be loadable. | 5.5.3, "Handling of PDPT Entries in PAE Mode" |
| A17 | Long mode: PML5E and PML4E bits 8:7 are MBZ, where Intel reserves bit 7 and ignores bit 8. A PDPTE or PDE that references a table has bit 7 0 and bit 8 ignored. A 1-GByte PDPTE has bits 29:13 MBZ, a 2-MByte PDE bits 20:13. Bits 62:52 of every long-mode entry are available to software or, in a leaf, bits 62:59 the protection key. | Figures 5-19 to 5-22, 5-26 to 5-29, 5-32 to 5-34 |
| A18 | Legacy PAE: a PDPTE has bits 63:52, 8:5 and 2:1 MBZ; a PDE bits 62:52, and a 2-MByte PDE also bits 20:13. Non-PAE: a 4-MByte PDE holds address bits 39:32 in bits 20:13 and has bit 21 MBZ. | Figures 5-8, 5-10, 5-11, 5-14, 5-15; 5.2.2 |
| A19 | Long-mode CR3 bits 51:12 locate the root; bits 63:52 are MBZ, except bit 63 when CR4.PCIDE = 1. Table base addresses are 52 bits; software clears the base-address bits a processor does not implement. | Figure 5-16, 5.3.2; 5.4.1 "Translation-Table Base Address Field" |
| A20 | A reserved bit set to 1 faults with #PF in long mode, and in legacy mode when CR4.PSE or CR4.PAE is 1. An entry with P = 0 leaves every other bit to software. | 5.4.1 "Reserved Bits" and "Present (P) Bit"; 8.2.15 |

The AMD bits agree with A8 to A12 at every level of section 4.1, and reserve more at PML5E and PML4E (A17). A bit that only one vendor reserves cannot be tested, because the image does not say which vendor's processor wrote it, so bit 8 is not tested. Intel's reserved CR3 bits 60:52 lie inside AMD's 62:52 (A5, A19). AMD differs once: A8's PDPTE rule holds on Intel only (A16).

The M that a processor reports is not in the image. Every reserved-bit test below uses only the bits that are reserved for every M that A6 allows. Bit 63 (XD) is reserved only when IA32_EFER.NXE = 0, which the image does not record, so it is never tested.

## 4. Algorithm

1. **Candidates.** Pointer width 8: 5-level and 4-level (A2). Pointer width 4: PAE and 32-bit (A2). Any other width is an error.
2. **Root location.** 4-level and 5-level: Root bits 51:12 (A5). A Root with any of bits 60:52 set is refuted for both modes (A5, reserved). PAE: Root bits 31:5 (A4). 32-bit: Root bits 31:12 (A3). A Root at or above 4 GBytes is refuted for PAE and for 32-bit (A3, A4).
3. **Reading.** For each candidate, walk the tables as that mode defines them:
   - Read the root table: 4 KBytes, or 32 bytes for PAE. An unreadable root ends the whole detection with an error.
   - Check every present root entry against the mode's reserved bits (table below). A set bit refutes the reading (A7, A8). For PAE only PDPTEs 2 and 3 are checked: an AMD processor checks a PDPTE only when a walk uses it (A16), and a 32-bit kernel's walks use PDPTEs 2 and 3 (A15). PDPTEs 0 and 1 are read with the root but skipped: they are neither checked nor followed.
   - Count the present root entries in the upper half (A14, A15). None refutes the reading: the root does not map a kernel.
   - Visit the tables below the upper-half root entries breadth first, each (table, level) pair once. A present entry is either a leaf (a large page where the mode allows one) or a reference to a next table.
     - Any reserved bit set: the reading is refuted.
     - A leaf: its reserved alignment bits are checked, it is counted, and the walk stops there.
     - A reference: the next table's address must be below the image's size (A13). If it is not, the reading is refuted. If the next table is a page table (the last level), it is not read, because a page-table entry has no reserved bit that A6 lets the walk test. Otherwise the next table is queued.
   - A table that cannot be read (a hole in the image) is skipped and counted. It is evidence of nothing.
   - The walk stops after the table budget (section 8).
4. **Decision for pointer width 8.**
   - 5-level, when its reading is unrefuted and holds at least one large page. A 4-level table read as 5-level shifts every level by one. Its 2-MByte pages are then read as 1-GByte pages, and each one not 1-GByte aligned sets a reserved bit in 29:13 (A12). Its 1-GByte pages are read at PML4E level, where bit 7 is reserved (A11). So a 4-level kernel table that maps any large page does not survive the 5-level reading.
   - Otherwise 4-level, when its reading is unrefuted and the 5-level reading is refuted.
   - Otherwise 5-level, when its reading is unrefuted and the 4-level reading is refuted.
   - Otherwise undecided.
5. **Decision for pointer width 4.**
   - PAE, when its reading is unrefuted. A 32-bit page directory read as a PDPT gives PDPTEs 2 and 3 from PDEs 4 to 7. A writable PDE sets bit 1, which is reserved in a PDPTE (A8). The PDE paired above it lands in bits 63:32, where bits 63:52 are reserved. So a 32-bit directory that maps that range seldom survives the PAE reading.
   - Otherwise 32-bit, when its reading is unrefuted.
   - Otherwise undecided.
6. **Evidence.** A decision records the chosen reading's counts (tables read, large pages, tables skipped) and the first refutation of the other reading, so the diagnostic says why.

### 4.1 Reserved bits tested

| Mode | Level | Entry | Bits tested | Source |
|---|---|---|---|---|
| 5-level | PML5E | reference | 7 | A11 |
| 4-level, 5-level | PML4E | reference | 7 | A11 |
| 4-level, 5-level | PDPTE | 1-GByte page (PS = 1) | 29:13 | A12 |
| 4-level, 5-level | PDE | 2-MByte page (PS = 1) | 20:13 | A12 |
| PAE | PDPTE | reference, PDPTEs 2 and 3 only | 2:1, 8:5, 63:52 | A8, A16, A18 |
| PAE | PDE | reference (PS = 0) | 62:52 | A9 |
| PAE | PDE | 2-MByte page (PS = 1) | 20:13, 62:52 | A9 |
| 32-bit | PDE | 4-MByte page (PS = 1) | 21 | A10 |

The address field of an entry is bits 51:12 for the 8-byte modes and bits 31:12 for 32-bit paging. 32-bit leaves are not followed, so their PSE-36 high bits are not decoded.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| A present entry sets no reserved bit of section 4.1. | A7, A8, A17, A18, A20: the processor could not have used it. | The reading is refuted. |
| A PAE PDPTE is evidence only when it is 2 or 3. | A15, A16. | PDPTEs 0 and 1 are skipped. |
| A referenced table lies below the image's size. | A13: page tables are in RAM, and a capture covers RAM. | The reading is refuted. |
| The root maps the upper half. | A14, A15. | The reading is refuted. |
| A PAE or 32-bit root lies below 4 GBytes. | A3, A4. | The reading is refuted. |
| An 8-byte-mode root sets none of bits 60:52. | A5. | Both 8-byte readings are refuted. |

## 6. Failure modes

- Pointer width other than 4 or 8: `layers: page table at 0x<root>: pointer width <n> names no paging mode`.
- The root cannot be read: `layers: page table at 0x<root table>: read root: <err>`, where the address is the root table's location from step 2.
- No reading survives, or two survive without the evidence of section 4: `layers: page table at 0x<root>: paging mode undecided: <each reading's first refutation or counts>`.

The session then reads the kernel as 4-level paging, as it did before detection existed, and records the error as a diagnostic.

## 7. Result schema

`PagingModeDecision{Mode PagingMode, Evidence string}`, or an error from section 6. `Mode` is one of the four presets of `layers`.

## 8. Limits

- Table budget: at most 256 tables below the root are tried per reading, counting both the tables read and the tables that do not read: 1 MByte at 4 KBytes each. Breadth-first order reads every table that the upper-half root entries reference before any table below them. The project's choice: the 2-MByte pages of a kernel image sit in page directories two levels below the root, inside the budget on the lab images.
- Each (table, level) pair is read once, so a self-referencing root entry cannot loop.

## 9. Acceptance

- Synthetic tables for each mode, built from the entry formats of section 4.1, are decided as their mode.
- A 4-level table with a 2-MByte page that is not 1-GByte aligned refutes the 5-level reading, and is decided as 4-level.
- A 5-level table with a large page is decided as 5-level.
- A reserved bit at the root refutes a reading. A root with no upper-half entry refutes a reading.
- A reference beyond the image refutes a reading. An unreadable lower table does not.
- A PAE root above 4 GBytes is not PAE.
- A PAE root whose PDPTE 0 sets a reserved bit is still PAE (A16).
- A self-referencing root terminates.
- A fuzz target over arbitrary root bytes, lower tables and widths: no panic, a bounded number of reads, and a decided mode always matches its width.

## 10. Open points

- AMD APM Volume 2 chapter 5 was not fetched. The reserved bits tested are the Intel ones. The project expects AMD to reserve the same bits, or more, at these levels. Owner decision 2026-11-12: schedule now. Done: APM Volume 2, publication 24593 revision 3.46 (October 2026), chapter 5 read (section 3.1, A16 to A20). Every bit tested is reserved by AMD too, and AMD reserves PML5E and PML4E bit 8 as well, which is not tested. AMD loads PAE PDPTEs only when used, so the PAE reading now checks only PDPTEs 2 and 3 (section 4 step 3, table 4.1, section 5); `layers/pagingmode_evidence.go` and a test in `layers/pagingmode_evidence_test.go`. No capture uses PAE paging, so no measured decision changes.
- A 32-bit Linux kernel built with `VMSPLIT_1G` runs below bit 31. Its root fails the upper-half test.
- A 4-level kernel table that maps no large page in its first 256 tables, and a 5-level one that maps none, both leave the 8-byte decision undecided.
- mem1_win11 is undecided: the 5-level reading is refuted at PDPTE 435 of the table at 0x4915000 (reserved bits 0x3f400000 of a 1-GByte page), and the 4-level reading at PDE 262 of the table at 0xb1cbb000, whose 8 bytes are all ones (reserved bits 0x1fe000 of a 2-MByte page). No processor walk could use that entry (A7). The session reads the image as 4-level paging (section 6), which every other result on mem1 confirms. Skipping a table that is all ones would need a source that says what such a table is. Owner decision 2026-11-12: keep strict; fix test message. Done: no change to the detection. mem1 stays undecided, and its diagnostic names that PDE; no other capture gives that diagnostic.

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Schedule now |
| O2 | Leave unsupported |
| O3 | Report undecided |
| O4 | Keep strict; mem1 stays undecided; fix test message |

## 11. Provenance

Sources: as cited in section 3, accessed 2026-11-11; the AMD APM of section 3.1, accessed 2026-11-12. Author: the project.
