# S35: Windows executable memory that no image file backs

Version 1, 2026-11-12.

## 1. Purpose

Code that a process runs normally comes from an image file: the loader maps the file as an image section, and the view's pages are backed by that file. Code that was written into memory at run time has no such file. A just-in-time compiler produces it, and so does a loader that copies a module into memory or a thread injected by another process. An examiner wants the regions of a process's user space that hold executable code with no image file behind them, with the facts that tell an ordinary just-in-time heap from a copied module: how the region was allocated, which of its pages the processor may execute, whether those pages hold bytes, whether the region starts with a PE header, and where its first instruction leads.

This specification defines which regions are reported (`any.memory.find_code` on a Windows profile), the page-level evidence read from each region's page tables, the facts read from the region's bytes, and the diagnostics. The Linux half of the tool is out of scope.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | Kernel virtual reads: the process list, the VAD tree, the symbol `MmProtectToValue`. |
| Process memory | One address space per process, built from its `DirectoryTableBase` (`tools.Context.ProcessSpace`). It must expose page-table leaf entries (`LeafEntry`). |
| Symbol table | The kernel types of section 3.2 and the VAD layout of S24. |
| Processes | From `any.process.list` (S25), kept by the `pid` option. |
| VADs | From `memoryranges.Decoder` (S24): range, protection name, kind, path. |
| Options | `pid`, `strict`, `diagnostics`; `any.memory.find_code.hexdump_size` (preview length), `any.memory.find_code.dump_regions` with `output_dir` and `max_dump_size` (4.10). `any.memory.find_code.show_all_dirty_pages` has no effect on Windows. |
| Limits | `MaxRegionScanBytes` (leaf entries per region), `RowPreviewBytes` (default preview), `MaxArtifactBytes` (largest preview and dump). |

## 3. Facts from the sources

### 3.1 Documentation

| # | Fact | Source |
|---|---|---|
| D1 | `MEMORY_BASIC_INFORMATION.AllocationProtect` is "the memory protection option when the region was initially allocated"; `Protect` is "the access protection of the pages in the region". `Type` is `MEM_IMAGE` (pages "mapped into the view of an image section"), `MEM_MAPPED` ("mapped into the view of a section") or `MEM_PRIVATE` ("private (that is, not shared by other processes)"). | Microsoft Learn, "MEMORY_BASIC_INFORMATION (winnt.h)", ms.date 2018-12-05, accessed 2026-11-12. |
| D2 | `VirtualProtect` "changes the protection on a region of committed pages"; "the region of affected pages includes all pages containing one or more bytes" of the range. For mapped views the new value "must be compatible with the access protection specified when the view was mapped". | Microsoft Learn, "VirtualProtect function (memoryapi.h)", ms.date 2024-02-05, accessed 2026-11-12. |
| D3 | "Memory allocated by this function is automatically initialized to zero." With `MEM_COMMIT` "the contents will be zero" on first access. "To execute dynamically generated code, use VirtualAlloc to allocate memory and the VirtualProtect function to grant PAGE_EXECUTE access." | Microsoft Learn, "VirtualAlloc function (memoryapi.h)", ms.date 2024-02-05, accessed 2026-11-12. |
| D4 | DEP "enables the system to mark one or more pages of memory as non-executable". Memory that runs code "must be marked PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, or PAGE_EXECUTE_WRITECOPY". Applications that perform "Just-In-Time code generation" must mark the generated code executable. | Microsoft Learn, "Data Execution Prevention", ms.date 2022-01-25, accessed 2026-11-12. |
| D5 | The protection constants and their values: `PAGE_EXECUTE` 0x10, `PAGE_EXECUTE_READ` 0x20, `PAGE_EXECUTE_READWRITE` 0x40, `PAGE_EXECUTE_WRITECOPY` 0x80; the other base values are below 0x10 and the modifiers above 0x80 (S24 D1). | Microsoft Learn, "Memory Protection Constants (WinNT.h)", through S24 D1. |
| D6 | "At location 0x3c, the stub has the file offset to the PE signature." The signature is "PE\0\0". The optional header magic is 0x10b for PE32 and 0x20b for PE32+. `IMAGE_FILE_MACHINE_AMD64` is 0x8664, `IMAGE_FILE_MACHINE_I386` 0x14c, `IMAGE_FILE_MACHINE_ARM64` 0xaa64. The DOS header's first two bytes are "MZ" (S18). | Microsoft Learn, "PE Format", ms.date 2026-09-10, accessed 2026-11-12; S18. |
| D7 | A paging-structure entry's bit 0 is P (present). In an entry that maps a page, bit 1 is R/W (writes allowed when set), bit 6 is D (dirty: "software has written to the page"), and bit 63 is XD when IA32_EFER.NXE = 1: "if 1, instruction fetches are not allowed" from the page. With NXE = 0 bit 63 is reserved and must be 0. The processor ignores the other bits of an entry whose P is 0. | Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 3A, "Paging" chapter, entry format tables and "Access Rights". AMD64 APM Vol. 2, "Page Translation and Protection", the NX bit. |
| D8 | Instruction forms: `E9 cd` is JMP rel32 and `E8 cd` CALL rel32, the target being the next instruction's address plus the sign-extended displacement. `FF /4` is JMP near absolute indirect; with ModRM 0x25 the operand in 64-bit mode is RIP-relative (`[RIP + disp32]`) and in 32-bit mode the absolute `[disp32]`. `REX.W B8` is MOV RAX, imm64; `FF E0` is JMP RAX. Operand size in 32-bit mode truncates the target to 32 bits. | Intel SDM Vol. 2, JMP, CALL, MOV and "Instruction Formats" (ModR/M, RIP-relative addressing). |

### 3.2 Kernel types

Read through the project's kernel tables for builds 26100 (mem1, mem6, mem7), 19045 (mem2) and 14393 (mem5) with `codefacts -types`.

| # | Fact |
|---|---|
| T1 | `_MMPTE_HARDWARE` (8 bytes) has `Valid` bit 0, `Dirty1` bit 1, `Dirty` bit 6, `LargePage` bit 7 and `NoExecute` bit 63 on every build, the hardware positions of D7. |
| T2 | `_MMPTE_SOFTWARE.Protection` and `_MMPTE_TRANSITION.Protection` are bits 5..9 (5 bits) on every build; `Prototype` is bit 10 and `Transition` bit 11 in both. |
| T3 | `_MMPTE_PROTOTYPE.Protection` is bits 5..9 on 26100 and 19045 and bits 11..15 on 14393; its entry points at a prototype entry of the section, not at a page. |
| T4 | `MmProtectToValue` is present on every build (S24 T9); its first 2^5 entries map a 5-bit protection index to a `PAGE_*` value (S24 M2). |

### 3.3 Measurements

M1 to M8 come from `codefacts` on 2026-11-12 over mem1_win11, mem2_win10, mem5_server2016, mem6_server2025 and mem7_server2025, without a pagefile. The script walks every VAD's leaf entries page by page through the process's own address space and decodes each entry by D7 and T2.

| # | Measured | mem1 | mem2 | mem5 | mem6 | mem7 |
|---|---|---|---|---|---|---|
| M1 | Processes (WoW64) | 83 (3) | 153 (1) | 71 (2) | 101 (5) | 90 (1) |
| M1 | VADs image (VAD protection executable) | 4,430 (4,387) | 8,315 (8,277) | 3,489 (3,484) | 4,859 (4,812) | 4,490 (4,453) |
| M1 | VADs mapped (executable) | 3,033 (0) | 5,533 (306) | 2,372 (0) | 3,949 (0) | 3,392 (0) |
| M1 | VADs private (executable) | 3,284 (4) | 7,935 (24) | 3,947 (16) | 5,285 (17) | 3,039 (0) |
| M2 | Present pages in private VADs whose protection is not executable: XD clear / XD set | 71 / 129,888 | 654 / 188,691 | 815 / 134,939 | 115 / 127,007 | 49 / 52,317 |
| M2 | Not-present pages there whose own protection is executable (software / transition) | 0 / 0 | 272 / 25 | 117 / 0 | 9 / 4 | 41 / 7 |
| M3 | Present pages in private VADs whose protection is executable: XD clear / XD set | 6 / 0 | 341 / 0 | 44 / 0 | 932 / 0 | none |
| M3 | Present pages in mapped VADs whose protection is executable: XD clear / XD set | none | 431 / 3,957 | none | none | none |
| M4 | Present pages with XD clear in image VADs whose protection is not executable, and in mapped VADs whose protection is not executable | 0, 0 | 0, 0 | 0, 35 | 0, 0 | 0, 0 |
| M5 | Private or mapped regions with an executable VAD protection, or with at least one page whose own protection is executable (of them, by page only) | 9 (5) | 476 (146) | 89 (73) | 141 (124) | 30 (30) |
| M5 | Of M5: with a resident page; with a page that holds a nonzero byte | 9; 9 | 437; 435 | 89; 89 | 123; 123 | 6; 5 |
| M6 | Executable mapped regions by backing: every one is a section with a control area and no file (306 on mem2, 1 on mem5); none is a view of a data file. | | | | | |
| M7 | Region start: a PE32+ header (machine 0x8664) once (mem2); no header elsewhere; first page unreadable 1, 57, 4, 4, 2. First instruction at the first page holding bytes: `jmp rel32` 2 (mem1) and 2 (mem2), `call rel32` 5, `jmp [rip+disp32]` 18, `mov rax, imm64; jmp rax` 2 (mem2), none on mem5, mem6, mem7. | | | | | |
| M8 | Process names with regions holding bytes, regions per name, and whether the process maps an image whose name contains `jit`. mem1: SearchHost.exe 6, the capture program 1, explorer.exe 1, svchost.exe 1; none maps such an image. mem2: PhoneExperienc 304 (`clrjit.dll`), dwm.exe 40, SearchApp.exe 31, explorer.exe 29, powershell.exe 12 (`clrjit.dll`), MsMpEng.exe 5, msedge.exe 5, smartscreen.ex 3, LogonUI.exe 2, OneDrive.exe 2, the capture program 1, TextInputHost. 1. mem5: dwm.exe 43, msedge.exe 14, powershell.exe 12 (`clrjit.dll`), MsMpEng.exe 11, explorer.exe 5, LogonUI.exe 2, GenValObj.exe 1, MicrosoftEdgeU 1. mem6: dwm.exe 98, MsMpEng.exe 8, WindowsTermina 6, explorer.exe 4, SearchHost.exe 2, ShellExperienc 2, StartMenuExper 2, LogonUI.exe 1. mem7: dwm.exe 4, LogonUI.exe 1. | | | | | |

M2 shows that a VAD's protection is not the protection of its pages: the VAD keeps the allocation protection (D1 `AllocationProtect`), and `VirtualProtect` changes the pages (D2, D3). M3 and M4 show that XD agrees with an executable protection wherever the VAD protection is executable, and that it is clear in a page whose VAD protection is not executable only where the page was made executable. M8's names are truncated to the 15-byte `ImageFileName`. The two processes that map `clrjit.dll`, the .NET just-in-time compiler, hold 316 of mem2's 435 regions.

## 4. Algorithm

### 4.1 Setup

1. The profile must be Windows (otherwise `ErrUnsupportedOS`; the Linux half is dispatched before this step).
2. The process list, filtered by `pid`.
3. The VAD decoder of S24. Its failure fails the run.
4. **Page protection.** `_MMPTE_SOFTWARE.Protection` and `_MMPTE_TRANSITION.Protection` (T2) and the first 2^(width) entries of `MmProtectToValue` (T4). If any is absent or does not read, not-present entries give no protection (4.3 step 4) and one diagnostic says so.
5. **Options** (4.10).

### 4.2 Per process

1. The process's VADs from the decoder. A tree that does not read: diagnostic, the process has no rows; strict mode fails the run.
2. Its address space from `ProcessSpace(DirectoryTableBase)`. Failure: diagnostic, no rows; strict mode fails. The kernel's layer is never used for user reads: it may belong to another process.
3. The address space must give leaf entries. Otherwise `ErrNoPageEntries`: diagnostic, no rows; strict mode fails.
4. Instruction mode: 32-bit when the process list reports the process as WoW64, else 64-bit.
5. Each VAD whose kind is `private` or `mapped` goes through 4.3 to 4.9. `image` and `unknown` VADs are not candidates (O3).

### 4.3 Page walk

The range is walked from `Start` to `End` in 4 KB steps.

1. `LeafEntry(page)`. A miss above the leaf (`UnmappedPageError` with a `Span`) skips to the end of that span. Any other failure counts the page as having no entry.
2. More leaf entries than `MaxRegionScanBytes` / 4096 stop the walk with `ErrRegionScanCut`: the region keeps what was counted, one diagnostic per region; strict mode fails.
3. **Present** (bit 0 set, D7, T1): the page is resident; it is executable when bit 63 is clear; it is written when bit 6 is set.
4. **Not present.** The processor ignores the entry (D7); the memory manager's forms apply (T2):
   1. Prototype (bit 10): the protection is the section's; the page has no protection of its own.
   2. Transition (bit 11): the page is resident; its protection is `MmProtectToValue[_MMPTE_TRANSITION.Protection]`.
   3. Zero: no entry, no protection of its own.
   4. Otherwise the software form: protection `MmProtectToValue[_MMPTE_SOFTWARE.Protection]`.
   A protection is executable when it holds one of the four execute values of D5 (`value & 0xF0 ≠ 0`).
5. A page with no protection of its own takes the VAD's (O2).

### 4.4 Rule

1. `allocation-executable` (`RuleAllocation`): the VAD's protection (S24 4.4) names an execute value (D1, D4, D5).
2. `page-executable` (`RulePage`): the VAD's protection names none, or is `unknown`, and at least one page's own protection is executable (4.3 steps 3 and 4; D2, D3, M2).
3. A region that meets neither is not a candidate.

### 4.5 Executable pages and content

1. An executable page is one whose protection, own or taken from the VAD by 4.3 step 5, is executable. Under `page-executable` only a page's own protection counts.
2. Each executable page is read as 4 KB through the process's address space (a supplied pagefile serves pages the entries place there). A page that reads and holds a nonzero byte is a content page.
3. A region with no content page is not reported: committed memory starts as zeros (D3), so such a region holds no code that can be shown. They are counted in one diagnostic.

### 4.6 Backing

`private`: `none`. `mapped`: through `memoryranges.FileNames.Resolve` (S24 4.6): `file` when the view's control area has a file object, `section` when the control area reads and has none (a section backed by the paging file), `unknown` when the subsection or control area does not read or the layout is absent (M6).

### 4.7 Header at the region start

The first page, or the whole range if smaller, read at `Start`.

1. Unreadable: `unread`.
2. `pe.ParseHeaders` (S18, D6): `pe32` or `pe32+` with the COFF machine when it succeeds; `nt` when the PE signature is found but the headers do not parse (the optional header magic is neither value, or another header check fails); `dos` when "MZ" is present but no PE signature lies within the bytes read.
3. No "MZ": `nt` when the doubleword at 0x3C points inside the bytes read at "PE\0\0" (a header whose DOS magic was erased), else `none`.

### 4.8 First instruction at the region start

From the bytes at `Start` (at least 16 when readable), in the mode of 4.2 step 4. The project's decoder must decode the instruction with the length the form implies (D8):

1. `E9 cd`: `jmp-rel32`, target = `Start` + 5 + sign-extended displacement.
2. `E8 cd`: `call-rel32`, same target.
3. `FF 25 disp32`: `jmp-indirect`. The slot is `Start` + 6 + sign-extended displacement in 64-bit mode and the displacement itself in 32-bit mode; the target is the pointer read there (8 or 4 bytes). An unreadable slot leaves the target unread.
4. 64-bit only: `48 B8 imm64` followed by `FF E0`: `mov-jmp-rax`, target = imm64.
5. In 32-bit mode targets are truncated to 32 bits.
6. The target's image is the path of the process's `image` VAD whose range holds the target, if any.

### 4.9 Row

One `Finding` per reported region (7), with the preview: up to the preview length of bytes from the first content page's start, unreadable bytes as zeros (`extract.ReadPadded`).

### 4.10 Options and dump

1. `any.memory.find_code.hexdump_size`: preview length in bytes; default `RowPreviewBytes`; above `MaxArtifactBytes` it is an option error.
2. `any.memory.find_code.dump_regions`: when true, `output_dir` is required (option error otherwise). Each reported region is written from `Start` to `End` through `extract.Region`, unreadable pages as zeros, to `extract.Name{Kind: region, Scope: process PID, Addresses: [Start, End], Ext: bin}`. A region at or above the dump limit (`max_dump_size` when set and below `MaxArtifactBytes`, else `MaxArtifactBytes`) or a failed write leaves `Artifact` empty; a partial file is removed. One diagnostic counts the failures.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| User reads only through the process's own space | 4.2 step 2 | process skipped, diagnostic |
| Leaf entries available | 4.3 needs D7 bits | `ErrNoPageEntries`; process skipped |
| Only `private` and `mapped` VADs | D1, O3 | not a candidate |
| Execute right in the VAD protection or a page's own protection | D1, D2, D4, M2, M3 | not a candidate |
| XD only in a present entry | D7 | not-present entries use T2 |
| A content page in an executable page | D3 | counted, not reported |
| At most `MaxRegionScanBytes` / 4096 leaf entries per region | 8 | `ErrRegionScanCut`; walk stops |
| Instruction form must decode at the implied length | D8 | no transfer |

## 6. Failure modes

| Case | Result |
|---|---|
| Profile not Windows | `any.memory.find_code: memorycode: profile os is not windows: "<os>"` (`ErrUnsupportedOS`) |
| VAD layout absent | the decoder's `ErrVADLayout`; the run fails |
| VAD tree not read | `any.memory.find_code: pid <pid> _EPROCESS at 0x<addr>: VAD tree not read: <error>`; strict: the run fails |
| Address space not built | `any.memory.find_code: pid <pid> _EPROCESS at 0x<addr>: address space not built: <error>`; strict: the run fails |
| No leaf entries | `any.memory.find_code: pid <pid> _EPROCESS at 0x<addr>: page-table entries not read: memorycode: process address space gives no page-table entries`; strict: the run fails |
| Page protection layout or table missing | `any.memory.find_code: MmProtectToValue: not read, protections of not-present pages unknown: <error>`, once |
| Walk cut | `any.memory.find_code: pid <pid> VAD at 0x<addr>: page walk stopped after <n> entries: memorycode: region page walk reached MaxRegionScanBytes`; strict: the run fails |
| Candidates without content | `any.memory.find_code: <n> executable regions hold no readable nonzero byte in an executable page and are not listed`, once |
| Dump failures | `any.memory.find_code: <n> regions not written, first: <name>: <reason>`, once |
| Option of the wrong type or too large | the run fails with `tools.ErrOptionType` |

## 7. Result schema

`Finding`, one per reported region, in process-list order, then `Start`:

| Field | Type | Meaning |
|---|---|---|
| `PID`, `Process` | uint64, string | the process |
| `VadAddress` | uint64 | the VAD's kernel address |
| `Start`, `End` | uint64 | the range, `End` inclusive (S24 4.3) |
| `Protection` | string | the VAD's protection name (S24 4.4) |
| `Kind` | string | `private` or `mapped` (`memoryranges.KindPrivate`, `KindMapped`) |
| `Backing`, `Path` | `Backing`, string | 4.6: `none`, `section`, `file`, `unknown`; the file's path when `file` and the name reads |
| `Rule` | `Rule` | `allocation-executable` or `page-executable` |
| `Pages` | uint64 | 4 KB pages in the range |
| `ExecutablePages`, `ContentPages` | uint64 | 4.5 |
| `ResidentPages` | uint64 | present and transition pages |
| `WrittenPages` | uint64 | present pages with D set |
| `FirstContent` | uint64 | address of the first content page |
| `Header`, `HeaderMachine` | `Header`, uint16 | 4.7: `none`, `unread`, `dos`, `nt`, `pe32`, `pe32+`; the machine when the PE signature was read, else 0 |
| `Transfer`, `TransferTarget`, `TransferTargetUnread`, `TransferImage` | `Transfer`, uint64, bool, string | 4.8: empty or `jmp-rel32`, `call-rel32`, `jmp-indirect`, `mov-jmp-rax`; the target; whether an indirect slot did not read; the image path holding the target, empty when none |
| `Preview` | []byte | 4.9 |
| `Artifact` | string | the dump's file name, empty when not written |

Counts are exact up to the walk cut (4.3 step 2).

## 8. Limits

- `MaxRegionScanBytes` (default 1 GiB, 262,144 leaf entries): the largest walked region on the captures stayed below the cut on every capture (no region cut, M5 run); a forged VAD of terabytes is bounded by it.
- `RowPreviewBytes` (default 128): the preview length unless the option sets one.
- `MaxArtifactBytes`: the largest preview, and the dump limit when `max_dump_size` is not set or is not below it.

## 9. Acceptance

1. Synthetic fixtures (`tools/any/memorycode/*_test.go`, on the shared process fixture with `_MMPTE_SOFTWARE`, `_MMPTE_TRANSITION` and a full `MmProtectToValue` added): each rule; present pages with and without XD; software, transition, prototype and zero entries; an executable VAD whose pages are XD; a region of zeros (not listed, counted); image views not listed; backing `section`; each header kind; each transfer form in both modes including an unreadable slot and a target in an image view; the preview option and its bound; the dump and its failure; a refused process space with no kernel reads; a reader without leaf entries; the walk cut; strict mode; span skipping over a reservation of 2^39 bytes.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzHeaderKind` (any bytes: no panic; `pe32`/`pe32+` only with "MZ" and the signature): 3,762,210 executions. `FuzzTransfer` (any bytes, address and mode: no panic; a target only for the four forms; 32-bit targets fit 32 bits): 2,299,252 executions. `FuzzPageEntry` (any entry and table: no panic; a present entry's executability is bit 63 clear): 3,324,079 executions.
3. On the captures, `codefacts -nofacts -tool`, 2026-11-12, without a pagefile:

| Capture | Rows (allocation, page) | Private, mapped (`section`) | Header (`none`, `unread`) | Transfers | Without content (diagnostic) | Executable / content / written pages | Time |
|---|---|---|---|---|---|---|---|
| mem1_win11 | 9 (4, 5) | 9, 0 | 8, 1 | `jmp-rel32` 2, target outside an image | 0 | 335 / 77 / 3 | 8.0 s |
| mem2_win10 | 165 (51, 114) | 128, 37 | 153, 12 | `jmp-indirect` 18 (16 outside an image, 2 slots unread), `jmp-rel32` 1, `mov-jmp-rax` 2 into `coreclr.dll` | 311 | 3,668 / 1,076 / 1,977 | 17.4 s |
| mem5_server2016 | 89 (16, 73) | 88, 1 | 85, 4 | none | 0 | 2,033 / 819 / 772 | 5.5 s |
| mem6_server2025 | 123 (8, 115) | 123, 0 | 119, 4 | none | 18 | 2,501 / 1,048 / 856 | 14.0 s |
| mem7_server2025 | 5 (0, 5) | 5, 0 | 3, 2 | none | 25 | 5 / 5 / 0 | 7.1 s |

   - Rows plus regions without content equal M5's candidates on every capture (9, 476, 89, 141, 30).
   - The rows are fewer than M5's regions holding bytes on mem2 (165 of 435) because 4.5 counts only executable pages: 3,957 present pages of mem2's executable mapped views have XD set (M3), and their views hold bytes only there. The one PE32+ header of M7 lies in such a view and is not listed.
   - No region reached the walk cut; no process lacked an address space or leaf entries.
   - Rows per process name: mem1 SearchHost.exe 6, the capture program 1, explorer.exe 1, svchost.exe 1. mem2 dwm.exe 40, PhoneExperienc 38, explorer.exe 29, SearchApp.exe 27, powershell.exe 12, MsMpEng.exe 5, msedge.exe 5, smartscreen.ex 3, LogonUI.exe 2, OneDrive.exe 2, the capture program 1, TextInputHost. 1. mem5, mem6 and mem7 as M8.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Only the leaf entry's XD is read. D7 makes a page non-executable when XD is set in any entry of the walk; the process layer does not give the upper entries. M4 shows no executable leaf in a non-executable image view, which is consistent with no upper-level XD, but does not prove it. | A layer call that returns every entry of the walk |
| O2 | A page whose entry holds no protection (zero or prototype) takes the VAD's protection. That the memory manager does so is not documented; it rests on D1 (`AllocationProtect`) and on M3. | A documented source or a controlled capture |
| O3 | Image views are not candidates. Code changed inside an image view (a patched page) is file-backed in the VAD sense; finding it needs the file's bytes (S18, S19). | A separate specification |
| O4 | No executable view of a data file was measured (M6); the `file` backing is untested on real data. | A capture with one |
| O5 | Rows of processes that map a just-in-time compiler are not marked. M8 measures `clrjit.dll` in two processes (316 of mem2's rows). Owner decision: whether to add such a mark, and from which list of images. | Owner decision |
| O6 | dwm.exe holds the most `page-executable` regions on mem5, mem6 and mem7 (M8) and maps no image named `jit`; the producer of that code is not determined. | A controlled capture |
| O7 | Only four instruction forms give a transfer (4.8). | Owner decision |
| O8 | 32-bit kernels: non-PAE entries have no XD bit (D7), so the page rule cannot apply; not measured. | A 32-bit capture (Q7) |
| O9 | Owner decision (Q2): row field names. Removed from 0.1.0: `Tag`, `CommitCharge`, `CommitChargeKnown`, `PrivateMemory`, `PrivateMemoryKnown`, `Notes`, `Header` ([]byte, now the typed header kind; the bytes are `Preview`), `Type` (now `Kind`), `Reason`, `Classification`, `DirtyPage`, `DirtyPageFound`. Added: `VadAddress`, `Backing`, `Path`, `Rule`, `Pages`, `ExecutablePages`, `ResidentPages`, `WrittenPages`, `ContentPages`, `FirstContent`, `HeaderMachine`, `Transfer`, `TransferTarget`, `TransferTargetUnread`, `TransferImage`, `Preview`, `Artifact`. | Owner decision |
| O10 | Owner decision (Q8): delete golden_findings.json; no test reads it after S35. | Owner decision |
| O11 | `show_all_dirty_pages` has no meaning on Windows and is ignored there; the option keys are shared with the Linux half and kept. `hexdump_size` sets the length of `Preview` here; a key named after the preview would match this half's vocabulary. | Owner decision (Q2) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Read leaf XD only |
| O2 | Take the VAD protection |
| O3 | Leave to a separate spec |
| O4 | Defer; untested on real data |
| O5 | Do not mark |
| O6 | Defer; report as found |
| O7 | Keep four forms |
| O8 | Defer |
| O9 | Accept the new names |
| O10 | Delete it |
| O11 | Keep the shared keys |

## 11. Provenance

Written 2026-11-12 from Microsoft Learn (memory protection, `MEMORY_BASIC_INFORMATION`, `VirtualAlloc`, `VirtualProtect`, Data Execution Prevention, PE Format), the Intel SDM and AMD APM, the ntoskrnl types in the project's symbol tables, specifications S18, S24 and S25, and the project's measurements. Every rule rests on the sources and measurements above.
