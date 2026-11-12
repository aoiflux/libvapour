# S47: Linux executable memory, version banners, literal search and layer export

Version 1, 2026-11-12.

## 1. Purpose

Four questions an examiner asks of a capture, answered by four tools:

- **Linux half of `any.memory.find_code`.** Which memory areas of a Linux process hold code the process did not load from a file, or code it can rewrite: executable areas with no file behind them, areas that are both writable and executable, executable file areas whose pages were written after they were mapped, and pages the processor may execute in areas the kernel did not make executable. The Windows half is S35; this half shares its row vocabulary (rule, backing, page counts, header, first transfer, preview, dump).
- **`any.image.find_banners`.** Where in physical memory the kernel's own version text lies (`linux_banner` for Linux, the CodeView record of the kernel's PDB for Windows), which other copies exist, what each says, and which copy is the running kernel's.
- **`any.image.find_literal`.** Where given byte strings occur in physical memory. The tool is a placeholder (owner decision 2026-11-12): a plain byte search that defines no analysis of its own. Its registered description starts "Placeholder:".
- **`any.image.dump_layers`.** The session's layers written to files an examiner can open with other software: the physical address space as a flat file, and the kernel's virtual address space as an ELF core file.

## 2. Inputs

| Input | Tool | Meaning |
|---|---|---|
| Kernel memory, symbol table | find_code (Linux), find_banners | Kernel virtual reads through `linuxobj.Kernel`; the symbols `special_mapping_vmops`, `legacy_special_mapping_vmops`, `linux_banner`. |
| Tasks | find_code | S01 task walk (`linuxwalk.Reader.Tasks`, threads excluded), kept by the `pid` option. |
| Memory areas | find_code | S39 walk (`memoryranges.LinuxWalker.TaskVMAs`) and S39 names (`AreaName`); `vm_flags` and `vm_ops` read through `linuxobj.Kernel`. |
| Process memory | find_code | `linuxobj.Kernel.ProcessLayer` (S14), which must expose page-table leaf entries (`LeafEntry`). |
| Physical layer | find_banners, find_literal, dump_layers | `tools.Context.PhysicalMemory`; its held ranges from `memory.MappedRanges`. |
| Kernel base | find_banners (Windows) | `tools.Context.KernelBase`. |
| Kernel page tables | dump_layers | `tools.Context.KernelDTB` and `PagingMode`; the walk `layers.IntelTranslator.Mapping`. |
| Options | find_code | `pid`, `strict`, `diagnostics`; `any.memory.find_code.hexdump_size`, `.show_all_dirty_pages`, `.dump_regions` with `output_dir` and `max_dump_size`. |
| Options | find_literal | `any.image.find_literal.literals` (string list), `.case_insensitive` (bool), `.max_scan_bytes` (unsigned). |
| Options | dump_layers | `any.image.dump_layers.list` (bool), `.layers` (string list), `.block_size` (unsigned), `output_dir`, `max_dump_size`. |
| Limits | all | `MaxRegionScanBytes`, `RowPreviewBytes`, `MaxArtifactBytes` (find_code); `MaxNameBytes`, `MaxBufferBytes`, `MaxMatchesPerChunk` (find_banners, find_literal), `RowPreviewBytes` (find_literal); `MaxBufferBytes`, `MaxImageBytes`, `MaxListEntries`, `NameAttempts` (dump_layers). |

## 3. Facts from the sources

Kernel tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17 unless a row names fewer. Paths are under the kernel tree, fetched from git.kernel.org on 2026-11-12. The captures run 6.17 (mem3, Ubuntu 24) and 6.14 (mem4, Fedora 40).

### 3.1 Linux memory areas and page entries

| # | Fact | Source |
|---|---|---|
| L1 | `VM_READ` 0x1, `VM_WRITE` 0x2, `VM_EXEC` 0x4, `VM_SHARED` 0x8, `VM_MAYSHARE` 0x80. | `include/linux/mm.h`, every tag. |
| L2 | `/proc/<pid>/maps` prints `r`, `w`, `x` by the first three flags and then `s` when `VM_MAYSHARE` is set, `p` otherwise. | `fs/proc/task_mmu.c`, v4.19, v6.17; S39 A4. |
| L3 | An area's page protection is `vm_get_page_prot(vm_flags)`, which indexes the x86 `protection_map` by `VM_READ`, `VM_WRITE`, `VM_EXEC`, `VM_SHARED`. Every entry without `VM_EXEC` is `PAGE_NONE`, `PAGE_READONLY`, `PAGE_COPY` or `PAGE_SHARED`; the last three carry `_PAGE_NX`, `PAGE_NONE` has no `_PAGE_PRESENT`. Entries with `VM_EXEC` are `PAGE_READONLY_EXEC`, `PAGE_COPY_EXEC` or `PAGE_SHARED_EXEC`, without `_PAGE_NX`. | `mm/mmap.c` v4.19 (`vm_get_page_prot`, `__P`/`__S` tables in `arch/x86/include/asm/pgtable_types.h`); `arch/x86/mm/pgprot.c` v6.1, v6.4, v6.14, v6.17; `mm/vma.c` v6.17. |
| L4 | `_PAGE_BIT_PRESENT` 0, `_PAGE_BIT_RW` 1, `_PAGE_BIT_DIRTY` 6 ("was written to (raised by CPU)"), `_PAGE_BIT_NX` 63. | `arch/x86/include/asm/pgtable_types.h`, every tag; Intel SDM Vol. 3A paging entry formats (S35 D7). |
| L5 | At v6.14 and v6.17 on x86-64 `_PAGE_BIT_SAVED_DIRTY` is `_PAGE_BIT_SOFTW5`, bit 58, and `pte_dirty` tests `_PAGE_DIRTY | _PAGE_SAVED_DIRTY`. `pte_mkdirty` and `pte_modify` move a set Dirty bit into SavedDirty whenever RW is clear (`mksaveddirty_shift`), so that no entry is Write=0, Dirty=1. At v4.19, v6.1 and v6.4 bit 58 is `_PAGE_BIT_SOFTW4`, used as `_PAGE_BIT_DEVMAP`, and `pte_dirty` tests `_PAGE_DIRTY` alone. | `arch/x86/include/asm/pgtable_types.h`, `arch/x86/include/asm/pgtable.h`. |
| L6 | A write fault on a private page copies it (`wp_page_copy`) and installs the copy with `maybe_mkwrite(pte_mkdirty(entry), vma)`: the entry is dirty, and writable only when the area has `VM_WRITE`. | `mm/memory.c`; `include/linux/mm.h` `maybe_mkwrite`; every tag. |
| L7 | `_install_special_mapping` gives an area `vm_ops = &special_mapping_vmops`; `legacy_special_mapping_vmops` is a second such table at v4.19, v6.1 and v6.4 and is gone at v6.14 and v6.17. The x86 vDSO is such an area with `VM_READ|VM_EXEC|VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC` and no file. | `mm/mmap.c`, every tag; `arch/x86/entry/vdso/vma.c`, v6.17. |
| L8 | The ELF identification starts `0x7f 'E' 'L' 'F'`; byte 4 is `EI_CLASS` (`ELFCLASS32` 1, `ELFCLASS64` 2); `e_machine` is the 16-bit value at offset 18 in both classes; `EM_386` 3, `EM_X86_64` 62. | ELF gABI, "ELF Header" (sco.com/developers/gabi/latest/ch4.eheader.html), accessed 2026-11-12. |

### 3.2 Version text

| # | Fact | Source |
|---|---|---|
| B1 | `linux_banner` is `"Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@" LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION "\n"`, a `const char[]`. | `init/version.c` v4.19; `init/version-timestamp.c` v6.1, v6.4, v6.14, v6.17. |
| B2 | `UTS_RELEASE` is `KERNELRELEASE`; the build stops when it is longer than `uts_len := 64`. `__NEW_UTS_LEN` is 64. | top-level `Makefile` v4.19, v6.17; `include/uapi/linux/utsname.h` v6.17. |
| B3 | `UTS_VERSION` is `#<build version>`, then `SMP`, then `PREEMPT`, `PREEMPT_DYNAMIC` or `PREEMPT_RT` when configured, then the build time, cut to 64 bytes. | `scripts/mkcompile_h` v4.19 (`UTS_LEN=64`); `init/Makefile` `filechk_uts_version`, v6.1, v6.4, v6.14, v6.17. |
| B4 | `LINUX_COMPILER` is the compiler's `-v` version line at v4.19, and `"${CC_VERSION}, ${LD_VERSION}"` from v6.1; both can contain parentheses. | `scripts/mkcompile_h`. |
| B5 | `/proc/version` prints `linux_proc_banner` ("%s version %s (by@host) (compiler) %s\n") with `sysname` "Linux", `release` and `version`, which gives B1's shape. `start_kernel` prints `linux_banner` with `pr_notice`, so the kernel log holds a copy. | `init/version.c`, `fs/proc/version.c`, `init/main.c`, v4.19, v6.17. |
| B6 | A CodeView record is `"RSDS"`, a 16-byte GUID (one 32-bit, two 16-bit little-endian and eight single-byte fields), a 32-bit age and a NUL-terminated PDB path. An image's debug directory entry of type `IMAGE_DEBUG_TYPE_CODEVIEW` (2) gives the record's `AddressOfRawData`, its RVA when loaded. | Microsoft Learn, "PE Format", "Debug Type" and "Debug Directory (Image Only)", accessed 2026-11-12; S32 F20. |
| B7 | The kernel PDB names are `ntoskrnl.pdb`, `ntkrnlmp.pdb`, `ntkrnlpa.pdb` and `ntkrpamp.pdb`, without regard to case. | S32 4.6 step 6. |
| B8 | `MAX_PATH` is 260 characters including the terminating NUL. | Microsoft Learn, "Naming Files, Paths, and Namespaces", "Maximum Path Length Limitation", accessed 2026-11-12. |

### 3.3 File formats

| # | Fact | Source |
|---|---|---|
| F1 | An ELF64 file header is 64 bytes: `e_ident[16]`, `e_type` (16), `e_machine` (16), `e_version` (32), `e_entry`, `e_phoff`, `e_shoff` (64 each), `e_flags` (32), `e_ehsize`, `e_phentsize`, `e_phnum`, `e_shentsize`, `e_shnum`, `e_shstrndx` (16 each). `EI_DATA` (byte 5) `ELFDATA2LSB` 1, `EI_VERSION` (byte 6) `EV_CURRENT` 1. `ET_CORE` is 4. | ELF gABI, "ELF Header". |
| F2 | An ELF64 program header is 56 bytes: `p_type`, `p_flags` (32 each), `p_offset`, `p_vaddr`, `p_paddr`, `p_filesz`, `p_memsz`, `p_align` (64 each). `PT_LOAD` is 1, `PF_R` 4. Loadable entries "appear in ascending order, sorted on the p_vaddr member". `p_offset` and `p_vaddr` must be congruent modulo `p_align`. | ELF gABI, "Program Header". |
| F3 | When the number of program headers is `PN_XNUM` (0xffff) or more, `e_phnum` holds `PN_XNUM` and the count is in `sh_info` of the section header at index 0. | ELF gABI, "ELF Header" and "Sections". |
| F4 | `lseek` may set the offset past the end of the file; "subsequent reads of data in the gap shall return bytes with the value 0". `ftruncate` to a larger size makes "the extended area appear as if it were zero-filled". | POSIX.1-2017, XSH `lseek`, `ftruncate`. |
| F5 | In the POSIX locale the `upper` class is `A` to `Z` and `tolower` maps them to `a` to `z`; no other byte changes. | POSIX.1-2017, XBD 7.3.1 "LC_CTYPE", POSIX locale. |

### 3.4 Measurements

M1 to M4 come from `linuxcodefacts`, M5 to M8 from `bannerfacts` and M9 from `layerfacts`, 2026-11-12, on mem3_ubuntu24, mem4_fedora40 and (M5 to M8) mem1_win11, mem2_win10, mem5_server2016, mem6_server2025, mem7_server2025.

| # | Measured | mem3 (6.17) | mem4 (6.14) |
|---|---|---|---|
| M1 | Processes with an address space; time for the walk of every area's leaf entries | 115; 7.5 s | 123; 9.1 s |
| M1 | `special_mapping_vmops` present; `legacy_special_mapping_vmops` | yes; absent | yes; absent |
| M2 | Executable areas: file without `VM_WRITE`; anonymous without `VM_WRITE`; anonymous with `VM_WRITE`; special mappings (all `[vdso]`, one per process); file with `VM_WRITE` | 4,918; 48; 20; 114; 0 | 5,272; 50; 5; 123; 0 |
| M2 | `vm_flags & 0xff` of the executable areas: 0x75 (`VM_READ|VM_EXEC|VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC`, M3 aside), 0x77 for the writable ones; no `VM_SHARED` | yes | yes |
| M3 | Present pages: anonymous executable areas 171 (RW 0, D 0, bit 58 171); writable executable areas 94 (RW 15, D 15, bit 58 79); file executable areas 207,283 (D 0, bit 58 0); special 218 (D 0, bit 58 0). NX set in a present page of an executable area: 0 | as left | anonymous 75 (RW 0, D 0, bit 58 75); writable 45 (RW 0, D 0, bit 58 43); file 181,491 (D 0, bit 58 0); special 236; NX 0 |
| M3 | Present pages in areas without `VM_EXEC`, and of them with NX clear | 313,207; 0 | 309,341; 0 |
| M4 | Owners of anonymous executable areas: gnome-shell 39, gjs 9 (mem3); gnome-shell 46, gjs 4 (mem4). Writable executable: gnome-shell 11, gjs 3, gnome-session-b 2, gnome-terminal- 3, unattended-upgr 1 (mem3); gnome-session-b 2, gnome-terminal- 2, gnome-shell 1 (mem4). First bytes at the start of these areas: `F3` 25 and 46 times (`F3 0F 1E FA`, ENDBR64, the start of compiled code), zero 23 and 4, unreadable 9 and 3; no ELF header. All 237 special areas that read start with an ELF64 header for `EM_X86_64`. | | |

M3 shows L5 at work: the anonymous executable areas are read-only, yet every present page has bit 58 set: the pages were written while the area was writable and then made executable, and `pte_modify` moved D into SavedDirty. It shows L3 too: no page outside a `VM_EXEC` area is executable. No file executable area holds a written page on either capture.

| # | Measured | mem3 | mem4 | mem1 | mem2 | mem5 | mem6 | mem7 |
|---|---|---|---|---|---|---|---|---|
| M5 | Physical ranges; scan time (4 MiB windows) | 6; 2.2 s | 5; 2.2 s | 1; 12.9 s | 1; 2.0 s | 1; 2.4 s | 309; 2.5 s | 4; 2.8 s |
| M6 | `Linux version ` hits; of them B1-shaped (release, by@host, compiler, `#` version); ended by "\n"; same text as the running `linux_banner`; at its physical address | 10; 4; 8; 1; 1 | 25; 23; 4; 20; 1 | 0 | 0 | 0 | 0 | 0 |
| M7 | Kernel PDB CodeView records; same fingerprint as the running kernel's; at the running kernel's record | 0 | 0 | 6; 6; 1 | 2; 1; 1 | 1; 1; 1 | 3; 1; 1 | 2; 1; 1 |
| M8 | Longest banner text 301 bytes (mem3; the release 17, `UTS_VERSION` and a distribution suffix 139) and 211 (mem4). mem3's running banner is `UTS_VERSION` cut at 64 bytes ("... UTC 2") followed by " (Ubuntu 6.17.0-35.35~24.04.1-generic 6.17.13)", a suffix B1 does not have. Non-banner hits: "Linux version dependencies," (5, mem3), "Linux version of Organic Maps ..." and "Linux version in order to ..." (mem4). Copies cut or overwritten by other text: 4 on mem3, 2 on mem4. Other kernels' records: mem2 one `ntoskrnl.pdb`, mem6 two, mem7 one; mem4 one banner of 6.12.6-100.fc40. | | | | | | | |
| M9 | Physical layer: type; size; held | segmented; 2,147,483,647; 2,096,001,019 | segmented; 2,147,483,647; 2,146,332,667 | flat; 10,871,635,968 (all held) | flat; 4,429,185,024 | flat; 4,429,185,024 | segmented; 2,147,483,648; 1,951,334,400 | segmented; 2,147,483,648; 2,146,369,536 |
| M9 | Kernel layer: mapped runs; held bytes; ELF size; listing time | 5,763; 2,245,537,792; 2,245,861,376; 0.0 s | 6,748; 2,311,778,304; 2,312,159,232; 0.0 s | 457,284; 2,153,627,648; 2,179,235,840; 1.6 s | 82,880; 544,866,304; 549,511,168; 0.1 s | 71,682; 446,771,200; 450,789,376; 0.0 s | 311,322; 1,410,269,184; 1,427,705,856; 3.1 s | 320,112; 1,447,493,632; 1,465,421,824; 3.6 s |

## 4. Algorithm

### 4.1 Linux executable areas (`any.memory.find_code`, Linux profile)

**Setup.**

1. The profile must be Linux (`ErrNotLinux`); `RunAny` sends a Linux profile here and every other profile to S35.
2. Options: `hexdump_size` and `dump_regions` as S35 4.10; `show_all_dirty_pages` (4.1 step 12).
3. The S39 area walker (`NewLinuxWalker`); failure fails the run.
4. The task walk (S01), filtered by `pid`; its losses are reported as S01 says.
5. The special-mapping tables: the addresses of `special_mapping_vmops` and, when present, `legacy_special_mapping_vmops` (L7). With neither, special mappings are not told apart; one diagnostic.
6. The written-while-read-only bit (L5). The kernel release is read from `linux_banner` (B1: the token after "Linux version "). Release 6.14 or later: a present entry is written when bit 6 or bit 58 is set. Release 6.4 or earlier: bit 6 only. Otherwise (no release, or 6.5 to 6.13, which no checked tag covers): bit 6 only, and one diagnostic says pages written while read-only are not counted.

**Per task.**

7. `ProcessLayer`. A task without an address space of its own (`ok` false, no reason) has no rows. One that has one that cannot be reached: diagnostic, no rows; strict mode fails. The layer must give leaf entries, else `ErrNoPageEntries`: diagnostic, no rows; strict mode fails.
8. `comm`, `pid`; `TaskVMAs`. Area losses are one diagnostic for the task (strict mode fails); the areas kept are examined.
9. For each area, `vm_flags` and `vm_ops`. A flag that does not read: diagnostic for the area (strict mode fails), the area is passed over.

**Page walk (each area, `vm_start` to `vm_end - 1` in 4 KB steps).**

10. `LeafEntry(page)`. A miss above the leaf with a span skips to the end of that span. More than `MaxRegionScanBytes / 4096` entries stop the area's walk with `ErrRegionScanCut` (diagnostic, strict fails); what was counted stays. A present entry (bit 0, L4) is resident; it is executable when bit 63 is clear; written per step 6. A not-present entry counts as nothing (on x86 the processor ignores it; the kernel's forms hold no execute right).
11. NX in use: the task has at least one present entry with bit 63 set. Without it, bit 63 says nothing (L4: XD is reserved when NXE is 0), and rule 4 below does not apply.

**Rule (one per area, the first that holds).**

12. `writable-executable` (`RuleWritable`): `VM_EXEC` and `VM_WRITE` (L1).
13. `anonymous-executable` (`RuleAnonymous`): `VM_EXEC`, no `vm_file`, and `vm_ops` is not a special-mapping table (L7). A special mapping is not a candidate: the kernel installed it.
14. `written-file-executable` (`RuleWrittenFile`): `VM_EXEC`, a `vm_file`, no `VM_WRITE`, and at least one written page (L6: such a page is a private copy written after the mapping).
15. `page-executable` (`RulePage`, S35's name): no `VM_EXEC`, NX in use (step 11), and at least one present page with bit 63 clear, which `vm_get_page_prot` never gives (L3).
16. Other areas are not candidates.

**Content and row.**

17. Executable pages are the present pages with bit 63 clear (all present pages when NX is not in use). Each is read as 4 KB through the process layer; one that reads and holds a nonzero byte is a content page. A candidate without a content page is not listed; such areas are counted in one diagnostic (S35 4.5 step 3).
18. Header at `vm_start` (one page, or the area if smaller): `unread` when it does not read; `elf` with `HeaderMachine` = `e_machine` when it starts with the ELF magic and `EI_CLASS` is 1 or 2 (L8); otherwise S35 4.7 (a PE header, `dos`, `nt` or `none`).
19. First transfer at `vm_start`: S35 4.8 in 64-bit mode. The target's area is the file area of the task that holds the target; its name is `TransferImage`.
20. Preview: S35 4.9 from the first content page. Dump: S35 4.10 with the area's bounds, through the process layer.
21. `show_all_dirty_pages`: when true, `WrittenAddresses` lists every written page; otherwise it is empty. `FirstWritten` is always the first written page (0 when none).

### 4.2 Version banners (`any.image.find_banners`)

1. The physical layer is required (`ErrNoPhysical`).
2. **The running kernel's copy.** Linux profile: `linux_banner` (B1) read from kernel memory, at most `MaxNameBytes`, to its NUL; its physical address by translating the symbol's address. Windows profile: the kernel image at `KernelBase`, its debug directory and CodeView record (B6); the record's physical address by translating `KernelBase + AddressOfRawData`. Either failing: one diagnostic; no row is marked running.
3. **Scan.** `memory.ScanWindows` over the held ranges, windows of `MaxBufferBytes` with an overlap of `MaxNameBytes`, or of 284 bytes (a CodeView head of 24 and `MAX_PATH`) when that is larger. A hit is taken from the window it starts in, below the window's step. More than `MaxMatchesPerChunk` hits in one window stop that window; one diagnostic counts such windows. Unreadable windows: one diagnostic; strict mode fails.
4. **Linux hit.** "Linux version " followed by a release token of 1 to 64 bytes in 0x21 to 0x7E (B2) and then " (". Anything else is not a banner. The text runs from the hit to the first "\n", NUL or byte outside 0x20 to 0x7E, at most `MaxNameBytes`; `Terminated` when it stopped at "\n" (B1).
   - `Release`: the token.
   - `Version`: from the `#` after the last ") #" to the end of the text, empty when there is none (B3, B4: the compiler may hold parentheses, `UTS_VERSION` starts with `#`; a distribution suffix stays in it, M8).
5. **Windows hit.** "RSDS", 20 bytes of GUID and age, then a path of 1 to 259 bytes ended by NUL (B8). Its last component after `\` or `/` must be a kernel PDB name (B7). `Banner` is the fingerprint `<pdb>/<GUID>-<age>` (S32 4.6 step 2).
6. **Marks.** `RunningCopy`: the hit's offset is the running copy's physical address (step 2). `SameAsRunning`: the text (Linux, without the final "\n") or the fingerprint (Windows) equals the running kernel's.
7. Rows in offset order.

### 4.3 Literal search (`any.image.find_literal`)

1. Options: `literals`, each 1 to `MaxNameBytes` bytes (option error otherwise; the option reader trims white space around each item and drops empty ones), exact duplicates kept once; `case_insensitive`; `max_scan_bytes` (0 or unset: the whole layer). No literal: one diagnostic and no rows.
2. The physical layer is required (`ErrNoPhysical`).
3. With `case_insensitive`, the literal and the window are compared after mapping `A` to `Z` onto `a` to `z` (F5); other bytes compare exactly.
4. `ScanWindows` with windows of `MaxBufferBytes` and an overlap of the longest literal less one, so a match is whole in the window it starts in. A match is taken from a window when it starts below the window's step and ends at or below `max_scan_bytes`. Matches may overlap one another.
5. More than `MaxMatchesPerChunk` matches in one window stop that window; one diagnostic. Unreadable windows: one diagnostic; strict mode fails.
6. `Preview`: the layer's bytes from the match, `RowPreviewBytes` of them or the match's length if longer, cut back to the match when the longer read runs into a gap; bytes outside 0x20 to 0x7E are written as `.`.
7. Rows sorted by offset, then literal.

### 4.4 Layer export (`any.image.dump_layers`)

1. **Layers.**
   - `physical`: the physical layer. `Type` is `segmented` when the reader gives segments (the capture holds ranges with gaps between them) and `flat` otherwise. `Size` is the end of the highest held range; `Held` the sum of the ranges.
   - `kernel`: listed when the session gives a kernel page-table root and a paging mode the layers package walks. `Type` is the paging mode's name. Its mapped runs are `IntelTranslator.Mapping`'s: virtual and physical runs adjacent in both spaces, page tables of one repeated entry left out, frames outside the held ranges left out. `Held` is the sum of the runs; `Runs` their number; `Size` the ELF file's size (step 5). A walk that fails leaves the layer listed with `Unavailable` set.
2. **List** (`list` true): one row per layer, no files.
3. **Write.** `output_dir` is required (`ErrNoOutputDir`). `layers` names the layers, `physical` when empty; an unknown name is an option error. `block_size` is the read size, default `MaxBufferBytes`, 1 to `MaxBufferBytes` (option error otherwise). Every named layer's `Size` must be at most `max_dump_size`, or `MaxImageBytes` when that is not set, before any file is written (`ErrTooLarge`); an unavailable layer fails the run (`ErrUnavailable`).
4. **Physical file** `region.phys.bin` (S00 names, `extract.CreateUnique`): byte `n` of the file is physical address `n`. Each held range is read in `block_size` pieces and written at its address. Gaps between ranges and pieces that do not read are not written: the file's size is set to `Size` at the end, so they read as zeros (F4). Pieces that do not read are counted in `Zeroed` and one diagnostic; strict mode fails.
5. **Kernel file** `region.kernel.elf`: an ELF64 core file (F1). `e_type` `ET_CORE`, `e_machine` `EM_X86_64` for 4- and 5-level paging and `EM_386` for PAE and 32-bit paging, one `PT_LOAD` per run in `Mapping` order (ascending virtual address, F2) with `p_vaddr` the run's virtual address, `p_paddr` its physical address, `p_filesz` = `p_memsz` = its size, `p_flags` `PF_R`, `p_align` 4096, `p_offset` page-aligned in run order after the headers. With `PN_XNUM` runs or more, one section header holds the count (F3). The data is read from the physical layer at `p_paddr`; pieces that do not read are left as zeros and counted as in step 4. More than `MaxListEntries` runs make the layer unavailable, with the `ErrTooManyRuns` text as its reason (step 1).
6. A write failure removes the partial file and fails the run.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| User reads only through the task's own layer | S14, S35 4.2 step 2 | task skipped, diagnostic |
| Leaf entries available | L4 | `ErrNoPageEntries`; task skipped |
| Special mappings are not anonymous candidates | L7, M2 | not listed |
| Bit 58 means written only at 6.14 and later | L5 | bit 6 alone, diagnostic for unverified releases |
| NX clear outside `VM_EXEC` counts only when NX is in use | L3, L4, M3 | rule 4 not applied |
| A content page in an executable page | S35 D3 | counted, not listed |
| Banner release token 1 to 64 bytes, then " (" | B1, B2 | not a banner |
| CodeView path ends in NUL within 260 bytes; kernel PDB name | B6, B7, B8 | not a record |
| Literal of 1 to `MaxNameBytes` bytes | 8 | option error |
| `block_size` 1 to `MaxBufferBytes`; known layer names | 8 | option error |
| Output within `max_dump_size` or `MaxImageBytes` | 8 | `ErrTooLarge`, nothing written |

## 6. Failure modes

| Case | Result |
|---|---|
| find_code, profile not Linux in `RunLinux` | `any.memory.find_code: memorycode: profile os is not linux: "<os>"` (`ErrNotLinux`) |
| Area walker or task walk unusable | the run fails with the walker's error |
| `pid` or `comm` not read | `any.memory.find_code: task_struct at 0x<addr>: pid not read: <error>` (or `pid <pid> task_struct ...: comm not read`); the task has no rows; strict: the run fails |
| Task layer not reached | `any.memory.find_code: pid <pid> task_struct at 0x<addr>: address space not built: <error>`; strict: the run fails |
| No leaf entries | `any.memory.find_code: pid <pid> task_struct at 0x<addr>: page-table entries not read: memorycode: process address space gives no page-table entries`; strict: the run fails |
| Area losses | `any.memory.find_code: pid <pid> task_struct at 0x<addr>: memory areas walked in part: <losses>`; strict: the run fails |
| `vm_flags` not read | `any.memory.find_code: pid <pid> vm_area_struct at 0x<addr>: vm_flags not read: <error>`; strict: the run fails |
| Walk cut | `any.memory.find_code: pid <pid> vm_area_struct at 0x<addr>: page walk stopped after <n> entries: memorycode: region page walk reached MaxRegionScanBytes`; strict: the run fails |
| No special-mapping table | `any.memory.find_code: special_mapping_vmops: not in symbols, kernel-installed areas are not told apart`, once |
| Written bit not settled | `any.memory.find_code: linux_banner: <reason>: pages written while read-only are not counted`, once |
| Candidates without content, dump failures | the S35 messages |
| find_banners, no physical layer | `any.image.find_banners: imagebanners: session has no physical layer` (`ErrNoPhysical`) |
| Running copy not read | `any.image.find_banners: running kernel's banner not read: <error>`, once |
| Window cap | `any.image.find_banners: <n> windows held more than MaxMatchesPerChunk (<cap>) hits; the rest of each was not searched`, once |
| Unreadable windows | `any.image.find_banners: <coverage error>`; strict: the run fails |
| find_literal, no physical layer | `any.image.find_literal: imageliteral: session has no physical layer` (`ErrNoPhysical`) |
| No literal | `any.image.find_literal: no literals given in any.image.find_literal.literals`, once |
| Window cap, unreadable windows | as find_banners, named `any.image.find_literal` |
| dump_layers, no output directory | `any.image.dump_layers: imagelayers: needs output_dir` (`ErrNoOutputDir`) |
| No physical layer | `any.image.dump_layers: imagelayers: session has no physical layer` (`ErrNoPhysical`) |
| Layer too large | `any.image.dump_layers: imagelayers: layer exceeds the size limit: <layer> is <n> bytes, limit <m>` (`ErrTooLarge`) |
| Layer unavailable | `any.image.dump_layers: imagelayers: layer unavailable: kernel: <reason>` (`ErrUnavailable`) |
| Too many runs | The kernel layer is listed with `Unavailable` `imagelayers: kernel layer has more mapped runs than MaxListEntries` (the `ErrTooManyRuns` text); writing it fails as an unavailable layer |
| Unreadable pieces | `any.image.dump_layers: <layer>: <n> bytes in <k> pieces did not read and are zeros, first at 0x<addr>`; strict: the run fails and the file is removed |
| Option of the wrong type or value | the run fails with `tools.ErrOptionType` |

## 7. Result schema

**`memorycode.LinuxFinding`**, one per listed area, in task-walk order, then `Start`:

| Field | Type | Meaning |
|---|---|---|
| `PID`, `Process` | int64, string | `task_struct.pid` and `comm` |
| `AreaAddress` | uint64 | the `vm_area_struct` |
| `Start`, `End` | uint64 | `vm_start`, `vm_end - 1` (inclusive, as S35) |
| `Protection` | string | L2's four characters, as `/proc/<pid>/maps` |
| `Backing` | `Backing` | `none` without `vm_file`, `file` with one |
| `Path`, `PathAvailable` | string, bool | S39's area name; false when no name was built |
| `Rule` | `Rule` | `writable-executable`, `anonymous-executable`, `written-file-executable`, `page-executable` |
| `Pages`, `ExecutablePages`, `ResidentPages`, `WrittenPages`, `ContentPages` | uint64 | 4 KB pages; 4.1 steps 10 and 17 |
| `FirstContent`, `FirstWritten` | uint64 | first content page, first written page (0 when none) |
| `WrittenAddresses` | []uint64 | every written page with `show_all_dirty_pages`, else empty |
| `Header`, `HeaderMachine` | `Header`, uint16 | 4.1 step 18 (`elf` added to S35's kinds) |
| `Transfer`, `TransferTarget`, `TransferTargetUnread`, `TransferImage` | as S35 | 4.1 step 19 |
| `Preview`, `Artifact` | []byte, string | 4.1 step 20 |

**`imagebanners.Banner`**, in offset order:

| Field | Type | Meaning |
|---|---|---|
| `Offset` | uint64 | physical address of the hit |
| `Kind` | `Kind` | `linux` or `windows-pdb` |
| `Banner` | string | Linux: the text without its final "\n"; Windows: `<pdb>/<GUID>-<age>` |
| `Release`, `Version` | string | Linux only (4.2 step 4) |
| `Terminated` | bool | Linux: the text ended in "\n" |
| `RunningCopy`, `SameAsRunning` | bool | 4.2 step 6 |

**`imageliteral.Finding`**, by offset then literal: `Literal` string (as given), `Offset` uint64, `Length` uint64, `Preview` string. `any.image.find_literal` is a placeholder (section 1, owner decision 2026-11-12); its rows say only where the bytes lie.

**`imagelayers.Layer`** (list): `Name`, `Type`, `Size`, `Held` (bytes), `Runs` (kernel), `Unavailable` (reason, empty when usable). **`imagelayers.Status`** (write): `Layer`, `Artifact` (file name), `Size`, `Read`, `Zeroed` (bytes), `Runs`.

## 8. Limits

- `MaxRegionScanBytes` (default 1 GiB, 262,144 entries per area): the largest area walked on the captures is far below it (M1); a forged `vm_end` is bounded by it.
- `RowPreviewBytes` (default 128): the find_code preview unless set; the literal preview.
- `MaxArtifactBytes`: the largest find_code preview, and its dump limit when `max_dump_size` is not set.
- `MaxNameBytes` (default 4096): the longest banner text read (M8: 301) and the longest literal; the scan overlap.
- `MaxBufferBytes` (default 64 MiB): the scan window and the default and largest `block_size`.
- `MaxMatchesPerChunk` (default 1,000,000): hits per window; a window full of one repeated prefix cannot make unbounded rows.
- `MaxImageBytes` (default 1 TiB): the largest layer file unless `max_dump_size` is set.
- `MaxListEntries` (default 2^20): kernel runs.
- `NameAttempts`: the collision suffixes tried for a layer file name.

## 9. Acceptance

1. Synthetic fixtures:
   - find_code Linux (`tools/any/memorycode/linux_test.go`, on `linuxobjtest` tasks, VMA list and user page tables): each rule; a special mapping not listed; a W+X area that is also anonymous gets `writable-executable`; bit 58 counted on 6.17 and not on 6.4 and on 6.10 (with the diagnostic); written addresses with and without the option; an area of zeros (not listed, counted); NX not in use (rule 4 off); the ELF header; a transfer into a file area; the preview, its bound and the dump; a task without an address space; a layer without leaf entries; the walk cut; strict mode.
   - find_banners: a B1 banner, a cut one, a non-banner "Linux version" text, a forged 65-byte release, a CodeView record of a kernel PDB and of another PDB, an unterminated path; a hit across a window boundary; running copy and same-text marks for both systems; the window cap.
   - find_literal: exact and case-folded matches, overlapping matches, a match across a window boundary, `max_scan_bytes` cutting a match, segmented layers, an unreadable window, the window cap, option errors.
   - dump_layers: list; a flat and a segmented physical layer with a gap and an unreadable piece; a kernel ELF read back with `debug/elf` (header, runs, data); `PN_XNUM`; the size limit; unknown layer and bad `block_size`; missing output directory.
2. Fuzz targets, 30 s each: `FuzzLinuxBanner` (any bytes: no panic; a banner has the prefix, a 1 to 64-byte release and no byte outside 0x20 to 0x7E), `FuzzCodeViewRecord` (any bytes: a record only with "RSDS", a kernel PDB name and a NUL inside 260 bytes), `FuzzLinuxEntry` (any entry and flags: a non-present entry is never resident, executable or written), `FuzzFoldedMatch` (any window and literal: every match compares equal after folding and lies inside the window).
3. Fuzz runs, 30 s each on 2026-11-12, no failure: `FuzzLinuxEntry` 1,325,747 executions, `FuzzLinuxBanner` 2,909,138, `FuzzCodeViewRecord` 4,777,017, `FuzzFoldedMatch` 4,463,369, `FuzzKernelELFHeaders` 3,421,157 (any runs: the header parses with Go's `debug/elf` and gives each run back).
4. On the captures, 2026-11-12, without a pagefile.

   find_code (`linuxcodefacts -tool -nofacts`, then with `show_all_dirty_pages`, `dump_regions` and an output directory):

| Capture | Rows (anonymous, writable) | Without content (diagnostic) | Executable / content / written pages | Written addresses listed | Rows by process | Dumps | Time |
|---|---|---|---|---|---|---|---|
| mem3 | 61 (41, 20) | 7 | 264 / 250 / 264 | 264 | gnome-shell 47, gjs 8, gnome-terminal- 3, gnome-session-b 2, unattended-upgr 1 | 61 files, 12 MB | 5.4 s (10.1 s with dumps) |
| mem4 | 52 (48, 4) | 3 | 120 / 120 / 118 | 118 | gnome-shell 47, gjs 2, gnome-terminal- 2, gnome-session-b 1 | 52 files, 11 MB | 12.2 s (16.2 s) |

   - Rows plus areas without content equal M2's anonymous and writable executable areas (68 and 55); the 237 special mappings are not listed; no file area is `written-file-executable` and no area `page-executable` (M3).
   - Every row's header is `none` (M4: the areas start with ENDBR64 or zeros) and none starts with a transfer form of S35 4.8.
   - Diagnostics are S39's area losses in one task on each capture (S39 X2) and S01's broken backward walk on mem4; none for the written mark (6.17 and 6.14) or the special-mapping table.

   find_banners (`bannerfacts -tool -nofacts`):

| Capture | Rows | Running copy (offset) | Same as running | Other releases or kernels | Time |
|---|---|---|---|---|---|
| mem3 | 5 linux (3 ended by a newline, 5 with a version) | 0x721c6660, the session's `linux_banner` | 2 | none | 1.6 s |
| mem4 | 23 linux (3 ended by a newline) | 0x538d93a0 | 20 | 6.12.6-100.fc40.x86_64 once | 2.0 s |
| mem1 | 6 windows-pdb | 0x3df5839c | 6 | none | 18.2 s |
| mem2 | 2 | 0x3041100 | 1 | `ntoskrnl.pdb` 13D62BF4... | 4.7 s |
| mem5 | 1 | 0x103899920 | 1 | none | 3.5 s |
| mem6 | 3 | 0x7d84983c | 1 | two `ntoskrnl.pdb` | 4.5 s |
| mem7 | 2 | 0x7d85983c | 1 | one `ntoskrnl.pdb` | 5.2 s |

   - On every capture exactly one row is the running copy, at the physical address the session's kernel gives, and it names the kernel the session identified (mem3 6.17.0-35-generic, mem4 6.14.5-100.fc40.x86_64; the ntkrnlmp fingerprints of S32). The raw scan's 6 non-banner "Linux version" texts are not rows.

   dump_layers (`layerfacts -write` on mem4 and mem7): physical files of 2,147,483,647 and 2,147,483,648 bytes with every held byte read and none zeroed; 31 sampled pages each equal to the layer. Kernel files of 2,312,159,232 bytes (6,748 runs) and 1,465,421,824 bytes (320,112 runs, so `PN_XNUM` is used) parse with Go's `debug/elf` as `ET_CORE`, `EM_X86_64`; 70 and 3,301 sampled runs equal the kernel layer's reads at their `p_vaddr`. Time 14.1 s and 18.7 s for both files.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Bit 58 as a written mark is verified at v6.14 and v6.17 and refuted at v6.4; kernels 6.5 to 6.13 count bit 6 only. | A check of the tags in between (owner decision: which tags may be fetched) |
| O2 | A not-present entry in an executable area counts as nothing. NUMA-hinting entries (`_PAGE_PROTNONE`) are resident but not present; the layer does not read them. | A capture with NUMA balancing active |
| O3 | Instructions are decoded in 64-bit mode; a 32-bit (compat) task's code would decode wrongly. No capture holds one. | A capture with a 32-bit task |
| O4 | Special mappings are not listed. The vDSO is the kernel's code; a uprobes XOL area is also a special mapping and is not listed either. Owner decision: list special mappings with their own rule instead. | Owner decision |
| O5 | Owner decision (Q2): Linux row field names. Removed from 0.1.0: `Hexdump` (now `Preview`), `Disasm` (now the first transfer, as S35), `FileOutput` (now `Artifact`), `Flag` and the type `MaliciousFlag` with `FlagRWX`, `FlagRX`, `FlagXDirty`, `RegionStart`, `RegionSize`, `VMA` (now `AreaAddress`). Added: `AreaAddress`, `Backing`, `Rule`, the page counts, `FirstContent`, `FirstWritten`, `WrittenAddresses`, `Header`, `HeaderMachine`, the transfer fields, `Artifact`. `show_all_dirty_pages` now fills `WrittenAddresses`. | Owner decision |
| O6 | Owner decision (Q2): banner fields `Kind`, `Release`, `Version`, `Terminated`, `RunningCopy`, `SameAsRunning` added; `PhysicalBlocks` removed. The Windows text is the PDB fingerprint, not a free-form string. Mac OS banners are no longer searched (no source in the allowed set). | Owner decision |
| O7 | Owner decision (Q2): find_literal rows are now sorted by offset first; the preview shows image bytes, not the literal. A missing physical layer is an error, where 0.1.0 searched the kernel's virtual layer. | Owner decision |
| O8 | Owner decision (Q2): dump_layers. The `image` layer (the capture file) is gone: the session does not give it to tools. The physical `Type` is `flat` or `segmented`, not the container format, which the session does not record. The kernel layer is an ELF core file of its mapped runs, not a flat file of the whole virtual space. `Status` and `Layer` fields renamed (`FileName` to `Artifact`, `Padded` to `Zeroed`; `Held`, `Runs`, `Unavailable` added). An unknown layer name is an error, where 0.1.0 gave a row. The 0.1.0 constants for the image layer, the container formats and the paging types, `DefaultBlockSize`, `ErrListMode` and `ErrZeroBlockSize` are removed. | Owner decision |
| O9 | The kernel ELF file uses `ELFCLASS64` for 32-bit paging too, with `EM_386`. | Owner decision |
| O10 | A banner whose text was overwritten in place (M8) is listed as found; nothing tells a stale copy from the running one but the running mark. | None |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep bit 6 only for 6.5 to 6.13 |
| O2 | Count as nothing |
| O3 | Defer |
| O4 | Leave unlisted |
| O5 | Accept the new names |
| O6 | Accept both |
| O7 | Accept all three changes |
| O8 | Accept the redesign |
| O9 | Use ELFCLASS64 with EM_386 |
| O10 | Keep listing it |

## 11. Provenance

Written 2026-11-12 from the Linux kernel source at v4.19, v6.1, v6.4, v6.14 and v6.17 (files named in section 3), the ELF gABI, POSIX.1-2017, Microsoft Learn (PE Format, Naming Files), the Intel SDM, specifications S00, S01, S14, S18, S32, S35 and S39, and the project's measurements. Every rule rests on the sources and measurements above.
