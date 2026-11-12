# S05: VMCOREINFO note

Version 1, 2026-11-11.

## 1. Purpose

A Linux kernel built with crash-dump support keeps a text table about itself, VMCOREINFO, in an ELF note in its own memory. A capture of physical memory holds that note without any symbol file. This specification finds every copy of the note in an image, reads its table exactly as the kernel writes it, says when a copy is damaged, and derives the x86-64 kernel layout a session needs: the kernel's page-table root, its virtual KASLR shift, its paging depth and its physical address width.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Physical | memory reader | The image's physical address space. When it lists segments, only their bytes are read. |
| Limits | `limits.Limits` | The project's read bounds (section 8). |

## 3. Constraints from the kernel source

References are to the Linux kernel at tags v4.13, v4.19 (K16 only), v5.4, v5.15, v6.1, v6.8, v6.14 and v6.17. The generic code is `kernel/crash_core.c` up to v6.8 and `kernel/vmcore_info.c` from v6.14. The x86 hook `arch_crash_save_vmcoreinfo` is in `arch/x86/kernel/machine_kexec_64.c` up to v5.4, `crash_core_64.c` and `crash_core_32.c` from v5.15 to v6.8, and `vmcore_info_64.c` and `vmcore_info_32.c` from v6.14.

| # | Constraint | Source |
|---|---|---|
| K1 | `append_elf_note` writes a header of three 4-byte words, `n_namesz`, `n_descsz`, `n_type`, then the name, then the descriptor. Name and descriptor are each padded to a multiple of 4 bytes. The words are `Elf_Word`, which is `__u32` for both ELF classes, in the kernel's byte order: little-endian on x86. | `append_elf_note`, all tags; `include/uapi/linux/elf.h` (`Elf32_Word`, `Elf64_Word`), v6.17 |
| K2 | The VMCOREINFO note has name `"VMCOREINFO"`, so `n_namesz` = 11 and the padded name is the 12 bytes `VMCOREINFO\0\0`. Its type is 0. The note buffer is allocated zeroed, so the padding byte is 0. | `VMCOREINFO_NOTE_NAME`; `update_vmcoreinfo_note`; `alloc_pages_exact(..., __GFP_ZERO)`, all tags |
| K3 | `n_descsz` is `vmcoreinfo_size`. The note is not written while that size is 0. The size never exceeds `VMCOREINFO_BYTES`, which is `PAGE_SIZE`. | `update_vmcoreinfo_note`; `vmcoreinfo_append_str`; `VMCOREINFO_BYTES` in `crash_core.h` / `vmcore_info.h` |
| K4 | Every line is written by one `vmcoreinfo_append_str` call. It formats into `char buf[0x50]` with `vscnprintf`, so one call writes at most 79 bytes, and copies them without the terminating NUL. Every format string ends in `\n`. A line of more than 79 bytes is therefore cut to its first 79 bytes and loses its `\n`; the next call's text follows it directly. | `vmcoreinfo_append_str`, all tags |
| K5 | When the table reaches `VMCOREINFO_BYTES`, the last call is cut at that size. | `vmcoreinfo_append_str` (`min(r, VMCOREINFO_BYTES - vmcoreinfo_size)`) |
| K6 | The first line is `OSRELEASE=%s`. Every tag also writes `PAGESIZE=%ld` with the value of `PAGE_SIZE`. | `crash_save_vmcoreinfo_init`, all tags |
| K7 | The note is written at boot, at the end of `crash_save_vmcoreinfo_init`, and written again at crash time with `CRASHTIME=` appended. | `crash_save_vmcoreinfo_init`; `crash_save_vmcoreinfo` |
| K8 | Value formats, from the macros: `SYMBOL(n)=%lx`; `SIZE(n)=%lu`; `OFFSET(s.f)=%lu`; `LENGTH(n)=%lu`; `NUMBER(n)=%ld`; `PAGESIZE=%ld`; `CONFIG_n=y`; `OSRELEASE=%s`; `BUILD-ID=%20phN` (present at v5.15, absent at v5.4). Direct calls: `KERNELOFFSET=%lx`; `CRASHTIME=%lld` (`%ld` on v4.13); `NUMBER(pgtable_l5_enabled)=%d`; `NUMBER(VMALLOC_START)=0x%lx` (v6.14 on). The integer arguments are `unsigned long`, `long` or `int`, at most 64 bits. | `VMCOREINFO_*` macros; `vmcoreinfo_append_str` calls, all tags |
| K9 | `%lx` prints lowercase hex digits with no prefix. `%lu` prints decimal digits. `%ld`, `%lld` and `%d` print decimal digits after an optional `-`. | printf conversion semantics, which the kernel's `vsnprintf` follows for these conversions |
| K10 | x86-64 writes `NUMBER(phys_base)`, `SYMBOL(init_top_pgt)`, `KERNELOFFSET`, `NUMBER(KERNEL_IMAGE_SIZE)` on every tag listed, `NUMBER(pgtable_l5_enabled)` from v4.17 (absent at v4.13, present at v5.4), and `NUMBER(sme_mask)` (absent at v4.13, present at v5.4). The generic code writes `SYMBOL(swapper_pg_dir)` on every tag and `NUMBER(MAX_PHYSMEM_BITS)` (absent at v5.4, present at v5.15). 32-bit x86 writes none of the x86-64 keys and writes `CONFIG_X86_PAE=y` on a PAE build. | the x86 hooks and generic code above |
| K11 | On x86-64, `swapper_pg_dir` is a macro for `init_top_pgt`, the kernel's top-level page table. `SYMBOL(swapper_pg_dir)` stringifies the unexpanded name and prints the address of `init_top_pgt`. | `arch/x86/include/asm/pgtable_64.h`, v6.17 |
| K12 | `__START_KERNEL_map` is 0xffffffff80000000. A kernel-image address x has physical address x − `__START_KERNEL_map` + `phys_base`. `phys_base` is printed with `%ld` and may be negative. | `arch/x86/include/asm/page_64_types.h`; `page_64.h` (`__phys_addr_symbol`), v6.17 |
| K13 | `KERNEL_IMAGE_SIZE` is 1 GiB with `CONFIG_RANDOMIZE_BASE` and 512 MiB without. It bounds the kernel image's virtual end and is at most 1 GiB. | `page_64_types.h`; `vmlinux.lds.S` (`ASSERT(_end - LOAD_OFFSET <= KERNEL_IMAGE_SIZE)`), v6.17 |
| K14 | `kaslr_offset()` is `&_text − __START_KERNEL`, and `__START_KERNEL` is `__START_KERNEL_map + LOAD_PHYSICAL_ADDR`. The decompressor picks the virtual address as `LOAD_PHYSICAL_ADDR` plus a whole number of `CONFIG_PHYSICAL_ALIGN` slots, so the offset is a multiple of `CONFIG_PHYSICAL_ALIGN`, which on x86-64 is a multiple of 0x200000. | `arch/x86/include/asm/setup.h`; `page_types.h`; `arch/x86/boot/compressed/kaslr.c` (`find_random_virt_addr`); `arch/x86/Kconfig` (`PHYSICAL_ALIGN`), v6.17 |
| K15 | The processor loads the root of 4-level and 5-level paging from CR3 bits M−1:12, so the root is 4-KByte aligned and below 2^52. | S04, A5 and A6 |
| K16 | `PAGE_SIZE` is `1 << PAGE_SHIFT`. On x86, 32-bit and 64-bit, `PAGE_SHIFT` is 12: a constant in `arch/x86/include/asm/page_types.h` at v4.19, and from the `PAGE_SIZE_4KB` choice at v6.17, the only page size x86 selects (`select HAVE_PAGE_SIZE_4KB`). So `VMCOREINFO_BYTES` (K3) is 4096 on x86. The largest page size each other architecture allows at v6.17, from its `select HAVE_PAGE_SIZE_*` lines: 256 KiB powerpc and hexagon; 64 KiB arm64, loongarch, mips and parisc; 16 KiB arc; 8 KiB alpha, m68k, openrisc and sparc; 4 KiB arm, csky, microblaze, nios2, riscv, s390, um and xtensa. | `arch/x86/include/asm/page_types.h` v4.19; `include/vdso/page.h`, `arch/Kconfig` (`PAGE_SHIFT`, `PAGE_SIZE_*`) and `arch/<arch>/Kconfig`, v6.17 |
| K17 | The release line is `OSRELEASE=%s` of `init_uts_ns.name.release`, a `char[__NEW_UTS_LEN + 1]` with `__NEW_UTS_LEN` 64. `%s` copies every byte up to the first NUL and escapes none. The line is therefore at most 75 bytes and never cut (K4), and its value may hold any byte but NUL and `\n`. | `kernel/vmcore_info.c` and `include/linux/vmcore_info.h` (`VMCOREINFO_OSRELEASE`), `include/uapi/linux/utsname.h`, v6.17 |

The ELF gABI describes notes in 64-bit objects with 8-byte words. The kernel does not follow it for this note (K1), so the scan reads 4-byte words for every kernel.

## 4. Algorithm

### 4.1 Finding copies

1. Read the mapped ranges of Physical in windows of the scan step (section 8). Consecutive windows overlap by 11 bytes, so a 12-byte name that crosses a window boundary is seen once, in the window it starts in.
2. In each window, find every occurrence of the 12 bytes `VMCOREINFO\0\0` (K2). Each one is a candidate name at offset N. A candidate with N < 12 has no room for a header and is not a note.
3. The note starts at N − 12. Read its header (K1). The candidate is a note only when `n_namesz` = 11, `n_type` = 0 and 1 ≤ `n_descsz` ≤ the descriptor bound (section 8; K2, K3). Otherwise it is skipped silently: the bytes are the name text in some other place.
4. Read `n_descsz` bytes at N + 12. The candidate is a note only when the descriptor begins with `OSRELEASE=` (K6). Otherwise it is skipped silently.
5. Parse the descriptor (4.2). A parse failure makes the copy damaged.
6. A window that cannot be read is recorded as damaged at the window's start. A header or descriptor that cannot be read makes its copy damaged.

Copies are reported in ascending offset order.

### 4.2 Reading the table

1. Every descriptor byte is printable ASCII (0x20 to 0x7e) or `\n` (K8, K9), except in the release line, the first line up to its `\n` or its first 79 bytes: there any byte but NUL is read (K17). The release value is kept with every byte outside 0x20 to 0x7e written as `\xNN`, two lowercase hex digits, and every `\` written as `\\`. Each `\` in the Text then starts an escape, so a release that itself holds the text `\x` and two hex digits reads apart from an escaped byte, and the Text gives back the release's bytes exactly.
2. Split the descriptor at each `\n`. A piece of 79 bytes or more was cut (K4), because a whole line holds at most 78 bytes before its `\n`: its first 79 bytes are one cut line, and the rest is read again as the next piece. A last piece with no `\n` after it was cut (K5). A cut line is marked cut.
3. An empty line is damage: no call writes one (K4, K8).
4. A line is KEY=VALUE, cut at its first `=`. A line with no `=` is damage.
5. The value is read in the format of 4.3. A whole line whose value does not match is damage. A cut line keeps its value as text only.
6. A key the table holds twice keeps its first value. The kernel writes each key once on the tags listed, so this rule only decides a table something else wrote to.
7. When the table holds a whole `PAGESIZE` line, `n_descsz` must not exceed that value (K3).

### 4.3 Value formats

| Key | Format | Value |
|---|---|---|
| `SYMBOL(...)`, `KERNELOFFSET` | 1 or more of `0-9a-f` | unsigned, below 2^64 |
| `SIZE(...)`, `OFFSET(...)`, `LENGTH(...)` | 1 or more of `0-9` | unsigned, below 2^64 |
| `PAGESIZE`, `CRASHTIME` | optional `-`, then 1 or more of `0-9` | signed, within 64 bits |
| `NUMBER(...)` | `0x` then 1 or more of `0-9a-f`, unsigned below 2^64; or optional `-` then 1 or more of `0-9`, signed within 64 bits | |
| any other key | text | none |

A numeric value must be the exact text printf writes for its number (K9): no width or flag is used, so there is no `+`, no leading zero except in the value 0, no `-0`, and hex digits are lowercase.

### 4.4 The x86-64 layout

From one table, in this order:

1. `CONFIG_X86_PAE=y` means a 32-bit kernel (K10). The table gives no x86-64 layout.
2. `SYMBOL(swapper_pg_dir)` is required. A value below 2^32 is a 32-bit kernel's.
3. `NUMBER(phys_base)` and `KERNELOFFSET` are required (K10).
4. The image mapping size is `NUMBER(KERNEL_IMAGE_SIZE)` when present, which must be positive and at most 1 GiB, otherwise 1 GiB (K13).
5. `SYMBOL(swapper_pg_dir)` must lie in [0xffffffff80000000, 0xffffffff80000000 + mapping size) (K11, K12, K13). When `SYMBOL(init_top_pgt)` is present it must equal `SYMBOL(swapper_pg_dir)` (K11).
6. DTB = `SYMBOL(swapper_pg_dir)` − 0xffffffff80000000 + `NUMBER(phys_base)` (K12). DTB must be at least 0, below 2^52 and a multiple of 4096 (K15).
7. VirtualShift = `KERNELOFFSET`. It must be a multiple of 0x200000 and below the mapping size (K13, K14).
8. FiveLevel = `NUMBER(pgtable_l5_enabled)` is 1. The value must be 0 or 1. When the key is absent or cut (K10: kernels before v4.17), the session confirms the depth with S04 on the DTB (4.5); this step alone gives 4-level.
9. PhysAddrBits = `NUMBER(MAX_PHYSMEM_BITS)`, which must be in 13 to 52 (a frame number needs bits above the 4-KByte offset; S04 A6). Absent is 0: the session then uses the architectural 52.
10. SMEMask = `NUMBER(sme_mask)`, which must not be negative. Absent is 0.

A cut line does not supply a value to this step.

### 4.5 Depth from the tables

`ConfirmDepth` runs only when the table holds no whole `NUMBER(pgtable_l5_enabled)`. It decides the paging mode of the tables at DTB with S04, with 8-byte pointers. A decision sets FiveLevel to the 5-level result and keeps S04's evidence in DepthEvidence. An undecided or failed detection leaves FiveLevel false, the depth S04 section 6 falls back to, and is returned as an error; the caller keeps the layout and records the error as a diagnostic, `autoload: VMCOREINFO at 0x<note>: no NUMBER(pgtable_l5_enabled), read as 4-level: <S04 error>`.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Header: `n_namesz` = 11, `n_type` = 0, 1 ≤ `n_descsz` ≤ bound. | K1, K2, K3 | Not a note; skipped silently. |
| Descriptor begins `OSRELEASE=`. | K6 | Not a note; skipped silently. |
| Bytes are printable ASCII or `\n`; in the release line, any byte but NUL. | K8, K9, K17 | Damaged copy. |
| No empty line; every line has `=`. | K4, K8 | Damaged copy. |
| Whole-line values match 4.3 and fit 64 bits. | K8, K9 | Damaged copy. |
| `n_descsz` ≤ `PAGESIZE`. | K3, K6 | Damaged copy. |
| Each step of 4.4. | K10 to K15 | The table gives no layout; the copy itself is not damaged. |

## 6. Failure modes

A skip's error reads `VMCOREINFO ...`; its diagnostic text, `DamagedVMCoreInfo.String`, adds the prefix `autoload: skipped `.

- A window cannot be read: `VMCOREINFO scan at 0x<off>: read 0x<n> bytes: <err>`.
- A window holds more candidate names than the limit: `VMCOREINFO scan at 0x<off>: more than <n> candidate names, rest of window skipped`.
- A copy is damaged: `VMCOREINFO at 0x<note>: <reason>`, where the reason is one of `read note header: <err>`, `read 0x<n>-byte descriptor: <err>`, `byte 0x<b> at descriptor offset <i> is not text`, `line <n> is empty`, `line <n> has no '='`, `line <n>: <key> value "<v>" is not <format>`, `0x<n>-byte descriptor exceeds PAGESIZE <p>`.
- No copy is usable and at least one is damaged: the scan returns `*VMCoreInfoDamageError`, `autoload: <count> VMCOREINFO copies or ranges skipped: <each>`. It unwraps to each skip's error.
- No layout: `autoload: VMCOREINFO at 0x<note>: <reason>`, where the reason names the key that fails its 4.4 step.
- Depth undecided without the flag: the error of 4.5, which `linuxkernel.FindKernel` records as a diagnostic of the kernel it returns.

No copy and no damage is not an error: the scan returns no tables.

## 7. Result schema

- `VMCoreInfoScan{Tables []VMCoreInfo, Damaged []DamagedVMCoreInfo}`.
- `VMCoreInfo{Offset uint64, Entries []VMCoreInfoEntry}`. Offset is the note header's offset.
- `VMCoreInfoEntry{Key string, Text string, Int *big.Int, Cut bool}`. Int is nil for text keys and cut lines. The release's Text is escaped (4.2 step 1).
- `DamagedVMCoreInfo{Offset uint64, Err error}`, and `VMCoreInfoDamageError{Damaged}`.
- `VMCoreInfoLayout{VirtualShift uint64, PhysBase int64, DTB uint64, FiveLevel bool, DepthEvidence string, PhysAddrBits uint, SMEMask uint64}`. DepthEvidence is empty when the flag gave the depth.
- `VMCoreInfo.ConfirmDepth(physical, layout) (VMCoreInfoLayout, error)` (4.5).

## 8. Limits

- Scan step: 4 MiB, or `MaxBufferBytes` when smaller. The project's choice: large reads, few windows.
- Descriptor bound: the largest `PAGE_SIZE` of the architecture the scan reads, or `MaxTextBytes` when smaller (K3, K16). The scan reads x86 kernels only (the header is little-endian and 4.4 is x86-64), so the bound is 4096. A port to another architecture takes its bound from K16.
- Candidates per window: at most `MaxMatchesPerChunk`. Past it, the rest of the window is recorded as one damaged range.

## 9. Acceptance

- A note in the kernel's layout is found, and its entries read in the formats of 4.3.
- A name with a wrong header, a name in the first 12 bytes, and a descriptor without `OSRELEASE=` are skipped with no damage.
- A release holding a control byte, a byte above 0x7e and DEL keeps them escaped as `\xNN`; a `\` in the release is written `\\`, so a release holding the text `\x01` reads apart from the byte 0x01; a release of 69 such bytes is cut by bytes, not by escaped text; a NUL in the release is damage.
- A non-text byte outside the release line, an empty line, a line with no `=`, a malformed value, a value past 64 bits, and a descriptor larger than its `PAGESIZE` each make a damaged copy at the note's offset.
- An 80-byte line is read as one cut line of 79 bytes and the following line. A descriptor that ends without `\n` ends in a cut line.
- A key held twice keeps its first value.
- A name across a window boundary is found once. The result does not depend on the scan step.
- An unreadable window is recorded, and copies elsewhere are still found. Only damaged copies make the scan an error that unwraps to `*VMCoreInfoDamageError`.
- Layout: the DTB, shift and flags of a table built from K10 to K12, a negative `phys_base`, and one failure case for each step of 4.4.
- Depth (4.5): without the flag, 4-level and 5-level tables give their depth with S04's evidence, and undecided tables give 4-level and the error; with the flag no tables are read. `FindKernel` on a 5-level fixture without the flag walks five levels with no diagnostic.
- On the captures (`symbolloadfacts`, 2026-11-12): mem3_ubuntu24 holds three copies, each with a 3,305-byte descriptor, mem4_fedora40 one of 3,259 bytes; all are under the bound of 4096 and carry `PAGESIZE=4096`. Both releases are printable, so their Text is unchanged. With the flag removed, S04 on each DTB decides 4-level (mem3: 70 upper-half root entries, 81 tables, 1,023 large pages; mem4: 70, 83, 994; the 5-level reading is refuted by a 2-MByte page read as a 1-GByte page), the depth the flag gives.
- Fuzz targets over the scan (any bytes, any step) and the parser: no panic; equal results for every step; every kept table opens with `OSRELEASE` and holds each key once; every entry's Text is printable ASCII; the release's Text reads back to the release's bytes; every whole numeric value round-trips through its format.

## 10. Open points

- `NUMBER(pgtable_l5_enabled)` is absent before v4.17. A 5-level kernel from v4.14 to v4.16 is read as 4-level. A session could confirm the depth with S04 on the DTB. Owner decision 2026-11-12: confirm depth with paging detection on the DTB. Done: `ConfirmDepth` (4.4 step 8, 4.5), called by `linuxkernel.FindKernel`, which records an undecided detection as a diagnostic; tests in `symbols/autoload/vmcoreinfo_note_test.go` and `symbols/linuxkernel/linuxkernel_test.go`; both captures measured (section 9). No pre-4.17 capture exists to check a real 5-level kernel.
- The release string `OSRELEASE` is assumed to be printable ASCII; nothing in the kernel guarantees this. Owner decision 2026-11-12: escape non-printable bytes in output. Done: the release line accepts any byte but NUL, and its Text writes bytes outside 0x20 to 0x7e as `\xNN` (K17, 4.2 step 1, section 5); `symbols/autoload/vmcoreinfo_note.go` and its tests. Owner decision 2026-11-12 (follow-up D1): escape a backslash as `\\`. Done: 4.2 step 1 and section 9 state it; `escapeRelease` in `symbols/autoload/vmcoreinfo_note.go` doubles it, `TestTheReleaseKeepsItsUnprintableBytesEscaped` checks a release holding the text `\x01` and a `\`, and `FuzzParseNoteTable` checks that every release's Text reads back to its bytes (30 s). `linuxkernel` compares the banner's release with each backslash doubled (S75 4.10 step 3; `TestABackslashInTheReleaseStillMatchesTheBanner`). Both captures' releases hold no `\`, so their Text is unchanged.
- The descriptor bound of 256 KiB is the project's assumption about the largest `PAGE_SIZE`, not checked against every architecture. Owner decision 2026-11-12: derive from architecture. Done: the bound is x86's `PAGE_SIZE`, 4096 (K16, section 8), and each architecture's largest page size at v6.17 is recorded in K16 for a later port; `symbols/autoload/vmcoreinfo_note.go` and its tests; the captures' descriptors measured under it (section 9).
- Big-endian kernels are out of scope: the header is read little-endian.
- 32-bit x86 tables are found and read, but give no layout: they carry no `phys_base`, and `PAGE_OFFSET` is not in the table.
- `NUMBER(sme_mask)` is not checked to be a single bit; the AMD APM was not consulted.

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Confirm depth with paging detection on the DTB |
| O2 | Escape non-printable bytes in output (overrides the recommendation) |
| O3 | Derive from architecture (overrides the recommendation) |
| O4 | Keep out of scope |
| O5 | Read and give no layout |
| O6 | Defer to v0.2.0 |

## 11. Provenance

Sources: as cited in section 3, fetched from git.kernel.org on 2026-11-11 (K16 and K17 on 2026-11-12), the System V ABI gABI chapter 5 (note section), and the project's measurements. Author: the project.
