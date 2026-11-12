# S75: Symbol loading: Windows kernel identification, PDB tables, Linux banner, kallsyms and BTF

Version 1, 2026-11-12.

## 1. Purpose

Every structure a tool reads is placed by a symbol table, and a table for the wrong kernel gives plausible, wrong answers everywhere. An examiner opening a capture needs the session to name the running kernel from the capture itself and to load or build the table for exactly that build.

For Windows this specification defines how the running kernel's PDB build is found (from a crash dump header, from the processor start page, or by scanning for the kernel's CodeView record), how a downloaded PDB becomes a table declaration, and when a cached table may stand for a build. For Linux it defines how the kernel's banner is read and recognised, how the kernel's own symbol table (kallsyms) is decoded from the addresses VMCOREINFO publishes, how the kernel's BTF blob is parsed, and how `symbols/linuxkernel` joins these into the session's kernel and its table.

The PDB streams, the processor start page and the symbol-server path are S32; the VMCOREINFO note and its layout keys are S05; turning BTF and kallsyms into a table is S59; naming addresses with kallsyms is S38.

## 2. Inputs

| Input | Type | Used by |
|---|---|---|
| Physical memory | `memory.MemoryReader`, optionally with `CrashHeader() memory.CrashDumpHeader` | Windows identification, banner scan, VMCOREINFO scan |
| Kernel address space | `memory.MemoryReader` (a `layers.VirtualMemoryLayer`) | kallsyms, BTF, `linux_banner` |
| VMCOREINFO | `autoload.VMCoreInfo` (S05) | kallsyms seeds, `OSRELEASE`, `SYMBOL()` checks |
| PDB file | bytes from the symbol server (S32) | the declaration |
| Cached table | a `.vsym` file (S32 4.6) | the cache check |
| Limits | `limits.Limits` | `MaxKernelImageBytes`, `MaxNameBytes`, `MaxTableEntries`, `MaxRecursionDepth`, `PTECacheEntries` (section 8) |

No tool options; these are library entry points the session calls.

## 3. Facts from the sources

Linux tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17, fetched from git.kernel.org on 2026-11-12. "All tags" means all five. `kernel/vmcore_info.c` exists from v6.14, `kernel/crash_core.c` before; `kernel/kallsyms_internal.h` and `init/version-timestamp.c` from v6.1; `Documentation/bpf/btf.rst` from v6.1. Windows sources: Microsoft Learn, "PE Format" (revision 2026-09-10, accessed 2026-11-12), "Maximum Path Length Limitation" (accessed 2026-11-12); the captures' kernel PDB types through the project's tables; S32 and S55 for facts they already state.

### Windows

| # | Fact | Source |
|---|---|---|
| W1 | At file offset 0x3C the MS-DOS stub holds the offset of the `PE\0\0` signature; the 20-byte COFF header follows it, then the optional header with magic 0x10B (PE32) or 0x20B (PE32+). The data directories start 96 (PE32) or 112 (PE32+) bytes into the optional header; Debug is entry 6 (offset 144 or 160). | PE Format: Signature, Optional Header Data Directories |
| W2 | A debug directory is an array of 28-byte entries: `Characteristics` 0, `TimeDateStamp` 4, `MajorVersion` 8, `MinorVersion` 10, `Type` 12, `SizeOfData` 16, `AddressOfRawData` 20 ("the address of the debug data when loaded, relative to the image base"), `PointerToRawData` 24 ("the file pointer"). `IMAGE_DEBUG_TYPE_CODEVIEW` is 2. | PE Format: Debug Directory (Image Only), Debug Type |
| W3 | A CodeView record is `RSDS`, the 16-byte GUID, the 32-bit age and the PDB path; the GUID and age are the PDB's (DBI age). | S32 F20, M5 |
| W4 | `MAX_PATH` is 260 characters including the terminating NUL. | Maximum Path Length Limitation |
| W5 | The kernel ships as `ntoskrnl`, `ntkrnlmp`, `ntkrnlpa` or `ntkrpamp`, each with a PDB of that name. | S32 4.6 step 6 |
| W6 | `_LIST_ENTRY.Flink` is at 0; `_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks` at 0 and `DllBase` at 0x30, as is `_LDR_DATA_TABLE_ENTRY.DllBase`, in the ntkrnlmp PDBs of builds 14393, 19045 and 26100 (M25). The first entry of `PsLoadedModuleList` is `ntoskrnl.exe` at the kernel base on all five captures. | ntkrnlmp PDB types (M25); S55 T1, T3, M1 |
| W7 | With 4-level paging CR3 bits 51:12 are the PML4's physical address; a PDPTE or PDE with PS set maps a 1 GiB or 2 MiB page. | Intel SDM Vol. 3A, 4-level paging (the `layers` walker, S04) |

### Linux

| # | Fact | Source |
|---|---|---|
| L1 | VMCOREINFO carries `SYMBOL(_stext)` at all tags. With `CONFIG_KALLSYMS` it carries `SYMBOL(kallsyms_names)`, `kallsyms_num_syms`, `kallsyms_token_table` and `kallsyms_token_index` from v6.1, plus `kallsyms_offsets` and `kallsyms_relative_base` (v6.1 and v6.4 only with `CONFIG_KALLSYMS_BASE_RELATIVE`, else `kallsyms_addresses`; unconditional at v6.14 and v6.17). v4.19 carries no kallsyms keys. | `kernel/crash_core.c` v4.19, v6.1, v6.4; `kernel/vmcore_info.c` v6.14, v6.17 |
| L2 | `kallsyms_num_syms` is written as `PTR` (8 bytes on 64-bit) at v4.19 and `.long` from v6.1; `kallsyms_relative_base` is `PTR`. `kallsyms_token_index` is 256 `.short` offsets into `kallsyms_token_table`, which is 256 NUL-terminated strings. `kallsyms_offsets` is one `.long` per symbol. | `scripts/kallsyms.c` `write_src`, all tags; `kernel/kallsyms_internal.h` v6.1 to v6.17 |
| L3 | A `kallsyms_names` record is its token count, then that many token indexes. At v4.19 the count is one byte. From v6.1 a count up to 0x7F is one byte and a larger one two, `(len & 0x7F) | 0x80` then `(len >> 7) & 0x7F`; counts above 0x3FFF and zero are build errors. `kallsyms_expand_symbol` concatenates the tokens; the first character is the type letter. | `scripts/kallsyms.c` `write_src`; `kernel/kallsyms.c` `kallsyms_expand_symbol`; all tags |
| L4 | A name is shorter than `KSYM_NAME_LEN`, 128 at v4.19 and 512 from v6.1, and the type letter is ASCII. | `scripts/kallsyms.c` `read_symbol`; `include/linux/kallsyms.h`; all tags |
| L5 | `kallsyms_sym_address(i)` is `kallsyms_relative_base + (u32)kallsyms_offsets[i]`; up to v6.14, with `CONFIG_KALLSYMS_ABSOLUTE_PERCPU`, a non-negative offset is the address itself and a negative one is `kallsyms_relative_base - 1 - offset`. v6.17 has only the first form. The writer emits the absolute form for per-CPU symbols and the negative form for all others. | `kernel/kallsyms.c`, `scripts/kallsyms.c`, all tags |
| L6 | The table is sorted by address before it is written, and `get_symbol_pos` binary-searches it. A symbol's size is the distance to the next greater address; after the last group, `_einittext` for an address in init text, else `_end` with `CONFIG_KALLSYMS_ALL`, else `_etext`. | `scripts/kallsyms.c` `sort_symbols`; `kernel/kallsyms.c` `get_symbol_pos`, all tags |
| L7 | `linux_banner` is `"Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@" LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION "\n"`, a `const char[]`, so it ends `"\n\0"`. `linux_proc_banner`, `"%s version %s (" … ") %s\n"`, is defined in `init/version.c` at all tags. | `init/version.c` v4.19; `init/version-timestamp.c` v6.1 to v6.17 |
| L8 | From v6.1 `init/version.c` declares `linux_banner` `__weak` and includes `version-timestamp.c` ("compiled with __weak first, and without __weak later"); the link step adds `init/version-timestamp.o` built last. Two banners then lie in read-only data: the weak one beside `linux_proc_banner`, and the strong one, which `linux_banner` names. | `init/version.c` v6.1, v6.17; `scripts/link-vmlinux.sh` v6.17 |
| L9 | `KERNELVERSION` is `$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)`, and the release is it followed by the local version; it starts with a digit and holds a dot. | top-level `Makefile`, v4.19, v6.17 |
| L10 | The kernel image is linked at `__START_KERNEL_map` 0xFFFFFFFF80000000 and must end below `KERNEL_IMAGE_SIZE`, 1 GiB with `CONFIG_RANDOMIZE_BASE` (512 MiB without); modules follow. | `arch/x86/include/asm/page_64_types.h`, all tags; `Documentation/arch/x86/x86_64/mm.rst` v6.17 |
| L11 | vmlinux BTF is `__start_BTF` to `__stop_BTF`; `btf_parse_vmlinux` parses exactly that span. | `kernel/bpf/btf.c` v6.1 to v6.17; S59 B1 |
| L12 | `struct btf_header` is `magic` (0xEB9F, u16), `version` (1), `flags`, `hdr_len`, `type_off`, `type_len`, `str_off`, `str_len`; offsets are from the end of the header. The magic "can be used to test whether BTF is generated for big- or little-endian target". | `include/uapi/linux/btf.h`, `btf.rst` 2, v6.1 to v6.17 |
| L13 | `btf_parse_hdr` refuses data shorter than `hdr_len`, a non-zero byte past the known header, a wrong magic or version, and non-zero flags. `btf_check_sec_info` sorts the two sections and refuses a gap, an overlap or bytes past them, so they fill the data after the header exactly. `btf_parse_str_sec` wants the string section at the end, at least 1 byte, at most `BTF_MAX_NAME_OFFSET + 1` (0x1000000), its first and last bytes NUL. `btf_parse_type_sec` wants `type_off` 4-aligned and `type_len` non-zero. | `kernel/bpf/btf.c` v6.1, v6.17 |
| L14 | `btf_check_meta`: a record is 12 bytes; `info` bits outside 0x9F00FFFF are refused; kinds 1 to 19 (`BTF_KIND_MAX`, v6.1 on); `name_off` must lie in the string section. Trailing data: INT 4 bytes, ARRAY 12, STRUCT and UNION 12 per member, ENUM 8 per constant, FUNC_PROTO 8 per parameter, VAR 4, DATASEC 12 per variable, DECL_TAG 4, ENUM64 12 per constant, others none. A member's offset word with `kind_flag` is `bitfield_size << 24 | bit_offset`. FUNC's `vlen` is its linkage. | `btf.h`; `btf.rst` 2.2; `btf_check_meta` and the per-kind `check_meta`, v6.1, v6.17 |
| L15 | INT data outside 0x0FFFFFFF is refused; `BTF_INT_OFFSET + BTF_INT_BITS` is at most 128 and fits `size` bytes; the encoding is 0 or one of SIGNED 1, CHAR 2, BOOL 4. ARRAY and FWD records have 0 in their size/type word. `BTF_MAX_TYPE` is 0xFFFFF. | `btf_int_check_meta`, `btf_array_check_meta`, `btf_fwd_check_meta`; `btf.h`; v6.1, v6.17 |

### Measurements

M1 to M25 measured with `symbolloadfacts`, 2026-11-12. Linux: `-os linux` on mem3_ubuntu24 (6.17.0-35-generic) and mem4_fedora40 (6.14.5-100.fc40.x86_64). Windows: `-os windows` on mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 and mem7_server2025 (26100, crash dumps).

| # | Measurement | mem3_ubuntu24 | mem4_fedora40 |
|---|---|---|---|
| M1 | VMCOREINFO notes found, damaged; scan time | 3, 0; 3.4 s | 1, 0; 2.8 s |
| M2 | `kallsyms_num_syms` read as u32 and as u64 | 223671, 223671 | 256744, 256744 |
| M3 | Rule chosen by `_stext`; `_stext` offset; relative base | relative; 0; 0xffffffff92400000 | absolute per-CPU; 0xffffffff (−1); 0xffffffff89000000 |
| M4 | Order inversions under the chosen rule, under the other | 0, 0 | 0, 251598 |
| M5 | Records with a two-byte count; longest expansion (letter and name); empty names | 0; 188; 0 | 2; 257; 0 |
| M6 | Tokens: empty, one byte, longest | 0, 64, 47 | 0, 64, 23 |
| M7 | Type letters | B 861, D 1372, R 66, T 76004, V 1, W 372, b 3682, d 21077, r 17871, t 102365 | A 414, B 3480, D 1201, R 73, T 80016, V 1, W 366, b 3681, d 47775, r 16960, t 102777 |
| M8 | Symbols of size 0; distinct names; global by letter | 1; 212684; 78676 | 2; 219461; 85551 |
| M9 | Decode time | 98 ms | 106 ms |
| M10 | BTF span and bytes; header | 0xffffffff9434f000 to 0xffffffff949e7cc7, 6917319; 0xEB9F little-endian, version 1, flags 0, `hdr_len` 24, types 0+4170820, strings 4170820+2746475 | 0xffffffff8b0ddbd0 to 0xffffffff8b71402b, 6513755; same magic, version, flags and `hdr_len`, types 0+3791816, strings 3791816+2721915 |
| M11 | BTF types (with `kind_flag`); parse time | 165529 (668); 118 ms | 149710 (651); 122 ms |
| M12 | Banners ending `"\n\0"`; followed by `linux_proc_banner`; gap to it; template's `linux_proc_banner` address | 3; 1 at 0x720000e0; 7 bytes; 0xffffffff93a001e0 | 3; 1 at 0x53600960; 10 bytes; 0xffffffff8a600a20 |
| M13 | The banner beside the template | build `#35~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC` with no date (L8) | `# SMP PREEMPT_DYNAMIC` with no number or date |
| M14 | `linux_banner` from kallsyms: address (physical); release; equals OSRELEASE; among the scanned banners, followed by the template | 0xffffffff93bc6660 (0x721c6660); 6.17.0-35-generic; yes; yes, no | 0xffffffff8a8d93a0 (0x538d93a0); 6.14.5-100.fc40.x86_64; yes; yes, no |
| M15 | `SYMBOL()` values in the image window (L10), outside | 15; `vmemmap`, `mem_section` | 15; `vmemmap`, `mem_section` |
| M16 | Session: VMCOREINFO symbols the table agrees with; open time | 13; 2.3 s | 13; 3.0 s |

| # | Measurement | mem1 | mem2 | mem5 | mem6 | mem7 |
|---|---|---|---|---|---|---|
| M17 | Crash dump header: `DirectoryTableBase`, `PsLoadedModuleList` | none | none | none | 0x7d5000, 0xfffff804a7a94770 | 0x7d5000, 0xfffff801a2744770 |
| M18 | Identification: method; base; DTB; time | start page; 0xfffff8037d130000; 0x7d5000; 839 ms | start page; 0xfffff80563400000; 0x7d4000; 488 ms | start page; 0xfffff80145019000; 0x7d2000; 966 ms | header; 0xfffff804a6ba0000; 0x7d5000; 2 ms | header; 0xfffff801a1850000; 0x7d5000; 2 ms |
| M19 | Build | ntkrnlmp 0D960CE1…-1 | ntkrnlmp F57E740B…-1 | ntkrnlmp 3DFC5F72…-1 | ntkrnlmp 953A8DE8…-1 | ntkrnlmp 953A8DE8…-1 |
| M20 | Without the header (start page): same build, base and DTB | yes, 128 ms | yes, 54 ms | yes, 93 ms | yes, 352 ms | yes, 375 ms |
| M21 | Scan: kernel records; builds; declared records; time | 6; 1; 1; 21.4 s | 2; 2; 1; 8.5 s | 1; 1; 0; 6.5 s | 3; 3; 2; 2.6 s | 2; 2; 1; 2.6 s |
| M22 | Scan selection | the build | the build (provisional) | the build | refused: 2 builds declared | the build (provisional) |
| M23 | Declared kernel records: distance from header = `AddressOfRawData`; = `PointerToRawData` | 0x5a39c; yes; yes | 0x41100; yes; no (0x40900) | none | 0x5783c yes, yes; and an `ntoskrnl.pdb` (BA0E7292…) 0xd814 yes, yes | 0x5783c; yes; yes |
| M24 | `PsLoadedModuleList` = kernel base + its RVA in the table; = the header's | 0xfffff8037e025290; – | 0xfffff8056402a420; – | 0xfffff8014531e060; – | yes; yes | yes; yes |
| M25 | Kernel table: `_LIST_ENTRY.Flink`, `_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks`, `_KLDR_DATA_TABLE_ENTRY.DllBase`, `_LDR_DATA_TABLE_ENTRY.DllBase` | 0, 0, 0x30, 0x30 | same | same | same | same |

## 4. Algorithm

### 4.1 Windows: identification order (`IdentifyKernel`, `IdentifyRunningKernel`)

1. Crash dump header (4.2), when the reader has one.
2. Processor start page (S32 4.7).
3. Only for `IdentifyKernel`: the CodeView scan (4.3) and selection (4.4). The scan finds the builds an image holds, not the one running, so it comes last (M21: copies of other builds on four captures).
4. `IdentifyRunningKernel` returns no identity and no error when neither 1 nor 2 applies (no header, no start page); when one applied and failed, it returns that failure. A failure of 1 or 2 is carried in the final error when later steps fail too.

### 4.2 Crash dump header

1. Take `DirectoryTableBase` and `PsLoadedModuleList` from the header (M17); either zero is a failure.
2. Read the kernel space through the 4-level tables at `DirectoryTableBase` (W7).
3. Read `Flink` at the list head (W6). Zero, or the head itself, is an empty list.
4. Read `DllBase` at `Flink + 0x30` (W6): the first entry is the kernel (S55 M1).
5. Read the image's CodeView records at that base (W1 to W3, through `layers.ImageCodeViews`) and take the first that names a PDB. It must name a kernel PDB (W5). The identity is that build, the base and `DirectoryTableBase`.

### 4.3 CodeView scan (`ScanKernelCandidates`)

1. Scan the readable physical ranges in 4 MiB windows overlapping by 285 bytes, the longest record (24 + 260 + 1, W3, W4). A record is kept only by the window it starts in.
2. At each `RSDS`, the path must have its NUL within 260 bytes (W4) and its base name, cut after the last `\` or `/`, must be a kernel PDB name (W5). The candidate is the GUID, age and name, and the record's physical offset.
3. For each candidate walk back from the record's page, page by page, at most `MaxKernelImageBytes`. Unreadable pages and pages that are not an image header are passed over. The first page with `MZ` and a `PE\0\0` signature inside the page (W1) is the record's image: `ImageBase`. Only it is asked; walking past it would in time meet a header that names the build by chance.
4. `Corroborated` is set when that header's debug directory, read at the RVAs it gives (W2), yields a CodeView record with the candidate's name, GUID and age. A kernel file held in the page cache is laid out by file offset, so its header reads the record at the wrong place unless the two offsets are equal (M23).
5. No candidate found and a window did not read: error with the first read failure.

### 4.4 Selection (`SelectKernel`)

1. No candidates: `errNoKernelRecord`.
2. One build, however many copies: that build, not provisional.
3. Several builds: the declared candidates. One build among them: that build, provisional, because one image can declare another build too (M23, mem6), and the session confirms it against the mapped kernel. None: `errKernelUndeclared`. Several: `errKernelAmbiguous`. Both list each build, its first offset (a declared one's when there is one), copy count and whether declared, in offset order.

### 4.5 PDB to declaration (`pdbToDeclaration`)

1. Read the MSF container and the type, debug-information and PDB information streams (S32 4.1, 4.2); a missing stream is refused.
2. The GUID from stream 1 and the age from the DBI header must equal the build asked for, letter case aside (S32 4.2 step 1). A server or proxy answering with another build's PDB would otherwise be cached as this build.
3. The machine gives the pointer width (S32 4.2 step 5); an unknown machine is refused. No section headers, or no symbol with a place, is refused: such a table could not place anything.
4. Types, enumerations and addresses come from S32 4.3 and 4.4. A type chain past `MaxRecursionDepth` refuses the PDB (S32 4.3 step 7).
5. Assemble: scalars are the fixed scalar set plus `pointer` of the machine's width; records with no members are left out (they place nothing); every name becomes UTF-8 by replacing each byte that is not UTF-8 with U+FFFD (the table format is UTF-8, `symbols/FORMAT.md`). Lists are built in name order; two names that become one after the repair keep one entry, the later in name order taking the earlier's place, so the result does not depend on map order. The output is the one `BuilderVersion` 10 tables hold (S32 section 9 table identity).

### 4.6 Download and cache acceptance

1. A response whose declared length exceeds `MaxDownload` is refused before it is read; otherwise at most `MaxDownload + 1` bytes are read and more than `MaxDownload` is refused.
2. A cached table is used only when it reads, it names this build (or no build), and it holds at least one symbol; a table naming another build or holding none would answer for this build with wrong or no addresses.

### 4.7 Linux banner (`ScanLinuxBanners`, `LinuxKernelBanner`, `ReadLinuxBanner`)

1. A banner is `Linux version ` followed by printable ASCII (0x20 to 0x7E) up to `"\n\0"`, within `MaxNameBytes` (L7). The terminator separates the kernel's string from log and journal text; the printable rule refuses a copy with binary spliced in (M12: all six banners on the captures are printable).
2. The release is the word after the prefix; it must start with a digit and contain a dot (L9).
3. Scan windows of 4 MiB overlap by `MaxNameBytes` + 31 + the template prefix, so a banner and what follows it are seen whole in the window it starts in, which alone keeps it.
4. `InKernelRodata`: the template prefix `%s version %s (` starts within 31 bytes after the terminator. The template is at a 32-byte boundary on both captures (M12), so padding before it is under 32 bytes.
5. `LinuxKernelBanner`: the one banner followed by the template; none or several is an error naming up to eight banners. From v6.1 that banner is the weak copy (L8, M13): its release is the running kernel's, its text is not `linux_banner`'s (M14).
6. `ReadLinuxBanner(space, address)`: read page by page from `address` until a NUL or `MaxNameBytes + 1` bytes; the bytes must be a banner (steps 1, 2). The result runs through the NUL, as the char array holds it and as a table's `linux_banner` constant stores it.

### 4.8 kallsyms (`SeedsFromVMCoreInfo`, `Decode`)

1. Seeds: the `SYMBOL()` values of `kallsyms_num_syms`, `kallsyms_names`, `kallsyms_token_table`, `kallsyms_token_index`, `kallsyms_offsets`, `kallsyms_relative_base` and `_stext` (L1). A missing, cut or non-64-bit value refuses the note, naming every missing key.
2. Count: 4 bytes little-endian at `kallsyms_num_syms` (L2: both widths give the same value below 2^32, M2); it must be 1 to `MaxTableEntries`.
3. Base: 8 bytes at `kallsyms_relative_base`.
4. Tokens: the 256 16-bit offsets, and each token read up to its NUL within `MaxNameBytes`, a page at a time so a token ending before an unmapped page reads (L2).
5. Offsets: 4 bytes per symbol, read whole.
6. Names: read the records in order (L3): one count byte, a second when bit 7 is set (low seven bits first), then the token indexes. The expansion is the tokens joined; a longer expansion than `MaxNameBytes` is refused (L4: at most 512). The first byte is the type letter, the rest the name; a record of no tokens gives an empty name and letter 0. Each record's place follows from every record before it, so a read failure ends the decode.
7. Rule: the record named `_stext` decides. Its address under the relative rule and under the absolute per-CPU rule (L5) is compared with `SYMBOL(_stext)`; exactly one must match. None or both, or no `_stext`, refuses the table: nothing else in the table states the rule (M4: on mem3 both rules give an ordered table).
8. Addresses by the rule; the table must be in non-decreasing address order (L6, M4), or it was misread and is refused.
9. Sizes (L6): the next greater address after the symbol, found in one backward pass; after the last group, `_einittext` when the address lies in [`_sinittext`, `_einittext`), else `_end` when the table holds it (only `CONFIG_KALLSYMS_ALL` tables do), else `_etext`. A size that is zero, negative or above 2^63 − 1 is 0, "not established" (a per-CPU symbol whose next address is kernel text, M8).
10. `Global` is an upper-case letter or `u`, `v`, `w` (S59 K3; M7 shows the letters used).

### 4.9 BTF (`Parse`, `ReadKernel`)

1. Header (L12, L13): at least 24 bytes; magic 0xEB9F read little- or big-endian fixes the byte order; version 1 and flags 0; `hdr_len` at least 24 (a shorter one leaves `str_len` zero, which L13 refuses) and within the data; bytes from 24 to `hdr_len` zero.
2. Sections (L13): `type_off` 0 and `type_len` non-zero; `str_off` equal to `type_len`; strings ending the data. The string section is 1 to 0x1000000 bytes with NUL first and last.
3. Records in order from id 1 (L14): the 12-byte head; `info` within 0x9F00FFFF; kind 1 to 19; name offset inside the strings; the kind's trailing data present. INT data per L15; ARRAY and FWD with a zero size/type word. Size is kept for INT, STRUCT, UNION, ENUM, ENUM64, DATASEC and FLOAT, the referenced type for the others. Members split their offset word when `kind_flag` is set. ENUM values are the 32-bit pattern zero-extended; ENUM64 values are `lo | hi << 32`. FUNC's linkage is its `vlen`, VAR's its data word, DECL_TAG's component its signed data word. More than `BTF_MAX_TYPE` types is refused.
4. References: every type id a record names (its type, array element and index, members, parameters, section variables) must be at most the last id.
5. `ReadKernel(space, start, stop)`: the span must hold 1 to `MaxKernelImageBytes` bytes (M10: 6.9 MB at most); it is read whole and parsed. L13 makes the span exact: one byte short or long fails the section rule.

### 4.10 The Linux kernel (`symbols/linuxkernel`)

1. `FindKernel`: scan for VMCOREINFO (S05). In scan order, the first note that gives a layout (`KernelLayout`, S05) and seeds (4.8 step 1) is the kernel. Damaged notes become diagnostics and `DamageError`; with no usable note the error lists each note's reason and, when there were damaged notes, wraps the damage error.
2. The kernel space walks the tables at the layout's DTB, five levels when VMCOREINFO says so or, when it lacks `NUMBER(pgtable_l5_enabled)`, when S04 on the DTB decides 5-level (S05 4.5, owner decision 2026-11-12 on S05; an undecided detection is a diagnostic of the kernel), frames cut to the kernel's physical width and the memory-encryption bit removed (S05, S04). A cache of `PTECacheEntries` is used for immutable captures.
3. `Declaration`: decode kallsyms (4.8); `__start_BTF`, `__stop_BTF` and `linux_banner` must each have one address; parse the BTF span (4.9); read `linux_banner` (4.7 step 6); its release, with each backslash doubled as S05 4.2 step 1 writes it, must equal `OSRELEASE`'s Text. Then S59 assembles the table with the KASLR shift and pointer size 8 (S05 accepts only x86-64).
4. `InKernelImage`: [0xFFFFFFFF80000000, 0xFFFFFFFFC0000000) (L10). Only symbols there move with the KASLR shift; `SYMBOL()` values outside are stored pointers (M15).
5. `CheckTable(table, banner)`: the banner must be non-empty; the table's `linux_banner` must read, through the kernel space, the same bytes (NUL aside); each `SYMBOL()` value in the image window that the table holds must equal the table's address. It returns the count that agree (M16).

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Crash header fields non-zero; list non-empty; first entry's image names a kernel PDB | W5, W6, S55 M1 | Header path fails with its reason; later paths tried |
| RSDS path NUL within 260 bytes; base name a kernel PDB | W4, W5 | Not a candidate |
| Only the nearest image header within `MaxKernelImageBytes` is asked | 4.3 step 3 | Not declared |
| Declared means the header's record, read at its RVA, is this build | W2, M23 | Not declared |
| One build, or one declared build | 4.4 | `errNoKernelRecord`, `errKernelUndeclared`, `errKernelAmbiguous` |
| A PDB is the build asked for, of a known machine, with sections and placed symbols | S32 4.2 | `errPDBUnusable` |
| A cached table names this build and holds a symbol | 4.6 | `errCacheMismatch`; rebuilt or refused offline (S32) |
| A download within `MaxDownload` | 4.6 | `errBodyTooLarge` |
| A banner is printable ASCII ending `"\n\0"` within `MaxNameBytes` with a numeric release | L7, L9, M12 | Not a banner; `ErrNoLinuxBanner` from `ReadLinuxBanner` |
| kallsyms count 1 to `MaxTableEntries` | L2, Limits | `ErrCount` |
| Every table read succeeds | L3 | `ErrUnreadable` |
| An expansion within `MaxNameBytes` | L4 | `ErrRecord` |
| `_stext` decides the rule | L1, L5 | `ErrAddressRule` |
| Addresses in order | L6, M4 | `ErrOrder` |
| BTF header, sections, records and references per L12 to L15 | the kernel's own parser | `ErrHeader`, `ErrSections`, `ErrStrings`, `ErrRecord`, `ErrReference` |
| BTF span 1 to `MaxKernelImageBytes`, read whole | L11, M10 | `ErrKernelSpan` |
| One address for `__start_BTF`, `__stop_BTF`, `linux_banner` | L11, L8 | `linuxkernel: kallsyms holds no …` / `… at both …` |
| Banner release equals `OSRELEASE` | L7, S05 | Declaration refused |
| Table banner and in-window `SYMBOL()` values agree with the image | L10, M15 | `CheckTable` error |

## 6. Failure modes

| Case | Result |
|---|---|
| Crash header leads nowhere | `errNoModuleList` or `errNotKernelPDB`, wrapped as `autoload: the crash dump header's loaded module list did not lead to a kernel: …` |
| Start page leads nowhere | S32 errors, wrapped as `autoload: the processor start page did not lead to a kernel: …` |
| Scan finds no record and a window did not read | `autoload: no kernel pdb record in the image in the readable part of the N-byte image: …` with the read error |
| Scan finds nothing, or cannot choose | `errNoKernelRecord`, `errKernelUndeclared`, `errKernelAmbiguous`; earlier path failures appended |
| PDB unusable | `errPDBUnusable: …` (`…, not the one requested` for another build; `MaxRecursionDepth (N)` for a cycle) |
| Banner absent or ambiguous | `ErrNoLinuxBanner`, `ErrLinuxBannerAmbiguous` |
| VMCOREINFO lacks kallsyms keys (v4.19, or a kernel without `CONFIG_KALLSYMS`) | `ErrNoSeeds`; `FindKernel` reports the note's reason |
| kallsyms unreadable or inconsistent | `ErrCount`, `ErrUnreadable`, `ErrRecord`, `ErrAddressRule`, `ErrOrder`, with the symbol index or address |
| BTF malformed or span wrong | the `btf` sentinels with the offending value |
| No VMCOREINFO | `linuxkernel.ErrNoVMCoreInfo` |
| Table without banner | `linuxkernel.ErrNoBanner` |
| Limits hit | the sentinel of the step, naming the limit |

Strict mode does not change these: every failure here refuses the identification or table, and only damaged VMCOREINFO copies are reported without failing (`DamageError` lets the session refuse them in strict mode, S05).

## 7. Result schema

- `KernelIdentity{Fingerprint, Method, Base, DTB, Provisional}`. `Method` is one of `MethodCrashDumpHeader` ("crash dump header's loaded module list"), `MethodLowStub` ("processor start page"), `MethodScan` ("kernel codeview record scan"). `Base` and `DTB` are 0 for the scan. `Provisional` only from 4.4 step 3.
- `KernelCandidate{Fingerprint, Offset, ImageBase, Corroborated}`: physical offsets; `ImageBase` 0 when no header was found.
- `LinuxBanner{Raw, Release, Offset, InKernelRodata}`: `Raw` without `"\n\0"`; `Offset` physical.
- `kallsyms.Table{Symbols, Rule, RelativeBase}`, symbols in table order; `Symbol{Name, Type, Address, Size, EncodedLength, Offset}`: `Size` in bytes, 0 when not established; `EncodedLength` is the token count; `Offset` the stored 32-bit value.
- `btf.Spec{ByteOrder, Types}`, `Types[0]` void; `Type` fields per 4.9 step 3.
- `linuxkernel.Kernel{VMCoreInfo, Layout, Space, Seeds, Damaged, Diagnostics, Limits}`; `Declaration` returns `symbols.Declaration` and S59's `LinuxReport`.

## 8. Limits

| Limit | Applies to | Reason |
|---|---|---|
| `MaxKernelImageBytes` (64 MiB) | start-page and scan walk-back; BTF span | No measured kernel image or BTF approaches it (M10, M23); it bounds a walk from a stray record |
| `MaxNameBytes` (4096) | banner length; kallsyms token and expansion | `KSYM_NAME_LEN` is 512 (L4); M5 longest 257 |
| `MaxTableEntries` (2^22) | kallsyms count | M2: 256744 at most |
| `MaxRecursionDepth` | PDB type chains | S32 4.3 step 7 |
| `MaxDownload` | PDB download | S32 |
| `PTECacheEntries` | Linux kernel space | S04 |

Fixed values: 4 MiB scan windows (one read per window, like S05's scan); 285-byte record overlap (W3, W4); 31-byte template gap (M12); `BTF_MAX_TYPE` (L15).

## 9. Acceptance

1. Unit tests in `symbols/autoload` (`s75_identify_test.go`, `s75_banner_test.go`, `s75_declare_test.go`, fixtures `s75_fixture_test.go`): a declared and an undeclared record; only the nearest header asked; non-kernel names and paths without a NUL in 260 bytes skipped; scan results independent of the window step; the walk bound; a hole in a segmented capture and an unreadable capture; every selection outcome and the order of the listing; a crash dump identified from its module list, each way it leads nowhere with the scan taking over, and `IdentifyRunningKernel` with neither direct path; path base names with either separator; banners with and without the template, at the gap bound and one past it; non-terminated, non-printable and release-less text; one, two and no banners in read-only data; banner scan independent of the step; `ReadLinuxBanner` through the NUL, inside the text, past the image, past `MaxNameBytes`, at the top of the address space; download bounds; cache acceptance; UTF-8 repair and collisions; the S32 and start-page tests still pass with the new fixtures.
2. `symbols/kallsyms`: both rules; aliases sharing a size; `_stext` elsewhere, absent, and a base where both rules agree; out-of-order table; each last-group bound; two-byte counts; every unreadable table and the name bound; a token ending before an unmapped page; seeds with a cut and an absent key; the rule arithmetic and `Global`.
3. `symbols/btf`: every kind in both byte orders; every header, section and string refusal; a longer zero header; each record and reference refusal; `ReadKernel` spans; kind names.
4. `symbols/linuxkernel`: frame masking and the encryption bit; five-level walk; first usable note, damaged notes, missing layout, missing kallsyms keys, no note; the image window; a table built from the image alone and not cached as a file; every `Declaration` refusal; `CheckTable` agreement, missing and other banners, a moved symbol.
5. Fuzz targets, 30 s each on 2026-11-12, no failure: `FuzzKernelScanWindows` (125,270 executions), `FuzzBannerScanWindows` (54,992), `FuzzReadLinuxBanner` (4,237; each input is a whole image) (autoload), `FuzzDecode` (kallsyms; 333,791 executions), `FuzzParse` (btf; 9,023,203 executions).
6. On the captures (section 3, M1 to M24): both Linux kernels decode, parse and assemble, the table's banner matches and 13 `SYMBOL()` values agree on each; all five Windows captures identify the kernel, base and page-table root that S32 M9 found from the process list, by the header on the crash dumps and by the start page on the others, and the start page gives the same answer without the header on all five.
7. Real-image tests (`-tags realimage`, `s75_realimage_test.go`) compile; they read `LIBVAPOUR_TEST_WINDOWS_IMAGES` and `LIBVAPOUR_TEST_LINUX_IMAGES`, which existed before.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The scan alone refuses mem6 (M22): an `ntoskrnl.pdb` image (BA0E7292…, a 28-byte debug directory) is declared beside the running kernel. The header and start page identify mem6, so no session is affected. | Owner decision: keep refusing (default) or prefer `ntkrnlmp` |
| O2 | `Corroborated` now means "the nearest header's record, read at its RVA, is this build" rather than "the header's RVA equals this record's distance". On the captures the two agree (M23). | Owner decision (Q2 wording); default kept |
| O3 | `Method` texts changed to "crash dump header's loaded module list", "processor start page", "kernel codeview record scan"; the session prints them in diagnostics. | Owner decision (Q2) |
| O4 | `pdbBaseName` now cuts at `\` as well as `/` on every host; before, on a non-Windows host, a Windows path kept its directories and no kernel PDB matched. | None; recorded as a behaviour change |
| O5 | kallsyms sizes are no longer computed on addresses cut to 48 bits; a per-CPU symbol followed by kernel text now has size 0 (M8) where it had a large estimate. | Owner decision; default follows L6 |
| O6 | A table out of address order is now refused (`ErrOrder`); M4 shows none on the captures. | A capture of another kernel (Q7) |
| O7 | v4.19 and kernels without `CONFIG_KALLSYMS` (or v6.1 and v6.4 without `CONFIG_KALLSYMS_BASE_RELATIVE`, which publish `kallsyms_addresses`) cannot be decoded: VMCOREINFO does not locate an offsets table (L1). | A pre-v6.1 capture (Q7); a design for `kallsyms_addresses` |
| O8 | The 31-byte template gap rests on two kernels built with 32-byte data alignment (M12); a build aligning further would hide the template and `LinuxKernelBanner` would refuse. Only the real-image test uses it. | More captures |
| O9 | The PDB declaration writes members in name order, while `symbols/FORMAT.md` says source order; changing it needs a new `BuilderVersion` (S32). | Owner decision |
| O10 | The offsets of W6 have no source but the PDBs the identification is looking for; they rest on three builds (M25). | A capture of another build |
| O11 | New exports: `btf.ErrHeader`, `ErrSections`, `ErrStrings`, `ErrRecord`, `ErrReference`, `ErrKernelSpan`; `kallsyms.ErrNoSeeds`, `ErrCount`, `ErrUnreadable`, `ErrRecord`, `ErrAddressRule`, `ErrOrder`; `autoload.ErrNoLinuxBanner`, `ErrLinuxBannerAmbiguous`; `linuxkernel.ErrNoVMCoreInfo`, `ErrNoBanner`. `btf.Kind.String` of an unknown kind reads `kind N`; `AddressRule.String` of an unknown rule `address rule N`. | Owner decision (Q2) |
| O12 | 4.10 step 2 was edited by a later wave (one line), outside that wave's scope. | Owner decision 2026-11-12 (follow-up D3): accept. Done: the line stays as written. |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep refusing |
| O2 | New meaning |
| O3 | Accept |
| O4 | Yes |
| O5 | Size 0 per L6 |
| O6 | Refuse |
| O7 | Defer to v0.2.0 |
| O8 | Provide more captures |
| O9 | Keep name order |
| O10 | Provide captures |
| O11 | Accept |

## 11. Provenance

Author: the project, 2026-11-12. Sources: Linux kernel `kernel/kallsyms.c`, `kernel/kallsyms_internal.h`, `scripts/kallsyms.c`, `include/linux/kallsyms.h`, `kernel/crash_core.c`, `kernel/vmcore_info.c`, `init/version.c`, `init/version-timestamp.c`, `scripts/link-vmlinux.sh`, `Makefile`, `arch/x86/include/asm/page_64_types.h`, `Documentation/arch/x86/x86_64/mm.rst` (`Documentation/x86/x86_64/mm.txt` at v4.19), `include/uapi/linux/btf.h`, `Documentation/bpf/btf.rst`, `kernel/bpf/btf.c` and `include/asm-generic/vmlinux.lds.h` at v4.19, v6.1, v6.4, v6.14 and v6.17 (https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=<tag>, accessed 2026-11-12); Microsoft Learn "PE Format" (revision 2026-09-10) and "Maximum Path Length Limitation" (accessed 2026-11-12); Intel SDM Vol. 3A paging; the captures' ntkrnlmp PDB types through the project's tables; the project's specifications S04, S05, S32, S55 and S59; and the measurements of section 3. No other analysis tool's source, table or output was read; the files replaced were read only for their exported names and callers. Reviewer: pending.
