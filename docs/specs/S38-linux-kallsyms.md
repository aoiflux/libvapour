# S38: Linux kernel symbols in memory, module lookup through mod_tree, and in-memory ELF headers

Version 1, 2026-11-12.

## 1. Purpose

A kernel stack, a hooked function pointer or a callback table holds addresses, and an examiner needs to know which function each one is in: in the kernel image, in a loaded module, in a JIT-compiled BPF program, in the freed init code of a module, or in an ftrace trampoline. The kernel answers that question for itself (`kallsyms_lookup`) and lists its symbols in `/proc/kallsyms`. This specification defines how the same two answers are read from a memory image: naming one address, and listing the module, ftrace and BPF symbols. It also defines how the ELF header, program headers, dynamic section and dynamic-linker list of an ELF image mapped into a process are read, which the library and ELF-file tools use.

Decoding the kernel's own compressed table (`kallsyms_names`) is the project's `symbols/kallsyms` decoder; this specification states the table facts the lookup relies on. Module records, regions and symbol tables are S06; list walks are S01.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxobj.Kernel` | Kernel memory, the symbol table, the canonical address form, the effective Limits. |
| Module model | `linuxmodule.Model` from the kernel (S06) | Module records, regions, symbols and the `modules` list. |
| Symbols | symbol table | `kallsyms_num_syms`, `kallsyms_names`, `kallsyms_token_table`, `kallsyms_token_index`, `kallsyms_offsets`, `kallsyms_relative_base`, `_stext`, `_etext`; optional `_sinittext`, `_einittext`, `_end`, `__init_begin`, `__init_end`, `mod_tree`, `bpf_tree`, `bpf_kallsyms`, `ftrace_mod_maps`, `ftrace_ops_trampoline_list`. |
| Process memory | `memory.MemoryReader` | For ELF images: one process's address space. |
| Limits | effective `limits.Limits` | Section 8. |

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17, fetched from git.kernel.org on 2026-11-12. A row names the tags where it was read; "all tags" means all five. ELF facts also cite the System V ABI, ELF gABI (chapters 4 and 5, sco.com edition, accessed 2026-11-12).

### The kernel's table

| # | Fact | Source |
|---|---|---|
| K1 | `scripts/kallsyms.c` sorts the table by address before writing it. Among symbols with one address, non-weak names come first, then names that are not linker-script provided, then names with fewer leading underscores. `kallsyms_relative_base` is the lowest address in the table. | `scripts/kallsyms.c` `compare_symbols`, `record_relative_base`, v6.17. |
| K2 | Without `--all-symbols` only symbols in `[_stext, _etext]` and `[_sinittext, _einittext]` (both ends included), plus names starting `__start_` or `__stop_`, are kept. `scripts/link-vmlinux.sh` passes `--all-symbols` when `CONFIG_KALLSYMS_ALL` is set. | `scripts/kallsyms.c` `symbol_valid`, `symbol_in_range`, v6.17; `scripts/link-vmlinux.sh`, all tags. |
| K3 | `kallsyms_names` holds one record per symbol: a length, then that many token indexes. The length is one byte; from v6.1 a length above 0x7F is two bytes, low seven bits first with bit 7 of the first byte set. Each token index selects the NUL-terminated string at `kallsyms_token_table[kallsyms_token_index[i]]`; the 256 tokens follow each other in `kallsyms_token_table`. The first character of a symbol's expansion is its type letter, and the rest is its name. | `scripts/kallsyms.c` `write_src`; `kernel/kallsyms.c` `kallsyms_expand_symbol`, `kallsyms_get_symbol_type`; all tags (two-byte lengths from v6.1). |
| K4 | `kallsyms_markers` gives the byte offset in `kallsyms_names` of every 256th record: `unsigned long` at v4.19, `unsigned int` from v6.1. `kallsyms_num_syms` is `unsigned long` at v4.19 and `unsigned int` from v6.1. | `scripts/kallsyms.c` `write_src`; `kernel/kallsyms_internal.h` v6.1, v6.17. |
| K5 | A symbol's address is `kallsyms_relative_base + (u32)kallsyms_offsets[i]`. Up to v6.14, with `CONFIG_KALLSYMS_ABSOLUTE_PERCPU`, a non-negative offset is the address itself and a negative one is `kallsyms_relative_base - 1 - offset`; v6.17 has only the first form. | `kernel/kallsyms.c` `kallsyms_sym_address`, all tags. |
| K6 | From v6.4 (absent at v6.1) `kallsyms_seqs_of_names` holds, three bytes per symbol, big-endian, the table positions in name order; `kallsyms_lookup_name` binary-searches it. | `scripts/kallsyms.c`, `kernel/kallsyms.c`, v6.4, v6.14, v6.17. |
| K7 | `is_ksym_addr(a)` is, without `CONFIG_KALLSYMS_ALL`, `a` in `[_stext, _etext)` or `[_sinittext, _einittext)`; with it, `a` in `[_stext, _end)` or `[__init_begin, __init_end)`. Either form also accepts the gate area. v4.19 includes the ends `_etext`, `_einittext` and `_end`. | `include/linux/kallsyms.h` and `include/asm-generic/sections.h`, v6.1, v6.17; `include/linux/kallsyms.h`, v4.19. |
| K8 | `get_symbol_pos(a)` takes the last table position whose address is not above `a`, then moves back while the previous position has the same address. The symbol's size runs to the next greater address in the table; with none, to `_einittext` for an address in `[_sinittext, _einittext)`, else to `_end` with `CONFIG_KALLSYMS_ALL`, else to `_etext`. | `kernel/kallsyms.c`, all tags. |
| K9 | `kallsyms_lookup` returns the length of the expanded name, so a core symbol whose name is empty gives no answer, and the module and BPF steps are not tried. For any other address it tries, in order, `module_address_lookup`, `bpf_address_lookup` and `ftrace_mod_address_lookup`. A BPF answer has no module name. | `kernel/kallsyms.c` `kallsyms_lookup_buildid` v6.17 (`kallsyms_lookup` v4.19); `include/linux/filter.h` `bpf_address_lookup`, v6.1, v6.4. |
| K10 | `KSYM_NAME_LEN` is 128 at v4.19 and 512 from v6.1. | `include/linux/kallsyms.h`. |
| K11 | `/proc/kallsyms` lists the core symbols, then module symbols, then ftrace symbols, then BPF symbols, then kprobe pages. A symbol with an empty name is not shown. A module, ftrace or BPF symbol's letter is printed upper-case when the symbol is exported and lower-case when not. | `kernel/kallsyms.c` `update_iter_mod`, `s_show`, v6.17. |
| K12 | The type letter is the one the build's `nm` listing gives the symbol: `scripts/link-vmlinux.sh` passes that listing to `scripts/kallsyms`, whose `read_symbol` stores the letter unchanged as the record's first character, and `s_show` prints a core symbol's letter as stored. From v6.14 the x86-64 linker script links the kexec relocation code, the input sections `.text..relocate_kernel` (flags `ax`) and `.data..relocate_kernel`, inside the `.data` output section, between `_sdata` and `_edata` (`KEXEC_RELOCATE_KERNEL`, with `CONFIG_X86_64` and `CONFIG_KEXEC_CORE`). At v6.1 that code is in `.text`. | `scripts/link-vmlinux.sh`, `scripts/kallsyms.c` `read_symbol`, `kernel/kallsyms.c` `s_show`, v6.17; `arch/x86/kernel/vmlinux.lds.S` and `arch/x86/kernel/relocate_kernel_64.S`, v6.1, v6.14, v6.17. |

### Latch trees

| # | Fact | Source |
|---|---|---|
| L1 | `struct latch_tree_root { seqcount_latch_t seq; struct rb_root tree[2]; }` (v4.19: `seqcount_t seq`). `struct latch_tree_node { struct rb_node node[2]; }`. | `include/linux/rbtree_latch.h`, all tags. |
| L2 | `seqcount_t` is `struct seqcount { unsigned sequence; ... }`, and `seqcount_latch_t` wraps one `seqcount_t seqcount` (v6.1 on), so the sequence is the first four bytes of `seq`. | `include/linux/seqlock.h` v4.19, v6.1; `include/linux/seqlock_types.h` v6.17. |
| L3 | Each insert and erase changes `tree[0]` and then `tree[1]`, raising the sequence before each. A reader uses `tree[sequence & 1]`. | `include/linux/rbtree_latch.h` `latch_tree_insert`, `latch_tree_erase`, `latch_tree_find`, all tags. |
| L4 | `__lt_find` starts at `tree[idx].rb_node`; at each `rb_node` it takes the `latch_tree_node` whose member `node[idx]` is that `rb_node`, compares the key with it, and goes to `rb_left` for a negative result, `rb_right` for a positive one, and stops on zero. | `include/linux/rbtree_latch.h`, all tags. |
| L5 | `struct rb_node { unsigned long __rb_parent_color; struct rb_node *rb_right; struct rb_node *rb_left; }`; `struct rb_root { struct rb_node *rb_node; }`. | `include/linux/rbtree.h` v4.19; `include/linux/rbtree_types.h` v6.17. |
| L6 | The longest root-to-leaf path of a red-black tree is at most twice the number of black nodes on any path. Lockless lookups see no loops in program order. | `lib/rbtree.c` header comments, v6.17. |

### Modules

| # | Fact | Source |
|---|---|---|
| M1 | `struct mod_tree_node { struct module *mod; struct latch_tree_node node; }`. It is the member `mtn` of `struct module_layout` (v4.19, v6.1) or of `struct module_memory` (v6.4, v6.14, v6.17), under `CONFIG_MODULES_TREE_LOOKUP`. | `include/linux/module.h`. |
| M2 | `struct mod_tree_root` holds, under `CONFIG_MODULES_TREE_LOOKUP`, `struct latch_tree_root root`, then `unsigned long addr_min`, `addr_max`, and with `CONFIG_ARCH_WANTS_MODULES_DATA_IN_VMALLOC` (v6.4 on) `data_addr_min`, `data_addr_max`. v6.1 keeps the data bounds in a second root, `mod_data_tree`. | `kernel/module.c` v4.19; `kernel/module/internal.h` v6.1, v6.4, v6.14, v6.17. |
| M3 | The tree orders nodes by the base of their layout or memory region; the compare gives −1 when the key is below `base`, +1 when it is at or above `base + size`, 0 otherwise. | `kernel/module.c` `mod_tree_comp` v4.19; `kernel/module/tree_lookup.c` v6.1 to v6.17. |
| M4 | `mod_tree_insert` sets `mtn.mod = mod` and inserts one node per non-empty region (v6.4 on, every `mod_mem_type`) or the core layout and a non-empty init layout (v4.19). Init nodes are removed when init memory is freed, all nodes when the module goes. | Same files. |
| M5 | `__module_address(a)` returns nothing unless `addr_min ≤ a ≤ addr_max` (or within the data bounds); it then takes the tree's answer, and drops a module in `MODULE_STATE_UNFORMED`. The kernel asserts that the module holds `a`. Without the tree, it walks `modules` for the first module that holds `a`. | `kernel/module.c` v4.19; `kernel/module/main.c` v6.1, v6.4, v6.17; `kernel/module/internal.h` `mod_find`, v6.17. |
| M6 | `find_kallsyms_symbol` takes, among symbols 1 and up with `st_shndx` not `SHN_UNDEF`, a non-empty name and no mapping-symbol name, the one with the largest value not above the address and above symbol 0's value; the first of equal values wins. The size runs to the smallest such value above the address, or to the end of the module's init text (address in init memory) or core text. | `kernel/module/kallsyms.c` v6.1, v6.17; `kernel/module.c` `get_ksymbol` v4.19. The mapping-symbol test is S06 F13. |
| M7 | `module_get_kallsym` walks `modules`, skips `MODULE_STATE_UNFORMED`, and gives each symbol's value, `typetab` letter, name, module name and `is_exported(name, value, mod)`. | `kernel/module/kallsyms.c` v6.17. |
| M8 | `is_exported` finds the name in `mod->syms[0 .. num_syms)` and checks that the entry's value equals the symbol's. `struct kernel_symbol` is `{ int value_offset; int name_offset; }` (v6.1 on, also `int namespace_offset`) with `CONFIG_HAVE_ARCH_PREL32_RELOCATIONS`, else `{ unsigned long value; const char *name; }` (v6.1 on, also `const char *namespace`). An offset is read as `offset_to_ptr`: the offset's own address plus its value. | `kernel/module/kallsyms.c` v6.17; `include/linux/export.h` v4.19, v6.1, v6.4; `kernel/module/internal.h` v6.14, v6.17; `include/linux/compiler.h` all tags. |
| M9 | Symbol 0 of an ELF symbol table is the undefined entry, all zero. | System V ABI, ELF gABI, chapter 4 "Symbol Table". |

### BPF

| # | Fact | Source |
|---|---|---|
| B1 | From v6.1, `struct bpf_ksym { unsigned long start; unsigned long end; char name[KSYM_NAME_LEN]; struct list_head lnode; struct latch_tree_node tnode; bool prog; }`. `bpf_ksym_add` appends to the list `bpf_kallsyms` and inserts into the latch tree `bpf_tree`. | `include/linux/bpf.h`, `kernel/bpf/core.c`, v6.1, v6.4, v6.14, v6.17. |
| B2 | The `bpf_tree` compare gives −1 below `start`; +1 at or above `end` at v6.1 and v6.4, and only above `end` at v6.14 and v6.17 (so that a return address just past a program's last call counts as inside it). | `kernel/bpf/core.c` `bpf_tree_comp`. |
| B3 | `__bpf_address_lookup` gives the name, size `end - start` and offset `a - start`. `bpf_get_kallsym` gives `start`, the type `BPF_SYM_ELF_TYPE` (`'t'`) and the name, in list order, under the module name `bpf`, not exported. | `kernel/bpf/core.c`; `include/linux/filter.h`; `kernel/kallsyms.c` `get_ksymbol_bpf`, v6.17. |
| B4 | At v4.19 the tree and list nodes are `bpf_prog_aux.ksym_tnode` and `ksym_lnode`. A program's region is `[hdr, hdr + hdr->pages * PAGE_SIZE)` (E7) with `hdr = prog->bpf_func & PAGE_MASK` and `struct bpf_binary_header { u32 pages; ... }`; `aux->prog` is the program. Its name is `bpf_prog_`, then the 8 bytes of `prog->tag` in lower-case hexadecimal, then `_` and `aux->name` when `aux->name[0]` is not 0. | `kernel/bpf/core.c` `bpf_get_prog_addr_region`, `bpf_get_prog_name`, `bpf_tree_comp`; `include/linux/filter.h` `bpf_jit_binary_hdr`; `include/uapi/linux/bpf.h` `BPF_TAG_SIZE` 8, `BPF_OBJ_NAME_LEN` 16; `lib/hexdump.c` `hex_asc`; v4.19. |

### ftrace

| # | Fact | Source |
|---|---|---|
| R1 | `struct ftrace_mod_map { ...; struct list_head list; struct module *mod; unsigned long start_addr, end_addr; struct list_head funcs; unsigned int num_funcs; }` on the list `ftrace_mod_maps`; `struct ftrace_mod_func { struct list_head list; char *name; unsigned long ip; unsigned int size; }`. A map is made when a module's init memory is freed, with one function per traced init function, so that its name survives. | `kernel/trace/ftrace.c`, all tags. |
| R2 | `ftrace_mod_address_lookup` takes the first map, in list order, holding a function with `ip ≤ a < ip + size`, and gives its name, size, offset and the map's module name. | `kernel/trace/ftrace.c`, all tags. |
| R3 | `ftrace_mod_get_kallsym` lists the functions with type `'T'`, exported, under the map's module name. Its position arithmetic (`if (symnum > 1) symnum--`) shows the first function twice and never the last. | `kernel/trace/ftrace.c`, all tags. |
| R4 | From v6.1, `ftrace_ops` with an allocated trampoline are on `ftrace_ops_trampoline_list` (member `list`). `/proc/kallsyms` shows each with a non-zero `trampoline` as `ftrace_trampoline`, type `'t'`, module `__builtin__ftrace`, not exported. `ftrace_ops_trampoline` treats `[trampoline, trampoline + trampoline_size)` as ftrace text. | `kernel/trace/ftrace.c` v6.1, v6.4, v6.14, v6.17 (no list at v4.19). |

### ELF images in memory

| # | Fact | Source |
|---|---|---|
| E1 | `e_ident` is 16 bytes: `\x7fELF`, then `EI_CLASS` at 4 (`ELFCLASS32` 1, `ELFCLASS64` 2) and `EI_DATA` at 5 (`ELFDATA2LSB` 1). | gABI chapter 4 "ELF Identification"; `include/uapi/linux/elf.h` v4.19, v6.17. |
| E2 | `Elf64_Ehdr`: `e_type` at 16 (2 bytes), `e_machine` 18, `e_version` 20, `e_entry` 24, `e_phoff` 32, `e_shoff` 40, `e_flags` 48, `e_ehsize` 52, `e_phentsize` 54, `e_phnum` 56. `Elf32_Ehdr`: `e_type` 16, `e_phoff` 28, `e_phentsize` 42, `e_phnum` 44. `ET_EXEC` 2, `ET_DYN` 3. | gABI chapter 4 "ELF Header"; `include/uapi/linux/elf.h`. |
| E3 | `Elf64_Phdr` (56 bytes): `p_type` 0, `p_flags` 4, `p_offset` 8, `p_vaddr` 16, `p_paddr` 24, `p_filesz` 32, `p_memsz` 40, `p_align` 48. `Elf32_Phdr` (32 bytes): `p_type`, `p_offset`, `p_vaddr`, `p_paddr`, `p_filesz`, `p_memsz`, `p_flags`, `p_align`, 4 bytes each. `PT_LOAD` 1, `PT_DYNAMIC` 2. `PT_LOAD` entries are in ascending `p_vaddr` order. | gABI chapter 5 "Program Header"; `include/uapi/linux/elf.h`. |
| E4 | The base address is the difference between the memory address of the lowest-`p_vaddr` `PT_LOAD` segment and that `p_vaddr`, both truncated to the page size. | gABI chapter 5 "Base Address". |
| E5 | The dynamic section is an array of `{ d_tag; d_val or d_ptr }` (16 bytes for ELF64, 8 for ELF32) ending at `DT_NULL` (0). `d_ptr` values are file virtual addresses, relocated by the base address. `DT_DEBUG` (21) "is used for debugging. Its contents are not specified for the ABI". | gABI chapter 5 "Dynamic Section"; `include/uapi/linux/elf.h`. |
| E6 | The kernel's ELF loader refuses a program or interpreter whose `e_phentsize` is not `sizeof(struct elf_phdr)`. | `fs/binfmt_elf.c` `load_elf_phdrs`, v4.19, v6.17. |
| E7 | x86 `PAGE_SHIFT` is 12, so `PAGE_SIZE` is 4096 and `PAGE_MASK` clears the low 12 bits. | `arch/x86/include/asm/page_types.h`, v6.17. |

### Measurements

Measured with `kallsymsfacts` (`-shapes`), 2026-11-12, on mem3_ubuntu24 (6.17) and mem4_fedora40 (6.14).

| # | Measurement | Data |
|---|---|---|
| S1 | Both symbol tables type `latch_tree_root` (`seq` at 0, `tree` at 8, 24 bytes), `rb_root` (8 bytes), `rb_node` (24 bytes, `rb_right` 8, `rb_left` 16), `latch_tree_node` (48 bytes), `seqcount_latch_t` (4 bytes), `mod_tree_node` (`mod` 0, `node` 8), `mod_tree_root` (`root` 0, `addr_min` 0x18, `addr_max` 0x20, 40 bytes, no data bounds), `module_memory` with `mtn` (0x10 on mem3, 0x18 on mem4), `bpf_ksym` (600 bytes, `lnode` 0x210, `tnode` 0x220), `ftrace_mod_map`, `ftrace_mod_func`, `ftrace_ops` (`trampoline` 0x90, `trampoline_size` 0x98, `list` 0xa0), `kernel_symbol` in the offset form (12 bytes) and `elf64_hdr`, `elf64_phdr` matching E2 and E3. | `-shapes` output. |
| S2 | No allowed source defines the dynamic linker's structures that `DT_DEBUG` points at (E5). The layout read in 4.8 step 5 is measured: every list entry's third field equals its object's base address plus that object's `PT_DYNAMIC` `p_vaddr` (1487 of 1487 checks on mem3, 697 of 697 on mem4), and the fifth field of the next entry points back at the entry (1730 of 1748, 721 of 721). The 4-byte word at the start of the structure is 1 in 46 of 51 lists on mem3 and 19 of 19 on mem4. | Section 9. |
| S3 | Letters by section, from the decoded table and the vsym bounds (`kallsymsfacts -names`). Every symbol in `[_sdata, _edata)` is `T` or `t`: mem3 3244 `T` and 19241 `t`, mem4 6215 `T` and 19222 `t`, among them `init_task`, `psi_system`, `rcu_state` and `tasklist_lock`. `relocate_kernel` is the symbol at `__relocate_kernel_start`, inside that range (mem3 0xffffffff94e76e00, mem4 0xffffffff8bc48f00). `[__start_rodata, __end_rodata)` holds `D`, `d`, `R`, `r` and one `V`; `[__bss_start, __bss_stop)` `B`, `b` and one `D`; `[_stext, _etext)` `T`, `t`, `W`. Each name decodes at the address the vsym table gives it. |

## 4. Algorithm

### 4.1 Core table

1. Read the addresses of the K3 to K5 tables, `_stext` and `_etext` from the symbol table. Decode the table with `symbols/kallsyms`, which applies K3 and K5 and gives each symbol's name, letter, address and K8 size. A missing symbol or a decode failure is an error.
2. Read `_sinittext`, `_einittext`, `_end`, `__init_begin` and `__init_end` where present.
3. The table holds all symbols (K2) when it has a symbol, other than one named `__start_*` or `__stop_*`, whose address lies outside `[_stext, _etext]` and `[_sinittext, _einittext]`.
4. The core range (K7) is `[_stext, _etext)` and `[_sinittext, _einittext)`; when the table holds all symbols, it is `[_stext, _end)` and `[__init_begin, __init_end)` instead. A bound missing from the symbol table drops its range. The gate area is not included (O3).

### 4.2 Naming one address

All comparisons are on canonical addresses. Results give addresses in the masked form. Each answer is kept for the address.

1. **Core** (K7, K8, K9). For an address in the core range: the position is the last one whose address is not above it, moved back over equal addresses. The answer is that symbol: name, letter, its K8 size, offset, module `kernel`, subsystem `core`. An empty name is no answer, and no other step runs.
2. **Module** (4.3, M6). The owning module's symbol: name, letter (4.5), size and offset per M6, module name, subsystem `module`. A module that owns the address but has no qualifying symbol gives no answer; the steps below run.
3. **BPF** (4.6, B2, B3). Name, letter `t`, size `end − start`, offset, module `bpf`, subsystem `bpf`.
4. **ftrace functions** (R2). The first function holding the address: its name, letter `T`, size, offset, the map's module name, subsystem `ftrace`.
5. **ftrace trampolines** (R4). An address in `[trampoline, trampoline + trampoline_size)` of a listed `ftrace_ops`: name `ftrace_trampoline`, letter `t`, module `__builtin__ftrace`, subsystem `ftrace`.

Steps 1 to 4 are the kernel's order (K9). Step 5 is not in `kallsyms_lookup`; it is added because the kernel's unwinder treats trampolines as text (R4).

### 4.3 The owning module

1. **Tree.** When `mod_tree` exists and `module_memory` (else `module_layout`) has `mtn` (M1): read `addr_min` and `addr_max`, and `data_addr_min` and `data_addr_max` when the type has them. An address outside every bound has no module (M5).
2. Find the node with the 4.4 walk of `mod_tree.root`, comparing by M3 with `base` and `size` of the region that contains the node (`container_of` through `mtn.node`). The module is the `mod` pointer of the node's `mod_tree_node`.
3. **List.** Without the tree, the module is the first on the `modules` list (S06 `List`) that holds the address.
4. Read the module (S06). A module in `MODULE_STATE_UNFORMED` gives no module. A module that does not hold the address (S06 regions), against M5's assertion, is a failure (`ErrTreeModule`) and gives no module.

### 4.4 Latch tree walk

Given a `latch_tree_root` address and a compare:

1. Read the sequence: the 32-bit value at the start of `seq` (L2). The copy is `idx = sequence & 1` (L3). A sequence that does not read is `ErrLatchTreeRead`.
2. Start at `tree[idx].rb_node`. At each node *n*, the latch node is `n − idx × sizeof(rb_node) − offset(latch_tree_node.node)` (L4, L5). Go left, right or stop by the compare's sign.
3. A node seen before is `ErrLatchTreeCycle`; more than `MaxRecursionDepth` steps is `ErrLatchTreeDepth` (L6). A read that fails is an error.

### 4.5 Module symbols, their letters and exports

1. A module's symbols are S06 4.4's. The M6 choice uses symbols with a non-zero section, a non-empty name and no mapping-symbol name, and a value above 0 (M9).
2. The export table is `module.syms` with `module.num_syms` entries (M8), read once per module. With `value_offset` in `kernel_symbol` an entry's value and name pointer are its member's address plus the signed 32-bit member value; otherwise they are `value` and `name`. Names are read up to `KSYM_NAME_LEN` from v6.1, 512 bytes (K10).
3. A symbol is exported when the export table has its name with its value. The letter is then upper-case, otherwise lower-case (K11). When the export table does not read, the letter is kept as stored and the export state is unknown.

### 4.6 BPF programs

1. **Form.** `bpf_ksym` with `lnode` (B1), else `bpf_prog_aux` with `ksym_lnode` (B4). Neither: no BPF symbols. The lookup also needs `tnode` (or `ksym_tnode`) and the `bpf_tree` symbol.
2. **Lookup.** The 4.4 walk of `bpf_tree`. A `bpf_ksym` node compares −1 below `start` and +1 above `end` (B2, v6.14 and v6.17 form; O4). A v4.19 node compares by its B4 region.
3. **List.** The S01 walk of `bpf_kallsyms` through `lnode` (or `ksym_lnode`). Each entry gives its name (`bpf_ksym.name` up to its first NUL, or the B4 name), start and size.

### 4.7 ftrace

1. **Functions.** The S01 walk of `ftrace_mod_maps` (`ftrace_mod_map.list`), and within each map the walk of `funcs` (`ftrace_mod_func.list`). Each function gives its name (NUL-terminated, up to 512 bytes), `ip`, `size` and the map's module name (S06 read of `mod`).
2. **Trampolines.** The S01 walk of `ftrace_ops_trampoline_list` (`ftrace_ops.list`); entries with `trampoline` 0 are skipped (R4).

### 4.8 ELF images

1. **Header.** At the image base, read 16 bytes. Without `\x7fELF` (or unreadable) there is no image. A class other than 1 or 2, or data other than `ELFDATA2LSB`, is `ErrELFClass`. Read `e_type`, `e_machine`, `e_phoff`, `e_phentsize` and `e_phnum` for the class (E2); a header that does not read is `ErrELFRead`.
2. **Program headers.** `e_phnum` entries of `e_phentsize` bytes at `base + e_phoff`. `e_phentsize` must be at least the E3 entry size (E6 asks for equality only of what the kernel loads); otherwise `ErrELFRead`. At most `MaxTableEntries` entries are read. A header that does not read is `ErrELFRead`.
3. **Base address** (E4). From the lowest `PT_LOAD` by `p_vaddr`: base address = `trunc(image base) − trunc(p_vaddr − p_offset)`, truncating to 4096 bytes (E7). The image base is the address of file offset 0, the area start the header is read at. No `PT_LOAD` gives no base address, and step 4 then finds nothing.
4. **Dynamic section** (E5). The `PT_DYNAMIC` segment at `base address + p_vaddr`, `p_memsz` bytes, read up to `DT_NULL` and at most `MaxTableEntries` entries. `DT_DEBUG`'s `d_ptr`, when non-zero, is the debugger structure's address.
5. **Library list** (S2). At `DT_DEBUG`'s address: a 4-byte word, then, one pointer from the start, the first list entry. Each entry begins with four pointer-sized fields: base address, name pointer, dynamic section address, next. Walk `next` from the first entry until 0, a revisited entry, a read failure (`ErrELFRead`, with the entries read so far) or `MaxTableEntries` entries.
6. **Names.** A name is the bytes before the first NUL within `MaxNameBytes`; with no NUL in that span, or a read that fails, there is no name.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| A core answer needs an address in the core range and a non-empty name | K7, K9 | No answer |
| A module answer needs the address inside the module the tree gives | M5 | `ErrTreeModule`, counted |
| Unformed modules give no answer | M5 | No answer |
| Module symbols need a non-zero section, a name, no mapping name and a value above 0 | M6, M9 | Not chosen |
| Latch walks stop on a revisited node or at `MaxRecursionDepth` steps | L6 | `ErrLatchTreeCycle`, `ErrLatchTreeDepth`, counted |
| An export counts only with the same name and value | M8 | Not exported |
| An ELF image needs the magic, class 1 or 2 and little-endian data | E1 | None, or `ErrELFClass` |
| Program header entries are at least the class's entry size | E3 | `ErrELFRead` |
| A library-list walk stops at 0, a revisited entry or the cap | 4.8 step 5 | End of list |

## 6. Failure modes

| Case | Result |
|---|---|
| A K table symbol, `_stext` or `_etext` missing, or the decode fails | `NewKallsyms` error |
| `mod_tree`, `bpf_tree`, the ftrace lists absent | The step is skipped silently |
| The module model, a tree walk, a module read, its symbols or exports, a BPF or ftrace read fail | The step gives no answer; the failure is counted by reason in `Report`, with the first message. A symbol table without `module.syms` makes every export state unknown without a count. |
| `modules` missing | `ModuleSymbols` error |
| A list walk that breaks | Counted in `Report`; the entries before the break are kept |
| ELF header or tables unreadable | `ErrELFRead` |
| ELF class or data encoding not supported | `ErrELFClass` |

Errors are package sentinels with the prefix `linuxobj:`. Callers add the tool and address.

## 7. Result schema

`KernelSymbol` (one answer or one listed symbol):

| Field | Meaning |
|---|---|
| `Name` | The symbol name |
| `Type`, `TypeKnown` | The letter as a one-byte string; known when the stored letter is not 0 |
| `Address` | The symbol's start, masked |
| `Offset` | Address asked minus start; 0 for listed symbols |
| `Size` | Bytes: K8, M6, `end − start`, the ftrace function's `size`, the trampoline's `trampoline_size`; for listed module symbols `st_size` |
| `Module`, `ModuleKnown` | `kernel`, a module name, `bpf` or `__builtin__ftrace`; known when it read |
| `Subsystem` | `core`, `module`, `bpf` or `ftrace` |
| `Exported`, `ExportedUnknown` | 4.5 step 3 for module symbols; ftrace functions exported, BPF and trampolines not (B3, R3, R4); unknown for core answers |
| `NameUnknown` | Unused by this specification's answers; kept for callers |

`SymbolFailures`: reason to `{Count, First}`.

`ELF`: `Base`, `Class` (32 or 64), `Type` (`e_type`), `Machine`, and the program header fields `PhOff`, `PhEntSize`, `PhNum`; methods `ProgramHeaders`, `LoadSegments` (the `PT_LOAD` entries, `p_vaddr` as stored), `LoadBias` (4.8 step 3), `DebugAddress` (4.8 step 4), `LinkMap` (step 5) and `NameAt` (step 6). `ProgramHeader`: `Type`, `Flags`, `Offset`, `Vaddr`, `Filesz`, `Memsz`, `Align`. `LinkMapEntry`: `Address` (the entry), `LoadBias`, `Name` (pointer), `Dynamic`.

Listing order: modules in `modules` order and symbol table order; ftrace functions in map and function list order, then trampolines; BPF symbols in list order (K11).

## 8. Limits

- `MaxRecursionDepth`: latch tree steps (L6 bounds a valid tree's depth at 2 × 64).
- `MaxListEntries`: each S01 list walk.
- `MaxTableEntries`: export table entries per module, program headers, dynamic section entries, library-list entries.
- `MaxNameBytes`: library names; symbol names use K10's 512 bytes.

## 9. Acceptance

- Synthetic fixtures (`tools/linuxobj/linuxobjtest/s38_fixture.go`, with the shared `kallsyms.go`, `kallsymslist.go` and `modules.go`): a core table with aliases, an empty name and init text, with and without data symbols; a module tree with three modules, four regions and a module missing from the list; an odd sequence over a broken first copy; a cycle; a node of another module; the depth limit; a missing tree (list fallback); an unformed module; exports in both `kernel_symbol` forms and an unreadable export table; BPF programs in both forms; ftrace maps and trampolines; a broken list; ELF64 and ELF32 images with a library list, refused identifications, a header across an unmapped page, short program header entries, an unreadable and a revisited entry.
- Fuzz targets: `FuzzKallsymsLists` (module, export, ftrace and BPF structures over arbitrary bytes), `FuzzLatchTree` (tree nodes and root over arbitrary bytes), `FuzzELF` (header, program headers, dynamic section and library list over arbitrary bytes), 30 s each.
- Measured with `kallsymsfacts`, 2026-11-12. The symbol table built for each capture and the kernel's own structures check each other; no host output was used.

| Figure | mem3_ubuntu24 (6.17) | mem4_fedora40 (6.14) |
|---|---|---|
| Core symbols decoded; offset form (K5) | 223671; relative | 256744; absolute per-CPU |
| Decoded names in the symbol table; at the same address | 210475; 210420 | 216555; 216498 |
| Consecutive pairs in address order (K1); pairs with equal addresses | 223670 of 223670; 5614 | 256743 of 256743; 4734 |
| Symbols outside both text ranges, so built with `--all-symbols` (K2) | 67940 | 99576 |
| Records with a two-byte length (K3) | 1815 | 1371 |
| Token table bytes; longest token (K3) | 1066; 47 | 1014; 23 |
| `kallsyms_seqs_of_names`: distinct positions; in name order (K6) | 223671; 223671 | 256744; 256744 |
| Every symbol's own address named by the core table at that address; outside the core range | 223665; 6 | 256325; 419 (414 of them letter `A`) |
| `mod_tree` sequence (L3); nodes in each copy; deepest node | 1004; 222; 12 | 946; 207; 12 |
| Listed modules with one node per non-empty region (M4); tree modules not listed; nodes outside their module | 63 of 63; 0; 0 | 61 of 61; 0; 0 |
| `addr_min` to `addr_max` covers every listed region (M5) | yes | yes |
| Module symbols (defined, named, not mapping names, inside their module) named at their own address in their module; of them an earlier symbol of the same value (M6) | 15553 of 15553; 203 | 18772 of 18772; 206 |
| Listed module symbols; exported (upper-case) | 15729; 227 | 18924; 176 |
| `kernel_symbol` form (M8) | offsets | offsets |
| ftrace functions listed; their addresses named by ftrace, by a module that now occupies the freed init memory | 0 | 58; 10, 48 |
| BPF programs listed; named by `bpf_tree` at start + 1 | 19; 19 | 32; 32 |
| Kernel stack values named (`linux.process.read_kernel_stack`): kernel, modules; module answers inside the module the list view gives | 18766, 13; 13 of 13 | 15611, 21; 21 of 21 |
| ELF identifications at area starts, in tasks with an address space | 3938 in 115 tasks | 4170 in 123 tasks |
| `e_phentsize` 56; 0 (refused, `ErrELFRead`) | 3835; 103 | 4054; 116 |
| Images whose tables do not read; images with `DT_DEBUG` set | 469; 51 | 1640; 19 |
| Library-list entries; with a name | 1794; 1729 | 740; 721 |
| `linux.library.list` rows; processes | 1729; 46 | 721; 19 |

The ftrace figures on mem4 show the K9 order at work: once a module's init memory is freed, a module loaded later can occupy it, and the module step answers first. The 6 and 419 symbols outside the core range are absolute symbols and symbols past `_end`. The images with `e_phentsize` 0 carry the identification but not the rest of a header; the cause is not known.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision: `LookupAddress` is renamed `SymbolAt`, `KASSymbol` is `KernelSymbol`, `KallsymsReport` and `KallsymsPass` are `SymbolFailures` and `SymbolFailure`, `ExportsTypeError` is `RelativeExports`, and `BPFBefore57Unsupported` is removed (both BPF forms are read). On `ELF`, `LinkMaps`, `LinkMapAddr`, `LinkMapNamePointer` and `LinkMapName` become `LinkMap` and `NameAt`, the `Type` method becomes a field, and `ProgramHeaders`, `LoadBias` and `DebugAddress` are added. | Owner choice |
| O2 | Owner decision: ftrace functions are listed once each, not with R3's repeated first entry and missing last one. | Owner choice |
| O3 | The vsyscall gate area (K7) and kprobe instruction pages (K11) are not named. | A capture with kprobes, if wanted |
| O4 | The v6.1 and v6.4 BPF compare stops at `end`; the v6.14 and v6.17 one includes it. One rule (the later one) is used, since the symbol table does not say which kernel built it. | Owner decision |
| O5 | The v4.19 BPF form, the `module_layout` tree form, the `kernel_symbol` address form and ELF32 images are written from the sources only. | A capture of such a kernel (Q7) |
| O6 | Owner decision: S2's library-list layout has no allowed source. | Owner names a source, or accepts the measurement |
| O7 | Owner decision: BPF answers carry the module name `bpf`, as the listing does, although `bpf_address_lookup` gives none (K9). | Owner choice |
| O8 | The library list is reached only through the executable's `DT_DEBUG`, so a process whose executable has that page paged out, or no `DT_DEBUG`, lists no libraries: 46 of 115 processes on mem3 and 19 of 123 on mem4 list some. A second route (the dynamic linker's own entries in each object's global offset table) has no allowed source either. | Owner decision: add a route and name its source, or keep one |
| O9 | Kernel stack rows name data objects (`init_task`, `psi_system`, `rcu_state`) with letter `T` or `t`, 132 on mem3 and 151 on mem4 (S61). Owner decision 2026-11-12 (follow-up PU2): probe the reader before release. Done: not a bug. The letters are the kernel's own: `.data` holds executable input sections from v6.14 (K12), and S3 measures `T` or `t` on every symbol of `[_sdata, _edata)` on both captures, with each name at its vsym address, so the decoder reads the stored letter (K3, 4.1 step 1) as `/proc/kallsyms` prints it (K11). `kallsymsfacts` gained `-names`. No library change. | Owner decision |
| O10 | A library list can end at an entry that reads as 32 zero bytes: its `next` is 0, so 4.8 step 5 ends the walk without an error, although the process maps more images (mem8 pid 1082; mem3 pids 2096, 2199, 2281 and four more, S61 M21e). The walk is not changed: such a list is what the image holds. Owner decision 2026-11-12 (follow-up N3): S61 4.10 step 5 takes a last entry of zero bytes as a list that ended early and reads the process's mapped images beside it. | Owner decision (S61 O14) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept the renames |
| O2 | List once each |
| O3 | Leave unnamed |
| O4 | Use the later rule for all |
| O5 | Defer; sources only |
| O6 | Accept the measurement |
| O7 | Carry the name bpf |
| O8 | Keep the DT_DEBUG route |

## 11. Provenance

Written from the Linux kernel sources at v4.19, v6.1, v6.4, v6.14 and v6.17 (git.kernel.org, accessed 2026-11-12), the System V ABI ELF gABI chapters 4 and 5, and the project's measurements on mem3_ubuntu24 and mem4_fedora40. Every rule rests on the sources and measurements above. Author: the project.
