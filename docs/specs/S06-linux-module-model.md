# S06: Linux module model

Version 1, 2026-11-12.

## 1. Purpose

A loaded Linux kernel module is code the kernel runs with full privilege, and a module an attacker loads is the most common way to hide inside a Linux kernel. An examiner needs, for each module: where its `struct module` lives, its name and load state, which address ranges its code and data occupy, which symbols it defines, and which module (or the kernel image itself) owns any code address another tool finds, such as a hooked function pointer.

This specification defines how one `struct module` is read and checked, how its memory regions and symbols are derived, and how an address is matched to its owner. Discovery of the set of modules is S07. The ELF rebuild of a module is S08.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Reader | `linuxwalk.Reader` (S01 section 2) | Memory, symbol table, address form and limits. |
| Module address | address | The address of one `struct module`, in the reader's address form. |
| Kernel namer | function from address to names, optional | Names an address inside the kernel image from the session's symbol table. |

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17. The supported captures run 6.14 (Fedora 40) and 6.17 (Ubuntu 24).

| # | Fact | Source |
|---|---|---|
| F1 | `struct module` begins with `enum module_state state`, then `struct list_head list`, then `char name[MODULE_NAME_LEN]`. | `include/linux/module.h`, every tag. |
| F2 | `MODULE_NAME_LEN` is `64 - sizeof(unsigned long)`: 56 bytes with 8-byte longs, 60 with 4-byte longs. The kernel copies the name with a terminating NUL. | `include/linux/moduleparam.h` (`MAX_PARAM_PREFIX_LEN`, v4.19 to v6.14; `__MODULE_NAME_LEN`, v6.17). |
| F3 | `enum module_state` has four values: `MODULE_STATE_LIVE` 0, `MODULE_STATE_COMING` 1, `MODULE_STATE_GOING` 2, `MODULE_STATE_UNFORMED` 3. | `include/linux/module.h`, every tag. |
| F4 | `mod_sysfs_init` sets `mod->mkobj.mod = mod`, so a module that has reached sysfs set-up holds its own address in `mkobj.mod`. | `kernel/module.c` v4.19; `kernel/module/sysfs.c` v6.1 to v6.17. |
| F5 | The `struct module` of a loaded module is the `.gnu.linkonce.this_module` section of its ELF file. After the sections are moved, `load_module` takes `mod` as that section's run-time address. The section is allocated and writable, so it is placed in the module's core data. | `kernel/module.c` `layout_and_allocate` v4.19; `kernel/module/main.c` v6.17, including the checks that the section exists once and has `SHF_ALLOC`. |
| F6 | Up to v6.3 a module's memory is two `struct module_layout` members, `core_layout` and `init_layout`, each with `base`, `size`, `text_size`, `ro_size` and `ro_after_init_size`. | `include/linux/module.h` v4.19, v6.1. |
| F7 | Inside one layout, `layout_sections` places executable sections first, then read-only data, then data that becomes read-only after init, then writable data. It records the running size after each group, so `text_size`, `ro_size` and `ro_after_init_size` are end offsets from `base`, in that order, and `size` is the end of the writable data. | `kernel/module/main.c` `layout_sections` v6.1; `kernel/module.c` v4.19. |
| F8 | From v6.4 a module's memory is `struct module_memory mem[MOD_MEM_NUM_TYPES]`, each with `base` and `size`. The index is `enum mod_mem_type`: `MOD_TEXT` 0, `MOD_DATA` 1, `MOD_RODATA` 2, `MOD_RO_AFTER_INIT` 3, `MOD_INIT_TEXT` 4, `MOD_INIT_DATA` 5, `MOD_INIT_RODATA` 6. The three `MOD_INIT_*` types are init memory; the rest are core. | `include/linux/module.h` v6.4, v6.14, v6.17. |
| F9 | `mod_update_bounds` widens `mod_tree.addr_min` and `addr_max` to cover every non-empty region of every module that is loaded. Nothing narrows them. With `CONFIG_ARCH_WANTS_MODULES_DATA_IN_VMALLOC`, core data goes to `data_addr_min` and `data_addr_max` instead. | `kernel/module.c` v4.19; `kernel/module/main.c` v6.1, v6.17; `kernel/module/internal.h` v6.17. |
| F10 | `struct mod_kallsyms { Elf_Sym *symtab; unsigned int num_symtab; char *strtab; }`. From v6.1 it also has `char *typetab`. `module.kallsyms` points at one of these. When a module's init finishes, `do_init_module` points `kallsyms` at `core_kallsyms`, the copy kept in core memory. | `include/linux/module.h` v4.19, v6.1, v6.17; `kernel/module.c` v4.19 and `kernel/module/main.c` v6.17 (`rcu_assign_pointer(mod->kallsyms, &mod->core_kallsyms)`). |
| F11 | A symbol's name is the NUL-terminated string at `strtab + st_name`. `KSYM_NAME_LEN` is 128 at v4.19 and 512 from v6.1. | `kernel/module/kallsyms.c` `kallsyms_symbol_name` v6.17; `include/linux/kallsyms.h`. |
| F12 | Before `typetab` existed, `add_kallsyms` overwrote each symbol's `st_info` with its one-letter type. With `typetab`, `st_info` is kept and the letter goes in `typetab[i]`. | `kernel/module.c` `add_kallsyms` v4.19; `kernel/module/kallsyms.c` `add_kallsyms` v6.17. |
| F13 | To name an address in a module, the kernel takes the symbol with the largest value not above the address. It skips entry 0, undefined symbols (`st_shndx == SHN_UNDEF`), symbols with an empty name, and mapping symbols. The mapping-symbol test widens over time: v4.19 and v6.1 skip names that begin `.L`, and `$a`, `$d`, `$t` or `$x` alone or followed by `.`; v6.4 adds names that begin `L0`; v6.17 skips every name that begins `$`. | `kernel/module.c` `get_ksymbol` and `is_arm_mapping_symbol` v4.19; `kernel/module/kallsyms.c` v6.1, v6.17; `include/linux/module_symbol.h` v6.4, v6.17. |
| F14 | `Elf64_Sym` is 24 bytes: `st_name` (4), `st_info` (1), `st_other` (1), `st_shndx` (2), `st_value` (8), `st_size` (8). `Elf32_Sym` is 16 bytes: `st_name`, `st_value`, `st_size` (4 each), `st_info`, `st_other` (1 each), `st_shndx` (2). `SHN_UNDEF` is 0. | System V ABI, ELF gABI, "Symbol Table"; `include/uapi/linux/elf.h` v6.17. |
| F15 | x86 is little-endian. | S01 X1. |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | Symbol-table shapes. Both captures' tables have `module.mem` as an array of 7 `module_memory`, `mod_kallsyms` with `typetab`, and `elf64_sym` of 24 bytes. `module_memory` is 72 bytes on 6.17 and 80 on 6.14; `base` is at 0 on both, and `size` moves (0xc and 0x14). | `modulefacts` on mem3_ubuntu24 and mem4_fedora40, 2026-11-12. |
| M2 | Module values. mem3_ubuntu24 lists 63 modules and mem4_fedora40 lists 61. Every one is live, self-linked and placed, and its name passes the section 5 rule; the names use only `0-9`, `A-Z`, `a-z` and `_`. Every one is also 64-byte aligned. Symbol tables read for all of them: 15,729 and 18,924 symbols. | Same script, 2026-11-12. |

## 4. Algorithm

### 4.1 Shape

Resolve once per reader, from the symbol table:

1. The offsets of `module.state`, `module.list`, `module.name`, `module.mkobj` and `module_kobject.mod`, and the length of the `module.name` array. A missing member, or a name array with no length, is an error that wraps `ErrUnsupported`.
2. The memory form:
   - **Regions** (v6.4 on, F8): `module.mem` is an array whose element type has `base` and `size`. The element size comes from the element type. The array length must be at least 7.
   - **Layouts** (to v6.3, F6): `module.core_layout` and `module.init_layout` exist, and `module_layout` has `base`, `size` and `text_size`. `ro_size` and `ro_after_init_size` are used when present.
   - Neither form: an error that wraps `ErrUnsupported`.
3. The symbol fields, which are optional: `module.kallsyms`, `mod_kallsyms.symtab`, `num_symtab`, `strtab`, and `typetab` if present. Without them, the symbol steps (4.4) return `ErrNoSymbols`.
4. `module.taints` (used by S07) is optional.

### 4.2 Reading one module

Given an address A:

1. Read `state` as an integer of its member's width. A failed read is `ErrUnreadable`.
2. Read the `name` array. A failed read is `ErrUnreadable`. The name is the bytes before the first NUL. No NUL in the array, an empty name, or a byte outside 0x21 to 0x7E, is `ErrName`.
3. Read `mkobj.mod`, put it through the address form, and record whether it equals A (**self-linked**, F4).
4. Read the regions (4.3).
5. Record whether A lies in a core data region (**placed**, F5).
6. Read `taints` if the member exists.

A state above 3 is `ErrState`. Failed reads, a state above 3, a failing name and a region error (4.3) end the read with an error. Self-linked and placed are facts on the result, and S07 decides what they mean for each source.

### 4.3 Regions

Each region has a kind, a base (put through the address form) and a size. Only regions with a nonzero size are kept.

- **Regions form:** entry *i* of `mem` has kind *i* in F8 order. Entries past index 6 are ignored.
- **Layouts form:** each layout L (core, then init) yields up to four regions, from F7:
  - text: `[base, base + text_size)`
  - read-only data: `[base + text_size, base + ro_size)`
  - read-only after init: `[base + ro_size, base + ro_after_init_size)`
  - data: `[base + ro_after_init_size, base + size)`

  A missing `ro_size` is taken as `text_size`, and a missing `ro_after_init_size` as `ro_size`. If the end offsets do not rise in that order (`text_size ≤ ro_size ≤ ro_after_init_size ≤ size`), the layout yields one region, of kind text for the core layout and init text for the init layout, covering `[base, base + size)`, and the module is marked **layout disordered**.

A region whose end wraps past 2^64, or past 2^32 with 4-byte pointers, is `ErrRegion`.

Derived values:
- **Base:** the base of the core text region (`MOD_TEXT`, or `core_layout.base`). It is 0 if that region is empty.
- **Core size:** the sum of core region sizes. **Init size:** the sum of init region sizes. **Text size:** the size of the core text region.

### 4.4 Symbols

1. Read the `kallsyms` pointer. A null or unreadable pointer is `ErrNoSymbols`. Read `symtab`, `num_symtab`, `strtab` and, if present, `typetab` from the `mod_kallsyms` it points at.
2. The entry size is 24 bytes, or 16 with 4-byte pointers (F14). A symbol-table size for `elf64_sym` (or `elf32_sym`) that differs from it is not used.
3. A count above `MaxTableEntries` is cut to that many, and the result says so (`Capped`).
4. Read the table. For each entry *i* ≥ 1, decode it by F14. An entry that does not read is counted as unread and skipped.
5. The name is read from `strtab + st_name`, up to 512 bytes (F11), and ends at the first NUL. A name with no NUL in that span is kept, cut at 512 bytes, and counted as cut.
6. The type letter is `typetab[i]` when `typetab` exists, and `st_info` read as a byte otherwise (F12).
7. The value is `st_value` put through the address form.

The result is the list of symbols, in table order, with `Unread` and `Cut` counts.

### 4.5 Address lookup

Given a set of modules and an address X, put through the address form:

1. The owners are the modules with a region that holds X. More than one owner is reported as a count, and the first owner in the set's order is used.
2. Without an owner, if X lies in `[_text, _etext)` from the symbol table, the owner is the kernel image, and the symbol is the first name the kernel namer gives for X.
3. With a module owner, the symbol is chosen by F13: the symbol with the largest value not above X, among symbols with index ≥ 1, `st_shndx` not 0, a non-empty name, and a name that does not begin with `$`, `.L` or `L0`. The v6.17 mapping-symbol test is applied on every tag, because it is the widest. The offset is X minus that value. If no symbol qualifies, the lookup gives the owner and no symbol.

Symbols for each module are read once per model and kept.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| State is 0 to 3 | F3 | `ErrState` |
| Name has a NUL inside the array, is not empty, and every byte is 0x21 to 0x7E | F2. The byte range is a decision (open point O1). M2. | `ErrName` |
| Self-linked: `mkobj.mod` equals the module's address | F4 | Fact on the result |
| Placed: the address lies in a core data region (`MOD_DATA`, or the data part of `core_layout`) | F5, F7, F8 | Fact on the result |
| Region ends do not wrap | Arithmetic bound | `ErrRegion` |
| Layout end offsets rise in F7 order | F7 | One region per layout; marked layout disordered |

## 6. Failure modes

| Case | Result |
|---|---|
| A member section 4.1 needs is missing | Error wrapping `ErrUnsupported` |
| A module's fields do not read | `ErrUnreadable`, with the address |
| State outside the enum | `ErrState` |
| Name fails its rule | `ErrName` |
| Region end wraps | `ErrRegion` |
| No symbol fields, or a null `kallsyms` | `ErrNoSymbols` |
| Symbol count above the cap | Cut; `Capped` on the result |
| Unreadable symbol entries or names | Skipped, counted in `Unread` |

Errors are package sentinels with the prefix `linuxmodule:`. Callers add the tool and address.

## 7. Result schema

`Module`: `Address`, `Name`, `State` (typed, with the names `live`, `coming`, `going` and `unformed`), `Regions` (kind, base, size), `SelfLinked`, `Placed`, `LayoutDisordered`, `Taints` (raw bits), `HasTaints`, `TaintsUnread`. Methods give base, core size, init size, text size, and whether an address is inside.

`Symbol`: `Name`, `Address`, `Type` (letter), `Section` (`st_shndx`), `Info` (`st_info`), `Size` (`st_size`).

`Symbols` (the table): `List`, `Unread`, `Cut`, `Capped`, `HasType` (a `typetab` exists).

`Owner` (lookup result): `Found`, `Kernel` (true for the kernel image, shown with the module name `kernel`), `Module` (when not the kernel), `Owners` (count), `Symbol`, `Offset`, `Unnamed` (the owner's symbols did not read). For display, the owner is its module name (`kernel` for the kernel image) and the symbol is `name+0x<offset>`, or the bare name when the offset is 0.

## 8. Limits

- `MaxTableEntries` caps the symbols read per module.
- Symbol names are read up to 512 bytes (F11).

## 9. Acceptance

- Synthetic fixtures for both memory forms, built from section 3: a self-linked placed module, a module with each failing rule, a disordered layout, a module with no `kallsyms`, and a table with mapping symbols, undefined symbols and an empty name.
- A fuzz target over the module reader and the symbol reader on arbitrary memory.
- On both captures, every module on the `modules` list is self-linked and placed, its name passes, and every listed module's symbol table reads (M2: 63 and 61 modules, 0 failures).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The kernel does not restrict the bytes of a module name; modpost builds it from the file name. The 0x21 to 0x7E range is a decision. | Owner decision |
| O2 | The layouts form (v6.3 and earlier) and 4-byte pointers are written from the source only. No capture runs them. | A capture of an older or 32-bit kernel (Q7) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | 0x21 to 0x7E only |
| O2 | Ship as written, mark untested |

## 11. Provenance

Written from the kernel sources at the tags in section 3, the System V ELF gABI, and the project's measurements in section 3. Every rule rests on the sources and measurements above.
