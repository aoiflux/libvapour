# S08: Linux module ELF rebuild

Version 1, 2026-11-12.

## 1. Purpose

An examiner who finds a suspect module wants its code as a file that standard ELF readers and disassemblers can open. The loaded module is no longer an ELF file: the kernel copies its allocated sections into module memory, applies relocations, and frees the file. This specification rebuilds a relocatable ELF file from what stays in memory: the section names and addresses the kernel keeps for sysfs, the section contents in module memory, and the symbols the kernel kept for the module.

The result is a reconstruction for analysis. It is not the file that was loaded: relocations are already applied, unallocated sections (debug data, relocation tables) are gone, and section sizes are inferred.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Module | S06 `Module` | The module to rebuild, with its regions. |
| Symbols | S06 4.4 | The module's symbols. |
| Reader | `linuxwalk.Reader` | Memory and symbol table. |
| Byte cap | bytes | The tool's artefact cap (`MaxArtifactBytes`). |

## 3. Facts from the sources

| # | Fact | Source |
|---|---|---|
| E1 | `module.sect_attrs` points at `struct module_sect_attrs`, made by `add_sect_attrs` with one entry per section that is allocated (`SHF_ALLOC`) and not empty, in section-header order. Each entry's name is the section's name from the original file, and its address is the section's run-time address. | `kernel/module.c` `add_sect_attrs`, `sect_empty` v4.19; `kernel/module/sysfs.c` v6.1, v6.17. |
| E2 | Three entry forms: **A** (v4.19): `struct module_sect_attr { struct module_attribute mattr; char *name; unsigned long address; }` and a count `nsections`. **B** (v6.1): `struct module_sect_attr { struct bin_attribute battr; unsigned long address; }` with the name in `battr.attr.name`, and `nsections`. **C** (v6.14, v6.17): the entries are `struct bin_attribute` themselves, the name is `attr.name`, the address is `private`, and there is no count: `grp.bin_attrs` is an array of pointers to the entries, ended by a null pointer. | `kernel/module.c` v4.19; `kernel/module/sysfs.c` v6.1, v6.14, v6.17. |
| E3 | The kernel places each allocated section inside one module region by its flags (S06 F7, F8): executable sections in text, read-only in read-only data, writable in data, and `.init` sections in the init regions. Sections in one region are laid out one after another in the region, each at its alignment. | `kernel/module/main.c` `layout_sections` v6.1, v6.17, and `module_get_offset_and_type` v6.17. |
| E4 | After init, the kernel frees the init regions; their sizes read 0, and the section entries for `.init` sections keep their old addresses. | `kernel/module/main.c` `do_init_module` (sets `mem[type].size = 0` for the init types) v6.17. |
| E5 | The kernel's type letters for module symbols are: `t` executable, `r` read-only, `d` data, `g` small data, `b` zero-filled (NOBITS), `s` small zero-filled, `v` weak object, `w` other weak, `a` absolute or per-CPU, `U` undefined, `n` debug, `?` other. | `kernel/module/kallsyms.c` `elf_type` v6.17. |
| E6 | The core symbol table keeps only defined symbols with a name in core sections (`is_core_symbol`). | `kernel/module/kallsyms.c` v6.17; `kernel/module.c` v4.19. |
| G1 | ELF header: `e_ident` (16 bytes: 0x7f `E` `L` `F`, class 1 for 32-bit or 2 for 64-bit, data 1 for little-endian, version 1, OS ABI 0, zeros), `e_type` (2), `e_machine` (2), `e_version` (4), `e_entry`, `e_phoff`, `e_shoff` (address-sized), `e_flags` (4), `e_ehsize`, `e_phentsize`, `e_phnum`, `e_shentsize`, `e_shnum`, `e_shstrndx` (2 each). The header is 64 bytes for class 2 and 52 for class 1. | System V ABI, ELF gABI, "ELF Header". |
| G2 | `ET_REL` is 1. `EM_386` is 3, `EM_X86_64` is 62. `EV_CURRENT` is 1. | gABI, "ELF Header" (`e_type`, `e_machine` and `e_version` tables). |
| G3 | Section header (64-bit, 64 bytes): `sh_name` (4), `sh_type` (4), `sh_flags` (8), `sh_addr` (8), `sh_offset` (8), `sh_size` (8), `sh_link` (4), `sh_info` (4), `sh_addralign` (8), `sh_entsize` (8). 32-bit (40 bytes): the same fields, with `sh_flags`, `sh_addr`, `sh_offset`, `sh_size`, `sh_addralign` and `sh_entsize` 4 bytes each. Index 0 is a null header. | gABI, "Sections". |
| G4 | `SHT_PROGBITS` 1, `SHT_SYMTAB` 2, `SHT_STRTAB` 3. `SHF_WRITE` 1, `SHF_ALLOC` 2, `SHF_EXECINSTR` 4. `SHN_UNDEF` 0, `SHN_ABS` 0xfff1. | gABI, "Sections". |
| G5 | In a symbol table, local symbols come before all others, and `sh_info` of the `SHT_SYMTAB` header is one more than the index of the last local symbol. `sh_link` is the index of the string table the names are in. `sh_entsize` is the symbol size. | gABI, "Sections" (`sh_link` and `sh_info` table) and "Symbol Table". |
| G6 | `st_info` is `(bind << 4) + (type & 0xf)`. `STB_LOCAL` 0, `STB_GLOBAL` 1, `STB_WEAK` 2. `STT_NOTYPE` 0, `STT_OBJECT` 1, `STT_FUNC` 2. In a relocatable file, a defined symbol's `st_value` is an offset from the start of its section. | gABI, "Symbol Table", "Symbol Values". |
| G7 | A string table starts and ends with a NUL byte; a name is an offset into it. | gABI, "String Table". |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | Both captures use form C: `module_sect_attrs` is `grp` (an `attribute_group` with `bin_attrs`) followed by `attrs`, an array of `bin_attribute` (88 bytes) with `attr.name` and `private`. | `modulefacts`, 2026-11-12. |
| M2 | Every listed module rebuilds, and every rebuilt file parses with `debug/elf`, with the contents of every section equal to memory at its address: 63 of 63 on mem3_ubuntu24 (246 freed init sections dropped) and 61 of 61 on mem4_fedora40 (231 dropped). No page was unreadable. | `modulefacts`, 2026-11-12. |

## 4. Algorithm

### 4.1 Sections

1. Read `sect_attrs`. A null or unreadable pointer is `ErrNoSections`.
2. Choose the form from the symbol table: **C** when `module_sect_attrs.attrs` has element type `bin_attribute`; **B** when `module_sect_attr` has `battr` and `address`; **A** when `module_sect_attr` has `name` and `address`. None is `ErrUnsupported`.
3. Count: `nsections` for A and B. For C, read `grp.bin_attrs` and count pointers up to the first null. In C, pointer *i* must equal the address of entry *i*; a mismatch ends the count there, with the module marked **attrs disordered**. Any count above `MaxTableEntries` is cut, with a diagnostic.
4. For each entry, read the name pointer and the address (E2). The name is read up to `MaxNameBytes` and ends at the first NUL. An entry whose name or address does not read is skipped and counted.
5. **Region.** Each section is put in the module region (S06 4.3) that holds its address. A section in no region (E4: a freed init section) is left out and listed in the result as dropped.
6. **Size.** Within each region, sort the kept sections by address. A section's size is the distance to the next section in the same region, or to the region's end for the last one (E3). Sections at the same address take size 0, except the last of them.
7. **Flags.** `SHF_ALLOC`, plus `SHF_EXECINSTR` in a text region, plus `SHF_WRITE` in a data region (`MOD_DATA`, `MOD_INIT_DATA`, or the data part of a layout).

### 4.2 Symbols

1. Take the S06 symbols. Skip entries with an empty name and entries with `st_shndx` 0 (E6).
2. **Binding and type.** With `typetab` (S06 F12), use `st_info` as read. Without it, `st_info` holds the letter; derive from E5: `t` → global function; `r`, `d`, `g`, `b`, `s` → global object; `v` → weak object; `w` → weak, no type; `a` → global, no type; anything else → global, no type.
3. **Section.** The symbol's section is the kept section that holds its value (`addr ≤ value < addr + size`, or `value == addr` for a size-0 section). Its `st_shndx` is that section's new index, and `st_value` is the value minus the section's address (G6). A symbol in no kept section gets `SHN_ABS` and its address as `st_value`. Letter `a` always gets `SHN_ABS`.
4. **Order.** Index 0 is the null symbol. Then local symbols, then the others, each in S06 table order (G5).

### 4.3 File layout

In order:

1. The ELF header (G1, G2): class from the pointer width, `ET_REL`, `EM_X86_64` for 8-byte pointers and `EM_386` for 4-byte, `e_shoff` at item 4, `e_shstrndx` the last header.
2. The section contents, in E1 order, each read from memory at its address for its size. A page that does not read is written as zeros and counted. Each section starts at an offset aligned to 16.
3. `.symtab` at an offset aligned to 8, then `.strtab` and `.shstrtab` directly after it. The section headers start at the next offset aligned to 8.
4. The section headers: the null header; one per kept section in E1 order (`SHT_PROGBITS`, the 4.1 flags, `sh_addr` the run-time address, `sh_addralign` 1); `.symtab` (`SHT_SYMTAB`, `sh_link` the `.strtab` index, `sh_info` per G5, `sh_entsize` the symbol size, `sh_addralign` 8); `.strtab` and `.shstrtab` (`SHT_STRTAB`, `sh_addralign` 1).

The file is little-endian (S01 X1).

### 4.4 Size cap

Before reading contents, add up the file size. If it is above the byte cap, the rebuild fails with `ErrTooLarge` and writes nothing.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Form C pointers equal the entry addresses | E2 | Count ends; attrs disordered |
| A section lies in a live module region | E3, E4 | Dropped, listed |
| Sizes come from the next section or the region end | E3 | — |
| Locals precede other symbols | G5 | — |

## 6. Failure modes

| Case | Result |
|---|---|
| No `sect_attrs` | `ErrNoSections` |
| No recognised entry form | `ErrUnsupported` |
| No section kept | `ErrNoSections` |
| No symbols (S06 `ErrNoSymbols`) | The file is written with an empty `.symtab`, and the result says so |
| Unreadable pages | Zeros, counted |
| Over the byte cap | `ErrTooLarge` |

## 7. Result schema

`Rebuild`: `File` (the bytes), `Sections` (count kept), `Dropped` (names of dropped sections), `Skipped` (entries that did not read), `Capped` (section entries cut at the cap), `Symbols` (count written), `NoSymbols`, `ZeroPages`, `AttrsDisordered`. Each of `Dropped`, `Skipped`, `Capped`, `NoSymbols`, `ZeroPages` and `AttrsDisordered` is reported as a diagnostic by the tool.

`linux.module.dump` row: `Address`, `Name`, `Size` (file bytes), `Sections`, `Dropped` (count), `ZeroPages`, `File`. Option `linux.module.dump.base`: the `struct module` address, required.

File name: the S00 artefact name with kind module, scope kernel, the module's address in canonical form (S54 4.1 step 2) and its name, extension `elf`. The row's `Address` keeps the model's form.

## 8. Limits

- `MaxTableEntries`: section entries.
- `MaxNameBytes`: section names.
- `MaxArtifactBytes`: the file.

## 9. Acceptance

- Synthetic fixtures for form C (and A and B from section 3): sections in text and data, a freed init section, entries with equal addresses, a symbol in each kind of section and one outside every section.
- The rebuilt file of every fixture parses with Go's `debug/elf`: every section's data matches memory, and every symbol's section and value match the expected ones.
- A fuzz target over the section reader and the rebuild on arbitrary memory; the output either fails with an error or parses with `debug/elf`.
- On both captures: every listed module rebuilds, and the file parses with `debug/elf` (M2).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Sizes include alignment padding between sections, because the kernel keeps no section sizes. | No closure; stated in section 1 |
| O2 | Section types are all `SHT_PROGBITS`, so zero-filled sections (`.bss`) are written with their current memory contents. This is a decision: the contents may matter to an examiner. | Owner decision |
| O3 | Forms A and B and 4-byte pointers are written from the source only. | A capture that has them (Q7) |
| O4 | Without `typetab`, a symbol's binding is lost (E5 letters have no case for binding), so such symbols are written as global. | A capture of a kernel before v6.1 (Q7) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Include padding |
| O2 | Write current memory contents |
| O3 | Ship as written, mark untested |
| O4 | Keep global fallback |

## 11. Provenance

Written from the kernel sources at the tags in section 3, the System V ELF gABI, and the project's measurements. Every rule rests on the sources and measurements above.
