# S59: Linux symbol table built from the image

Version 1, 2026-11-12.

## 1. Purpose

A Linux tool needs the layout of the kernel's structures and the addresses of its symbols, and an examiner rarely has a symbol file for the exact kernel in a capture. A kernel built with `CONFIG_DEBUG_INFO_BTF` carries a description of its own types, BTF, in memory, and every kernel carries its symbol names and addresses, kallsyms. This specification turns those two records, and the KASLR shift from VMCOREINFO, into a symbol table in the project's format (`symbols/FORMAT.md`): every type the BTF records, every symbol name kallsyms holds at one address, and the BTF type of every variable the BTF types. It types only what the image records. Nothing is assumed from a kernel version or from any other tool's table.

Finding the BTF bytes and the kallsyms table in memory is the caller's (`symbols/linuxkernel`, through `symbols/btf` and `symbols/kallsyms`, S38); parsing the BTF bytes into types is `symbols/btf`. The VMCOREINFO note and its `KERNELOFFSET` are S05. This specification starts from the parsed records.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| `BTF` | `*btf.Spec` | The parsed vmlinux BTF: byte order and the type list, type 0 being void. |
| `Symbols` | `[]kallsyms.Symbol` | The decoded kallsyms table: name, type letter, address as the running kernel computes it, stored offset (S38 K3 to K5). |
| `Rule` | `kallsyms.AddressRule` | How the stored offsets give addresses (S38 K5). |
| `VirtualShift` | `uint64` | `KERNELOFFSET` from VMCOREINFO (S05 4.4 step 7): how far KASLR moved the kernel image. |
| `Banner` | `[]byte` | `linux_banner` as read from the image, for the table's build check. |
| `PointerSize` | `int64` | 8 on x86-64 (S05 4.4); 4 or 8 accepted. |
| `Limits` | `limits.Limits` | `MaxRecursionDepth`, `MaxNameBytes`, `MaxTableEntries` (section 8). |

`TypesFromBTF` takes only the BTF, the pointer size and the Limits, and gives the types without addresses.

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17, fetched from git.kernel.org on 2026-11-12. "All tags" means all five; `Documentation/bpf/btf.rst` does not exist at v4.19, and `kernel/vmcore_info.c` exists from v6.14 (`kernel/crash_core.c` before). Bitfield placement cites the x86-64 psABI (gitlab.com/x86-psABIs/x86-64-ABI, `low-level-sys-info.tex`, master, accessed 2026-11-12). Symbol binding cites the System V ABI ELF gABI, chapter 4 "Symbol Table" (sco.com edition, accessed 2026-11-12).

### The BTF encoding

| # | Fact | Source |
|---|---|---|
| T1 | Type id 0 is `void`. Ids are given in type-section order from 1. | `btf.rst` 2.2, v6.1, v6.4, v6.14, v6.17 |
| T2 | v4.19 defines kinds 1 to 11 (INT to RESTRICT); from v6.1 there are also FUNC 12, FUNC_PROTO 13, VAR 14, DATASEC 15, FLOAT 16, DECL_TAG 17, TYPE_TAG 18 and ENUM64 19. `BTF_KIND_FUNC` "is not a type"; it is a defined subprogram. | `include/uapi/linux/btf.h` v4.19, v6.1, v6.17; `btf.rst` 2.2 |
| T3 | An INT has a size in bytes and a 32-bit word with `BTF_INT_ENCODING` (SIGNED 1, CHAR 2, BOOL 4, at most one), `BTF_INT_OFFSET` and `BTF_INT_BITS`; `size * 8` is at least the bits. Its name may be any string ("any valid offset"). | `btf.h` all tags; `btf.rst` 2.2.1 |
| T4 | A PTR's `type` is the pointee. An ARRAY is `{type, index_type, nelems}`, `nelems` 0 allowed; multidimensional arrays are written as one dimension of all the elements. | `btf.rst` 2.2.2, 2.2.3 |
| T5 | A STRUCT or UNION has its size in bytes and `vlen` members `{name_off, type, offset}`. Without `kind_flag`, `offset` is the member's bit offset, and a bitfield is a member whose INT type's `BTF_INT_BITS` is the field width (or a 32-bit int or enum). With `kind_flag`, `offset` is `bitfield_size << 24 | bit_offset`, a size of 0 means no bitfield, and an int bitfield's type must be regular: `BTF_INT_OFFSET` 0 and `BTF_INT_BITS` 8, 16, 32, 64 or 128. A member starts at bit `offset + BTF_INT_OFFSET`. `kind_flag` does not exist at v4.19. | `btf.rst` 2.2.1, 2.2.4; `btf.h` v6.1, v6.17; `kernel/bpf/btf.c` `btf_type_int_is_regular`, v6.17 |
| T6 | An ENUM has size 1, 2, 4 or 8 and `vlen` constants `{name_off, __s32 val}`; from v6.1 `kind_flag` 1 marks it signed and 0 unsigned, and a signed value of a size under 4 is sign-extended into 4 bytes. At v4.19 `val` is `__s32` and there is no flag. ENUM64 (v6.1 on) holds `{name_off, val_lo32, val_hi32}`. | `btf.rst` 2.2.6, 2.2.19; `btf.h` v4.19, v6.1, v6.17 |
| T7 | A FWD is a named forward declaration, `kind_flag` 0 for a struct and 1 for a union. | `btf.rst` 2.2.7 |
| T8 | A TYPEDEF names the type "which can be referred by name at `name_off`". VOLATILE, CONST and RESTRICT qualify their type. TYPE_TAG carries an attribute; the chain is pointer, type tags, qualifiers or typedefs, then the base type. | `btf.rst` 2.2.8 to 2.2.11, 2.2.18 |
| T9 | FUNC_PROTO holds a return type and parameters. | `btf.rst` 2.2.13 |
| T10 | A VAR has a name, a type and a linkage. A DATASEC is named after a section and lists `{type, offset, size}`: each VAR's offset inside the section. | `btf.rst` 2.2.14, 2.2.15 |
| T11 | FLOAT sizes are 2, 4, 8, 12 or 16. DECL_TAG attaches an attribute string to a type, member, function or variable. | `btf.rst` 2.2.16, 2.2.17 |

### The kernel's own BTF

| # | Fact | Source |
|---|---|---|
| B1 | vmlinux BTF is the `.BTF` output section, between `__start_BTF` and `__stop_BTF` (`__start_BTF = .; KEEP(*(.BTF)) __stop_BTF = .` at v6.1 to v6.14, `BOUNDED_SECTION_BY(.BTF, _BTF)` at v6.17). v4.19 has no such section. The kernel parses that span as `vmlinux` and exports it as `/sys/kernel/btf/vmlinux`. | `include/asm-generic/vmlinux.lds.h`; `kernel/bpf/btf.c` `btf_parse_vmlinux`; `kernel/bpf/sysfs_btf.c`; v6.1, v6.4, v6.14, v6.17 |
| B2 | The link step generates `.BTF` from the kernel's DWARF. Variables are encoded only as per-CPU variables (`Makefile.btf`: old encoders "can't handle zero-sized per-CPU vars" and skip variables). | `scripts/link-vmlinux.sh` all tags; `scripts/Makefile.btf` v6.14, v6.17 |
| B3 | On load the kernel checks each type's own data (`btf_check_all_metas`, then `btf_check_type_tags`); it does not check vmlinux members against their types' sizes. | `btf_parse_vmlinux` v6.1, v6.4; `btf_parse_base` v6.14, v6.17 |
| B4 | The struct and union check: a name is empty or a valid identifier; a member name is empty or a valid identifier; a member's type is not void; a union member is at bit offset 0; a struct member's offset is not below the one before it (equal allowed, for a trailing `char a[0]`); a member's offset rounded up to bytes is not past the size. | `btf_struct_check_meta`, v6.1, v6.4, v6.14, v6.17 |
| B5 | A valid identifier starts with a letter or `_`, continues with letters, digits or `_`, and is shorter than `KSYM_NAME_LEN`; from v6.4 `.` is allowed anywhere, at v6.1 only in section names. Typedef and enum constant names must be valid identifiers. v4.19 checks no names. | `__btf_name_char_ok`, `btf_name_valid_identifier`, v4.19, v6.1, v6.4, v6.14, v6.17 |
| B6 | When the kernel does check members (BTF loaded by programs and modules), a pointer member or a non-bitfield `kind_flag` int member must start on a byte. | `btf_ptr_check_member`, `btf_int_check_kflag_member`, v6.17 |
| B7 | The per-CPU output section starts with `__per_cpu_start = .`, then the `.data..percpu*` input sections. | `PERCPU_INPUT` in `vmlinux.lds.h`, all tags |
| B8 | Some typedefs are empty anonymous structures in one configuration and something else in another: `lockdep_map_p` is a pointer to `struct lockdep_map` with `CONFIG_LOCKDEP` and an anonymous structure with no members without it. The kernel's flexible-array declaration in a union puts an empty anonymous structure member named `__empty_` plus the array's name before the array. | `include/linux/maple_tree.h`, `include/uapi/linux/stddef.h` (`__DECLARE_FLEX_ARRAY`), v6.14, v6.17 |

### Symbols and bitfields

| # | Fact | Source |
|---|---|---|
| K1 | A symbol's address is `kallsyms_relative_base + (u32)offset`; with `CONFIG_KALLSYMS_ABSOLUTE_PERCPU` (up to v6.14) a non-negative offset is the address itself, an absolute per-CPU value. | S38 K5; `kernel/kallsyms.c` `kallsyms_sym_address`, all tags |
| K2 | For a name held at several addresses, `kallsyms_lookup_name` gives the lowest: from v6.4 the name-sorted list (`compare_names`: name, then address) is searched and the search moves back to the first match; at v6.1 the address-ordered table is walked from the start. | `kernel/kallsyms.c` v6.1, v6.4, v6.17; `scripts/kallsyms.c` v6.17 |
| K3 | An upper-case type letter, and `u`, `v`, `w`, mark a global symbol (`kallsyms.Symbol.Global`); the core letters come from the link step's symbol listing, whose POSIX description writes global symbols upper-case and local ones lower-case. | `scripts/link-vmlinux.sh`, `scripts/kallsyms.c` `read_symbol`, all tags; POSIX.1-2024 XCU, symbol-table listing utility, STDOUT |
| K4 | `STB_GLOBAL` symbols are visible to every object file combined; "the link editor does not allow multiple definitions of `STB_GLOBAL` symbols with the same name". `STB_LOCAL` symbols are not visible outside their object file, so files may define locals of one name. | ELF gABI chapter 4, "Symbol Table", symbol binding |
| P1 | x86-64 bitfields "are allocated from right to left", "must be contained in a storage unit appropriate for its declared type" and "may share a storage unit with other struct / union members". | x86-64 psABI 3.1.2, "Bit-Fields" |

### Measurements

Measured with `btffacts`, 2026-11-12, on mem3_ubuntu24 (6.17) and mem4_fedora40 (6.14).

| # | Measurement | mem3_ubuntu24 | mem4_fedora40 |
|---|---|---|---|
| M1 | `__start_BTF` to `__stop_BTF` (B1); bytes; inside `__start_rodata` to `__end_rodata` | 0xffffffff9434f000 to 0xffffffff949e7cc7; 6917319; yes | 0xffffffff8b0ddbd0 to 0xffffffff8b71402b; 6513755; yes |
| M2 | Header magic, version, flags, `hdr_len` | 0xeb9f, 1, 0, 24 | 0xeb9f, 1, 0, 24 |
| M3 | Types | 165529 | 149710 |
| M4 | INT, PTR, ARRAY | 15, 25142, 4016 | 15, 17609, 4040 |
| M5 | STRUCT (named; with `kind_flag`), UNION (named) | 12621 (11335; 599), 2148 (203) | 12475 (11231; 587), 2274 (190) |
| M6 | ENUM (named; `kind_flag`), ENUM64 (named) | 2716 (1819; 64), 15 (10) | 2566 (1707; 60), 14 (9) |
| M7 | FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, TYPE_TAG | 119, 2606, 24, 3861, 10, 0 | 106, 2764, 24, 3939, 5, 0 |
| M8 | FUNC, FUNC_PROTO, VAR, DATASEC, FLOAT, DECL_TAG | 68425, 43370, 439, 1, 1, 0 | 67598, 35672, 411, 1, 2, 195 |
| M9 | INTs with a non-zero `BTF_INT_OFFSET` or narrower than their size; members of a struct without `kind_flag` that start inside a byte | 0; 0 | 0; 0 |
| M10 | Unnamed members; typedefs that name an anonymous type; anonymous structs and unions no type refers to | 1151; 276; 1101 | 1109; 260; 1264 |
| M11 | Names held by several STRUCT, UNION, ENUM or TYPEDEF types of one kind; those types | 29; 66 | 29; 65 |
| M12 | The one DATASEC: name, size, VARs | `.data..percpu`, 217344, 439 | `.data..percpu`, 233728, 411 |
| M13 | Every VAR's kallsyms address equals `__per_cpu_start` plus its DATASEC offset (B7); `__per_cpu_start` | 439 of 439; 0xffffffff9539e000 | 411 of 411; 0 (absolute) |
| M14 | kallsyms symbols; names; names at several addresses; of them with one global address (K3) | 223671; 212684; 2318; 49 | 256744; 219461; 3016; 51 |
| M15 | Anonymous STRUCT and UNION types with no members; typedefs of them; members of them (B8) | 2 (a 0-byte STRUCT, an 8-byte UNION); 5 (`local_lock_t`, `lockdep_map_p`, `netdevice_tracker` and `netns_tracker` of the STRUCT, `release_pages_arg` of the UNION); 33 | 2 (the same); 5 (the same); 32 |

## 4. Algorithm

### 4.1 Checks on the inputs

1. The BTF exists and has types; the pointer size is 4 or 8; the BTF holds no more types than `MaxTableEntries`. Otherwise `ErrNoBTF`, `ErrPointerSize`, `ErrTooManyTypes`.
2. For a table with addresses: the banner is non-empty UTF-8 with no NUL before its last byte (`ErrBanner`), and the address rule is one of the two (`ErrAddressRule`).

### 4.2 Seeing through

A type reference is followed through TYPEDEF, CONST, VOLATILE, RESTRICT and TYPE_TAG to the first other kind (T8): qualifiers and tags change no layout, and a typedef is a name for its target. More than `MaxRecursionDepth` steps is a loop or a runaway chain, and refuses whatever asked.

### 4.3 Shapes

A member's or variable's type is read as a shape: its pointer and array operators, outermost first, then a leaf.

1. Type 0 is the leaf `void` (T1).
2. PTR adds a pointer and follows `type`; ARRAY adds `[nelems]` and follows the element (T4).
3. INT and FLOAT are scalar leaves, named by their own name; an INT or FLOAT whose name is empty, not UTF-8, has a control character or is longer than `MaxNameBytes` refuses the member (T3).
4. STRUCT, UNION and an ENUM or ENUM64 with constants are composite leaves. An enumeration with no constants is a declaration, since C has no empty enumeration, and is a forward leaf like FWD (T7); a forward needs an identifier name (B5).
5. FUNC_PROTO is a leaf only right under a pointer; it is written as a pointer to an unnamed type (`*`).
6. Any other kind (VAR, DATASEC, FUNC, DECL_TAG) refuses the member.
7. More than 32 operators, the most a type expression holds (`symbols/FORMAT.md`), refuses the member.

### 4.4 Anonymous types named by typedefs

A typedef whose type, past qualifiers and tags only, is an anonymous structure, union or enumeration that declares at least one member or constant gives that type its name: C has no other name for it. When several typedefs do, the first in type id order names it, and the others become aliases (4.11).

An anonymous structure or union that declares no members takes no typedef's name. It is named by its members (4.8 step 3), `struct{}` or `union{}`, like any other anonymous type, and every typedef of it is an alias (4.11). The BTF holds one such type of a kind and size, which every typedef and member declared empty shares (M15): the first typedef's name would type unrelated members, such as every flexible-array `__empty_` member (B8), and `lockdep_map_p` would read as the pointer it is in another configuration.

### 4.5 Drafts

**Enumerations.** A size other than 1, 2, 4 or 8 refuses the enumeration (T6). Each constant needs an identifier name (B5), and no name may repeat; otherwise the enumeration is refused. A 32-bit value is sign-extended when `kind_flag` is set and zero-extended otherwise (T6). An ENUM64 value is kept as its 64-bit pattern, so an unsigned value of 2^63 or more reads as negative in the table's signed constant (O3).

**Records.** For each member in order:

1. A non-empty name must be an identifier (B5).
2. The shape is read (4.3).
3. Bitfields (T5). With `kind_flag`, a non-zero bitfield size makes a bitfield; an INT member must be regular. Without `kind_flag`, an INT member whose type is not regular is a bitfield of `BTF_INT_BITS` bits starting at `offset + BTF_INT_OFFSET`. A bitfield's type must be a bare INT or enumeration; its storage unit is that type's size.
4. Placement (P1). The unit is the one of the type's size aligned to that size that holds the first bit. When the field does not fit in it, as in a packed record, the unit starting at the field's first byte is tried. A field that fits neither, or a unit that starts at or past the record's end, refuses the member. The member's offset is the unit's byte offset; its type is `@<bit in unit>:<width> <type>`.
5. A member that is not a bitfield must start on a byte (B6).
6. Order (B4): a union member must be at bit 0; a struct member's bit offset may not be below the previous kept member's; a member's offset rounded up to bytes may not be past the record's size. A name may not repeat in a record.
7. An unnamed member that is a bare structure or union is embedded: its members become the record's at its offset. Any other unnamed member is padding (C's unnamed bitfields) and is counted, not written. An unnamed member of a pointer or array type is refused.

A refused member is left out and counted by reason; the record keeps its other members.

### 4.6 Refused types

A structure, union or enumeration whose name is not an identifier (B5), or an enumeration refused in 4.5, is not written. Members, variables and typedefs that refer to it are refused.

### 4.7 One type per definition

Two drafts are one type when they are the same kind, size and own name (tag or 4.4 typedef name), hold the same members and constants at the same places, and every member's type is, in turn, one type. The partition is found by splitting: drafts start grouped by their own data with referred types told apart only by name; each round splits a group whose members refer to different groups. Splitting only raises the number of groups, and the number is at most the number of drafts, so the rounds end; `MaxRecursionDepth` rounds is a further bound. One type per group is written. This merges identical anonymous types and identical same-named definitions, and tells apart same-named definitions that differ only in what they point to.

### 4.8 Names

1. A group with an own name keeps it when no other group in its namespace has that name. Records (structures and unions, one C tag namespace) and enumerations are separate namespaces, as in the table format.
2. Several groups with one name are different definitions; each takes `name~1`, `name~2`, ... in type id order of their first type, and no group takes the bare name, which would answer for the wrong definition (O2).
3. An anonymous group is named by its members: `struct{a,b}`, `union{a,b}` or `enum{A,B}`, listing the names it gives access to in declaration order (an embedded member contributes its own members' names). `{` is not in any identifier, so such a name never equals one the kernel wrote. A name longer than `MaxNameBytes` less 8 bytes is cut after the last whole member name that fits and ends `...}`.
4. Anonymous groups whose names are equal take `~2`, `~3`, ... after the first, in type id order.

### 4.9 Scalars

Every named INT and FLOAT gives a scalar of its size: an INT with the BOOL encoding is `bool`, with CHAR is `char`, otherwise `integer`, signed with the SIGNED encoding; a FLOAT is `float` (T3, T11). INTs of one name with different sizes or encodings give no scalar, and the conflict is counted; narrow INTs that differ only in bits are the same scalar. `void` is always a scalar of width 0 (T1).

### 4.10 Forward declarations

A FWD whose name no record carries is written as a record with no members: the table knows the name and that it cannot be read.

### 4.11 Typedef aliases

A typedef is a name the kernel's source uses for a type, so the table answers a lookup by it.

1. Its target is its shape (4.3). A pointer, array, function or `void` target has no table name and is counted. A target only declared (4.10) is counted.
2. A scalar target gives a scalar of the typedef's name with the target's width and encoding; an enumeration target a copy of it under the typedef's name; a record target a record of the target's size whose one member embeds the target at offset 0.
3. A typedef whose name is its target's name, or the name of its 4.4 anonymous type, adds nothing. A name already used in the alias's namespace is not replaced. Typedefs of one name with different targets give no alias. A name that is not an identifier is refused (B5).

Member types are written as their shapes' targets, not as typedef names: `pid_t pid` is written `int`.

### 4.12 Addresses

1. Each kallsyms entry with a non-empty name gives a link-time address: under the absolute per-CPU rule a non-negative stored offset is the address itself; otherwise the address less `VirtualShift` (K1, S05). An address below the shift is not placed. A name that is not UTF-8 is not kept.
2. A name whose placed entries hold one address keeps it. A name at several addresses keeps the one global address when exactly one exists (K3, K4): every other file's reference binds to it. Any other name at several addresses is left out (O1), because kallsyms records no file and the table could not say which one a tool means.
3. `linux_banner` must keep an address; otherwise `ErrBannerSymbol`.

### 4.13 Variable types

1. Each VAR gives its name the shape of its type (4.3). VARs of one name with different shapes, or a shape that refers to a refused type, give no type.
2. In the DATASEC `.data..percpu`, when `__per_cpu_start` has an address, a VAR whose symbol's address is not `__per_cpu_start` plus its offset gets no type (B7, M13).
3. A kept symbol with a VAR type takes it as its table type.
4. A symbol the BTF does not type (B2) has no table type, and none is made for it: the table types only what the image records. A tool that needs such a symbol's extent or entry form takes them from other records of the image, not from a type the tool names. `linux.syscall.list` ends `sys_call_table` at the next symbol in the image's kallsyms order, with entries of the pointer width (S11). `linux.tracing.check_tracepoints` takes its section from the addresses of `__start___tracepoints_ptrs` and `__stop___tracepoints_ptrs`, and its entry form from the BTF type of `module.tracepoints_ptrs` (S62 TP1, TP4).

### 4.14 Output

Scalars, records, enumerations and addresses are sorted by name; members stay in declaration order. An enumeration's constants are in value order, then name, the order the table format writes them (`symbols/FORMAT.md`); an anonymous enumeration's name (4.8 step 3) still lists them in declaration order. A record with no members (an empty structure, a forward declaration, a record whose every member was refused) is kept, with an empty member list. The same BTF and kallsyms give the same table.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Names of records, enumerations, members, constants and typedefs are identifiers | B5 | The item is refused and counted |
| INT and FLOAT names are non-empty text within `MaxNameBytes` | T3; the table format writes UTF-8 | Members of that type are refused |
| Union members at offset 0; struct members in non-decreasing order; offsets inside the size | B4 | Member refused |
| Non-bitfield members start on a byte | B6 | Member refused |
| `kind_flag` int members are regular | T5 | Member refused |
| A bitfield fits a storage unit of its type | P1 | Member refused |
| Bitfields only on INT and enumeration types | T5 | Member refused |
| A function type only under a pointer | T9; C has no member of function type | Member refused |
| Type chains end within `MaxRecursionDepth` steps; expressions hold at most 32 operators | 4.2; `symbols/FORMAT.md` | Member refused |
| Enumeration sizes 1, 2, 4 or 8; constant names do not repeat | T6; C | Enumeration refused |
| INTs of one name agree | 4.9 | No scalar of that name |
| A name with several different definitions answers for none | 4.8 | `name~N` for each |
| A symbol name answers with one address | K2, K3, K4 | Name left out |
| A per-CPU variable's type needs its address to match its section offset | B7, M13 | No type |

## 6. Failure modes

| Case | Result |
|---|---|
| No BTF, wrong pointer size, more types than `MaxTableEntries` | `ErrNoBTF`, `ErrPointerSize`, `ErrTooManyTypes` (wrapped with the value) |
| Banner empty, not UTF-8, or with a NUL before its last byte | `ErrBanner` |
| Unknown address rule | `ErrAddressRule` |
| `linux_banner` without one address | `ErrBannerSymbol` |
| A member, type, typedef or scalar refused | Left out; `TypeReport.Refused` counts it under its reason |
| A symbol name left out | `LinuxReport.Ambiguous`, `Unplaced` or `NotUTF8` |
| A variable not typed | `LinuxReport.Untyped` or `Misplaced` |

Errors are package sentinels with the prefix `generator:`. Refusal reasons are lower-case phrases without a trailing period.

## 7. Result schema

`AssembleLinux` returns a `symbols.Declaration`: `PointerWidth`, `LinuxBanner` (the banner as given), `Scalars`, `Records`, `Enumerations`, `Addresses` (link-time; `Type` set for typed variables). `TypesFromBTF` returns `BTFTypes{Scalars, Records, Enumerations, Report}`.

`TypeReport`:

| Field | Meaning |
|---|---|
| `Merged` | Types identical to one already written (4.7) |
| `NamedByMembers` | Anonymous types named from their members (4.8 step 3) |
| `Suffixed` | Names given a `~N` suffix (4.8 steps 2 and 4) |
| `Conflicts` | Names with several different definitions, sorted (4.8 step 2) |
| `Aliases` | Typedef names added (4.11) |
| `Forwards` | Forward declarations written as names (4.10) |
| `Padding` | Unnamed non-record members not written (4.5 step 7) |
| `Refused` | Reason to count |

`LinuxReport`:

| Field | Meaning |
|---|---|
| `Names` | Distinct non-empty kallsyms names |
| `Ambiguous` | Names left out for several addresses, sorted |
| `Unplaced` | Names with no entry at or above the shift |
| `NotUTF8` | Names that are not UTF-8 |
| `Typed`, `Untyped`, `Misplaced` | Kept symbols typed by a VAR; VAR names with disagreeing or refused types; per-CPU variables off their section offset |
| `Types` | The `TypeReport` |

## 8. Limits

- `MaxRecursionDepth`: steps through typedefs, qualifiers, pointers and arrays (4.2, 4.3); depth of embedded members when naming; partition rounds (4.7).
- `MaxNameBytes`: every name read from the BTF (B5's `KSYM_NAME_LEN` is 512 from v6.1; the default 4096 is above it) and the length of member-list names (4.8).
- `MaxTableEntries`: BTF types accepted (4.1); the table builder applies it again to members.

## 9. Acceptance

- Synthetic BTF built with `symbols/btf/btftest` in `symbols/generator/types_test.go` and `assemble_test.go`: scalar kinds and conflicting INTs; member places and expressions (typedef and qualifier chains, pointers to forward declarations, arrays, pointers to functions and void, trailing zero-length arrays), each checked through an encode and decode of the table format; `kind_flag` bitfields, a packed record's fallback unit and a field no unit holds; narrow INT bitfields without `kind_flag`; a non-regular `kind_flag` int; an enumeration bitfield; every B4, B5 and B6 rule; refused chains (33 pointers, a typedef loop, a function member, a VAR member); embedded members and padding; identical anonymous unions merged and a different one suffixed; a name cut to `MaxNameBytes`; one name with two different definitions and an identical third; definitions told apart only by their pointees; typedef naming, scalar, record and enumeration aliases, derived typedefs and conflicting typedefs; empty anonymous structures and unions named `struct{}` and `union{}` with their typedefs as aliases; constants in value order and empty member lists kept; enumeration signedness and ENUM64; refused types and the members that refer to them; repeatability; input errors; link addresses under both rules; names with several addresses; per-CPU variable types, a misplaced and a disagreeing variable; a built table answering members, symbols and the banner.
- Fuzz target: `FuzzTypesFromBTF` (any bytes `symbols/btf` parses convert to a table that `symbols.BuildWith` accepts), 30 s.
- Measured with `btffacts`, 2026-11-12. The tool run records every type, member, constant and symbol the 53 linux and any tools ask the session's table for, and checks each unanswered one against the BTF and kallsyms themselves.

| Figure | mem3_ubuntu24 (6.17) | mem4_fedora40 (6.14) |
|---|---|---|
| Table: scalars, records, enumerations | 375, 13989, 2736 | 367, 13782, 2584 |
| Records named by the generator (member lists or suffixes) | 2048 | 1985 |
| Members: all; embedded, bitfields, arrays, pointers | 79667; 1316, 3237, 5025, 18446 | 78318; 1266, 3033, 5272, 17768 |
| Merged (4.7); named by members; suffixed | 1064; 2815; 192 | 1232; 2721; 188 |
| Names with different definitions (4.8 step 2) | 30 | 30 |
| Typedef aliases; forward names; padding | 530; 119; 0 | 514; 106; 0 |
| Typedefs of a pointer, array, function or void; of a declared-only type | 1808; 4 | 1966; 4 |
| Other refusals | 0 | 0 |
| Addresses; names left out for several addresses; unplaced; not UTF-8 | 210415; 2269; 0; 0 | 216496; 2965; 0; 0 |
| Typed variables; untyped; misplaced | 439; 0; 0 | 411; 0; 0 |
| Generation time with no tools running: BTF read and parse; kallsyms decode; whole declaration (decode, read, banner, convert, addresses) | 74 ms; 75 ms; 612 ms | 52 ms; 74 ms; 585 ms |
| Tool requests for types: asked, answered (as a record or enumeration; as a scalar width) | 45; 43; 2 | 45; 43; 2 |
| Tool requests for members: asked, answered; unanswered that the BTF records | 406, 401; 0 | 409, 401; 0 |
| Tool requests for constants: asked, answered | 1, 1 | 1, 1 |
| Tool requests for symbols: asked, answered; unanswered that kallsyms holds | 99, 93; 0 | 98, 93; 0 |
| Tool requests for symbol types: asked, answered; that the BTF records | 1, 0; 0 | 1, 0; 0 |

The unanswered members are the alternatives the tools try for other kernels (`task_struct.pids`, `mod_tree_root.data_addr_min`, `netns_nf.hooks_decnet` and the like); none is in either capture's BTF. The unanswered symbols (`ia32_sys_call_table`, `x32_sys_call_table`, `nf_hooks`, `tcp_seq_ops`, `legacy_special_mapping_vmops`, and `tk_core` on mem3) are not in kallsyms. The one symbol type asked for, `sys_call_table`, has no VAR (B2); `linux.syscall.list` then bounds the table by kallsyms (4.13 step 4) and gives 470 rows on mem3_ubuntu24 and 467 on mem4_fedora40. `linux.tracing.check_tracepoints` asks for no symbol type and gives 1064 and 1367 rows (`btffacts -only`, 2026-11-12). No tool asked for any of the 30 names with several definitions.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision: a symbol name at several addresses keeps its one global address, else is left out (2269 and 2965 names). The kernel's own `kallsyms_lookup_name` would give the lowest address (K2). | Owner choice |
| O2 | Owner decision: a name with several different definitions answers for none; each definition is `name~N` in type id order (30 names on each capture, none asked for by a tool). | Owner choice |
| O3 | Owner decision: an unsigned ENUM64 constant of 2^63 or more is written as its bit pattern, a negative signed constant, because table constants are signed 64-bit. | Owner choice, or a table format change |
| O4 | A pre-v6.1 kernel's ENUM has no signedness flag and stores `__s32` (T6); this specification reads `kind_flag` 0 as unsigned, which turns such a kernel's negative constants into large positive ones. No capture of such a kernel exists. | A pre-v6.1 capture (Q7) |
| O5 | BTF types only per-CPU variables (B2), so symbols such as `sys_call_table` and `__start___tracepoints_ptrs` have no type, and `linux.tracing.check_tracepoints` stops on both captures. Owner decision 2026-11-12: the type source is what the image records. Done: 4.13 step 4 states the rule; no code change was needed. `linux.tracing.check_tracepoints` already reads only the section bounds' addresses and the BTF type of `module.tracepoints_ptrs` (S62), and runs on both captures: 1064 and 1367 rows. `linux.syscall.list` bounds `sys_call_table` by kallsyms: 470 and 467 rows. Measured with `btffacts -only`, 2026-11-12. `linux.syscall.list` reads its entries at the pointer width, a fact of the kernel source (S11), not of the BTF. Owner decision 2026-11-12 (follow-up D8): accept pointer-width syscall entries. Done: recorded here; no code change. | Owner decision: give such tools a type source the image records, or let them name the type themselves |
| O6 | Owner decision: the names this specification makes (`struct{...}`, `union{...}`, `enum{...}`, `~N`), anonymous enumerations named by their constants like records by their members, and typedef aliases are new vocabulary of the table (Q2). `TypeReport`, `LinuxReport.Untyped`, `Misplaced`, `Types` and `BTFTypes.Report` are new; `LinuxReport.Unplaced` now counts names, not entries. | Owner choice |
| O7 | Owner decision: the DWARF generator (`GenerateFromELF`, `GenerateFromMachO`, `GenerateFromPE`, `Adapter`) is removed. It read a file, not the image, and had no caller; `symbols.Generator` and `symbols.Resolver` remain in the symbols package with no implementation. Owner decision 2026-11-12: remove the interfaces. Done: neither interface is in the `symbols` package any more (removed with S58 O1), and no file in the repository refers to `symbols.Generator` or `symbols.Resolver`; checked 2026-11-12, no caller needed a fix. | Owner choice: restore from a DWARF specification, or remove the interface |
| O8 | Owner decision: the old symbol-table converter script is removed (plan 5.2). README.md and `.gitignore` named it. Done: neither names it any more (checked 2026-11-12). | README and `.gitignore` edits |
| O9 | The specification did not say whether the order of an enumeration's constants and an empty member list are part of the generated output. Owner decision 2026-11-12 (follow-up L1): state it, constants in value order and empty member lists kept. Done: 4.14 states both. `byValue` in `symbols/generator/types.go` sorts every enumeration's constants, and its typedef copies', by value, then name, as `symbols/FORMAT.md` writes them; a forward declaration now carries an empty member list like every other record with no members. `TestTheOutputKeepsConstantsByValueAndEmptyMemberLists` checks both. The real-image round trip (`TestAssembledLinuxTableMatchesTheKernelsDebugInfo`) no longer reorders constants before it compares the table with the file read back, and passes on both captures. | Owner choice |
| O10 | 4.4 gave the one empty anonymous structure of the BTF the name of its first typedef, `lockdep_map_p`, so every empty member (`local_lock_t` locks, `netdevice_tracker` fields, flexible-array `__empty_` members) was typed by a name that reads as a pointer (B8, M15). Owner decision 2026-11-12 (follow-up L2): name anonymous types by their members, under the owner's 2026-11-11 rule, and reword 4.4. Done: 4.4 now leaves an anonymous structure or union with no members to 4.8 step 3, so it is `struct{}` or `union{}` and its typedefs are aliases (4.11); `memberless` in `symbols/generator/classes.go`; `TestAnEmptyAnonymousTypeIsNamedByItsMembersNotByATypedef`. On each capture two more records (`struct{}`, `union{}`), two more aliases (`lockdep_map_p`, `release_pages_arg`) and two more names by members (section 9). Every empty member is now typed `struct{}`, `union{}` or one of their aliases. | Owner choice |
| O11 | The generator adds typedef aliases by the rule of 4.11. Owner decision 2026-11-12 (follow-up L3): accept with counts. Done: recorded here. Before O10, 528 aliases on mem3_ubuntu24 and 512 on mem4_fedora40; after O10, 530 and 514 (section 9). | Owner choice |
| O12 | The type counts of section 9 were measured again on 2026-11-12. Owner decision 2026-11-12 (follow-up L4): accept the new counts. Done: recorded here; O10 changed them as stated there. | Owner choice |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Global address else omit |
| O2 | None, use name~N |
| O3 | Write bit pattern |
| O4 | Defer to v0.2.0 |
| O5 | Type source the image records; pointer-width syscall entries accepted |
| O6 | Accept |
| O7 | Remove the interfaces |
| O8 | Edit now |
| O9 | State: constants in value order, empty member list kept |
| O10 | Name anonymous types by members, reword 4.4 |
| O11 | Accept with counts |
| O12 | Accept |

## 11. Provenance

Written from the Linux kernel sources at v4.19, v6.1, v6.4, v6.14 and v6.17 (git.kernel.org, accessed 2026-11-12), the x86-64 psABI (accessed 2026-11-12), the System V ABI ELF gABI chapter 4, POSIX.1-2024 XCU, the project's specifications S05 and S38 and `symbols/FORMAT.md`, and the project's measurements on mem3_ubuntu24 and mem4_fedora40. Every rule rests on the sources and measurements above. Author: the project.
