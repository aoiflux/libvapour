# S07: Linux module discovery, hidden-module and compare rules, taints and parameters

Version 1, 2026-11-12.

## 1. Purpose

A module that wants to hide unlinks itself from the kernel's module list, and sometimes also removes its sysfs directory. Its `struct module` and code stay in memory, because the kernel still runs them. An examiner finds such a module by comparing independent views of the module set: the module list, the sysfs view, and a scan of the memory modules are loaded into. This specification defines the three views, how they are combined into the five module tools, and how each module's taint flags and parameter values are reported.

The module model (reading and checking one `struct module`) is S06.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Model | S06 module model | Reads and checks one module. |
| Session symbol table | symbols | `modules`, `module_kset`, `mod_tree`, `taint_flags` and the `param_ops_*` symbols. |
| Limits | effective `limits.Limits` | Section 8. |
| Options | tool options | Section 7. |

## 3. Facts from the sources

Tags as S06 section 3.

| # | Fact | Source |
|---|---|---|
| D1 | `modules` is a `LIST_HEAD` of every module, linked through `module.list`. A module is added while `UNFORMED`, before its sysfs set-up. | `kernel/module.c` v4.19; `kernel/module/main.c` v6.17 (`LIST_HEAD(modules)`, `add_unformed_module`). |
| D2 | `module_kset` is a `struct kset *`. `mod_sysfs_init` sets `mod->mkobj.kobj.kset = module_kset` and adds the kobject, which links `kobject.entry` onto `kset.list`. | `kernel/params.c` and `kernel/module/sysfs.c` v6.17; `lib/kobject.c` `kobj_kset_join`; `include/linux/kobject.h`. |
| D3 | Built-in code that has parameters or a version also gets a `module_kobject` on `module_kset`, made by `lookup_or_create_module_kobject` with `mod = THIS_MODULE`. Outside a module `THIS_MODULE` is `((struct module *)0)`. | `kernel/params.c` v6.17; `include/linux/init.h` v6.17; `include/linux/export.h` v4.19. |
| D4 | A module's kobject is `module.mkobj.kobj`, and `module_kobject.mod` points back at the module (S06 F4). | `include/linux/module.h`; `kernel/module/sysfs.c`. |
| D5 | `mod_tree.addr_min` starts at `-1UL` and `addr_max` at 0. They grow to cover every module region ever loaded (S06 F9). | `kernel/module/main.c` v6.17; `kernel/module.c` v4.19. |
| D6 | On x86-64, modules are placed between `MODULES_VADDR` (`__START_KERNEL_map + KERNEL_IMAGE_SIZE`) and `MODULES_END`. `__START_KERNEL_map` is 0xffffffff80000000. `KERNEL_IMAGE_SIZE` is 512 MiB, or 1 GiB with KASLR. `MODULES_END` is 0xffffffffff000000, or 0xfffffffffe000000 with `CONFIG_DEBUG_KMAP_LOCAL_FORCE_MAP`. So every module address lies in [0xffffffffa0000000, 0xffffffffff000000). | `arch/x86/include/asm/pgtable_64_types.h`, `arch/x86/include/asm/page_64_types.h`, v4.19, v6.17. |
| D7 | On 32-bit x86, `MODULES_VADDR` is `VMALLOC_START` and `MODULES_END` is `VMALLOC_END`. They depend on the memory split and are not constants. | `arch/x86/include/asm/pgtable_32_areas.h` v6.17. |
| D8 | x86 pages are 4096 bytes. | `arch/x86/include/asm/page_types.h` v6.14. |
| T1 | `module.taints` is an `unsigned long` using the same bit numbers as the kernel's taint mask. | `include/linux/module.h`, every tag. |
| T2 | `struct taint_flag { char c_true; char c_false; bool module; }`; v6.14 and v6.17 also have `const char *desc` (v6.4 does not), set by `TAINT_FLAG` to the stringified flag name without the `TAINT_` prefix. `taint_flags[]` is indexed by bit number. | `include/linux/kernel.h` v4.19; `include/linux/panic.h` and `kernel/panic.c` v6.17. |
| T3 | The flag names and letters, by bit: 0 PROPRIETARY_MODULE P, 1 FORCED_MODULE F, 2 CPU_OUT_OF_SPEC S, 3 FORCED_RMMOD R, 4 MACHINE_CHECK M, 5 BAD_PAGE B, 6 USER U, 7 DIE D, 8 OVERRIDDEN_ACPI_TABLE A, 9 WARN W, 10 CRAP C, 11 FIRMWARE_WORKAROUND I, 12 OOT_MODULE O, 13 UNSIGNED_MODULE E, 14 SOFTLOCKUP L, 15 LIVEPATCH K, 16 AUX X, 17 RANDSTRUCT T, 18 TEST N, 19 FWCTL J. v4.19 has bits 0 to 17. | `include/linux/kernel.h` and `kernel/panic.c` v4.19; `include/linux/panic.h` and `kernel/panic.c` v6.17. |
| T4 | The kernel prints a module's taints (in `/proc/modules` and oops reports) as the `c_true` letters of the set bits whose entry has `module` true, in bit order. | `kernel/module/main.c` `module_flags_taint` v6.17; `kernel/module.c` v4.19. |
| P1 | `module.kp` points at `num_kp` entries of `struct kernel_param { const char *name; struct module *mod; const struct kernel_param_ops *ops; u16 perm; s8 level; u8 flags; union { void *arg; const struct kparam_string *str; const struct kparam_array *arr; }; }`. | `include/linux/moduleparam.h` v4.19, v6.17. |
| P2 | Each standard parameter type has one exported `kernel_param_ops` object, `param_ops_<type>`, and a getter that prints the value: `byte` `%hhu`, `short` `%hi`, `ushort` `%hu`, `int` `%i`, `uint` `%u`, `long` `%li`, `ulong` `%lu`, `ullong` `%llu`, `hexint` `%#08x` (present at v6.1, absent at v4.19); `bool` and `bool_enable_only` print `Y` or `N` from a `bool`; `invbool` prints the opposite; `bint` prints an `int`; `charp` prints the string `arg` points at; `string` prints `kparam_string.string`. | `kernel/params.c` `STANDARD_PARAM_DEF`, `param_get_bool`, `param_get_invbool`, `param_ops_bint`, `param_get_charp`, `param_get_string`, v4.19, v6.17. |
| P3 | `param_array_ops` prints an array as its elements joined by `,`, each printed by `kparam_array.ops`, element *i* at `elem + elemsize × i`. The count is `*num` when `num` is set and `max` otherwise. | `kernel/params.c` `param_array_get`; `struct kparam_array` in `include/linux/moduleparam.h`, v6.17. |
| P4 | The kernel prints a null `char *` through `%s` as `(null)`. | `lib/vsprintf.c` `string()`, v6.17. |
| P5 | Parameter getters write into a buffer of `PAGE_SIZE` bytes. | `kernel/params.c` (`scnprintf(buffer, PAGE_SIZE, ...)`), v6.17. |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | On both captures the symbol table types `mod_tree_root` with `addr_min` and `addr_max` and no `data_addr_*` members, `kset` with `list`, `module_kobject` with `kobj` and `mod`, `taint_flag` with `desc`, and `kernel_param`, `kparam_array` and `kparam_string` as in P1 and P3. | `modulefacts`, 2026-11-12. |
| M2 | View sizes and overlaps per capture. | Section 9 table. |

## 4. Algorithm

### 4.1 The list view

Walk `modules` forward with the S01 list walk, container `module`, member `list`. Read each entry with S06 4.2. The view is the entries that read, in list order. Entries that fail are counted per error. A walk that ends other than **Closed** is reported with where and why it ended (S01).

### 4.2 The sysfs view

1. Read the `module_kset` pointer and put it through the address form. A missing symbol is `ErrNoKset`. A null or unreadable pointer is `ErrNoKset` too.
2. Walk `kset.list` forward with the S01 list walk, container `kobject`, member `entry`.
3. For each kobject, take its `module_kobject` with `container_of` through `module_kobject.kobj` (D4), and read `mod`. A null `mod` is built-in code (D3): counted and skipped.
4. Read the module at `mod` with S06 4.2.

The view is the modules that read, in list order.

### 4.3 The scan view

1. **Ranges.** Read `mod_tree.addr_min` and `addr_max`, and `data_addr_min` and `data_addr_max` when the members exist (D5, S06 F9). A pair with `min ≥ max` is empty. A missing `mod_tree` is `ErrNoModuleArea`.
2. **Range check.** With 8-byte pointers, a range not inside [0xffffffffa0000000, 0xffffffffff000000) is refused with `ErrModuleArea` (D6). With 4-byte pointers there is no fixed area (D7), and only the cap applies. A range longer than `MaxRegionScanBytes` is refused with `ErrModuleArea`.
3. **Candidates.** For each 4096-byte page in the range (D8) that reads, and each address in it aligned to the pointer width: read `state` and `mkobj.mod`. The address is a candidate when the state is 0 to 3 (S06 F3) and `mkobj.mod` equals the address (S06 F4).
4. **Acceptance.** Read the candidate with S06 4.2. It is accepted when the read succeeds and the module is both self-linked and placed (S06 F4, F5).
5. Stop after `MaxListEntries` accepted modules, with a diagnostic.

The view is the accepted modules, in address order.

### 4.4 Combining the views

Module identity is the `struct module` address.

| Tool | Rows |
|---|---|
| `linux.module.list` | The list view. |
| `linux.module.find_hidden` | Scan-view modules whose address is not in the list view. |
| `linux.module.compare_sysfs` | List-view modules not in the sysfs view, then sysfs-view modules not in the list view. |
| `linux.module.compare` | The union of the three views: list order, then sysfs-only in sysfs order, then scan-only in address order. Each row says which views hold the module. |
| Known modules, for address lookup (S06 4.5) | The same union as `linux.module.compare`. |

A view that cannot be built (for example, `ErrNoKset`) fails the tools that need it. `linux.module.compare` and the known-module set build the views they can, report the failed ones in a diagnostic, and fail only when no view builds.

### 4.5 Taints

1. If the module has no `taints` member, the taints are absent.
2. For each set bit *i* below 8 × the pointer width, take the flag entry:
   - From the image: entry *i* of `taint_flags`, of the size of `taint_flag`. It is used when it reads, `c_true` is a letter A to Z, `c_false` is a space or a letter A to Z, and `module` is 0 or 1. The name is the `desc` string when that member exists and reads; otherwise the T3 name for bit *i*.
   - Otherwise, from T3 when *i* ≤ 19.
   - Otherwise, the flag is unknown, named `bit <i>`.
3. **Names** (the default form): the names of every set bit in bit order, joined by `,`.
4. **Letters** (the `plain_taints` option of `linux.module.compare`): the T4 string, the `c_true` letters of set bits whose entry has `module` true, in bit order. An unknown bit adds nothing.

### 4.6 Parameters

1. Resolve, from the session symbol table, the addresses of `param_ops_<type>` for every type in P2, and of `param_array_ops`. A missing symbol means that type cannot be decoded.
2. Read `kp` and `num_kp`. A count above `MaxTableEntries` is cut, with a diagnostic.
3. For each `kernel_param`: read `name` (a string up to `MaxNameBytes`) and `ops`, and decode by `ops`:
   - A P2 type: read the value at `arg` with the type's width (`bool` is 1 byte; `long` and `ulong` are pointer-width) and print it with P2's format.
   - `charp`: read the pointer at `arg`; print `(null)` for 0 (P4) and the string otherwise.
   - `string`: read `kparam_string.string` at `str` and print it.
   - `param_array_ops`: read the `kparam_array` at `arr` and print P3's list, decoding each element by the element `ops`. An element type that cannot be decoded leaves the whole array undecoded.
   - Anything else is undecoded.
4. Strings are read up to 4096 bytes (P5) and end at the first NUL.
5. The text is `name=value` for each decoded parameter and `name` alone for an undecoded one, joined by a space, in table order.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| A scan candidate has state 0 to 3 and `mkobj.mod` equal to its own address | S06 F3, F4 | Not a candidate |
| An accepted scan module is placed | S06 F5 | Not accepted |
| Scan ranges lie in the x86-64 module area | D6 | `ErrModuleArea` |
| A taint entry from the image has the shape in 4.5 step 2 | T2, T3 | The T3 table is used |
| A `module_kobject` with a null `mod` is built-in | D3 | Skipped and counted |

List and sysfs entries are not required to be self-linked or placed: a module still in `UNFORMED` is on the list before its sysfs set-up (D1). The row reports the S06 facts.

## 6. Failure modes

| Case | Result |
|---|---|
| `modules` missing | `ErrNoModuleList` |
| `module_kset` missing, null or unreadable | `ErrNoKset` |
| `mod_tree` missing | `ErrNoModuleArea` |
| Range outside the module area or over the cap | `ErrModuleArea` |
| A list or kset walk ends other than Closed | Diagnostic with the end and the place |
| Entries that do not read | Counted per error, one diagnostic per view |
| Taint entry not readable | T3 table, no diagnostic |
| Parameters not readable | Diagnostic; the readable ones are kept |
| Strict mode | A view that left anything out (failed entries, a walk that did not close, or the cap) is an error. Unread parameters stay a diagnostic. |

## 7. Result schema

Module row (`linux.module.list`, `linux.module.find_hidden`, `linux.module.compare_sysfs`):

| Field | Meaning |
|---|---|
| `Address` | `struct module` address |
| `Name` | S06 |
| `State` | S06 state name |
| `Source` | `list`, `sysfs` or `scan`: the view the row comes from |
| `Base` | S06 base |
| `CoreSize`, `InitSize` | S06, in bytes |
| `Taints` | Names (4.5 step 3); empty when absent |
| `TaintsUnread` | The `taints` member did not read |
| `Parameters` | 4.6 step 5 |
| `File` | Name of the ELF file written (S08), or empty |
| `FileState` | `none` (no dump asked), `written`, or `failed` |

Compare row (`linux.module.compare`): `Address`, `Name`, `InList`, `InSysfs`, `InScan`, `Taints` (names, or letters with `plain_taints`), `TaintsUnread`.

Options: `<tool>.dump` (bool) on the three module-row tools, which writes each module's ELF rebuild (S08) to the output directory; `linux.module.compare.plain_taints` (bool).

## 8. Limits

- `MaxListEntries`: list and kset walks (S01), and accepted scan modules.
- `MaxRegionScanBytes`: total length of the scan ranges.
- `MaxTableEntries`: parameters per module.
- `MaxNameBytes`: parameter names.

## 9. Acceptance

- Synthetic fixtures: a list, a kset with a built-in entry, a module area holding a listed module and a hidden one, a candidate that is self-linked but not placed, each taint path, and each parameter type including arrays and a null `charp`.
- A fuzz target over the scan and the parameter decoder on arbitrary memory.
- On both captures:

| Capture | List | Sysfs | Scan | Hidden | List not in sysfs | Sysfs not in list |
|---|---|---|---|---|---|---|
| mem3_ubuntu24 | 63 | 63 (129 built-in skipped) | 63 | 0 | 0 | 0 |
| mem4_fedora40 | 61 | 61 (117 built-in skipped) | 61 | 0 | 0 | 0 |

Measured with `modulefacts`, 2026-11-12. On both captures the three views hold the same modules, and no list or kset walk ends other than Closed. The scan ranges are 0xffffc04dd000 to 0xffffc0987000 and 0xffffc0409000 to 0xffffc08ec000 in the 48-bit address form. Neither capture has a tainted module, so taint decoding is checked by fixtures only.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Scan candidates are taken at pointer alignment. `struct module` is cache-line aligned, which would allow a coarser step, but the line size depends on the kernel configuration. | Kept; no closure needed unless speed requires it |
| O2 | A module that also clears its own `mkobj.mod`, or moves its `struct module` out of its core data, is not found by the scan. | A later scan rule, if a sample shows it |
| O3 | 4-byte pointers and `data_addr_*` ranges are written from the source only. | A capture that has them (Q7) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Pointer alignment |
| O2 | Defer to v0.2.0 |
| O3 | Ship as written, mark untested |

## 11. Provenance

Written from the kernel sources at the tags in S06 section 3 and the project's measurements. Every rule rests on the sources and measurements above.
