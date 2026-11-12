# S11: Linux system call table check

Version 1, 2026-11-12.

## 1. Purpose

A rootkit that overwrites a system call table slot runs its own code in place of `read`, `getdents64` or `kill` for every process. An examiner needs each entry of each system call table the kernel has: the handler address, the module or kernel symbol it lies in, and whether the kernel still dispatches system calls through that table at all. Between v6.4 and v6.14 (the tags checked) the x86 kernel moved to dispatch through a `switch`, and keeps `sys_call_table` only for tracing, so a rewritten entry there no longer changes what a system call runs; the rows say so.

This specification defines which tables exist at each tag, how a table's length is found when the symbol table gives no type, and how each handler is named. Address ownership is S06 4.5.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxkern.Kernel` | Memory, symbol table, pointer width, address form and the symbol list. |
| Module model | S06 model, with the S07 known-module set | Owner of an address outside the kernel image. |
| Symbols | session symbol table | `sys_call_table`, `ia32_sys_call_table`, `x32_sys_call_table`; `x64_sys_call`, `ia32_sys_call`, `x32_sys_call`; `_text`, `_etext`; the declared type of a table when the symbol table has it. |
| Limits | effective `limits.Limits` | Section 8. |
| Options | none | The tool takes no options. |

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17. The supported captures run 6.14 (Fedora 40) and 6.17 (Ubuntu 24).

| # | Fact | Source |
|---|---|---|
| T1 | v4.19 defines `sys_call_table[__NR_syscall_max+1]` with every entry first set to `&sys_ni_syscall` and then `[nr] = sym` for each table line. From v6.1 it is `sys_call_table[]` filled in order with `__x64_##sym` from `<asm/syscalls_64.h>`, so its length is the number of lines the generated header holds. | `arch/x86/entry/syscall_64.c`, every tag. |
| T2 | From v6.1 the header generator emits `__SYSCALL(nxt, sys_ni_syscall)` for every number missing below the next table line, and `__SYSCALL(nr, sys_ni_syscall)` for a line with no entry point. So the header has one line for every number from 0 to the highest, and no entry is null. At v4.19 the `[0 ... max]` default gives the same. | `scripts/syscalltbl.sh` v6.1 to v6.17; `arch/x86/entry/syscalls/syscalltbl.sh` and `syscall_64.c` v4.19. |
| T3 | ABIs per generated header: `syscalls_64.h` from the `common` and `64` lines of `syscall_64.tbl`, `syscalls_x32.h` from `common` and `x32`, `syscalls_32.h` from the `i386` lines of `syscall_32.tbl`. At v4.19 `syscalls_64.h` also holds the `x32` lines (numbers 512 to 547) when `CONFIG_X86_X32_ABI` is set, and x32 calls index `sys_call_table` after `__X32_SYSCALL_BIT` is masked off. | `arch/x86/entry/syscalls/Makefile` v6.1 to v6.17; `syscalltbl.sh` and `arch/x86/entry/common.c` v4.19. |
| T4 | Highest numbers, so table lengths (highest + 1): `common`/`64`: 334 at v4.19, 450 at v6.1 and v6.4, 466 at v6.14, 469 at v6.17. `i386`: 386, 450, 450, 466, 469. `x32`: 512 to 547 at every tag. | `arch/x86/entry/syscalls/syscall_64.tbl` and `syscall_32.tbl`, every tag. |
| T5 | Tables that exist on x86-64: v4.19 `sys_call_table` and, with `CONFIG_IA32_EMULATION`, `ia32_sys_call_table`; v6.1 and v6.4 also `x32_sys_call_table` with `CONFIG_X86_X32_ABI`; v6.14 and v6.17 only `sys_call_table`. At v6.14 and v6.17 `ia32_sys_call_table` and `x32_sys_call_table` are not defined, and `ia32_sys_call`, `x32_sys_call` and `x64_sys_call` are `switch` functions over the same headers. | `arch/x86/entry/syscall_64.c`, `syscall_32.c`, `syscall_x32.c` (absent at v4.19 and v6.17) and `arch/x86/include/asm/syscall.h`, every tag. |
| T6 | Dispatch: at v4.19, v6.1 and v6.4 `do_syscall_64` and the 32-bit path call `sys_call_table[nr]`, `x32_sys_call_table[xnr]` and `ia32_sys_call_table[nr]`. At v6.14 and v6.17 they call `x64_sys_call`, `x32_sys_call` and `ia32_sys_call`. v6.14 notes that "the sys_call_table[] is no longer used for system calls, but kernel/trace/trace_syscalls.c still wants to know the system call address"; that file's `arch_syscall_addr` reads `sys_call_table[nr]`. | `arch/x86/entry/common.c` v4.19 to v6.14; `syscall_64.c` and `syscall_32.c` v6.17; `kernel/trace/trace_syscalls.c` v6.17. |
| T7 | On 32-bit x86 the i386 table is the symbol `sys_call_table`: `asm/syscall.h` has `#define ia32_sys_call_table sys_call_table` under `CONFIG_X86_32` (v4.19 to v6.4), and v6.14 and v6.17 define `sys_call_table` in `syscall_32.c` only under `CONFIG_X86_32`. | `arch/x86/include/asm/syscall.h` v4.19, v6.1; `arch/x86/entry/syscall_32.c` v6.14, v6.17. |
| T8 | `sys_call_ptr_t` is a pointer to a function; every table is `const`. | `arch/x86/include/asm/syscall.h`, every tag. |
| T9 | x86-64 builds per-ABI stubs for each system call, named `__x64_sys_<name>`, `__ia32_sys_<name>`, `__ia32_compat_sys_<name>`, and for x32 compat calls `__x32_compat_sys_<name>` (v4.19) or `__x64_compat_sys_<name>` (v6.1 on). Tables name `__x64_` stubs for the 64-bit and x32 ABIs and `__ia32_` stubs for the i386 ABI. | `arch/x86/include/asm/syscall_wrapper.h`, every tag; `syscall_64.c`, `syscall_32.c`, `syscall_x32.c`. |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | Both captures list `sys_call_table`, `x64_sys_call`, `ia32_sys_call`, `__x64_sys_ni_syscall` and `__ia32_sys_ni_syscall`, and none of `ia32_sys_call_table`, `x32_sys_call_table` or `x32_sys_call`. No symbol has a declared type. `__x64_sys_ni_syscall`, `__ia32_sys_ni_syscall` and `__do_sys_ni_syscall` share one address. | `syscallfacts` on mem3_ubuntu24 and mem4_fedora40, 2026-11-12. |
| M2 | The next symbol after `sys_call_table` is 472 pointers on (mem3) and 468 (mem4). The words past T4's length up to it are null: entries 470 and 471 on mem3, 467 on mem4. | Same script. |
| M3 | Every entry up to T4's length points inside `[_text, _etext)` at a symbol with the `__x64_sys_` prefix. | Section 9 table. |

## 4. Algorithm

### 4.1 Tables

With 8-byte pointers the tables are, in this order:

| Symbol | Stub prefix | Dispatch function |
|---|---|---|
| `sys_call_table` | `__x64_` | `x64_sys_call` |
| `ia32_sys_call_table` | `__ia32_` | `ia32_sys_call` |
| `x32_sys_call_table` | `__x64_` | `x32_sys_call` |

With 4-byte pointers there is one table, `sys_call_table`, with prefix `__ia32_` and dispatch function `ia32_sys_call` (T7, T9).

A missing `sys_call_table` is `ErrNoTable`. A missing other table is skipped without a diagnostic: v6.14 and later never have one (T5).

### 4.2 Length

1. If the symbol table declares the table as an array with a length, that is the length.
2. Otherwise:
   1. From the symbol list, take the table's link-time address and the lowest address above it. The bound is their distance in pointers. With no higher symbol the bound is `MaxTableEntries`.
   2. Read every word below the bound.
   3. The length is one past the last word that is unreadable or not null. Null words that read at the end are padding (T2: no entry is null; M2).
   4. A length of 0 is `ErrNoSize`. A symbol table that cannot list its symbols, or a list without the table, is `ErrNoSize` too.
3. A length above `MaxTableEntries` is cut to it, with a diagnostic.

### 4.3 Entries

For each index below the length, in order:

1. Read a pointer-width word at the table's running address plus index × width. An unreadable word is counted and has no row.
2. The handler address is the word in the address form.
3. Name it (4.4).

### 4.4 Naming a handler

1. The kernel namer gives the symbol-table names at exactly the address, in byte order, with the first name that begins with the table's stub prefix moved to the front (T9: the ni stubs of several ABIs share one address, M1).
2. Look the address up with S06 4.5 and no modules. A kernel-image owner gives the module name `kernel` and the namer's first name.
3. Otherwise build the S07 known-module set once per run and look the address up in it. A module owner gives its module name and symbol.
4. Otherwise module and symbol are empty.

### 4.5 Dispatch

`Dispatches` is true when the table's dispatch function is not in the symbol table (T5, T6).

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| No table entry is null | T2 | Trailing nulls before the next symbol are padding (4.2); a null inside the table is a row with an empty owner |
| A handler is in the kernel image | T1, T9 | Module name, or empty module and symbol |
| The table is used for dispatch | T6 | `Dispatches` false |

## 6. Failure modes

| Case | Result |
|---|---|
| `sys_call_table` missing | `ErrNoTable` |
| No declared length and no usable symbol list, or nothing but nulls | `ErrNoSize` |
| Length above `MaxTableEntries` | Cut, with a diagnostic |
| Unreadable entries | Counted; one diagnostic per table |
| The known-module set cannot be built, or a view is lossy | The S07 view diagnostics; module handlers have an empty owner |
| Strict mode | Unreadable entries, a cut table and a lossy or failed module view are errors. |

Sentinels have the prefix `syscalllist:`. Diagnostics have the form `linux.syscall.list: <table> at 0x<addr>: <what failed>`.

## 7. Result schema

One row per entry that reads, tables in 4.1 order, entries in index order.

| Field | Type | Meaning |
|---|---|---|
| `TableAddress` | uint64 | The table's running address, in the address form |
| `TableName` | string | The table's symbol name |
| `Index` | uint64 | The system call number in the table's ABI |
| `HandlerAddress` | uint64 | The entry, in the address form |
| `HandlerSymbol` | string | 4.4; `name+0x<offset>` inside a module (S06 7); empty when unknown |
| `Module` | string | `kernel`, a module name, or empty |
| `Dispatches` | bool | 4.5 |

## 8. Limits

- `MaxTableEntries` caps the entries read per table, and is the bound when no symbol follows the table.
- The known-module set uses the S07 limits.

## 9. Acceptance

- Synthetic fixtures: a table sized by the next symbol with trailing padding, a declared length, a KASLR shift, an alias named by the table's prefix, a hooked entry in a module, an unowned entry, a switch dispatcher, an ia32 table, all-null and missing tables, unreadable entries, the cap, and 4-byte pointers.
- Fuzz targets over the length rule and over the whole check on an arbitrary table.
- On both captures:

| Capture | Tables | Rows | Length vs T4 | `kernel` | Module | Unowned | Named | `ni_syscall` | `Dispatches` |
|---|---|---|---|---|---|---|---|---|---|
| mem3_ubuntu24 (6.17) | `sys_call_table` | 470 | 470 = 469 + 1 | 470 | 0 | 0 | 470, all `__x64_sys_` | 105 | false |
| mem4_fedora40 (6.14) | `sys_call_table` | 467 | 467 = 466 + 1 | 467 | 0 | 0 | 467, all `__x64_sys_` | 105 | false |

Measured with `syscallfacts`, 2026-11-12.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | From v6.14 (first checked tag with it) the dispatch `switch` (`x64_sys_call`) is code; a hook there is a code patch and is not seen by this check. | A code-integrity check against the kernel image |
| O2 | The padding rule (4.2) rests on two captures (M2). A kernel whose table is followed by non-null data before the next symbol gets extra rows, each with an owner outside the system call stubs. | More captures; a declared length removes the question |
| O3 | `TableName` now gives the symbol name (`sys_call_table`), and `TableAddress` the running address. | Owner decision |
| O4 | `ia32_sys_call_table`, `x32_sys_call_table` and 4-byte pointers are written from the sources only; neither capture has them. | A capture of a kernel older than the switch, or a 32-bit kernel (Q7) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Defer to v0.2.0 |
| O2 | Keep the padding rule |
| O3 | Symbol name and running address |
| O4 | Ship as written, mark untested |

## 11. Provenance

Author: the project, 2026-11-12. Sources: the kernel files in section 3 at the tags stated, fetched from git.kernel.org on 2026-11-12. Measurements: `syscallfacts` on the two Linux captures. Every rule rests on the sources and measurements above.
