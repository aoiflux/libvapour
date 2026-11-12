# S15b: Linux ftrace hooks

Version 1, 2026-11-12.

## 1. Purpose

The kernel's function tracer can call a handler on entry to almost any kernel function. A module that registers such a handler, a `struct ftrace_ops`, can watch or redirect those functions without patching their code, which makes ftrace a common way to hook system calls from a rootkit. An examiner needs every registered handler, the module (or the kernel image) its code belongs to, and the functions it is attached to.

This specification defines how the kernel's list of registered handlers is walked, how each handler's function filter is read, and how each address is matched to its owner. The tool is `linux.tracing.check_ftrace`.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kernel reader | `linuxkern.Kernel` | Memory, symbol table, address form (48-bit masked, as the module rows) and limits. |
| Module model | S06, S07 | `Model.Views`, `Views.Known`, `Model.Lookup`, `Owner.Names` and `KernelOwner`. |
| Hash chain walk | S01 hlist walk (`linuxwalk.Reader.HList`) | Walks each filter-hash bucket. |
| Symbol table | symbols | `ftrace_ops_list`, `ftrace_list_end` and the types in section 3. |
| Limits | effective `limits.Limits` | Section 8. |
| Options | `linux.tracing.check_ftrace.show_ftrace_flags` (bool) | Adds the flag names to each row. |
| Kernel release | `linux_banner` (`autoload.ReadLinuxBanner`) | Chooses the flag names (4.5); read only with the option. |

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17. `kernel/trace/ftrace_internal.h` does not exist at v4.19.

| # | Fact | Source |
|---|---|---|
| F1 | `struct ftrace_ops` begins `ftrace_func_t func; struct ftrace_ops __rcu *next; unsigned long flags; void *private; ftrace_func_t saved_func;`. With `CONFIG_DYNAMIC_FTRACE` it goes on with `struct ftrace_ops_hash local_hash; struct ftrace_ops_hash *func_hash; struct ftrace_ops_hash old_hash; unsigned long trampoline; unsigned long trampoline_size;`. v6.17 adds `list`, `subop_list`, `ops_func`, `managed` and `direct_call`. | `include/linux/ftrace.h`, every tag. |
| F2 | `struct ftrace_ops_hash { struct ftrace_hash __rcu *notrace_hash; struct ftrace_hash __rcu *filter_hash; struct mutex regex_lock; }`. `ftrace_ops_init` sets `ops->func_hash = &ops->local_hash`; an ops that shares the global filter points `func_hash` at `global_ops.local_hash`. | `include/linux/ftrace.h` and `kernel/trace/ftrace.c`, every tag. |
| F3 | `struct ftrace_hash { unsigned long size_bits; struct hlist_head *buckets; unsigned long count; unsigned long flags; struct rcu_head rcu; }`. `alloc_ftrace_hash` gives `1 << size_bits` buckets. | `kernel/trace/trace.h` and `kernel/trace/ftrace.c`, every tag. |
| F4 | `struct ftrace_func_entry { struct hlist_node hlist; unsigned long ip; }`, with `unsigned long direct` added from v6.1. It is in `kernel/trace/ftrace.c` at v4.19 and `include/linux/ftrace.h` from v6.1. Entries hang off the buckets through `hlist`. | As stated. |
| F5 | `ftrace_hash_empty(hash)` is `!hash \|\| !(hash->count \|\| (hash->flags & FTRACE_HASH_FL_MOD))`, with `FTRACE_HASH_FL_MOD = (1 << 0)`. | `kernel/trace/trace.h`, every tag. |
| F6 | `hash_contains_ip` traces an address when the filter hash is empty or holds it, and the notrace hash is empty or does not hold it. So an ops with an empty filter hash is called for every traceable function not in its notrace hash. Without `CONFIG_DYNAMIC_FTRACE`, `ftrace_ops_test` returns 1 for every address. | `kernel/trace/ftrace.c`, every tag; `kernel/trace/ftrace_internal.h` v6.17. |
| F7 | `ftrace_ops_list` starts as `&ftrace_list_end`. `add_ftrace_ops` sets `ops->next = *list` and then `*list = ops`, so the newest ops comes first. `while_for_each_ftrace_op` follows `next` until it meets `&ftrace_list_end`. Both objects are `static` in `kernel/trace/ftrace.c` at v4.19 and `extern` in `include/linux/ftrace.h` from v6.1. | `kernel/trace/ftrace.c` and `include/linux/ftrace.h`, every tag. |
| F8 | The ops flags are bits of an anonymous enum. Bits 0 to 15 are, in order, `ENABLED`, `DYNAMIC`, `SAVE_REGS`, `SAVE_REGS_IF_SUPPORTED`, bit 4, `STUB`, `INITIALIZED`, `DELETED`, `ADDING`, `REMOVING`, `MODIFYING`, `ALLOC_TRAMP`, `IPMODIFY`, `PID`, `RCU`, `TRACE_ARRAY`, each prefixed `FTRACE_OPS_FL_`. Bit 4 is `RECURSION_SAFE` at v4.19 and `RECURSION` from v6.1. v6.1 and v6.4 add 16 `PERMANENT` and 17 `DIRECT`; v6.14 adds 18 `SUBOP`; v6.17 adds 19 `GRAPH`. | `include/linux/ftrace.h`, every tag. |
| F9 | An ops with `FTRACE_OPS_FL_SUBOP` (v6.14 on) is managed by another ops through `subop_list`; the manager is the one on `ftrace_ops_list`. | `include/linux/ftrace.h` v6.14, v6.17. |
| F10 | x86 is little-endian. | S01 X1. |
| F11 | On x86 `arch_ftrace_update_trampoline` gives an ops with no trampoline one from `create_trampoline`, which allocates it with `alloc_tramp` (`module_alloc` at v4.19, v6.1 and v6.4; `execmem_alloc(EXECMEM_FTRACE, ...)` at v6.14; `execmem_alloc_rw` at v6.17) and sets `FTRACE_OPS_FL_ALLOC_TRAMP`. An ops whose caller set its own trampoline keeps it. So an allocated trampoline lies in module space but in no module's regions. | `arch/x86/kernel/ftrace.c`, every tag. |
| F12 | From v6.1 the direct-call registration sets `ops->func = call_direct_funcs` and `ops->trampoline = FTRACE_REGS_ADDR`, which is `ftrace_regs_caller` with `CONFIG_DYNAMIC_FTRACE_WITH_REGS`: a direct-call ops's trampoline is in the kernel image. v4.19 has no such assignment. | `kernel/trace/ftrace.c` v4.19, v6.1, v6.4, v6.14, v6.17; `include/linux/ftrace.h` v6.14. |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | Both captures' symbol tables type `ftrace_ops` (216 bytes) with `func` at 0x0, `next` 0x8, `flags` 0x10, `func_hash` 0x58 and `trampoline` 0x90; `ftrace_ops_hash` with `notrace_hash` 0x0 and `filter_hash` 0x8; `ftrace_hash` with `size_bits` 0x0, `buckets` 0x8, `count` 0x10, `flags` 0x18; `ftrace_func_entry` (32 bytes) with `hlist` 0x0 and `ip` 0x10. Both have the symbols `ftrace_ops_list` and `ftrace_list_end`, 0x30 bytes apart. | `tracinghistoryfacts`, 2026-11-12. |
| M2 | Ops counts, scopes and owners per capture. | Section 9 table. |
| M3 | The one filter entry on mem4_fedora40 is 4 bytes past the start of `bpf_lsm_file_open`; the symbol table has no name at the address itself. | Same script, 2026-11-12. |
| M4 | The mem4_fedora40 ops's trampoline, 0xffffffff89362d60, is the address of `ftrace_regs_caller` in the kernel image (F12); the capture's release is `6.14.5-100.fc40.x86_64`. | `tracinghistoryfacts`, 2026-11-12. |

## 4. Algorithm

### 4.1 Shape

1. `ftrace_ops_list` and `ftrace_list_end` must both be in the symbol table (F7); otherwise `ErrNoOpsList`.
2. `ftrace_ops` must have `func`, `next` and `flags`; otherwise an error wrapping `ErrUnsupported`.
3. The filter form: when `ftrace_ops` has `func_hash`, and `ftrace_ops_hash`, `ftrace_hash` and `ftrace_func_entry` have the members in F2 to F4, ops have filters. Otherwise every ops traces every function (F6).

### 4.2 The ops list

1. Read the pointer at `ftrace_ops_list`. A failed read is `ErrNoOpsList`.
2. While the pointer is not `ftrace_list_end`: take it as an ops, then read its `next`. The walk stops, with a diagnostic, at a null pointer, an ops that does not read, an ops already walked, or `MaxListEntries` ops.

Ops are in list order: newest first (F7).

### 4.3 One ops

1. Read `func`, `flags` and, when present, `trampoline`. An ops whose `func` or `flags` does not read ends the walk (4.2 step 2).
2. The callback owner is `Model.Lookup` over the known modules (S07 4.4) for `func` (S06 4.5). The kernel namer gives the names the symbol table has at the address; when it has none, the nearest symbol below the address in the session's symbol list, as `name+0x<offset>` (S06 7). An ftrace address is usually a few bytes past the start of its function (M3).
3. When `trampoline` is not 0 and the module model was built, it is looked up the same way. Its owner is the module name, or `kernel`, when a module's regions or the kernel image hold it (F12), and otherwise `allocated code outside modules` (F11). Without a module model the owner is empty.
4. With filters (4.1 step 3), read `func_hash`, then its `filter_hash` and `notrace_hash`, and read each hash (4.4).
5. The rows:
   - Filter hash empty (F5): one row with scope `all` (F6).
   - Filter hash with entries: one row per entry, scope `function`, in bucket order and chain order.
   - Filter hash not empty but with no entries (only `FTRACE_HASH_FL_MOD` set, F5): one row with scope `none`; the ops traces no function until its filter matches.
   - `func_hash` or the filter hash does not read, or the hash fails 4.4: one row with scope `unread`.
   - No filters (4.1 step 3): one row with scope `all`.
   Every row carries the number of notrace entries as `Excluded`, or -1 when the notrace hash did not read. Without filters `Excluded` is 0.
6. For a `function` row, the hooked owner is `Model.Lookup` for the entry's `ip`, with the kernel namer.

### 4.4 One hash

Given a hash pointer H:

1. H null is empty (F5).
2. Read `size_bits`, `buckets`, `count` and `flags`. A failed read fails the hash.
3. Empty when `count` is 0 and bit 0 of `flags` is clear (F5).
4. The bucket count is `1 << size_bits` (F3). A `size_bits` of 8 × the pointer width or more, or a bucket count above `MaxTableEntries`, fails the hash.
5. Each bucket is an `hlist_head` at `buckets + i × sizeof(hlist_head)`. The bucket array is read in full; a part that does not read fails the hash. Each bucket whose `first` is not null is walked with the S01 hlist walk, container `ftrace_func_entry`, member `hlist`, and `ip` is read from each entry (F4). A chain that ends other than at null is reported, and the entries before the end are kept. The entries of one hash stop at `MaxListEntries`, with a diagnostic.
6. When the entries found differ from `count`, a diagnostic says so.

### 4.5 Flag names

The names come from the running kernel's release: the text after `Linux version ` in `linux_banner`, up to the first space, read only when `show_ftrace_flags` is set. Its first two numbers are the major and minor version.

1. A name holds from the first checked tag that has it (F8): bits 0 to 3 and 5 to 15 from v4.19; `RECURSION_SAFE` for bit 4 at v4.19 only; `RECURSION` for bit 4, `PERMANENT` (16) and `DIRECT` (17) from v6.1; `SUBOP` (18) from v6.14; `GRAPH` (19) from v6.17.
2. Bit 4 has the opposite meaning at v4.19 and from v6.1 (F8), and no tag between them was checked, so a release from 4.20 to 6.0 gives neither name.
3. When the release does not read, does not parse, or is before 4.19, a bit is named only when every checked tag that has it gives it the same name; bit 4 is then unnamed. A release that does not read is one diagnostic.
4. A set bit without a name is `bit <n>`.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| The list ends at `ftrace_list_end` | F7 | Diagnostic; ops before the break are kept |
| No ops is walked twice | F7: a list built by `add_ftrace_ops` has no cycle | Walk stops, diagnostic |
| `size_bits` gives a bucket count within the pointer width and `MaxTableEntries` | F3; Limits | Scope `unread`, diagnostic |
| A bucket chain ends at null | S01 hlist | Diagnostic; entries before the break are kept |
| Entries found equal `count` | F3 | Diagnostic |

## 6. Failure modes

| Case | Result |
|---|---|
| Profile is not Linux | Error from `linuxkern.New` |
| `ftrace_ops_list` or `ftrace_list_end` missing, or the list head does not read | `ErrNoOpsList` |
| `ftrace_ops.func`, `next` or `flags` missing | Error wrapping `ErrUnsupported` |
| Wrong type for `show_ftrace_flags` | Option error |
| The module model cannot be built (S06 shape) | Diagnostic; no address has an owner |
| The module views cannot be built | Diagnostic; lookups find only the kernel image |
| Module views lossy (S07) | Diagnostic from the views |
| Walk stops early | Diagnostic `<tool>: ftrace_ops at 0x<addr>: <why the walk stopped>` |
| Hash does not read or fails 4.4 | Scope `unread`; diagnostic `<tool>: ftrace_ops at 0x<addr>: <hash> at 0x<addr>: <what failed>` |
| Chain broken, count mismatch, entries capped | Diagnostic |
| A module's symbols do not read during a lookup | Owner kept, symbol empty; one diagnostic |
| `show_ftrace_flags` set and `linux_banner` missing or unreadable | Diagnostic `<tool>: linux_banner: release not read, flag bits named differently across kernels are given by number: <err>`; names follow 4.5 step 3 |
| Strict mode | A walk that stops early, an `unread` scope, a notrace hash that does not read, a broken chain, capped entries, a failed module model, lossy or failed module views, and unread entry addresses are an error. |

`ErrNoOpsList` is a package sentinel with the prefix `tracingftrace:`. `ErrUnsupported` is the walker's own sentinel, `linuxwalk.ErrUnsupported`.

## 7. Result schema

`Hook`, in list order, then entry order:

| Field | Type | Meaning |
|---|---|---|
| `OpsAddress` | uint64 | `struct ftrace_ops` address |
| `CallbackAddress` | uint64 | `func` |
| `Callback` | string | Owner symbol, `name+0x<offset>` (S06 7); empty when not found |
| `Module` | string | Owner module name, `kernel` for the image; empty when not found |
| `ModuleAddress` | uint64 | The owner's `struct module` address (the S07 identity); 0 for the kernel image or no owner |
| `ModuleFound` | bool | The callback has an owner |
| `TrampolineAddress` | uint64 | `trampoline`; 0 when absent |
| `TrampolineOwner` | string | 4.3 step 3: a module name, `kernel`, or `allocated code outside modules` (`TrampolineAllocated`); empty when there is no trampoline or no module model |
| `Scope` | typed string | `function`, `all`, `none` or `unread` (4.3 step 5) |
| `HookedAddress` | uint64 | The entry's `ip`; 0 unless scope is `function` |
| `HookedModule` | string | Owner of `ip`, as `Module` |
| `HookedSymbol` | string | Symbol of `ip`, as `Callback` |
| `Excluded` | int | Notrace entries; -1 when unread |
| `FlagBits` | uint64 | `flags` |
| `Flags` | string | With `show_ftrace_flags`: the 4.5 names of the set bits without the `FTRACE_OPS_FL_` prefix, in bit order, joined by `,`; a bit without a name is `bit <n>`. Empty otherwise. |

## 8. Limits

- `MaxListEntries`: ops on the list, each bucket chain (S01), and the entries of one hash.
- `MaxTableEntries`: buckets per hash.

## 9. Acceptance

- Synthetic fixtures: a list of three ops ending at the marker; an empty filter; a filter with entries in two buckets owned by a module and the kernel; a notrace hash; a hash with `FTRACE_HASH_FL_MOD` and no entries; a `size_bits` past the pointer width; a cycle; a null `next`; an unreadable hash; the no-filter form; the flags option; strict mode; flag names for the releases 6.17, 6.14, 6.4, 6.1, 4.19, 5.10 and 4.14, an empty and an unparsed release, and a v4.19 banner read end to end; a trampoline outside every module, one inside a module, and none.
- A fuzz target over the ops and hash readers on arbitrary memory (`FuzzHashReader`).
- On both captures:

| Capture | Ops | Rows | Scopes | Callback owners | Hooked |
|---|---|---|---|---|---|
| mem3_ubuntu24 | 0 (`ftrace_ops_list` holds `&ftrace_list_end`) | 0 | none | none | none |
| mem4_fedora40 | 1 | 1 | `function` 1 | `kernel`, `call_direct_funcs` | `kernel`, `bpf_lsm_file_open+0x4` |

Measured with `tracinghistoryfacts`, 2026-11-12. The mem4_fedora40 row's `TrampolineOwner` is `kernel` (M4), and 4.5 leaves its flag names as they were (release 6.14). The mem4_fedora40 ops has the flags `ENABLED,DYNAMIC,SAVE_REGS,INITIALIZED,DIRECT`, an empty notrace hash and a trampoline; it is the direct-call ops that attaches the `LSM` BPF program of S15a section 9. Neither capture has a module-owned ops, so module ownership is checked by fixtures only. The tool gives no diagnostics on either capture.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Bit 4 is named `RECURSION`, the name from v6.1. On v4.19 the same bit is `RECURSION_SAFE`, with the opposite meaning. The tool does not read the kernel version to choose. Owner decision 2026-11-12: choose the name by kernel version. Done: 4.5 names each bit by the release in `linux_banner`, with every tag's enum rechecked; bit 4 has no name from 4.20 to 6.0, where no tag was checked. `FlagNames(bits, release)` in `tools/linux/tracingftrace/ops.go`, the release read in `check_ftrace.go`, tests in `check_ftrace_test.go`. | Owner decision (Q7, oldest supported kernel) |
| O2 | Sub-ops (F9) are not listed; their filters are part of the manager's hash. | A capture with function-graph sub-ops |
| O3 | Ops that unregistered and left the list, but stay in memory, are not found. | A later scan rule, if a sample needs it |
| O4 | The trampoline address is not looked up; a trampoline is allocated code that belongs to no module. Owner decision 2026-11-12: label it as allocated code outside modules. Done: 4.3 step 3 looks the trampoline up (F11, F12), and the new field `TrampolineOwner` gives its owner or `allocated code outside modules`; on mem4_fedora40 it is `kernel` (`ftrace_regs_caller`, M4). `tools/linux/tracingftrace/check_ftrace.go`, tests in `check_ftrace_test.go`. | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Choose name by kernel version |
| O2 | Leave unlisted |
| O3 | Defer to v0.2.0 |
| O4 | Label as allocated code outside modules |

## 11. Provenance

Written from the kernel sources at the tags in section 3 and the project's measurements. Every rule rests on the sources and measurements above.
