# S15a: Linux BPF programs

Version 1, 2026-11-12.

## 1. Purpose

A BPF program is code that user space loads into the kernel and the kernel runs on events: packets, system calls, function entries, tracepoints. A loaded program can watch or change what the system does without a kernel module, so an attacker can use one to hide files, filter packets or read credentials. An examiner needs the list of programs the kernel holds, with each one's type, name, tag, size and load time, and a sign when a program's own records disagree.

This specification defines how the kernel's program registry is read and how each program is decoded. The tool is `linux.tracing.list_bpf_programs`.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kernel reader | `linuxkern.Kernel` | Memory, symbol table, address form (48-bit masked, as the module rows) and limits. |
| Tree walk | S02 IDR walk (`linuxwalk.Reader.IDR`) | Lists the registry entries and their IDs. |
| Symbol table | symbols | `prog_idr`, and the types `bpf_prog`, `bpf_prog_aux` and the enums `bpf_prog_type` and `bpf_attach_type` when it has them. |
| Limits | effective `limits.Limits` | Section 8. |
| Options | none | The tool has no options of its own. |

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17. The supported captures run 6.14 (Fedora 40) and 6.17 (Ubuntu 24).

| # | Fact | Source |
|---|---|---|
| B1 | `prog_idr` is a `static DEFINE_IDR(prog_idr)`. `bpf_prog_alloc_id` stores the program with `idr_alloc_cyclic(&prog_idr, prog, 1, INT_MAX, GFP_ATOMIC)` and, on success, sets `prog->aux->id = id`. So every registry entry is a `struct bpf_prog *`, and its ID lies in [1, INT_MAX). | `kernel/bpf/syscall.c`, every tag. |
| B2 | `bpf_prog_free_id` removes the entry with `idr_remove(&prog_idr, prog->aux->id)` and then sets `aux->id` to 0. | `kernel/bpf/syscall.c` v6.17. |
| B3 | `struct bpf_prog` is declared in `include/linux/filter.h` at v4.19 and in `include/linux/bpf.h` from v6.1. Every tag has the members `jited:1` (a bit of a `u16` bit-field group), `enum bpf_prog_type type`, `enum bpf_attach_type expected_attach_type`, `u32 len` ("Number of filter blocks"), `u32 jited_len` ("Size of jited insns in bytes"), `u8 tag[BPF_TAG_SIZE]`, `struct bpf_prog_aux *aux` and the function pointer `bpf_func`. | `include/linux/filter.h` v4.19; `include/linux/bpf.h` v6.1, v6.4, v6.14, v6.17. |
| B4 | `BPF_TAG_SIZE` is 8 and `BPF_OBJ_NAME_LEN` is 16. | `include/uapi/linux/bpf.h`, every tag. |
| B5 | `struct bpf_prog_aux` has `u32 id`, `struct bpf_prog *prog`, `u64 load_time` ("ns since boottime") and `char name[BPF_OBJ_NAME_LEN]`. | `include/linux/bpf.h`, every tag. |
| B6 | `bpf_prog_alloc_no_stats` sets `fp->aux = aux` and `fp->aux->prog = fp`; `bpf_prog_realloc`, which moves a program, sets `fp->aux->prog = fp` again. So a live program's `aux->prog` points back at the program. | `kernel/bpf/core.c`, every tag. |
| B7 | `bpf_prog_load` sets `prog->aux->load_time` from `ktime_get_boot_ns()` (v4.19) or `ktime_get_boottime_ns()` (v6.1 on): nanoseconds of the boot-time clock. | `kernel/bpf/syscall.c`, every tag. |
| B8 | `bpf_obj_name_cpy` zeroes the 16-byte name, copies bytes up to the first NUL, and refuses a name with no NUL in the 16 bytes. It accepts only `isalnum` bytes and `_`, and from v6.1 also `.`. | `kernel/bpf/syscall.c` v4.19, v6.1, v6.4, v6.14, v6.17. |
| B9 | `enum bpf_prog_type` numbers its values from 0 with no explicit values. v4.19 has 22 values (`BPF_PROG_TYPE_UNSPEC` to `BPF_PROG_TYPE_SK_REUSEPORT`), v6.1 has 32, and v6.4, v6.14 and v6.17 have 33 (to `BPF_PROG_TYPE_NETFILTER`), then `__MAX_BPF_PROG_TYPE`. Each tag's list is the start of the v6.17 list. | `include/uapi/linux/bpf.h`, every tag. |
| B10 | x86 is little-endian, and its bit-fields fill each storage unit from the least significant bit. | S01 X1; System V x86-64 psABI, "Bit-Fields". |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | Both captures' symbol tables type `bpf_prog` (72 bytes) with `type` at 0x4, `expected_attach_type` at 0x8, `len` at 0xc, `jited_len` at 0x10, `tag` (8 bytes) at 0x14, `bpf_func` at 0x30, `aux` at 0x38, and `jited` as a bit-field of the `u16` at 0x2. `bpf_prog_aux` has `id` at 0x20 on both; `prog`, `load_time` and `name` are at 0x3b8, 0x3c8, 0x3e8 (6.17) and 0x3a8, 0x3b8, 0x3d8 (6.14). Both tables carry `enum bpf_prog_type` with the 33 B9 values plus `__MAX_BPF_PROG_TYPE`, and `enum bpf_attach_type` with 58 values plus `__MAX_BPF_ATTACH_TYPE`. | `tracinghistoryfacts`, 2026-11-12. |
| M2 | Program counts and types per capture. | Section 9 table. |

## 4. Algorithm

### 4.1 Shape

Resolve once, from the symbol table:

1. `prog_idr`. Missing is `ErrNoProgIDR`.
2. The members of `bpf_prog`: `type`, `aux` (required), and `expected_attach_type`, `len`, `jited_len`, `tag`, `jited` and `bpf_func` (each optional). The members of `bpf_prog_aux`: `id`, `prog`, `name` and `load_time`, each optional. A missing required member is an error wrapping `ErrUnsupported`.
3. The type names: the image's `enum bpf_prog_type` when the table has it; otherwise the B9 list at v6.17. The attach-type names come from the image's `enum bpf_attach_type` only.

### 4.2 The registry

Walk `prog_idr` with the S02 IDR walk. Each entry is a program address (B1); its index is the program ID. The walk's losses (unread nodes, revisited nodes, inconsistent or mismatched nodes, the cap) are reported as one diagnostic.

### 4.3 One program

For an entry P with ID I:

1. Read `bpf_prog` at P: `type`, `expected_attach_type`, `len`, `jited_len`, the `jited` bit (B10), `bpf_func`, the 8 `tag` bytes (B4) and `aux`. If `type` or `aux` does not read, the program is left out and counted.
2. The type name is the enumerator with `type`'s value. A value with no name leaves the name empty, and is counted.
3. Read `bpf_prog_aux` at `aux`: `id`, `prog`, `load_time` and the 16 `name` bytes (B4, B5). When `aux` is null or does not read, the row keeps the `bpf_prog` values and is marked aux-unread.
4. **Linked**: `aux->prog` equals P (B6). **ID matches**: `aux->id` equals I (B1). A member the symbol table lacks leaves its check passed.
5. The name is the bytes before the first NUL of the 16 (B8). A name with no NUL is left empty and counted.
6. The tag is the 8 bytes as 16 lowercase hexadecimal digits.
7. The load time is `load_time` nanoseconds as a duration since boot (B7). A value above the largest signed 64-bit duration is left zero.

Rows are in IDR index order, which is ID order.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| An entry's `type` and `aux` read | B3 | Left out, counted per error |
| `aux->prog` equals the entry | B6 | Row kept with `Linked` false, one diagnostic per program |
| `aux->id` equals the IDR index | B1 | Row kept with `IDMatches` false, one diagnostic per program |
| The name has a NUL in its 16 bytes | B8 | Name empty, counted |
| The type value has an enumerator | B9 | Type name empty, counted |

The name's characters are not checked: the kernel's `isalnum` follows its own character table, which this specification does not re-derive (section 10).

## 6. Failure modes

| Case | Result |
|---|---|
| Profile is not Linux | Error from `linuxkern.New` |
| `prog_idr` missing | `ErrNoProgIDR` |
| `bpf_prog.type` or `bpf_prog.aux` missing, or the IDR shape unsupported | Error wrapping `ErrUnsupported` |
| IDR walk losses | Diagnostic `linux.tracing.list_bpf_programs: prog_idr at 0x<addr>: walk incomplete: <counts>` |
| Program does not read | Left out; diagnostic `<tool>: bpf_prog at 0x<addr>: does not read: <err>` |
| Aux does not read | Row kept; diagnostic `<tool>: bpf_prog at 0x<addr>: aux at 0x<addr> does not read: <err>` |
| Not linked, ID mismatch | Row kept; diagnostic per program |
| Unnamed type, unterminated name | Counted; one diagnostic each |
| Strict mode | Walk losses, left-out programs and unread aux structures are an error. Mismatches are findings and stay diagnostics. |

`ErrNoProgIDR` is a package sentinel with the prefix `tracingbpf:`. `ErrUnsupported` is the walker's own sentinel, `linuxwalk.ErrUnsupported`.

## 7. Result schema

`Program`, one per registry entry, in ID order:

| Field | Type | Meaning |
|---|---|---|
| `Address` | uint64 | `struct bpf_prog` address |
| `ID` | uint64 | IDR index |
| `Type` | string | Enumerator name, such as `BPF_PROG_TYPE_KPROBE`; empty when unnamed |
| `TypeValue` | int64 | Raw `type` |
| `AttachType` | string | Enumerator name from the image; empty when absent or unnamed |
| `AttachTypeValue` | int64 | Raw `expected_attach_type` |
| `Name` | string | `aux->name`; empty when absent |
| `Tag` | string | 16 hexadecimal digits; empty when unread |
| `Instructions` | uint64 | `len` |
| `JITed` | bool | The `jited` bit |
| `JITedSize` | uint64 | `jited_len`, in bytes |
| `FuncAddress` | uint64 | `bpf_func` |
| `AuxAddress` | uint64 | `aux` |
| `AuxRead` | bool | The aux structure read |
| `LoadedAfterBoot` | `time.Duration` | B7; zero when aux did not read |
| `Linked` | bool | 4.3 step 4 |
| `IDMatches` | bool | 4.3 step 4 |

## 8. Limits

- `MaxTableEntries` and `MaxRecursionDepth`: the S02 walk.

## 9. Acceptance

- Synthetic fixtures: an IDR with programs at three IDs; an unknown type value; a program with no image enum (the B9 table); a broken back link; an ID mismatch; an aux that does not read; a program that does not read; a name with no NUL; the jited bit; strict mode.
- A fuzz target over the program decoder and the registry node on arbitrary memory (`FuzzProgramDecoder`).
- On both captures:

| Capture | Programs | Types | Linked | ID matches | Names |
|---|---|---|---|---|---|
| mem3_ubuntu24 | 19 (IDs 25 to 53) | `CGROUP_SKB` 10, `CGROUP_DEVICE` 9 | 19 | 19 | `sd_devices` 8, `sd_fw_egress` 5, `sd_fw_ingress` 5, `s_snapd_desktop` 1 |
| mem4_fedora40 | 31 (IDs 27 to 73) | `CGROUP_SKB` 16, `CGROUP_DEVICE` 14, `LSM` 1 | 31 | 31 | `sd_devices` 14, `sd_fw_egress` 8, `sd_fw_ingress` 8, `restrict_filesy` 1 |

Measured with `tracinghistoryfacts`, 2026-11-12. On both captures every program is JIT-compiled, every aux structure reads, the IDR walk reports no losses and the tool gives no diagnostics. The `LSM` program on mem4_fedora40 is the one the S15b measurement finds attached through ftrace.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Name characters are not checked against the kernel's `isalnum`, whose table is not re-derived here. | A rule from `lib/ctype.c` if a sample shows a forged name |
| O2 | Attach-type names come only from the image's enum; a table without it leaves `AttachType` empty. | Owner decision: add the uapi list as a fallback |
| O3 | Programs removed from `prog_idr` (B2) but still in memory are not found. A scan for them has no rule yet. | A later scan rule, if a sample needs it |
| O4 | The load time stays relative to boot. Turning it into a wall-clock time needs the boot time (`linux.boot.read_time`). | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | No check |
| O2 | Empty without the image's enum |
| O3 | Defer to v0.2.0 |
| O4 | Relative to boot |

## 11. Provenance

Written from the kernel sources at the tags in section 3 and the project's measurements. Every rule rests on the sources and measurements above.
