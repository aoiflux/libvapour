# S14: Linux task identity, credentials and address space

Version 1, 2026-11-12.

## 1. Purpose

Almost every Linux tool reports, for each task it looks at, who the task is: its process and thread IDs, its parent, its name, the user and group it runs as, and the address space its user memory lives in. This specification defines how each of these is read from a `task_struct`, which values are trusted, and what a tool is told when a read fails. It is the source for the task readers in `tools/linuxobj` that about 25 Linux tools call, and for the Linux columns of the `any.process.list` tool.

Which tasks exist, and how the process and thread lists are walked and checked, is S01. Page-table translation is S04. This specification starts from a task address that S01, a scan or a hash table has produced.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxobj.Kernel` | Kernel-space memory, the symbol table, the address form and the effective Limits. |
| Task | address, and optionally a reader | A `task_struct` address. A task found by a physical scan carries the physical reader it was found in; its own members are read through that reader, and every pointer it holds is followed in kernel space. |
| Symbols | symbol table | The types and members in section 3. No offset in this specification is a constant. |
| Session | `tools.Context` | The kernel layer's translation to physical addresses, the process-space builder, the PID set, strict mode. |
| Options | tool options | `any.process.list.threads` (bool), `any.process.list.decorate_comm` (bool). |
| Limits | effective `limits.Limits` | Section 8. |

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17 unless a row names fewer. The supported captures run 6.14 (Fedora 40) and 6.17 (Ubuntu 24). Paths are under the kernel tree.

### Identity

| # | Fact | Source |
|---|---|---|
| I1 | `task_struct` has `pid_t pid` and `pid_t tgid`. `pid_t` is `__kernel_pid_t`, an `int`. | `include/linux/sched.h`; `include/linux/types.h`; every tag. |
| I2 | `copy_process` sets `p->pid = pid_nr(pid)`, and `pid_nr` returns `pid->numbers[0].nr`, the number in the initial PID namespace. A thread (`CLONE_THREAD`) takes `p->tgid = current->tgid`; any other task takes `p->tgid = p->pid`. | `kernel/fork.c` `copy_process`; `include/linux/pid.h` `pid_nr`; every tag. |
| I3 | When a thread other than the leader calls exec, `de_thread` gives it the leader's pid: v4.19 assigns `tsk->pid = leader->pid`, and v6.1 onwards swaps them through `exchange_tids`, which writes both tasks' `pid`. A leader's pid therefore stays equal to its tgid. | `fs/exec.c` `de_thread`; `kernel/pid.c` `exchange_tids` (v6.1, v6.4, v6.14, v6.17). |
| I4 | `thread_group_leader(p)` is `p->exit_signal >= 0`; `copy_process` sets `exit_signal = -1` for `CLONE_THREAD`. | `include/linux/sched/signal.h`; `kernel/fork.c`; every tag. |
| I5 | `struct task_struct __rcu *real_parent` is the "real parent process". `copy_process` sets it to `current->real_parent` for `CLONE_PARENT` or `CLONE_THREAD`, else to `current`. So every thread of a group has the leader's real parent. | `include/linux/sched.h`; `kernel/fork.c`; every tag. |
| I6 | `getppid` returns `task_tgid_vnr(current->real_parent)`: the parent's tgid, not its pid. `/proc/<pid>/status` prints `PPid` the same way, and 0 when the task is no longer alive (`pid_alive`). | `kernel/sys.c` `getppid`; `fs/proc/array.c` `task_state`; v4.19, v6.17. |
| I7 | `init_task` sets `.real_parent = &init_task`, `.flags = PF_KTHREAD`, `.mm = NULL`; its pid is 0. A task whose real parent is `init_task` therefore has parent ID 0. | `init/init_task.c`, every tag. |

### Name

| # | Fact | Source |
|---|---|---|
| N1 | `char comm[TASK_COMM_LEN]`, the "executable name, excluding path". `TASK_COMM_LEN` is 16: a `#define` at v4.19, an enum value from v6.1. | `include/linux/sched.h`, every tag. |
| N2 | `__set_task_comm` always leaves a NUL inside the 16 bytes. v4.19 uses `strlcpy`, which writes the NUL but leaves the bytes after it as they were. v6.1 and v6.4 use `strscpy_pad`, and v6.14 and v6.17 copy at most 15 bytes and zero the rest, so from v6.1 every byte after the first NUL is 0. | `fs/exec.c` `__set_task_comm`; `include/linux/sched.h` comment at v6.17. |
| N3 | Any byte other than NUL can be written to `comm` (`prctl(PR_SET_NAME)` passes the user's string to `set_task_comm`). An empty name is possible. | `kernel/sys.c` `PR_SET_NAME` (`strncpy_from_user`, then `set_task_comm`); v6.17. |

### Kernel threads

| # | Fact | Source |
|---|---|---|
| K1 | `#define PF_KTHREAD 0x00200000` ("I am a kernel thread") in `task_struct.flags`, an `unsigned int`. | `include/linux/sched.h`, every tag. |
| K2 | v6.1 onwards, `copy_process` clears `PF_KTHREAD` and sets it only when `args->kthread`. | `kernel/fork.c`, v6.1, v6.4, v6.14, v6.17. |
| K3 | A kernel thread may adopt a user `mm` for a while: `kthread_use_mm` (v6.1 onwards; `use_mm` in `mm/mmu_context.c` at v4.19) sets `tsk->mm = mm` and warns unless `PF_KTHREAD` is set. `get_task_mm`, which `/proc` uses, returns no mm for a `PF_KTHREAD` task for that reason. | `kernel/kthread.c`; `mm/mmu_context.c` (v4.19); `kernel/fork.c` `get_task_mm`; every tag. |
| K4 | `#define PF_EXITING 0x00000004`, set by `exit_signals` in `do_exit` before `exit_mm`, which sets `current->mm = NULL`. A user task caught exiting can therefore have no `mm`. | `include/linux/sched.h`; `kernel/exit.c`; every tag. |

### Credentials

| # | Fact | Source |
|---|---|---|
| C1 | `task_struct` has `const struct cred __rcu *real_cred` ("objective and real subjective task credentials") and `const struct cred __rcu *cred` ("effective (overridable) subjective task credentials"). | `include/linux/sched.h`, every tag. |
| C2 | `__task_cred(task)` is `rcu_dereference(task->real_cred)`, and `get_task_cred` reads it: the objective credentials, which other tasks see. `/proc/<pid>/status` prints `Uid` and `Gid` from `get_task_cred` as real, effective, saved and filesystem IDs. | `include/linux/cred.h`; `kernel/cred.c` `get_task_cred`; `fs/proc/array.c` `task_state`; every tag. |
| C3 | `struct cred` has `kuid_t uid`, `kgid_t gid`, `kuid_t suid`, `kgid_t sgid`, `kuid_t euid`, `kgid_t egid`. `kuid_t` is `struct { uid_t val; }` and `kgid_t` is `struct { gid_t val; }`; `uid_t` and `gid_t` are `__kernel_uid32_t` and `__kernel_gid32_t`, unsigned 32-bit. The values are kernel-internal IDs, which equal the IDs seen in the initial user namespace. | `include/linux/cred.h`; `include/linux/uidgid.h` (to v6.4), `include/linux/uidgid_types.h` (v6.14, v6.17); `include/linux/types.h`; every tag. |

### Address space

| # | Fact | Source |
|---|---|---|
| A1 | `task_struct` has `struct mm_struct *mm` and `*active_mm`; `mm_struct` has `pgd_t *pgd`. | `include/linux/sched.h`; `include/linux/mm_types.h`; every tag. |
| A2 | `copy_mm` starts with `tsk->mm = NULL` and returns at once when the parent has no mm; with `CLONE_VM` it shares the parent's `mm`, else it duplicates it. Threads of a group therefore share one `mm`. | `kernel/fork.c` `copy_mm`, every tag. |
| A3 | On x86, `_pgd_alloc` takes the PGD from the page allocator (`__get_free_pages` or `__pgd_alloc`) at order `PGD_ALLOCATION_ORDER`, 1 with page-table isolation and 0 without (from v6.17 the function `pgd_allocation_order`). The PGD is therefore page aligned. | `arch/x86/mm/pgtable.c`; `arch/x86/include/asm/pgalloc.h`; every tag. |
| A4 | `build_cr3` loads CR3 with `__sme_pa(pgd)`, the physical address of `mm->pgd`, ORed with the PCID (and from v6.4 the LAM bits). | `arch/x86/include/asm/tlbflush.h` at v4.19; `arch/x86/mm/tlb.c` at v6.1, v6.4, v6.14, v6.17. |
| A5 | With page-table isolation, `__pti_set_user_pgtbl` writes every user-space PGD entry into both the kernel PGD and the user copy (`kernel_to_user_pgdp`, the page `PTI_PGTABLE_SWITCH_BIT` = `PAGE_SHIFT` above it), marking the kernel copy's entries NX. The kernel PGD therefore maps all of user space. | `arch/x86/mm/pti.c`; `arch/x86/include/asm/pgtable.h`; v4.19, v6.17. |
| A6 | In 4-level and 5-level paging, CR3 bits 51:12 hold the physical address of the top table, which is 4 KiB aligned. In 32-bit PAE paging CR3 bits 31:5 hold the address of the 32-byte page-directory-pointer table. | Intel SDM Vol. 3A, section 4.5 table 4-12 and section 4.4.1 table 4-7. |

### Measurements

Measured with `taskfacts` on 2026-11-12 over the S01 task walk with threads. Section 9 has the numbers. M1: every member in sections I, N, C and A is present on both captures with the sizes the sources give (`pid` and `tgid` `int`, `comm` `char [16]`, `kuid_t` and `kgid_t` 4 bytes with `val` at 0).

## 4. Algorithm

Every read of a task's own member goes through the task's reader (section 2). Every pointer read from it is put through the address form and followed in kernel space.

### 4.1 Process ID, thread ID and parent

1. The thread ID is `task_struct.pid` and the process ID is `task_struct.tgid`, each read as a signed integer of the table's width (I1, I2). Both are initial-namespace IDs (I2).
2. The parent ID is the `tgid` of the task `real_parent` points at (I5, I6). A null `real_parent` gives 0, the value `/proc` gives a task whose parent is gone (I6); it is not an error.
3. A PID filter keeps a process when the session PID set holds its `tgid`. It runs on leaders, after S01's checks (S01 4.4), so the leader's `tgid` already read.

### 4.2 Name

1. Read `comm` as `ArrayLength` bytes, the table's array length, or `TASK_COMM_LEN` (16, N1) when the table gives none.
2. The name is the bytes before the first NUL. A name with no NUL is taken whole (section 5).
3. The name is not re-encoded: bytes outside printable ASCII stay as they are (N3). Escaping is the output layer's job.
4. With `decorate_comm`, a kernel thread's name is written `[name]` and a thread that is not its group's leader (`pid != tgid`, I2, I3) `{name}`. Other names are unchanged.

### 4.3 Kernel thread

`PF_KTHREAD` set in `flags` marks the task as a kernel thread (K1). `mm == NULL` is not used for this: a kernel thread can hold a user `mm` (K3) and an exiting user task can have none (K4).

### 4.4 Credentials

1. The column credentials are the objective ones, from `real_cred` (C1, C2): what the kernel reports for the task to other tasks and in `/proc`.
2. Each ID is the `val` member of the `kuid_t` or `kgid_t` member of `struct cred`, read unsigned (C3). When the member has no `val` (a table that types it as a plain integer), the member is read directly.
3. A null `real_cred`, or one whose IDs do not read, gives no credentials: the row says so (section 7) and the tool reports it.
4. The task credential pointer that tools compare across tasks (`TaskCred`) is the subjective `cred` (C1), the one the task acts with. It is usable when it is not null and the whole `struct cred` reads.

### 4.5 Address-space root and process layer

1. A kernel thread (4.3) has no address space of its own: none, and nothing is reported (K3).
2. Read `mm`. A null `mm` gives none, and nothing is reported (A2, K4).
3. The kernel layer must translate virtual to physical addresses. If it cannot, the session cannot build any process layer: the error `ErrNoTranslator`, which a tool returns.
4. Read `mm->pgd` in kernel space. A null `pgd` gives none, with a reason.
5. Translate `pgd` through the kernel layer (A4). The root is that physical address. An address that does not translate gives none, with a reason.
6. The root must be aligned as A3 and A6 require: 4 KiB for 64-bit tables, 32 bytes for 32-bit ones. Otherwise none, with a reason wrapping `ErrRootMisaligned`.
7. The process layer is the session's process space at that root (`tools.Context.ProcessSpace`). A failure there gives none, with its reason.
8. The root maps user space in full (A5) and the kernel half as well (measured, section 9), so one layer reads both.

### 4.6 Task summary

A task summary holds, for one task: its address as given, the process ID, thread ID, parent ID, name (decorated or not) and undecorated name, the credentials, and the creation time (from the boot-time reader, not this specification).

1. The identity is the thread ID, process ID and name, and the flags when decoration is asked for. If any of these does not read, the summary fails with that error.
2. The parent, the credentials and the creation time are read on their own. A failure in one is kept in the summary next to the value it stops (section 7); the rest of the summary stands.

### 4.7 `any.process.list` on Linux

The process rows come from the S01 process walk without threads, with the session PID set applied as rule 3 of 4.1 says. This part makes the rows, adds the columns and, when asked, the threads.

1. Each task the walk returns becomes a process row in walk order: its `tgid` as the PID (a listed task leads its group, S01 T3, so `pid` and `tgid` agree), its undecorated name, and its address. A task whose `tgid` or name does not read, or whose `tgid` is negative, is left out with a diagnostic; in strict mode it is an error, and so is a walk that left tasks out (S01 4.4). A row the snapshot cross-check does not confirm is left out with a diagnostic; a cross-check that fails keeps the row with a diagnostic, and is an error in strict mode.
2. Read the two options as booleans; a value that is not a boolean is an error.
3. For each process row, read its task summary (4.6) into its Linux columns.
4. With `threads`, follow each process row with its threads in S01 thread-walk order (S01 4.5). A thread row has the thread ID as its PID, the undecorated name as its name, and `Thread` set. A thread whose task summary does not read gives no row.
5. Report each failure kind once with its first task, and once more with the count when there are more (section 6).
6. In strict mode, a failure that leaves no mark in the row is an error: a task summary that does not read, or a thread list that does not read, ends broken or leaves threads out. Parent and credential failures are marked in their rows (`PPIDRead`, `CredsRead`) and stay diagnostics. A creation-time failure is marked in `CreationTimeErr` only, with no diagnostic.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| A thread ID and process ID are what the task holds; their range is S01's rule (S01 4.3) for listed tasks, and a scanning tool's own rule for scanned ones. | I1, I2; S01 T7 | Not checked here. |
| The parent ID is the parent's `tgid`, not its `pid`. | I6 | Not applicable. |
| A null `real_parent` is parent 0. | I6, I7 | Value 0; not an error. |
| A name stops at its first NUL; bytes after it are ignored. | N2: v4.19 can leave stale bytes after the NUL. | Not applicable. |
| A name with no NUL in its 16 bytes is taken whole rather than refused. | N2 says the kernel never writes one, so only damage or tampering makes one, and refusing it would drop the task from every tool's output. | The whole array is the name. |
| `PF_KTHREAD` alone marks a kernel thread. | K1-K4 | Not applicable. |
| Column credentials come from `real_cred`; the compared pointer is `cred`. | C1, C2 | See 4.4. |
| IDs are read unsigned 32-bit. | C3 | Not applicable. |
| A process root is page aligned (4 KiB) on 64-bit tables, 32-byte aligned on 32-bit ones. | A3, A6; measured, section 9 | No layer, reason `ErrRootMisaligned`. |
| A kernel thread, or a task with no `mm`, has no process layer and is not reported. | K3, K4, A2 | Silent. |

## 6. Failure modes

- A missing type or member: the read fails with an error that names the type and member.
- A task member that does not read: the error names the member and the member's address (`linuxobj: task_struct.<member> at 0x<addr>: <cause>`).
- No layer for a task that has an `mm`: a reason, never an error, so a tool can count it and go on. Reasons: `linuxobj: mm_struct at 0x<addr>: pgd does not read: %w`; `linuxobj: mm_struct at 0x<addr>: pgd is null`; `linuxobj: pgd at 0x<addr>: does not translate: %w`; `linuxobj: pgd at 0x<addr>: root 0x<root>: ` wrapping `ErrRootMisaligned`; the process-space error.
- No translator: `ErrNoTranslator`, an error, because no task can have a layer.
- A null `real_cred`: `CredsErr` wraps `ErrNoCredentials`. Unreadable IDs: `CredsErr` is the read error.
- `any.process.list` diagnostics, one per failure kind, in the form `any.process.list: task at 0x<addr>: <what failed>: <cause>`, then `any.process.list: <n> more tasks: <what failed>` when the kind repeats. The kinds: `columns do not read`, `parent does not read`, `credentials do not read`, `thread list does not read`, `thread list ends early` (cause `after <n> threads at 0x<addr>: <end>`), `threads left out` (cause `<n>: <reason>`). The task of a thread-list kind is the leader.
- A task whose flags or `mm` do not read has no layer, with the read error as its reason.
- Strict mode: `any.process.list: strict mode: task at 0x<addr>: <what failed>: <cause>` for the first failure of the unmarked kinds in 4.7 step 6.

## 7. Result schema

Task summary (`linuxobj.TaskFields`):

| Field | Type | Meaning |
|---|---|---|
| `Offset` | uint64 | The task address as given: canonical kernel virtual, or physical for a scanned task. |
| `PID` | int64 | `tgid`. |
| `TID` | int64 | `pid`. |
| `PPID` | int64 | Parent's `tgid`; 0 when `real_parent` is null or `ParentErr` is set. |
| `Name` | string | The name, decorated when asked. |
| `Comm` | string | The name, never decorated. |
| `Creds` | `CredIDs` | `UID`, `GID`, `EUID`, `EGID` from `real_cred`; zero when `CredsRead` is false. |
| `CredsRead` | bool | The credentials read. |
| `CredsErr` | error | Why they did not; nil when they read. |
| `ParentErr` | error | Why the parent did not read; nil when it read or is null. |
| `CreationTime`, `CreationTimeErr` | time, error | From the boot-time reader. |

Linux columns of `any.process.list` (`processlist.LinuxColumns`): `Read` and `Unread` (the task summary read, or its error), `PID`, `TID`, `PPID`, `PPIDRead` (false when `ParentErr` is set, so a `PPID` of 0 from a null `real_parent` is told apart from one that did not read; false too on a row whose summary did not read), `Comm` (decorated when asked), `Thread`, `UID`, `GID`, `EUID`, `EGID`, `CredsRead`, `CreationTime`, `CreationTimeErr`. Rows keep the process walk's order, each process followed by its threads.

## 8. Limits

- The thread walk is capped by `Limits.MaxListEntries` per thread list (S01). Nothing else here loops.

## 9. Acceptance

- Synthetic fixtures: a leader, a thread, a kernel thread, a kernel thread holding an `mm`, an exiting user task with no `mm`; a null and an unreadable `real_parent`; a parent whose `pid` and `tgid` differ; `cred` and `real_cred` with different IDs; a null and an unreadable `real_cred`; IDs with the top bit set; a name with no NUL, one with stale bytes after the NUL, an empty one; both decorations; a `kuid_t` typed as a plain integer; a root that does not translate, one misaligned, and a kernel layer that does not translate; the tool with threads, decoration and strict mode (an unread parent marked `PPIDRead` false and kept as a diagnostic, a null `real_parent` marked read with `PPID` 0), and an option of the wrong type.
- Fuzz targets: `FuzzTaskName` (arbitrary `comm` bytes: never panics, never longer than the array, no NUL in the result); `FuzzTaskSummary` (arbitrary bytes for a task and its pointees: never panics).
- On both captures, `taskfacts`, 2026-11-12:

| | mem3_ubuntu24 (6.17) | mem4_fedora40 (6.14) |
|---|---|---|
| Tasks (S01 walk with threads) | 557 | 573 |
| Leaders, `pid == tgid` | 203 of 203 | 242 of 242 |
| Threads, `pid != tgid`, `tgid` names a listed leader | 354 of 354 | 331 of 331 |
| `exit_signal` sign matches the role (I4) | 557 of 557 | 573 of 573 |
| Kernel threads (`PF_KTHREAD`), all with `mm` null | 88 | 118 |
| Kernel threads holding an `mm` (K3) | 0 | 0 |
| User tasks with an `mm` | 468 | 454 |
| User tasks with no `mm`, all `PF_EXITING` (K4) | 1 (a thread) | 1 (a leader) |
| Threads sharing the leader's `mm` (A2) | 353 of 354 (the other is the exiting thread) | 331 of 331 |
| `real_parent` null | 0 | 0 |
| `real_parent` a listed task / `init_task` | 555 / 2 | 571 / 2 |
| `real_parent == parent` | 557 | 573 |
| Threads whose parent ID is the leader's (I5) | 354 of 354 | 331 of 331 |
| `comm` with a NUL, zero after it, non-empty, printable | 557 of 557 | 573 of 573 |
| `cred == real_cred` | 557 | 573 |
| `real_cred` IDs that do not read (all `PF_EXITING`) | 1 | 1 |
| IDs uid 0 and euid 0 / other | 177 / 379 | 207 / 365 |
| An ID equal to `(uid_t)-1` | 0 | 0 |
| Roots that translate | 468 of 468 | 454 of 454 |
| Roots 4 KiB aligned / 8 KiB aligned | 468 / 216 | 454 / 136 |
| Roots inside physical memory | 468 | 454 |
| Process layers that read the task's own `mm_struct` (kernel half) | 468 | 454 |
| The readers of section 4 over the same tasks: summaries that fail | 0 | 0 |
| Summaries whose IDs equal the raw `pid` and `tgid` | 557 | 573 |
| Summaries with `CredsRead` false / `ParentErr` set (so `PPIDRead` false) | 1 / 0 | 1 / 0 |
| Process layers built / none, silent / none with a reason / error | 468 / 89 / 0 / 0 | 454 / 119 / 0 / 0 |

About half the roots are 8 KiB aligned, which is what order-0 allocation gives and order 1 (A3) would not, so neither capture runs with page-table isolation; the 4 KiB rule holds on all. The two tasks with unreadable credentials are the two exiting tasks: the rule that keeps them listed, marked `CredsRead` false and reported, is exercised on both captures.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision: `decorate_comm` marks a kernel thread `[name]` and a non-leader thread `{name}`. The option key is kept; the marks are a display choice with no kernel source. | Owner choice at the final stage |
| O2 | Owner decision: `processlist.FileOutputDisabled` (`"Disabled"`) stays exported; no Linux column carries it. | Owner choice (Q2) |
| O3 | Owner decision: a parent that does not read leaves `PPID` 0 in the `any.process.list` row with only a diagnostic, because `LinuxColumns` keeps its shape in this wave. A `PPIDRead` field would mark it in the row. | Owner choice (Q2). Owner decision 2026-11-12: add a `PPIDRead` field. Done: `processlist.LinuxColumns.PPIDRead` set when the parent read or is null; an unread parent is now a marked failure, a diagnostic in strict mode too (4.7 step 6, section 7); `tools/any/processlist/linuxcolumns.go`, its test, and `examples/processlist` prints an unread parent as unreadable. Measured: `PPIDRead` false on 0 rows on both captures (section 9, `ParentErr` set 0). |
| O4 | IDs are initial-namespace values (I2, C3). Namespace-relative PIDs and user-namespace-mapped IDs, as a contained process sees them, are not reported. | A spec revision if needed |
| O5 | With memory encryption (AMD SME), `__sme_pa` clears the encryption bit from the root (A4). No capture uses it, so whether the kernel layer's translation of `pgd` carries the bit is not measured. | A capture with SME |
| O6 | No capture runs v4.19 (stale bytes after the NUL, N2), has a kernel thread holding an `mm` (K3), or has page-table isolation on (A3, A5). Those paths are checked by fixtures only. | Captures for Q7 and with PTI |
| O7 | `TaskCred` compares the subjective `cred`, the columns show the objective `real_cred`. They were equal on every measured task; they differ only while a task overrides its credentials. | Owner review |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep the marks |
| O2 | Keep the value |
| O3 | Add a PPIDRead field |
| O4 | Initial-namespace IDs only |
| O5 | Ship as written, mark untested |
| O6 | Keep fixture-only checks |
| O7 | Keep subjective compare |

## 11. Provenance

Written from the kernel sources at the tags in section 3, the Intel SDM Vol. 3A and the project's measurements. The sources were fetched from `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=<tag>` on 2026-11-12. Every rule rests on the sources and measurements above.
