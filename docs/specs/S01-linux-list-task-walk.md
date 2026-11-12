# S01: Linux circular list, hlist and task walk

Version 1, 2026-11-11.

## 1. Purpose

Most Linux kernel objects a memory examiner wants are reached through one of two intrusive list types: the circular doubly linked `list_head` and the null-terminated `hlist_head`. The set of processes and threads is the most important case. This specification defines one bounded, cycle-safe walker for each list type, and the task walk built on them, so that every Linux tool reads lists the same way and reports the same failures.

The image is untrusted. A list in memory an attacker controls, or one caught half-updated, can hold a loop that never returns to its head, a link into unmapped memory, or any number of distinct nodes. Every walk must stop, and must say why it stopped.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Memory | reader over kernel virtual memory | Reads bytes at an address. A read either returns every byte asked for or fails. |
| Symbol table | the session's Linux symbol table | Gives member offsets and structure sizes. No offset in this specification is a constant. |
| Address form | function from a pointer value to an address | Maps a pointer read from memory to the form Memory reads at and callers compare. The kernel layer defines it (masked, or masked and sign-extended). The walker applies it to every pointer it reads and every address it computes. |
| Limits | the effective `limits.Limits` | `MaxListEntries` (section 8). |
| Head | address | The `list_head` or `hlist_head` that heads the list. |
| Container, member | type name, member name | The structure the list links, and the member of that structure that holds the link. |
| Direction | forward or backward | Circular lists only: follow `next` or `prev`. |
| init_task | symbol | The task walk only: the `init_task` symbol from the symbol table, put through the address form. A missing symbol, or one at address 0, is an error. |

## 3. Constraints from the kernel source

Tags checked: v4.19, v6.14 and v6.17. The supported captures run 6.14 (Fedora 40) and 6.17 (Ubuntu 24).

| # | Constraint | Source |
|---|---|---|
| L1 | `struct list_head { struct list_head *next, *prev; }`. | `include/linux/types.h`, v4.19, v6.14, v6.17. |
| L2 | An empty list is a head whose `next` points at itself; `INIT_LIST_HEAD` sets both links to the head. | `include/linux/list.h` `INIT_LIST_HEAD`, `list_empty`, v6.17. |
| L3 | `list_for_each_entry` starts at `head->next` and stops when the cursor's link is the head itself. The head is not an entry. `list_for_each_entry_reverse` does the same through `prev`. | `include/linux/list.h` `list_for_each_entry`, `list_entry_is_head`, `list_for_each_entry_reverse`, v4.19, v6.14, v6.17. |
| L4 | An entry is its link's address minus the offset of the member in the container (`container_of`). | `include/linux/container_of.h` v6.14, v6.17; `include/linux/kernel.h` v4.19. |
| L5 | On a well-formed list, for each link from A to B through `next`, `B->prev == A`, and the reverse through `prev`. The kernel's list debugging checks exactly this before it changes a list. | `lib/list_debug.c` `__list_add_valid_or_report`, v6.14. |
| L6 | `list_del` overwrites a removed entry's links with `LIST_POISON1` and `LIST_POISON2`, values that are not addresses of a `list_head`. | `include/linux/list.h` `list_del`, `include/linux/poison.h`, v6.14. |
| H1 | `struct hlist_head { struct hlist_node *first; }` and `struct hlist_node { struct hlist_node *next, **pprev; }`. | `include/linux/types.h`, v4.19, v6.14, v6.17. |
| H2 | `hlist_for_each_entry` starts at `head->first` and stops at a null `next`. The list is not circular. | `include/linux/list.h` `hlist_for_each_entry`, v4.19, v6.14, v6.17. |
| H3 | A node's `pprev` holds the address of the previous node's `next`, or of `head->first` for the first node. | `include/linux/list.h` `hlist_add_head`, v6.17. |
| T1 | `task_struct` has `struct list_head tasks`. `init_task.tasks` is initialised to itself and heads the process list. | `include/linux/sched.h`, `init/init_task.c`, v4.19, v6.14, v6.17. |
| T2 | `for_each_process` begins after `init_task` and ends when it returns to `init_task`, so `init_task` (PID 0) is not one of the processes it visits. | `include/linux/sched/signal.h` `for_each_process`, `next_task`, v4.19, v6.14, v6.17. |
| T3 | `copy_process` adds a task to `init_task.tasks` only when its pid is not 0 and it leads its thread group. | `kernel/fork.c` `copy_process`, v4.19, v6.14, v6.17. |
| T4 | Every thread of a group, the leader included, is on `signal->thread_head` through `task_struct.thread_node`: `copy_signal` starts the list with the leader and `copy_process` appends each other thread. `for_each_thread` walks this list. | `kernel/fork.c` `copy_signal`, `copy_process`; `include/linux/sched/signal.h` `__for_each_thread`; v4.19, v6.14, v6.17. |
| T5 | v4.19 also links threads through `task_struct.thread_group`, a circular list that runs through the leader and has no separate head. v6.14 and v6.17 have no `thread_group` member. | `include/linux/sched.h`, `kernel/fork.c`, v4.19, v6.14, v6.17. |
| T6 | A leader's `tgid` is its own `pid`. A thread's `tgid` is copied from the task that created it, so every thread of a group has the leader's `tgid`. | `kernel/fork.c` `copy_process`, v6.14. |
| T7 | `pid_t` is `int`. A pid is allocated below the namespace's `pid_max`, which never exceeds `PID_MAX_LIMIT`. `PID_MAX_LIMIT` is 4 × 1024 × 1024 when `long` is wider than 4 bytes and `PID_MAX_DEFAULT` (0x8000) otherwise, or `PAGE_SIZE * 8` under `CONFIG_BASE_SMALL`, which is never larger. | `include/linux/types.h`, `include/uapi/asm-generic/posix_types.h`, `include/linux/threads.h`, `kernel/pid.c`, v6.14, v6.17. |
| T8 | `copy_signal` runs before the task is put on either list, so a listed task has a `signal` pointer. | `kernel/fork.c` `copy_process`, v6.14, v6.17. |
| T9 | `char comm[TASK_COMM_LEN]` with `TASK_COMM_LEN` 16. | `include/linux/sched.h`, v4.19, v6.14, v6.17. |
| X1 | x86 is little-endian. | `arch/x86/include/uapi/asm/byteorder.h`, v6.14. |

## 4. Algorithm

### 4.1 Circular list (`list_head`)

1. Resolve the offset of `member` in `container`, and of `next` and `prev` in `list_head`, from the symbol table. If any is missing the walk does not start: an error that wraps `ErrUnsupported`.
2. Read the head's `list_head`. If it does not read, end with **HeadUnreadable** at the head.
3. Follow the chosen link (`next` forward, `prev` backward). Each step:
   1. A null link, or one whose `list_head` does not read, ends with **LinkUnreadable** at the `list_head` that held it (L6: a poisoned link does not read).
   2. A link equal to the head ends with **Closed** (L3).
   3. A link equal to a `list_head` already visited ends with **Revisited** at the `list_head` that held it. The list loops without passing its head.
   4. The entry is `link − offset(member)` (L4), put through the address form. If the entry's first byte does not read, end with **EntryUnreadable** at the link.
   5. If the entries already number `MaxListEntries`, end with **Capped** at the link.
   6. Record the entry. If the opposite link of the new `list_head` is not the `list_head` just left, count one **unpaired** link (L5). The walk continues: an unpaired link is evidence of tampering or of a list caught mid-update, not a reason to stop.
4. The walk never records the head (L3).

### 4.2 hlist (`hlist_head`)

1. Resolve the offset of `member` in `container`, and of `first`, `next` and `pprev`, as in 4.1 step 1.
2. Read `head->first`. If it does not read, end with **HeadUnreadable**.
3. Each step from the current link:
   1. A null link ends with **Closed** (H2).
   2. A link whose `hlist_node` does not read ends with **LinkUnreadable** at the address that held it.
   3. A link already visited ends with **Revisited**.
   4. Entry, `EntryUnreadable` and `Capped` as in 4.1 steps 3.4 and 3.5.
   5. If the node's `pprev` is not the address of the field that held the link (H3), count one **unpaired** link and continue.

### 4.3 Task validity

A task address passes when all of these hold. The first that fails is its reason, and the task is left out and counted under that reason.

1. The whole `task_struct`, `sizeof(struct task_struct)` bytes, reads. *Reason: "its task_struct does not read".*
2. `pid` and `tgid` read as `pid_t` (T7). Both are greater than 0 (T3) and below `PID_MAX_LIMIT` for the table's pointer width (T7). *Reason: "its pid or tgid is out of range".*
3. `signal` is not null and the first byte of the `signal_struct` reads (T8). *Reason: "its signal is null or does not read".*
4. For a thread found through 4.5, its `tgid` equals the leader's (T6). *Reason: "its tgid is not its leader's".*

### 4.4 Process walk

1. The head is `init_task + offset(task_struct, tasks)` (T1).
2. Walk the list forward, then backward (4.1). Two directions recover the tasks past a break from both sides, and find a task unlinked through one direction only.
3. Candidates are the forward entries in order, then the backward entries not already seen, in the order the backward walk met them. `init_task` is never a candidate (T2).
4. Each candidate is checked (4.3). A caller's filter, if any, runs on tasks that pass.
5. When the caller asks for threads, each kept leader is followed by its threads (4.5).

### 4.5 Thread walk

1. When `task_struct` has `signal` and `thread_node` and `signal_struct` has `thread_head` (T4): the head is `leader->signal + offset(signal_struct, thread_head)`, the member is `thread_node`.
2. Otherwise, when `task_struct` has `thread_group` (T5): the head is `leader + offset(task_struct, thread_group)`, the member is `thread_group`. The leader is the head, so it is not an entry.
3. Otherwise: an error that wraps `ErrUnsupported`.
4. Walk forward (4.1). Leave out the leader and any task already listed. Check each remaining entry (4.3, with step 4).

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| A circular walk is whole only when it ends at its head. | L3 | The end reason and the address it refers to are returned with the entries read so far. |
| An hlist walk is whole only when it ends at a null link. | H2 | As above. |
| No link is followed twice. | An image can hold a loop. | **Revisited**. |
| A walk records at most `MaxListEntries` entries. | Distinct nodes can be unbounded without a loop. | **Capped**. |
| Back links are checked but do not stop a walk. | L5, H3 | Counted as unpaired. |
| A listed task is a plausible task. | T3, T6, T7, T8 | Left out, counted by reason. |

## 6. Failure modes

- A missing type or member: an error wrapping `ErrUnsupported`, before any memory is read.
- `signal` of a leader does not read when threads are asked for: the leader is kept, its thread list counts as broken.
- Every memory failure inside a walk is an end reason, not an error. Strict mode belongs to the caller: a tool in strict mode turns an end other than **Closed** into its own error; otherwise it reports a diagnostic in the form `<tool>: <object> at 0x<addr>: <what failed>`.

## 7. Result schema

A list walk returns:

| Field | Meaning |
|---|---|
| Entries | Container addresses in walk order, in the address form. |
| End | Closed, HeadUnreadable, LinkUnreadable, EntryUnreadable, Revisited or Capped. |
| At | The address the end refers to: the head, or the link that ended the walk. Zero when Closed. |
| Unpaired | Number of links whose back link does not lead back. |

A task walk returns the kept task addresses, the two process-list walks, the count of left-out tasks per reason, and the number of thread lists that did not close.

## 8. Limits

- `Limits.MaxListEntries` entries per list walk. The visited set holds at most that many links; the head is compared on its own.
- A task walk makes two process-list walks and one thread-list walk per kept leader. Each is capped on its own.

## 9. Acceptance

- Fixtures for each end reason of both list types, in both directions.
- A list that loops without passing its head ends **Revisited**; a self-linked head is empty and **Closed**.
- `MaxListEntries` caps a long list with **Capped**.
- An unpaired back link is counted and the walk continues.
- A task walk unions the two directions, leaves out `init_task`, counts each validity reason, and lists threads after their leader without the leader twice; both thread layouts (T4, T5).
- Fuzz targets over the bytes of a circular list, an hlist and a process list: no panic, termination, at most `MaxListEntries` entries.

## 10. Open points

- Q7, the oldest supported kernel, is undecided. Kernels without `signal_struct.thread_head` and without `task_struct.thread_group` are refused (4.5 step 3).

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| Q7 | Only kernels with thread_head or thread_group |

## 11. Provenance

Sources: the Linux kernel source at tags v4.19, v6.14 and v6.17, files as cited in section 3, from git.kernel.org, accessed 2026-11-11. Author: the project.
