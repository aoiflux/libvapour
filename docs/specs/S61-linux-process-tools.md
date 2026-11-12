# S61: Linux process tools

Version 1, 2026-11-12.

## 1. Purpose

An examiner asks of each Linux process what the kernel says about it beyond its place in the task list: whether it is traced, and by whom; whether it can still be found by number when it is gone from the list; what its kernel stack holds; whether its credentials are its own; which capabilities it holds; which function a kernel thread runs and which module holds that function; whether its name, first argument and executable agree; what its command line is; which shared objects the dynamic linker loaded into it; which of its memory areas begin with an ELF image, and that image rebuilt as a file; and where a regular expression matches in its memory. This specification defines the eleven tools that answer those questions, one section group per tool:

| Tool | Package | Question |
|---|---|---|
| `linux.process.list_tracing` | `tools/linux/processtracing` | Which tasks trace or are traced under ptrace (4.1) |
| `linux.process.list_pid_hash` | `tools/linux/processpidhash` | Which tasks the initial PID namespace's number table reaches (4.2) |
| `linux.process.read_kernel_stack` | `tools/linux/processkernelstack` | Which words of each kernel stack name kernel symbols (4.3) |
| `linux.process.check_credentials` | `tools/linux/processcredentials` | Which credential structures more than one process acts with (4.4) |
| `linux.process.list_capabilities` | `tools/linux/processcapabilities` | Each task's five capability sets (4.5) |
| `linux.thread.list_kernel` | `tools/linux/threadkernel` | Each kernel thread's thread function and its owner (4.6) |
| `linux.process.check_identity` | `tools/linux/processidentity` | Whether comm and the first argument agree with the executable (4.7) |
| `any.process.read_arguments` | `tools/any/processarguments` | Each process's command line, Linux and Windows (4.8, 4.9) |
| `linux.library.list` | `tools/linux/librarylist` | The shared objects in the dynamic linker's list, or else the ELF images the process maps from their files (4.10) |
| `linux.memory.list_elf_files` | `tools/linux/memoryelffiles` | The memory areas that begin with an ELF header, optionally rebuilt (4.11) |
| `linux.memory.find_pattern` | `tools/linux/memorypattern` | Where a regular expression matches in process memory (4.12) |

The task walk is S01 (`tools/linuxwalk`), the IDR walk S02, the task model and a task's address space S14 (`linuxobj` task readers), the capability and ptrace readers S46, kernel symbols and the in-memory ELF reader S38, the memory-area walk and paths S39 (`memoryranges.LinuxWalker`), the module model S06 (`tools/linuxmodule`), the Windows process list S25 and the artefact names S00. They are used here, not re-derived.

## 2. Inputs

Every tool takes a `tools.Context` with kernel memory, the symbol table and the Linux profile (Windows for 4.9), and the shared options `strict`, `diagnostics` and Limits. A tool that reads a process's own memory needs process spaces (`ProcessSpace`, S14 A1 to A6).

| Tool | Options | Limits used |
|---|---|---|
| list_tracing | none | `MaxListEntries` (task and ptraced walks) |
| list_pid_hash | `linux.process.list_pid_hash.decorate_comm` (bool, default false) | S02 tree caps |
| read_kernel_stack | `pid`; `linux.process.read_kernel_stack.unresolved` (bool, default false) | `MaxListEntries` |
| check_credentials | none | `MaxListEntries` |
| list_capabilities | `pid` | `MaxListEntries` |
| list_kernel (threads) | none | S06 caps |
| check_identity | `pid` | S39 caps |
| read_arguments | `pid` | none of its own |
| library.list | `pid` | `MaxTableEntries` (program headers, dynamic entries, list entries), `MaxNameBytes` |
| list_elf_files | `pid`; `linux.memory.list_elf_files.dump` (bool) with `output_dir` | `MaxTableEntries`, `NameAttempts`, the dump limit |
| find_pattern | `pid`; `linux.memory.find_pattern.pattern` (string, required); `linux.memory.find_pattern.maxsize` (uint) | the scanner's chunk and match caps |

A wrong option type is an error (owner decision 2026-11-03).

## 3. Facts from the sources

Kernel tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17, fetched from `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=<tag>` on 2026-11-12, unless a row names fewer. ELF facts cite the System V ABI, ELF gABI chapters 4 and 5 (sco.com edition, accessed 2026-11-12). Windows facts cite the PDB types of each capture's own `ntkrnlmp` read through the project's symbol tables (builds 14393, 19045 and 26100) and Microsoft Learn, accessed 2026-11-12. The captures run 6.17 (Ubuntu 24, mem3) and 6.14 (Fedora 40, mem4).

### Ptrace (list_tracing)

| # | Fact | Source |
|---|---|---|
| T1 | `task->ptrace` holds `PT_PTRACED` while a task is traced, with `PT_SEIZED` and the option bits shifted by `PT_OPT_FLAG_SHIFT`; unlink sets it to 0. The bit names are S46 R1. | S46 R1 to R3 (`include/linux/ptrace.h`, `kernel/ptrace.c`, every tag) |
| T2 | `__ptrace_link` adds `child->ptrace_entry` to `new_parent->ptraced` and sets `child->parent = new_parent`; `__ptrace_unlink` restores `child->parent = child->real_parent`. | S46 R3, R4 (`kernel/ptrace.c`, every tag) |
| T3 | So while a task is traced its `parent` is the tracer and it is on the tracer's `ptraced` list; while it is not, `parent` equals `real_parent`. Ptrace attaches to one thread, so threads are traced and trace one by one. | T2; `kernel/ptrace.c` `ptrace_attach` (by `pid`), every tag |

### PID numbers (list_pid_hash)

| # | Fact | Source |
|---|---|---|
| H1 | `enum pid_type` is `PIDTYPE_PID, PIDTYPE_TGID, PIDTYPE_PGID, PIDTYPE_SID, PIDTYPE_MAX`: `PIDTYPE_PID` is 0. | `include/linux/pid.h` v4.19, v6.1, v6.4; `include/linux/pid_types.h` v6.14, v6.17 |
| H2 | `struct pid_namespace` has `struct idr idr`. `alloc_pid` reserves each level's number with `idr_alloc` (or `idr_alloc_cyclic`) into that level's `ns->idr` with a NULL entry, then `idr_replace(&upid->ns->idr, pid, upid->nr)`; `pid_idr_init` initialises `init_pid_ns.idr`. Level 0 is the initial namespace, so every `struct pid` is in `init_pid_ns.idr` at its initial number. | `include/linux/pid_namespace.h`, `kernel/pid.c`, every tag |
| H3 | `struct pid` has `struct hlist_head tasks[PIDTYPE_MAX]`; `pid_task(pid, type)` takes the first node of `pid->tasks[type]` and returns the `task_struct` that holds it at `pid_links[type]`. `task_struct` has `struct hlist_node pid_links[PIDTYPE_MAX]`. | `include/linux/pid.h`, `kernel/pid.c`, `include/linux/sched.h`, every tag |
| H4 | `copy_process` sets `p->pid = pid_nr(pid)`, the level-0 number. | S14 I2 |
| H5 | No tag checked keeps a `pid_hash` table; the IDR replaced it before v4.19. | `kernel/pid.c`, every tag |

### Kernel stacks (read_kernel_stack)

| # | Fact | Source |
|---|---|---|
| K1 | On x86-64 `THREAD_SIZE` is `PAGE_SIZE << THREAD_SIZE_ORDER` with `THREAD_SIZE_ORDER` `2 + KASAN_STACK_ORDER`, and `KASAN_STACK_ORDER` is 1 with `CONFIG_KASAN` and 0 without. `PAGE_SIZE` is 4096 (S38 E7). | `arch/x86/include/asm/page_64_types.h`, every tag |
| K2 | `mm/kasan` builds the generic runtime (`generic.c` from v6.1, `kasan.c` at v4.19) only with KASAN; it defines `__asan_load8` through `DEFINE_ASAN_LOAD_STORE(8)`. | `mm/kasan/Makefile`, `mm/kasan/generic.c` v6.1 to v6.17; `mm/kasan/kasan.c` v4.19 |
| K3 | `task_stack_page(task)` is `task->stack`. `alloc_thread_stack_node` takes the stack from `__vmalloc_node_range` or `__vmalloc_node` (kernel virtual memory) or from `alloc_pages_node` through `page_address`, so the stack is kernel memory whatever the task; `tsk->stack` is set to NULL when it is freed. | `include/linux/sched/task_stack.h`, `kernel/fork.c`, v4.19, v6.17 |
| K4 | `get_stack_pointer` returns `task->thread.sp` for any task other than the current one; `struct thread_struct` has `unsigned long sp`. `in_task_stack` accepts a stack address in `[task_stack_page(task), task_stack_page(task) + THREAD_SIZE)`. | `arch/x86/include/asm/stacktrace.h`, `arch/x86/include/asm/processor.h`, `arch/x86/kernel/dumpstack_64.c`, every tag |
| K5 | At `thread.sp` a switched-out task holds `struct inactive_task_frame`: `r15, r14, r13, r12, bx, bp, ret_addr` on x86-64. | `arch/x86/include/asm/switch_to.h`, every tag |
| K6 | `show_trace_log_lvl` scans every word of the stack from the stack pointer to the stack's end and prints each word that is a kernel text address, marking those the unwinder did not reach as unreliable. | `arch/x86/kernel/dumpstack.c`, every tag (the loop read at v4.19, v6.1, v6.4, v6.14, v6.17) |
| K7 | An x86-64 linear address is canonical only when bits 63 down to the top implemented bit (47 with 4-level paging, 56 with 5-level) are all equal; a non-canonical value is no address, so it is no kernel text address either. | Intel SDM Vol. 1 3.3.7.1 "Canonical Addressing"; Vol. 3A 4.5 |

### Credentials (check_credentials)

| # | Fact | Source |
|---|---|---|
| C1 | `task_struct.cred` is the subjective credentials a task acts with and `real_cred` the objective ones others see. | S14 C1, C2 |
| C2 | `copy_creds` shares the parent's cred only for `CLONE_THREAD` (without a thread keyring); every other new task gets its own from `prepare_creds`. | `kernel/cred.c`, v4.19, v6.17 |
| C3 | `init_task` starts with `cred` and `real_cred` set to `&init_cred`. | `init/init_task.c`, v4.19, v6.17 |

### Capabilities (list_capabilities)

| # | Fact | Source |
|---|---|---|
| P1 | `/proc/<pid>/status` prints `CapInh`, `CapPrm`, `CapEff`, `CapBnd` and `CapAmb` from `__task_cred(p)`, the objective `real_cred`. Credentials are per task, and `/proc/<pid>/task/<tid>/status` shows each thread's. | `fs/proc/array.c` `task_cap`; S14 C2; every tag |
| P2 | `cap_ambient_invariant_ok`: the ambient set lies within permitted and inheritable. | S46 P5 |
| P3 | Set reading, the running kernel's full set and the text form are S46 P1 to P4 and 4.4. | S46 |

### Kernel threads (list_kernel)

| # | Fact | Source |
|---|---|---|
| W1 | From v6.1 `to_kthread(k)` is `k->worker_private` for a `PF_KTHREAD` task, and `set_kthread_struct`, called from `copy_process` for a kernel thread from v6.1, sets it; at v4.19 it is `set_child_tid`. | `kernel/kthread.c`, `kernel/fork.c`, every tag |
| W2 | `struct kthread` has `int (*threadfn)(void *)` and `char *full_name` from v6.1; neither at v4.19. `kthread()` stores the creator's `threadfn` and, from v6.4, `full_name` for every thread; at v6.1 `full_name` is set only when the formatted name is `TASK_COMM_LEN` or longer. `kthread_func` returns `threadfn`. | `kernel/kthread.c`, every tag |
| W3 | `struct kthread` has `struct task_struct *task` from v6.14, set by `set_kthread_struct`. | `kernel/kthread.c`, v6.14, v6.17 |
| W4 | `proc_task_name` shows a kernel thread's `full_name` through `get_kthread_comm` into `char tcomm[64]` with `strscpy_pad`, so at most 63 bytes. | `fs/proc/array.c`, `kernel/kthread.c`, v6.17 |
| W5 | The owner of an address is the S06 lookup over the module views (`Model.Lookup`, `Owner.Names`). | S06 |

### Identity (check_identity)

| # | Fact | Source |
|---|---|---|
| I1 | `/proc/<pid>/exe` is the `f_path` of `mm->exe_file`. | S39 F4 |
| I2 | `kbasename` returns the part after the last `/`. | `include/linux/string.h`, v4.19, v6.17 |
| I3 | `d_path` appends ` (deleted)` to the path of an unlinked dentry. | S39 P3 |
| I4 | Exec sets `comm` with `__set_task_comm(me, kbasename(bprm->filename), true)`: the base name of the path given to execve, not of the file reached through symbolic links, and the script's name for `#!`. From v6.14 an exec through an empty name on a descriptor takes the name from the file's dentry. `__set_task_comm` keeps at most `TASK_COMM_LEN - 1` bytes (S14 N2). `prctl(PR_SET_NAME)` writes any name later (S14 N3). | `fs/exec.c`, every tag (`comm_from_dentry` v6.14, v6.17) |
| I5 | The first argument is whatever the caller passed as `argv[0]`, and a process may overwrite its argument area (A3). | `fs/exec.c` `copy_strings`; A3 |

### Command lines, Linux (read_arguments)

| # | Fact | Source |
|---|---|---|
| A1 | `mm_struct` has `unsigned long arg_start, arg_end, env_start, env_end`. | `include/linux/mm_types.h`, every tag |
| A2 | `get_mm_cmdline` returns nothing when `env_end` is 0 or `arg_start >= arg_end`, and otherwise the bytes of `[arg_start, arg_end)` as read, stopping at the first page that does not read. | `fs/proc/base.c`, v6.1, v6.4, v6.14, v6.17 |
| A3 | When the byte at `arg_end - 1` is not NUL the argument area was overwritten (`setproctitle`), and `get_mm_proctitle` returns at most one page from `arg_start` up to and including its first NUL. v4.19 instead lets the read run up to one page into a contiguous environment. | `fs/proc/base.c`, v6.1 to v6.17; v4.19 |
| A4 | Arguments are NUL-terminated strings laid out one after another by `copy_strings`. | `fs/exec.c`, every tag |
| A5 | `bprm_stack_limits` (v6.1 on; `get_arg_page` at v4.19) bounds argv and envp of one exec to `_STK_LIM / 4 * 3` (at most), and `_STK_LIM` is 8 MiB, so 6 MiB; a larger area was set later through `prctl(PR_SET_MM)`. | `fs/exec.c`, `include/uapi/linux/resource.h`, v4.19, v6.17 |

### Command lines, Windows (read_arguments)

| # | Fact | Source |
|---|---|---|
| N1 | `_EPROCESS.Peb` points to the process's user-mode `_PEB`; `_PEB.ProcessParameters` points to its `_RTL_USER_PROCESS_PARAMETERS`, whose `CommandLine` is a `_UNICODE_STRING`. Both structures are user-mode memory of the process. | PDB types (M24); Microsoft Learn "PEB structure (winternl.h)", "RTL_USER_PROCESS_PARAMETERS structure (winternl.h)" |
| N2 | `_UNICODE_STRING` is `Length` (bytes, not counting a terminating NUL), `MaximumLength` and `Buffer`. | Microsoft Learn "UNICODE_STRING structure (ntdef.h)"; PDB types (M24) |
| N3 | Processes that run no user-mode image (System, Registry, MemCompression, Secure System) have a null `Peb`. | M24 |

### Shared objects (library.list)

| # | Fact | Source |
|---|---|---|
| L1 | `DT_DEBUG`'s contents are not specified by the ABI; the dynamic linker fills the executable's with the address of its debugger structure, whose list gives base address, name, dynamic section and next for each loaded object. The layout is measured. | S38 E5, S2 |
| L2 | An image's identification, program headers, base address, dynamic section and list are read by S38 4.8. | S38 |
| L3 | `vm_area_struct.vm_pgoff` is "the offset in vm_file corresponding to vm_start" in `PAGE_SIZE` units; `mmap_region` (`__mmap_region` in `mm/vma.c` from v6.14) sets `vm_pgoff` to the mapping's page offset and `vm_file` to the mapped file. So an area of a file with `vm_pgoff` 0 begins with that file's first byte. | `include/linux/mm_types.h`, every tag; `mm/mmap.c` v4.19, v6.1, v6.4; `mm/vma.c` v6.14, v6.17 |
| L4 | An ELF file's header is at file offset 0 (E2), and the image base used for the base address is the address of file offset 0 (S38 4.8 step 3). An area as in L3 whose first bytes are `\x7fELF` therefore holds an image whose base address S38 4.8 step 3 gives from its own program headers. Which code made the mapping (the kernel, the dynamic linker or a later `mmap`) is not recorded. | L3; E1, E2; S38 E4 |
| L5 | Exec maps the executable's segments from `bprm->file` (`elf_map`; `elf_load` from v6.14) and sets `mm->exe_file` to the same `bprm->file` (`set_mm_exe_file`), so the executable's areas carry `vm_file == mm->exe_file`. | `fs/binfmt_elf.c` `load_elf_binary`, `fs/exec.c`, every tag |

### ELF areas (list_elf_files)

| # | Fact | Source |
|---|---|---|
| E1 | `e_ident` begins `\x7fELF`. | S38 E1 |
| E2 | The ELF header is at file offset 0, and a loader that maps the segment holding offset 0 puts the header at that mapping's start. | gABI chapter 4 "ELF Header", chapter 5 "Program Loading"; `fs/binfmt_elf.c` `elf_map`, every tag |
| E3 | A `PT_LOAD` segment maps file bytes `[p_offset, p_offset + p_filesz)` to `[base + p_vaddr, base + p_vaddr + p_filesz)`; bytes up to `p_memsz` beyond `p_filesz` are zero and have no file bytes. | gABI chapter 5 "Program Header", "Base Address"; S38 E3, E4 |
| E4 | The base address is S38 4.8 step 3 (`LoadBias`). | S38 E4 |

### Pattern search (find_pattern)

| # | Fact | Source |
|---|---|---|
| R1 | Patterns are RE2 syntax (owner decision COL-16), compiled with `.` matching newlines, over the bytes as Latin-1 text, in chunks with a lookahead and at most `MaxMatchesPerChunk` matches per chunk. | S64 4.11 (`tools/windows/kernelpattern`, the shared scanner) |
| R2 | A process's memory areas are its S39 VMAs; their pages are found through its own page tables (S46 4.6, `Translator`). | S39, S46 |

### Measurements

Run on 2026-11-12 with `linuxprocfacts` on mem3_ubuntu24 and mem4_fedora40, and with `-windows` on mem1_win11, mem2_win10, mem5_server2016 and mem6_server2025.

| # | Measurement | mem3_ubuntu24 | mem4_fedora40 |
|---|---|---|---|
| M1 | Tracing. Tasks walked (threads too); `PT_PTRACED` set; `ptraced` not empty; untraced tasks with `parent == real_parent` (T3); rows | 557; 0; 0; 557 of 557; 0 | 573; 0; 0; 573 of 573; 0 |
| M2 | PID table. `init_pid_ns.idr` entries, with none revisited, unread or inconsistent; rows; entries with no PID task; entries whose task's `pid` is not the index (left out); tasks walked; walked tasks not in the table; table tasks not walked | 558; 556; 2; 0; 557; 1 (pid 2175, a live thread, `exit_state` 0); 0 | 583; 577; 3; 3 (first: index 3098, task pid 2405); 573; 1 (an exiting task: `exit_state` 16, null stack and creds); 5 (`kworker/u16:*`, where the task list's backward walk is broken) |
| M3 | Kernel stacks. `__asan_load8` absent, `THREAD_SIZE` 0x4000; stacks null; `sp` inside the stack; stacks aligned to `THREAD_SIZE`; bytes from `sp` to the stack's end (min, median, max); `ret_addr` of the saved frame (K5) named `__schedule`; rows (named words); rows with `unresolved` | yes; 1; 556 of 556; 556; 480, 1928, 2936; 542 of 556; 18,625 (154 non-canonical words left unnamed, K7); 73,502 | yes; 1; 572 of 572; 572; 440, 1824, 2832; 551 of 572; 15,629 (3 non-canonical words left unnamed, K7); 67,281 |
| M4 | Credentials. Thread-group leaders; leaders with `cred == real_cred`; distinct `cred` among leaders; tasks; distinct `cred` among tasks; creds held by more than one thread group; leaders acting with `init_cred`; rows | 203; 203; 203; 557; 210; 0; 0; 0 | 242; 242; 242; 573; 245; 0; 0; 0 (1 task without a cred, the exiting task of M2) |
| M5 | Capabilities. `cap_last_cap` 40, full set 0x1ffffffffff; rows (threads); effective full / empty / other; bounding full; ambient not empty; ambient outside P2 | 556 (353); 151 / 367 / 38; 508; 9; 0 | 572 (331); 160 / 358 / 54; 502; 3; 0 |
| M6 | Kernel threads. `PF_KTHREAD` tasks; `worker_private` null; `threadfn` null (`kthreadd` only); `kthread.task` points back (W3); `full_name` set; longer than 15 bytes; rows; owners `kernel` / module | 88; 0; 1; 87 of 87; 87; 33; 87; 86 / 1 (`hv_balloon`) | 118; 0; 1; 117 of 117; 117; 48; 117; 116 / 1 (`hv_balloon`) |
| M20 | Linux command lines. Rows; tasks with an argument area; `env_start == arg_end`; last byte NUL / not NUL (A3) / not read; largest area; rows not read | 203; 115; 112; 107 / 7 / 1; 156 bytes; 1 | 242; 123; 119; 97 / 1 / 25; 159 bytes; 25 |
| M21 | Shared objects, linker list (4.10 steps 2 to 4). Processes with an address space; with one distinct `DT_DEBUG`; with none; processes listing objects; rows; entries with an empty name (the executable's at position 0); lists cut at a read | 115; 51; 64; 46; 1,729; 46 + 2; 15 | 123; 19; 104; 19; 721; 19; 0 |
| M21a | Why a process finds no `DT_DEBUG` (`-run libraryroutes`): the executable's header page does not read; its first area reads but does not begin with `\x7fELF`; its dynamic section does not read; `DT_DEBUG` absent or 0 | 44; 16 (pid 1 among them); 1; 3 | 98; 1; 3; 2 |
| M21b | Both routes (`-run libraryroutes`, after O6). Processes listing through the linker list / through mapped images / nothing (none of them with a mapped image read); rows by route; executables at offset 0 left out (L5); mapped images whose path is the executable's | 46 / 79 / 10 (after O14, 20 processes list by both routes; before, 46 / 59 / 10); 1,729 / 2,272 (before O14, 1,634); 54; 0 | 19 / 97 / 7; 721 / 3,252; 24; 0 (no list here ends early) |
| M21c | Cross-check where a linker list gives rows: the mapped images of L3 and L4 against the list by base address. Entries with a mapped image at that base and the same path / another path (the list names `/lib/...` where the mapping shows `/usr/lib/...`) / no mapped image at their base (`linux-vdso.so.1`, and images whose header page does not read); mapped images at no list base | 79 / 1,315 / 335; 638 (15 lists cut at a read, M21) | 80 / 579 / 62; 0 |
| M21d | pid 1 (`systemd`). mem3: the executable's first area reads but does not begin with an ELF header, so no `DT_DEBUG` is found; the mapped images give 24 rows (`libc.so.6`, `libsystemd-shared-255.so`, `libsystemd-core-255.so`, `ld-linux-x86-64.so.2` and 20 more). mem4: the executable's header page does not read; 24 rows the same way | 24 rows, route mapped image | 24 rows, route mapped image |
| M21e | Ground truth (mem8_fedora40, 6.14, 2026-11-12: `/proc/<pid>/maps` of every process taken just before the capture). Shared objects the maps show (the first area at offset 0 of each file named like a shared object, and the vDSO) against the rows: every row is at such an object's base; 3,282 rows, 2,906 by the linker list (2,562 of them under the linker's name for the file at that base, such as `/lib64/libdw.so.1` for `/usr/lib64/libdw-0.192.so`) and 376 by mapped images. Objects with no row: 24 vDSOs of processes listed by mapped images or not at all (4.10 step 7); 18 after a list cut short by a read failure (pid 2027); 19 after a list whose third entry reads as 32 zero bytes, so `next` is 0 and the walk ends with the executable's and the vDSO's entries (pid 1082); 271 whose first page does not read (260) or does not begin with an ELF header (11), among them `libzstd` that pid 2175 mapped with `mmap` and never read. The two objects pid 2174 loaded with `dlopen` (`libz.so.1`, `libbz2.so.1`) are linker-list rows. After O14 the 18 and 19 objects past the early ends are mapped-image rows except one whose first page is not an ELF header: 3,318 rows (412 by mapped images); objects with no row are 24 vDSOs and 272 whose first page does not read or is not an ELF header. (`linuxprocfacts -run librarytruth,objects`; gate `TestLinuxLibraryListMatchesTheCapturesGroundTruth`) | not measured (mem8 only) | not measured (mem8 only) |
| M22 | Identity. Rows; exe read; argument read; argument in title form; comm differs; argument differs; neither (kernel threads and exiting tasks). The differences seen are exec through a symbolic link (`udevadm` for `systemd-udevd`, `python3.12` for `python3`), `#!` scripts (`unattended-upgr`, `firewalld`), names set later (`(sd-pam)`, `(udev-worker)`, `init` for `systemd`, `@dbus-daemon`) and titles. An empty first argument occurs (`systemd-oomd`, `rsyslogd`, `pipewire`) and is not compared | 203; 115; 114; 7; 9; 20; 88 | 242; 123; 98; 1; 7; 9; 119 |
| M23 | ELF areas. Rows (all with a path); file-backed areas with the header at file offset 0; at another file offset; anonymous areas with a header; images whose program headers do not read (`e_phentsize` 0); rebuilt size within the file's `i_size`; pid 1 dump: rows, artefacts written | 3,938; 3,720; 107; 111; 103; 3,723 of 3,724; 26, 25 | 4,170; 3,935; 116; 119; 116; 3,935 of 3,935; 26, 25 |
| M25 | Pattern `GLIBC_2\.[0-9]+` in pid 1: matches; matches whose bytes read the same through the process layer; distinct texts | 270; 270; 34 | 253; 253; 34 |

| # | Measurement | mem1_win11 (26100) | mem2_win10 (19045) | mem5_server2016 (14393) | mem6_server2025 (26100) |
|---|---|---|---|---|---|
| M24 | `_EPROCESS.Peb`; `_PEB.ProcessParameters`; `CommandLine`; `_UNICODE_STRING` `Length`/`MaximumLength`/`Buffer` | 0x2e0; 0x20; 0x70; 0/2/8 | 0x550; 0x20; 0x70; 0/2/8 | 0x3f8; 0x20; 0x70; 0/2/8 | 0x2e0; 0x20; 0x70; 0/2/8 |
| M24 | Rows; with a command line; empty (null `Peb`: N3); not read (parameters or buffer paged out or not captured) | 83; 75; 4; 4 | 153; 142; 4; 7 | 71; 67; 1; 3 | 101; 84; 2; 15 |

## 4. Algorithm

Every Linux tool first validates the context and refuses a profile that is not Linux, walks the tasks with S01 (`Walker().Tasks`) and reports the walk's losses as diagnostics.

### 4.1 list_tracing

1. Walk every task, threads included (T3).
2. A task is listed when `PT_PTRACED` is set in `ptrace` or its `ptraced` list is not empty (T1, T2).
3. Its row gives `comm`, `tgid`, `pid`, whether it is traced, the tracer's `pid` (S46 4.5 step 2; 0 when not traced or `parent` is null), its tracees' `pid`s in list order (S46 4.5 step 3) and the option text: the S46 R1 names joined by `|`, then any bits without a name as one hexadecimal value.
4. Cross-check (T3): a traced task whose tracer is listed but does not hold it on its `ptraced` list is a diagnostic.

### 4.2 list_pid_hash

1. Without `pid_namespace.idr` the kernel layout is not supported (H5).
2. Walk `init_pid_ns.idr` with S02 (H2); each entry is a `struct pid` at its initial number.
3. `PIDTYPE_PID` is the table's enumerator when it has one, else 0 (H1).
4. The task is the holder of the first node of `tasks[PIDTYPE_PID]` at `pid_links[PIDTYPE_PID]` (H3). A null first node is a number with no task (a group or session number whose leader is gone) and gives no row.
5. The task's identity, parent and name are S14's (`TaskFields`, with `decorate_comm`). A task whose `pid` is not the entry's index is left out with a diagnostic (H4).
6. Sort by `tgid`, then `pid`.

### 4.3 read_kernel_stack

1. Walk every task, threads included, filtered by `pid`.
2. `THREAD_SIZE` is 32 KiB when the table names `__asan_load8` and 16 KiB otherwise (K1, K2).
3. Read `task->stack` and `task->thread.sp` from kernel memory (K3, K4). A null stack gives no rows. An `sp` outside `[stack, stack + THREAD_SIZE)` skips the task with a diagnostic (K4).
4. Read the pointer-sized little-endian words from `sp` to the stack's end, a page at a time; a page that does not read ends the words with a diagnostic.
5. Every non-zero word that is a canonical address as stored (K7) and that S38 `SymbolAt` names gives a row (K6). S38 4.2 compares canonical forms, so a word is tested before it is named: a non-canonical word would otherwise be named by the canonical form of its low bits. With `unresolved`, every non-zero word gives a row, unnamed when it is not canonical. The slot is the word's index from `sp`.
6. S38 lookup failures are diagnostics, one per reason.

### 4.4 check_credentials

1. Without `task_struct.cred` the layout is not supported.
2. Walk the thread-group leaders. A leader's `cred` (C1) is read with S14 `TaskCred`; one that is null or does not read is counted.
3. Group the leaders' `tgid`s by `cred` address. A `cred` held by two or more groups is a row (C2), marked when it is `init_cred` (C3).
4. Within a row the `tgid`s are ascending; rows are sorted by their first `tgid`.

### 4.5 list_capabilities

1. All five `cred.cap_*` members are required.
2. A `cap_last_cap` above the named capabilities is a diagnostic; the full set is S46 4.4 step 2.
3. Walk every task, threads included (P1), filtered by `pid`.
4. Read `real_cred` (P1); a null one fails the task. Its `euid` (S14 C3) and five sets (S46 4.4 step 1) give the row in S46 text form.
5. An ambient set outside permitted and inheritable (P2) is a diagnostic.

### 4.6 list_kernel (threads)

1. `task_struct.worker_private` and `kthread.threadfn` are required (W1, W2); without them the kernel is not supported.
2. Build the S06 module views once and report their losses.
3. Walk every task, threads included. For a `PF_KTHREAD` task (S14 K1) read `worker_private`; null gives no row. Read `threadfn`; null gives no row (W2: a thread `kthread()` did not start, such as `kthreadd`).
4. The name is `comm`, or `full_name` when the table has it and it is set, read up to 64 bytes and kept to 63 (W4). A `full_name` that does not read keeps `comm` with a diagnostic.
5. The owner is the S06 lookup of `threadfn` (W5). An address no module or kernel image holds is listed with no owner.

### 4.7 check_identity

1. Walk the thread-group leaders, filtered by `pid`. Read `tgid`, the parent's `tgid` (S14 I6) and `comm`.
2. For a task that is not a kernel thread: the executable's path is the S39 path of `mm->exe_file` (I1); ` (deleted)` marks it unlinked (I3); its name is the base name (I2) of the path without that mark. The first argument is the 4.8 reading's first word, its base name, and whether it came from a title (A3).
3. Comparison, only when the executable's name was read: comm differs when it is not the executable's name cut to 15 bytes (I4); the argument differs when a non-empty first-argument name is not the executable's name (I5).

### 4.8 read_arguments, Linux

1. Rows follow the S25 process list, filtered by `pid`.
2. A task without its own address space (S14 `ProcessLayer`) has no argument area and an empty command line.
3. Read `arg_start`, `arg_end` and `env_end` (A1). `env_end` 0 or `arg_start >= arg_end` is an empty command line (A2).
4. Read the byte at `arg_end - 1`. If it does not read, the area is not read. If it is not NUL, read at most one page from `arg_start` a page at a time and keep the bytes before the first NUL as one word, marked title (A3).
5. Otherwise an area over 6 MiB (A5) is not read. Read `[arg_start, arg_end)` a page at a time, stopping at the first page that does not read (A2); drop one trailing NUL and split at NUL into words (A4). A short read keeps the words before the gap and marks the row not read.
6. `Cmdline` is the words joined by single spaces; bytes that are not UTF-8 are replaced (`util.DecodeUTF8Replace`).

### 4.9 read_arguments, Windows

1. Resolve `_EPROCESS.Peb`, `_PEB.ProcessParameters` and `_RTL_USER_PROCESS_PARAMETERS.CommandLine` from the table; a missing member fails the tool.
2. Rows follow the S25 process list, filtered by `pid`. Read `Peb` from kernel memory; null is an empty command line (N3).
3. Read `ProcessParameters` and the `CommandLine` string only through the process's own space (N1); a space that cannot be built, or a read that fails, marks the row not read. Null parameters are an empty command line.
4. The string is `util.ReadUnicodeString` (N2).

### 4.10 library.list

1. Walk the thread-group leaders, filtered by `pid`; skip tasks without their own address space.
2. For each S39 area of the process whose start holds an ELF image (L2), read `DT_DEBUG`. Each distinct non-zero value leads to one list (L1).
3. Walk each list (S38 4.8 step 5). An entry already seen, or with no name pointer, is skipped; a name that does not read cuts the list with a diagnostic; an empty name (the executable's own entry) gives no row.
4. A row is `comm`, `tgid`, the entry's base address and its name, in list order, with route `linker list`.
5. **Mapped images** (owner decisions O6, O14). A process is read a second way when its lists give no row (no `DT_DEBUG` found, or lists with no named entry), or when a list ends early: a read failure cuts it (step 3, S38 4.8 step 5), or its last entry reads as zero bytes in its base, name and dynamic-section fields (S38 O10, M21e). Each S39 area with a file whose `vm_pgoff` is 0 (L3) and whose first bytes are an ELF header (L4) is one image. Areas of `mm->exe_file` are left out (L5), as the list leaves out the executable's own entry. Where the lists gave rows, an image whose base address a linker-list row already has gives no row, so that an object is listed once.
6. The image's base address is S38 4.8 step 3 from its program headers; an image whose program headers do not read, or with no `PT_LOAD`, gives no row. Its path is the S39 area name; an area whose name cannot be built gives no row and is counted.
7. A row is `comm`, `tgid`, the base address and the path, in area order, with route `mapped image`, after the process's linker-list rows. Special mappings (`[vdso]`) have no file and give no row on this route.

### 4.11 list_elf_files

1. With `dump`, `output_dir` is required (`ErrNoOutputDir`).
2. Walk the thread-group leaders, filtered by `pid`; skip tasks without their own address space.
3. Each S39 area whose first 4 bytes read as `\x7fELF` (E1, E2) is a row with its start, end and S39 area name.
4. **Rebuild.** Parse the image (S38 4.8), take its base address (E4), and place each `PT_LOAD` segment with file bytes at its file offset: `p_filesz` bytes from `base + p_vaddr` at `p_offset` (E3). The file is as long as the largest `p_offset + p_filesz`. Pages that do not read are zero-filled and counted. An image with no such segment, a segment that wraps, or a file over the dump limit is not written; the failure is a diagnostic and the row has no artefact.
5. The artefact name is S00 `image.pid<N>.<0xaddr>.<label>.elf`, labelled by the area's path, or `comm` without one.

### 4.12 find_pattern

1. The pattern option is required and compiled as R1; `maxsize` caps the bytes kept per match. Physical memory is required.
2. Walk the thread-group leaders, filtered by `pid`. For each task with its own page tables (S14 `TaskDTB`), take its S39 areas as sections and search the pages its page tables map, read from physical memory, with the shared scanner (R1, R2; S64 4.11 steps 3 to 7), its per-chunk cap set to `MaxMatchesPerChunk`.
3. A row is `tgid`, `comm`, the match's virtual address, its kept bytes and their text (`util.DecodeUTF8Replace`).
4. Page tables that do not read, pages outside the capture, chunks that do not read and chunks that reached the match cap are diagnostics.

## 5. Validity rules

| Tool | Rule | Justification | On failure |
|---|---|---|---|
| list_tracing | A traced task is on its tracer's `ptraced` list | T3, M1 | Diagnostic |
| list_pid_hash | The task's `pid` equals its IDR index | H2, H4, M2 | Left out, diagnostic; error in strict mode |
| list_pid_hash | A number with no `PIDTYPE_PID` task has no row | H3 | Skipped |
| read_kernel_stack | `sp` lies in `[stack, stack + THREAD_SIZE)` | K4, M3 | Task skipped, diagnostic; error in strict mode |
| read_kernel_stack | Words are read only from readable pages | 4.3 step 4 | Words end, diagnostic |
| check_credentials | A cred is held by one thread group | C2, M4 | Row |
| list_capabilities | Ambient within permitted and inheritable | P2, M5 | Diagnostic |
| list_capabilities | `real_cred` is set | S14 C1 | Task not read |
| list_kernel | `worker_private` and `threadfn` set | W1, W2, M6 | No row |
| check_identity | comm is the executable's name cut to 15 bytes | I4, M22 | `CommDiffers` |
| check_identity | A non-empty first-argument name is the executable's name | I5, M22 | `ArgumentDiffers` |
| read_arguments | The area is at most 6 MiB, unless a title | A5 | Not read |
| list_elf_files | A rebuilt file fits the dump limit | Limits | Not written, diagnostic |
| library.list | A mapped image is a file area at `vm_pgoff` 0 that begins with an ELF header and is not the executable | L3 to L5, M21b, M21c | No row |

## 6. Failure modes

| Case | Result |
|---|---|
| Profile not Linux (Windows for 4.9) | Error `<tool>: unsupported profile os "<os>"` |
| A required member missing | Error naming the member, wrapping `linuxobj.ErrUnsupported` where the kernel layout is the cause |
| Task walk fails | Error; walk losses are diagnostics |
| One task's members do not read | Counted; one diagnostic `<tool>: <n> <objects> not read, first: task_struct at 0x<addr>: <why>`; error `<tool>: strict mode: …` in strict mode |
| A process space cannot be built | Counted diagnostic; for read_arguments the row is marked not read |
| An argument area does not read | `processarguments.ErrArgumentsUnread`; over 6 MiB `ErrArgumentArea` |
| A library list or area list is cut | Diagnostic; error in strict mode |
| A mapped image's `exe_file`, `vm_pgoff` or path does not read | `linux.library.list: <n> processes with mapped images not read, first: task_struct at 0x<addr>: <why>`; error in strict mode |
| A rebuilt image | `memoryelffiles.ErrNoLoadSegment`, `ErrSegmentWraps`, `ErrOverLimit` in a diagnostic |
| Dump without output directory | `memoryelffiles.ErrNoOutputDir` |
| No pattern, or no physical memory | Error |

## 7. Result schema

`linux.process.list_tracing` (`processtracing.Row`): `Process` (comm), `PID` (tgid), `TID` (pid), `Traced` (bool), `TracerTID` (0 when none), `Tracees` ([]int64, nil when none), `Options` (text, empty when none). Sorted by PID, TID.

`linux.process.list_pid_hash` (`processpidhash.Task`): `TaskAddress` (task_struct, canonical), `PID`, `TID`, `PPID` (0 when the parent does not read), `Comm` (decorated with the option). Sorted by PID, TID.

`linux.process.read_kernel_stack` (`processkernelstack.Entry`): `TID`, `Process`, `Slot` (word index from sp), `SlotAddress`, `Value` (as stored), `Named`, `Symbol`, `Offset` (from the symbol's start), `SymbolType` (kallsyms letter, empty when unknown), `Module` (`kernel` for the image, empty when unknown). In walk order, then slot order. `ThreadSize(*linuxobj.Kernel)` is exported for measurement.

`linux.process.check_credentials` (`processcredentials.SharedCred`): `CredAddress`, `PIDs` (ascending), `InitCred`. Sorted by first PID.

`linux.process.list_capabilities` (`processcapabilities.Process`): `Process`, `PID`, `TID`, `PPID`, `EUID`, `Inheritable`, `Permitted`, `Effective`, `Bounding`, `Ambient` (S46 text). In walk order.

`linux.thread.list_kernel` (`threadkernel.Thread`): `TID`, `Name`, `FunctionAddress`, `Module`, `Symbol` (S06 display form), `OwnerFound`. In walk order.

`linux.process.check_identity` (`processidentity.Process`): `PID`, `PPID`, `Comm`, `ExePath` (with any ` (deleted)`), `ExeName`, `ExeRead`, `ExeDeleted`, `ArgumentName`, `ArgumentRead`, `ArgumentTitle`, `CommDiffers`, `ArgumentDiffers`. Empty strings with false flags when not read.

`any.process.read_arguments` (`processarguments.ProcessCmdline`): `PID`, `Name`, `Address` (the `_EPROCESS` or `task_struct` address; owner decision O9), `Cmdline`, `Arguments` (Linux words; nil on Windows), `CmdlineUnreadable`. `ReadLinuxArguments` and `LinuxArguments` (`Words`, `Title`, `Partial`) are exported for check_identity; `MaxLinuxExecArea` (6 MiB) for the environment tool.

`linux.library.list` (`librarylist.Library`): `Process`, `PID`, `BaseAddress`, `Path`, `Route` (`RouteLinkerList` "linker list" or `RouteMappedImage` "mapped image"). In list order per process, then area order for the mapped-image route (4.10 step 7); a process can have rows of both routes when its list ends early (4.10 step 5).

`linux.memory.list_elf_files` (`memoryelffiles.ELF`): `PID`, `Process`, `StartAddress`, `EndAddress`, `Path`, `PathRead`, `Artefact` (empty when not written).

`linux.memory.find_pattern` (`memorypattern.Match`): `PID`, `Process`, `Address`, `Text`, `Bytes`.

## 8. Limits

The walks are capped by the S01, S02, S06, S38 and S39 Limits. A kernel thread's name is read to 64 bytes (W4). An argument area is read to 6 MiB (A5) and a title to one page (A3). A rebuilt image is capped by the dump limit. Pattern matches follow the shared scanner's chunk size, lookahead and `MaxMatchesPerChunk` (S64 4.11) and `maxsize`.

## 9. Acceptance

- Synthetic fixtures built from section 3 (`tools/linuxobj/linuxobjtest`, including `s61b_fixture.go`): a tracer and a seized tracee with an option bit, a tracee missing from its tracer's list and an unnamed bit; numbers with and without a task, a decorated thread, a task whose pid is not its index and a kernel without the IDR; named words from sp up, unresolved words, a non-canonical word left unnamed (K7), sp outside the stack, a page that does not read, the KASAN size; a cred shared by two groups and `init_cred` held twice; objective sets with threads, an ambient set outside P2, a null `real_cred` in strict mode; module-owned and unowned thread functions, `kthreadd` without one, a full name cut at 63 bytes, a kernel without `threadfn`; the identity, argument, library (linker list; mapped images from offset 0, with the executable, a later-offset area, an anonymous area and a non-ELF file left out; a list with no named entry falling back; a list cut by a read failure and one ending at a zero entry, each with a readable mapped image past the end listed by the second route and an image at a base the list already has left out), ELF-area and pattern (including the per-chunk cap) cases in their packages' tests.
- Fuzz targets, 30 s each: `FuzzReadWords` (processkernelstack), `FuzzBaseName` (processidentity), `FuzzArgumentArea` (processarguments), `FuzzLayout` (memoryelffiles). The library list and pattern tools parse nothing of their own; S38 `FuzzELF` and the scanner's `FuzzPatternMatches` (S64) cover their parsers.
- On both captures: the T3, H4, K4, C2, P2 and W2 invariants hold as M1 to M6 count, with the exceptions named there.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision: row fields are renamed to this specification's vocabulary: `processtracing.Row` drops `Depth`, `TracerAvailable`, `TraceeTID`, `TraceeAvailable`, `Flags`, `FlagsAvailable` for `Traced`, `Tracees`, `Options` (one row per task, not per tracee); `processpidhash.Task.Offset` is `TaskAddress`; `processkernelstack.Entry` `Comm`, `Position`, `Address`, `Name`, `NameAvailable`, `Type`, `TypeAvailable`, `ModuleAvailable` are `Process`, `Slot`, `SlotAddress`, `Symbol`, `Named`, `SymbolType` (and `Offset` is new); `processcredentials.SharedCred` `Cred`, `PIDList` are `CredAddress` and `InitCred`; `processcapabilities.Process` `Name`, `AmbientAvailable` are `Process` (and the flag is gone, the member exists at every tag); `threadkernel.Thread` `Handler`, `ModuleFound` are `FunctionAddress`, `OwnerFound`; `processidentity.Process`, `librarylist.Library`, `memoryelffiles.ELF` and `memorypattern.Match` as section 7. `memoryelffiles` drops `FileName`, `OutputDisabled` and `OutputError` for `Artefact`. Tool names and option keys are kept (Q2). | Owner decision (Q2) |
| O2 | `list_pid_hash` keeps its name although every supported kernel keeps an IDR (H5); kernels with `pid_hash` (before v4.15) are refused. | Owner decision (Q2, Q7) |
| O3 | mem3 has one live thread (pid 2175) on its thread list whose number gives no task in the IDR, and mem4 three numbers whose task carries another pid (M2). Neither is explained from the sources yet. | A controlled capture with known exits |
| O4 | `list_capabilities` now lists threads (P1), and `read_kernel_stack` reads every stack through kernel memory (K3) instead of the process's space. | Owner review |
| O5 | KASAN modes other than generic are not detected (K2); no capture has KASAN. | A KASAN capture |
| O6 | The library list depends on a measured layout (L1, S38 S2). A process whose executable has no `DT_DEBUG` lists nothing (M21: 64 of 115 and 104 of 123). | Owner decision on a second route. Owner decision 2026-11-12: add a second route. Done: 4.10 steps 5 to 7 from L3 to L5 (file areas at `vm_pgoff` 0 that begin with an ELF header, the executable left out), taken when the linker lists give no row; `Library.Route` marks each row; `tools/linux/librarylist`. Re-measured (M21a to M21d): processes listing nothing fall from 69 to 10 on mem3 and from 104 to 7 on mem4; none of those left has a mapped image whose header page reads, so they list nothing on either route. Owner decision 2026-11-12 (follow-up D5): the wider route stays (it also runs when the linker lists give no named row, 5 more processes on mem3), and `examples/processes` shows the route. Done: the library table prints Base, Route, Path (`examples/processes/main.go`, test `TestALibraryRowNamesItsRoute`; S77 section 7). |
| O7 | The pattern tool uses the shared scanner in `tools/windows/kernelpattern`, which has no specification of its own yet. | That package's rewrite. Owner decision 2026-11-12: schedule now. Done: the scanner is specified by S64 4.11, with provenance under S64; step 7 now names every part this tool uses (`Section`, `Block`, `Scanner.Matches`, `Scanner.Limit`, `Capped`). The one gap was in this tool, which left the per-chunk cap unset; it now sets `MaxMatchesPerChunk` and reports capped chunks (4.12, `tools/linux/memorypattern`). No capture reaches the cap (M25). |
| O8 | v4.19's command-line rule (A3, one page of slop into the environment) and the v4.19 kernel-thread layout (W1, W2: refused) are written from the sources only. | A capture of an older kernel (Q7) |
| O9 | `ProcessCmdline.EPROCESS` holds the `task_struct` address on Linux; renaming it is Q2. | Owner decision (Q2). Owner decision 2026-11-12: rename to `Address`. Done: `processarguments.ProcessCmdline.Address` (section 7); callers in `tools/windows/servicecandidates` and `examples/processes` updated. |
| O10 | `linux.library.list` gives a row for every entry of the linker's list, the vDSO's among them (4.10 steps 1 to 4), and no row for a mapped object the lists and the mapped-image route do not reach. Owner decision 2026-11-12 (follow-up PU1): accept the linker rows; take a controlled capture for the objects with no row. Done: mem8_fedora40 is that capture (M21e). Owner decision 2026-11-12 (follow-up N2): use the mem8 ground truth to classify the objects with no row. Done: M21e measures the rules: objects after a list cut short by a read failure, objects after a list that ends at an entry of 32 zero bytes (on mem3 also pids 2199 and 2281, S38 O10), objects whose first page does not read or is not an ELF header, and vDSOs of processes listed by mapped images. The objects after a cut or zero-ended list are images whose header reads; O14 lists them through the mapped-image route. | Closed |
| O11 | `read_kernel_stack` rows that name data objects (`init_task`, `psi_system`, `rcu_state`) with letter `T` or `t`: 132 on mem3, 151 on mem4. Owner decision 2026-11-12 (follow-up PU2): probe the kallsyms reader before release. Done: not a bug (S38 O9). From v6.14 `.data` holds the kexec relocation code, so the kernel's own table types every `.data` symbol `T` or `t` (S38 K12, S3); `SymbolType` is that letter, as `/proc/kallsyms` prints it. | Owner decision |
| O12 | `any.process.list` lists a task whose `real_cred` is null (a task being freed). Owner decision 2026-11-12 (follow-up PQ1): yes, flagged. Done: recorded; S14 4.4 step 3 already lists it with no credentials and `CredsErr` set; no change. | Owner decision |
| O13 | On Linux, `any.memory.find_code` (S47) writes a region's path by S47's own rule. Owner decision 2026-11-12 (follow-up PQ5): accept. Done: recorded; no change. | Owner decision |
| O14 | A process whose linker list is cut short, or ends at an entry of zero bytes, lists only the entries before that point; its other mapped images are not read (4.10 step 5), although their headers read (M21e: 37 objects on mem8). Running the mapped-image route for the bases such a list does not reach would list them. Owner decision 2026-11-12 (follow-up N3): yes. Done: 4.10 steps 5 and 7 and section 7; a list that ends early (cut by a read failure, or a last entry of zero bytes) also reads the mapped images, and an image at a base a linker-list row has gives no row; `tools/linux/librarylist/librarylist.go`, tests `TestAListCutShortAlsoReadsTheMappedImages`, `TestAListEndingAtAZeroEntryAlsoReadsTheMappedImages`. Re-measured in the mem8 ground-truth gate (M21e) and on mem3 and mem4 (M21b). | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept |
| O2 | Keep name, refuse old kernels |
| O3 | Defer to v0.2.0 |
| O4 | Accept |
| O5 | Defer to v0.2.0 |
| O6 | Add a second route |
| O7 | Schedule now |
| O8 | Defer to v0.2.0 |
| O9 | Rename to Address |

## 11. Provenance

Written from the Linux kernel sources at the tags in section 3, the System V ABI ELF gABI chapters 4 and 5, the PDB types of the Windows captures and the Microsoft Learn pages named in section 3, the project's specifications S00, S01, S02, S06, S14, S25, S38, S39 and S46, and the project's measurements in section 3. Every rule rests on the sources and measurements above. Author: the project.
