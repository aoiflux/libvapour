# S65: Process scan, process environment, WoW64 access, process columns and snapshot

Version 1, 2026-11-12.

## 1. Purpose

Six related questions, answered by three tools and three shared readers.

- `any.process.scan`: which processes existed, including those that no kernel list holds any more. On Windows the kernel allocates every process object from tagged pool; the tool finds every such allocation in physical memory and keeps those that hold values a process can hold. On Linux the tool finds every `task_struct` in physical memory by a pair of list heads that the kernel initialises in every new task, and keeps those whose members agree with what the kernel writes. A process that has exited, or that was cut from the lists, shows up here and not in the process list.
- `any.process.read_environment`: which environment variables each process had. On Windows the block is in the process's own memory, named by its process parameters. On Linux the strings lie between two addresses the memory descriptor records.
- `windows.service.find_candidates`: which processes are service hosts and which service group or service each hosts, from the command line alone. It is a placeholder: it reads no service records.
- The WoW64 accessors (`tools/wow64`): whether a process runs 32-bit code under WoW64, where its 32-bit PEB is, and which module bases its 32-bit loader lists hold. No tool calls them yet; `windows.library.list` reads the 32-bit loader lists with its own reader.
- The process columns (`processlist.ColumnReader`): the parent ID, thread count, handle count, session, WoW64 flag and creation and exit times that the process list, tree and scan report for each `_EPROCESS`.
- The snapshot cross-check (`processlist.SnapshotCrossChecker`, `LoadSnapshotCSV`): a process list taken on the live host before or after the capture, read from CSV, against which the process list confirms its rows.

## 2. Inputs

| Input | Used by | Meaning |
|---|---|---|
| Physical memory | scan | The scanned address space. The scan fails without it. |
| Kernel memory, symbol table | all | Kernel virtual reads; the types and globals of section 3. |
| Kernel frame map | scan (Windows) | Through `tools.Context.ExecutiveScan` (S31): residency, copies and kernel addresses. |
| Process spaces | environment, WoW64 | `tools.Context.ProcessSpace` for the page-table root from the process list (Windows); `linuxobj.Kernel.ProcessLayer` (S14) on Linux. |
| Process list | environment, columns, service hosts | `processlist.Run` (S25) on Windows; the S01 task walk through `linuxobj` on Linux. |
| Command lines | service hosts | `processarguments.Run`: PID, image name, `_EPROCESS` and the decoded command line. |
| `pid` | scan, environment, service hosts | The project's PID set. `pid` 0 names PID 0; an empty set is an error (owner decisions). |
| `<tool>.offset` | `windows.handle.list`, `windows.library.list` | Unsigned physical address of an `_EPROCESS` body as the scan reports it (section 4.3). |
| `any.process.list.cross_checker` | process list | A `CrossChecker`, such as the snapshot checker of 4.9. The session builds one from `ProcessListCrossCheckCSV`. |
| `strict` | all | Turns the failures section 6 marks into errors. |
| Limits | | `Workers` (pool sweep, S31), `MaxBufferBytes` (environment), `MaxListEntries` (32-bit loader lists, S03). |

A wrong option type is an error (owner decision 2026-11-03). Tool names and option keys are unchanged.

## 3. Facts from the sources

Linux tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17, unless a row names fewer. Paths are under the kernel tree, fetched from `git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=<tag>` on 2026-11-12. Windows kernel types are read through the project's tables for builds 26100 (mem1, GUID 0D960CE1…; mem6 and mem7, 953A8DE8…), 19045 (mem2, F57E740B…) and 14393 (mem5, 3DFC5F72…) with `procscanfacts`.

### 3.1 Windows documentation

| # | Fact | Source |
|---|---|---|
| D1 | "The environment block consists of a null-terminated block of null-terminated strings (meaning there are two null bytes at the end of the block), where each string is in the form: name=value". "Because the equal sign is a separator, it must not be used in the name of an environment variable." | Microsoft Learn, "Changing Environment Variables", dated 2025-07-14, accessed 2026-11-12. |
| D2 | "A Unicode environment block is terminated by four zero bytes: two for the last string, two more to terminate the block." "There is an environment variable named =C: whose value is the current directory on drive C." | Microsoft Learn, "CreateProcessW function (processthreadsapi.h)", dated 2018-12-05, accessed 2026-11-12. |
| D3 | "The maximum size of a user-defined environment variable is 32,767 characters. There is no technical limitation on the size of the environment block." Before Vista the block was limited to 32,767 characters. | Microsoft Learn, "Environment Variables", dated 2025-07-14, accessed 2026-11-12. |
| D4 | WoW64 is the x86 emulator that runs 32-bit applications on 64-bit Windows. Wow64.dll loads the x86 `Ntdll.dll`, which loads the 32-bit DLLs; "All user-mode address space above the 32-bit limit is reserved by the system." | Microsoft Learn, "WOW64 Implementation Details", dated 2018-05-31, and "Running 32-bit Applications", dated 2018-05-31, accessed 2026-11-12. |
| D5 | `ProcessWow64Information`: "If this value is nonzero, the process is running in a WOW64 environment." | Microsoft Learn, "NtQueryInformationProcess function (winternl.h)", dated 2018-12-05, accessed 2026-11-12. |
| D6 | `LIST_ENTRY` is `struct _LIST_ENTRY *Flink; struct _LIST_ENTRY *Blink;`, in that order. | Microsoft Learn, "LIST_ENTRY structure (ntdef.h)", dated 2018-12-05, accessed 2026-11-12. |
| D7 | `PEB` places `Ldr` after `BYTE Reserved1[2]; BYTE BeingDebugged; BYTE Reserved2[1]; PVOID Reserved3[2];`, so at 0x0C with 4-byte pointers; the 32-bit loader record layout L1 of S56. | S56 D1 to D3, L1. |
| D8 | A service program of type `SERVICE_WIN32_SHARE_PROCESS` hosts more than one service; "the generic service host process, Svchost.exe, which hosts internal Windows services" is the example. Services are organised into host groups, each run in its own instance of svchost.exe; from Windows 10 1703, on client systems with more than 3.5 GB of RAM, most services run in a svchost.exe of their own. | Microsoft Learn, "Service Programs", dated 2018-05-31, and "Service host grouping in Windows 10", dated 2017-07-20, accessed 2026-11-12. |
| D9 | Command-line arguments "are delimited by whitespace characters, which are either spaces or tabs"; "a string surrounded by double quote marks is interpreted as a single argument, whether it contains whitespace characters or not"; the first argument is the program name, and quotes in it only stop a space from ending it. | Microsoft Learn, "Parsing C command-line arguments", dated 2021-12-09, accessed 2026-11-12. |
| D10 | `Win32_Process` has `ProcessId`, `ParentProcessId` and `Name` ("Name of the executable file responsible for the process"). `tasklist /fo csv` reports `Image Name` and `PID`. `System.Diagnostics.Process` has `Id` and `ProcessName`. `Export-Csv` writes UTF-8 without a byte-order mark by default and with one under `-Encoding utf8BOM`; Windows PowerShell adds a `#TYPE` first line unless `-NoTypeInformation` is given. | Microsoft Learn, "Win32_Process class", dated 2020-07-23; "tasklist", dated 2017-10-16; "Process.Id Property" and "Process.ProcessName Property", dated 2025-07-01; "Export-Csv", dated 2025-12-27; accessed 2026-11-12. |
| D11 | "Do not assume case sensitivity. For example, consider the names OSCAR, Oscar, and oscar to be the same." | Microsoft Learn, "Naming Files, Paths, and Namespaces", dated 2024-08-28, accessed 2026-11-12. |
| D12 | CSV: records are lines; fields separated by commas; a field in double quotes may hold commas and line breaks. A UTF-8 stream may begin with the byte-order mark EF BB BF, which is not part of the text. | RFC 4180 section 2; RFC 3629 section 6. |
| D13 | The S17 process check, the S31 pool and object scan, the S03 `LIST_ENTRY` walker, the S25 process list, its session ID reader and the active filter. | S17, S31, S03, S25. |

### 3.2 Windows kernel types

| # | Fact |
|---|---|
| T1 | `_EPROCESS.Peb` is `_PEB*` (0x2e0 on 26100, 0x550 on 19045, 0x3f8 on 14393). `_PEB.ProcessParameters` is `_RTL_USER_PROCESS_PARAMETERS*` at 0x20. `_RTL_USER_PROCESS_PARAMETERS.Environment` is `void*` at 0x80 and `EnvironmentSize` is `unsigned long long` at 0x3f0 in all four tables. |
| T2 | `_EPROCESS.WoW64Process` is `_EWOW64PROCESS*` (0x310 on 26100, 0x580 on 19045, 0x428 on 14393); no table has `Wow64Process` (S25 T3). `_EWOW64PROCESS.Peb` is `void*` at 0. `_PEB32.Ldr` is `unsigned int` at 0x0c and `_PEB32.ProcessParameters` `unsigned int` at 0x10. `LIST_ENTRY32` is `Flink` at 0 and `Blink` at 4, both `unsigned int`. No table has `_PEB_LDR_DATA32`, `_LDR_DATA_TABLE_ENTRY32` or `_RTL_USER_PROCESS_PARAMETERS32` (S56 T4). |
| T3 | `_EPROCESS.InheritedFromUniqueProcessId` is `void*`; `ActiveThreads` `unsigned int`; `CreateTime` and `ExitTime` `_LARGE_INTEGER`; `ObjectTable` `_HANDLE_TABLE*`; no table has `_HANDLE_TABLE.HandleCount` (S25 T2, T6). `ImageFileName` is `unsigned char[15]` (S25 T1). |
| T4 | `_EPROCESS.Pcb.Header.Type` is the `unsigned char` that the kernel sets to `ProcessObject` (3) (S31 T5, T6). |

### 3.3 Linux kernel source

| # | Fact | Source |
|---|---|---|
| K1 | `task_struct` has `struct list_head ptraced;` and `struct list_head ptrace_entry;`, `int exit_state`, `pid_t pid`, `pid_t tgid`, `struct task_struct *group_leader`, `real_parent` and `parent`, and `char comm[TASK_COMM_LEN]`. | `include/linux/sched.h`, every tag. |
| K2 | `INIT_LIST_HEAD(list)` sets `list->next` and `list->prev` to `list` itself. | `include/linux/list.h`, every tag. |
| K3 | `copy_process` calls `ptrace_init_task(p, …)` for every new task, which runs `INIT_LIST_HEAD(&child->ptrace_entry)` and `INIT_LIST_HEAD(&child->ptraced)`. `__ptrace_link` adds `ptrace_entry` to the tracer's `ptraced`; `__ptrace_unlink` takes it out with `list_del_init`. Both heads are therefore empty unless the task traces or is traced. | `include/linux/ptrace.h`; `kernel/fork.c`; `kernel/ptrace.c`; every tag. |
| K4 | `alloc_task_struct_node` takes a `task_struct` from `kmem_cache_alloc_node(task_struct_cachep, …)`. `__va(x)` is `x + PAGE_OFFSET`, and `__PAGE_OFFSET` is the variable `page_offset_base`, defined in `arch/x86/kernel/head64.c` (moved by KASLR in `arch/x86/mm/kaslr.c`). | `kernel/fork.c`; `arch/x86/include/asm/page.h`; `arch/x86/include/asm/page_64_types.h`; `arch/x86/kernel/head64.c`; every tag. |
| K5 | `copy_process` sets `p->group_leader = p` for a new thread group and the creator's leader for a thread (`CLONE_THREAD`); a leader's `pid` equals its `tgid`, a thread's does not (S14 I2, I3). | `kernel/fork.c`, every tag; S14. |
| K6 | `alloc_pid` refuses a number below 1 or at or above `pid_max`, and `pid_max` never exceeds `PID_MAX_LIMIT`, which is 4 × 1024 × 1024 when `long` is wider than 4 bytes. The idle tasks of the other CPUs are made by `fork_idle` with `init_struct_pid`, whose number is 0. | `kernel/pid.c`; `include/linux/threads.h`; `kernel/fork.c` `fork_idle`; every tag. |
| K7 | `EXIT_DEAD` is 0x10, `EXIT_ZOMBIE` 0x20 and `EXIT_TRACE` is `EXIT_ZOMBIE | EXIT_DEAD`. `exit_notify` sets `EXIT_ZOMBIE` or `EXIT_DEAD`; `wait_task_zombie` moves `EXIT_ZOMBIE` to `EXIT_TRACE` or `EXIT_DEAD`. `exit_state` holds no other value. | `include/linux/sched.h`; `kernel/exit.c`; every tag. |
| K8 | `__set_task_comm` always leaves a NUL inside the 16 bytes of `comm` (S14 N2). `real_parent` and `parent` point to a `task_struct`: `init_task` or a slab object, both in the kernel half (S14 I5, I7). | S14. |
| K9 | `struct mm_struct` has `unsigned long arg_start, arg_end, env_start, env_end`. `create_elf_tables` sets `env_start` at the first environment string, advances by `strnlen_user` (which counts the terminating NUL) per string, and sets `env_end` after the last NUL. | `include/linux/mm_types.h`; `fs/binfmt_elf.c`; every tag. |
| K10 | `environ_read` returns nothing when the task has no `mm` or `env_end` is 0, and otherwise the raw bytes from `env_start` up to `env_end`. `prctl(PR_SET_MM)` lets a task move both, checked only for `env_start <= env_end` and both below `TASK_SIZE`. | `fs/proc/base.c`; `kernel/sys.c` `validate_prctl_map_addr`; every tag. |
| K11 | POSIX environment strings "have the form name=value; names shall not contain the character '='". | POSIX.1-2017, Base Definitions, chapter 8.1. |

### 3.4 Measurements

M1 to M14 come from `procscanfacts -rows`, run on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 and mem7_server2025 (26100), and with `-linux` over mem3_ubuntu24 (6.17) and mem4_fedora40 (6.14). Windows counts are given in that order; Linux counts as mem3, mem4.

| # | Measured |
|---|---|
| M1 | Process list: 83, 153, 71, 101, 90 processes (S25 M1). PEB null: 4, 4, 1, 2, 2. Exited (nonzero `ExitTime`): 4, 4, 3, 8, 9, and in every one of the 28 the process parameters do not read through the process's page tables. |
| M2 | Environment blocks read: 75, 142, 67, 82, 69, with 2,348, 4,557, 2,054, 2,573, 2,018 variables. `EnvironmentSize` is never 0; the largest is 4,912 bytes. It equals the bytes up to and including the block terminator (D2) in 408 blocks and exceeds it in 23; it is never smaller. In 22 of the 23 the bytes past the terminator are not all zero: on mem2 and mem7 they are the tails of earlier, longer blocks (`lsass.exe` on mem7: `…USERNAME=SYSTEM…` after the terminator), and on `ssh-agent.exe` (M4) binary data. |
| M3 | Blocks that do not read through: 0, 0, 0, 3 (one partly, two not at all), 12 (3 partly, 9 not at all); the parameters of 0, 1, 0, 3, 1 running processes and the `Environment` pointer of 0, 2, 0, 4, 0 do not read. |
| M4 | Names that begin with `=` (D2): 2, 11, 2, 5, 3. One block, `ssh-agent.exe` on mem7, holds 7 strings without any `=` before its terminator and no variable: its first 132 bytes are overwritten. No other string lacks a `=` after its first character. |
| M5 | Pool scan with every body accepted (S31): 88, 163, 71, 100, 104 allocations. The S17 process check refuses none of them. With a kernel address: all. `TypeIndexFailed`: 6, 10, 0, 0, 0. Not on the list: 6, 10, 0, 0, 15; on mem2 they are the 10 flagged ones. Listed but not found: `System` on mem1, mem6 and mem7 (S31 M6). No accepted `ImageFileName` holds a byte below 0x20 or 0x7f. |
| M6 | WoW64: `WoW64Process` nonzero in 3, 1, 2, 5, 1 processes. The 3 on mem1 and 3 of those on mem6 have exited, and their `_EWOW64PROCESS.Peb` reads 0. A PEB32 is reachable in 0, 1, 2, 2, 1, whose 32-bit load-order lists hold 0, 43, 66, 27, 39 records; the one mem6 walk that breaks fails a Blink check after 11 records. Every PEB32 address is below 4 GiB. |
| M7 | Service hosts: svchost.exe processes 42, 86, 18, 35, 37; with `-k <group>` 42, 85, 18, 33, 37 (the others' command lines do not read); with `-s <service>` 2, 74, 0, 1, 1; with `-p` 35, 75, 0, 24, 27. No other process has a `-k` argument. |
| M8 | mem7's host snapshot (`proc_after.csv`, from `Win32_Process`) begins with the UTF-8 byte-order mark and has the header `ProcessId,ParentProcessId,Name,CreationDate,SessionId` and 93 rows. Of the 90 listed processes, 81 have their PID in it: 68 under the same name, 13 under a longer name whose first 14 characters are the listed name. The listed name of each of these 13 is 14 bytes long: the kernel keeps 14 characters and a NUL in `ImageFileName` (T3). |
| M9 | Linux: `page_offset_base` reads 0xffff8d7e00000000 and 0xffff9d6600000000. Every listed task (557 and 573, threads included) translates to its own address less `page_offset_base`, and has both `ptraced` and `ptrace_entry` empty. In every listed task the leader rule of K5 holds, `exit_state` is 0 or `EXIT_DEAD` (1 each), `real_parent` has bit 63 set and `comm` has a NUL. |
| M10 | Linux sweep: 503,692 and 517,229 empty list heads lie at their own direct-map address. A `task_struct` shape around both `ptrace` heads: 58,669 and 32,645 candidates. Then IDs in range: 705, 821; leader rule: 618, 772; parents in the kernel half: 614, 739; `exit_state` valid: 611, 735; `comm` holds a NUL: 611, 708. Every listed task is among the accepted. Not listed: 54 (mem3) and 135 (mem4) tasks, all `EXIT_DEAD` except 6 running `kworker/u16:*` threads on mem4 created during acquisition. |
| M11 | Linux environment: user tasks 115, 124; areas read 114, 98, with 3,135 and 2,687 variables; unreadable areas 1, 25; one task on mem4 without `mm`. The largest area is 6,997 bytes. On mem3, 136 strings in 8 areas and on mem4 1 string lack a `=`: process titles written over the area (`avahi-daemon: … .local]`) and the binary data of `accounts-daemon`. 10 areas on mem3 hold empty strings, and 3 do not end with a NUL. |
| M12 | `_RTL_USER_PROCESS_PARAMETERS.Length` is `unsigned int` at 4 and is the structure's size, not the block's (T1); it is not used. |
| M13 | `_EWOW64PROCESS.Machine` (`unsigned short` at 8) is on 19045 and 14393, not on 26100. It is not used. |
| M14 | The previous snapshot parser could not read mem7's snapshot: the byte-order mark hid the `ProcessId` header. |

## 4. Algorithm

### 4.1 Windows process scan

1. Require physical memory (`ErrNoPhysicalMemory`).
2. Resolve the body type tag `_EPROCESS.Pcb.Header.Type` = `ProcessObject` (T4). Without it, every body passes that test, with a diagnostic.
3. Prepare the scan with `ExecutiveScan` and the process filter (S31). Keep TypeIndex mismatches whose body passes, flagged (S31 4.5 step 4).
4. The body decoder runs the S17 process check on the body in physical memory (D13). A refused body is counted under its S17 sentinel. An accepted one gives the PID and image name from the check, and the columns of 4.7, read with the physical reader for the `_EPROCESS` and kernel memory for what it points to.
5. Each row takes the body's kernel address (0 when the kernel maps no address of the frame), the body address of the first other mapped copy (0 when none) and the `TypeIndexFailed` flag from the scan (S31 4.7, 4.8). Rows come in the S31 order (4.9).
6. One diagnostic gives the row count, the tag hits and the scan's counters; one more gives the refusals per S17 sentinel when there are any, and one the count of flagged rows.
7. The tool keeps the rows the PID set names, reports the columns absent from the table and every unread column (4.7). `Run` returns every row, for callers that compare views.

### 4.2 Linux task scan

1. Require physical memory, 8-byte pointers and the `task_struct` members of K1 (`ErrNoTaskMember`). Read `page_offset_base` from kernel memory (`ErrNoDirectMap` when it does not resolve or read) (K4).
2. Sweep physical memory in 1 MiB windows overlapping by 8 bytes. At each 8-byte aligned physical address *a*, note an **own-address head** when the two words at *a* and *a* + 8 both equal `page_offset_base` + *a* (K2, K4).
3. A candidate is a physical address *t* with own-address heads at *t* + offset(`ptraced`) and *t* + offset(`ptrace_entry`) (K3). Its kernel address is `page_offset_base` + *t*.
4. Read from physical memory and apply in order; the first rule that fails refuses the candidate and counts it (section 5):
   1. `pid` and `tgid` read and each is at least 1 and below `PID_MAX_LIMIT` (K6).
   2. If `group_leader` is the candidate's kernel address, `pid` equals `tgid`; otherwise `group_leader` has bit 63 set and `pid` differs from `tgid` (K5).
   3. `real_parent` and `parent` have bit 63 set (K8).
   4. `exit_state` is 0, `EXIT_DEAD`, `EXIT_ZOMBIE` or `EXIT_TRACE` (K7).
   5. `comm` holds a NUL in its 16 bytes (K8).
5. Each accepted candidate is summarised by `linuxobj.TaskFields` with the physical reader (S14): `PID` is the thread-group ID, `TID` the task's own ID, `PPID` the real parent's thread-group ID read in kernel memory, `Comm` the name. A summary that fails is reported in a diagnostic and gives no row; strict mode fails.
6. Rows come in physical address order. The PID set keeps a row when it names `PID`.
7. An incomplete sweep is a diagnostic; strict mode fails. One diagnostic gives the row count, the heads found, the candidates and the refusals per rule.

### 4.3 Process at a physical offset

`ProcessesAtOffset(ctx, tool, key)` serves the `offset` options of other tools.

1. Without the option: no processes, not set. A value of 0: a diagnostic, not set.
2. Run the Windows scan (4.1) without the PID set. Keep the rows whose `Offset` equals the value.
3. A row without a kernel address is omitted with a diagnostic: the process cannot be read through kernel memory. Each other row is read again as a listed process at its kernel address (`processlist.ProcessAt`); a failure is a diagnostic.
4. The PID set applies; a process outside it is omitted with a diagnostic. When nothing matches, a diagnostic says so. Each process returned is named in a diagnostic.

### 4.4 Windows environment

1. Resolve `_EPROCESS.Peb`, `_PEB.ProcessParameters` and `_RTL_USER_PROCESS_PARAMETERS.Environment` (T1); without one the tool fails (`ErrNoEnvironmentMember`). `EnvironmentSize` and its width are optional.
2. Take the process list (S25) and keep the processes the PID set names.
3. Skip a process whose `ExitTime` reads nonzero: its user space is gone (M1). One diagnostic counts them.
4. Read `Peb` from kernel memory. Unreadable: a diagnostic, or an error in strict mode. Zero: no rows and no diagnostic (M1).
5. Open the process space from the listed page-table root. Read `ProcessParameters`, then `Environment`, then `EnvironmentSize`, through it. A pointer that does not read or is 0 ends the process with a diagnostic.
6. The size to read is `EnvironmentSize`, or `MaxBufferBytes` when the table lacks it or it reads 0 or does not read. A size above `MaxBufferBytes` is cut to it, with a diagnostic.
7. Read the block page by page, stopping at the first page that does not read. Nothing read: a diagnostic. A partial block that holds no terminator: a diagnostic with the bytes read, and the part read is split.
8. Split the bytes as 4.6. Each variable is one row, in block order. Strings without a name separator and a block without a terminator are reported once per block.

### 4.5 Linux environment

1. Walk the thread-group leaders (S01, S14) with the PID set; the walk reports its own breaks.
2. Skip kernel threads (`PF_KTHREAD`, S14 K1). A task without `mm` has no environment (K10) and is skipped silently.
3. Read `env_start` and `env_end` from the `mm_struct` (K9). If `env_end` is 0 or not above `env_start`, there is nothing to read (K10). If `env_end` has bit 63 set, the bounds are not user addresses (K10): counted and reported.
4. An area longer than `MaxBufferBytes` is cut to it, counted and reported.
5. Open the task's address space (S14). A task whose space cannot be reached is counted and reported.
6. Read the area page by page up to the first page that does not read. An area unread from its first byte is counted. A partial area loses its last, cut, string.
7. Split as 4.6. One row per variable, with the task's thread-group ID, its parent's, and its name.
8. Counts go into one diagnostic each, with the first task as example. A task member that does not read is counted and reported; strict mode fails.

### 4.6 Splitting a block

Windows (UTF-16LE, D1, D2):

1. Read the bytes as 16-bit little-endian units; a trailing odd byte is dropped.
2. Strings end at a NUL unit. The first empty string is the block terminator; nothing after it is read (M2).
3. A string cut by the end of the bytes, with no NUL, is dropped and the block is reported as unterminated.
4. The name is the text before the first `=` that is not the string's first character (D2, M4). A string with no such `=` is counted and skipped.
5. The text is decoded with U+FFFD for unpaired surrogates (`util.DecodeUTF16LE`).

Linux (bytes, K9, K11):

1. Strings end at a NUL byte. Text after the last NUL is dropped.
2. Empty strings are skipped (M11). A string without a `=`, or with nothing before its first `=`, is counted and skipped (K11, M11).
3. The name is the text before the first `=` (K11). The text is decoded as UTF-8 with U+FFFD for each ill-formed subpart (`util.DecodeUTF8Replace`).

### 4.7 Process columns

`NewColumnReader` resolves, each optional: `InheritedFromUniqueProcessId`, `ActiveThreads`, `ObjectTable` with `_HANDLE_TABLE.HandleCount`, `WoW64Process` (or `Wow64Process`, S25 4.7), `CreateTime`, `ExitTime` (T3), and the S25 session reader.

`Read(ctx, object, eprocess)` reads the `_EPROCESS` members through `object`, and the handle table and session space through kernel memory:

1. `PPID`: the pointer-wide value of `InheritedFromUniqueProcessId`.
2. `Threads`: `ActiveThreads`.
3. `Handles`: the 32-bit `HandleCount` of the table `ObjectTable` points to, sign-extended. No measured table has the member (T3), so it is always unreadable there.
4. `SessionID`: S25 4.8.
5. `Wow64`: the pointer is not 0 (D5).
6. `CreateTime`, `ExitTime`: FILETIME values as UTC times; 0 is the zero time and is read, not unreadable (S17 F1).

A member the table lacks, or a read that fails, sets the column's unreadable flag. `ReportAbsent` gives one diagnostic per absent parent, thread, creation-time or exit-time member. `ReportUnread` names every column whose member the table has but that did not read, keeps the row, and fails in strict mode. The handle count and the session take no part in either: the first is untyped on every measured build, the second has its own unreadable value.

### 4.8 WoW64 access

1. `ResolveOffsets` reads from the table: the WoW64 member of `_EPROCESS` (`WoW64Process`, else `Wow64Process`), `_EWOW64PROCESS.Peb`, `_PEB32.Ldr`, and `LIST_ENTRY32` (T2). `_PEB32.Ldr` defaults to 0x0C (D7). Without `LIST_ENTRY32` the 32-bit walk follows `Flink` at 0 (D6) and checks no `Blink`, as the S03 walker does for a type without one.
2. `PEB32(ctx, eprocess)`: read the WoW64 member in kernel memory; 0 means not WoW64 (D5); unreadable gives a reason. Then `_EWOW64PROCESS.Peb`; a table without it gives a reason; unreadable or 0 gives a reason; a value above 0xFFFFFFFF gives a reason (D4, M6).
3. `BasesRecovering(ctx, space, peb32, list)`: read the 32-bit `Ldr` at the PEB32; 0 gives no bases and no reason; unreadable gives a reason. Walk the list headed at `Ldr` + the head offset of L1 with the S03 recovering walker, 4-byte links, `MaxListEntries`, reporting nothing itself. Each entry's record is the link less the record's link offset (L1); its `DllBase` is the 32-bit value at 0x18. A record whose `DllBase` does not read is left out. A base found by the forward walk maps to false, one found only walking back to true. The forward and backward walk errors are returned as text.

### 4.9 Snapshot cross-check

1. `ParseSnapshotCSV` reads RFC 4180 records (D12), tolerant of ragged rows and leading spaces, after dropping a leading UTF-8 byte-order mark and a first line that starts with `#TYPE` (D10, M8, M14).
2. The first record is the header. The PID column is the first header that is, ignoring case and surrounding space, `ProcessId`, `PID` or `Id`; the name column `Name`, `Image Name` or `ProcessName`; the address column `EPROCESS` (D10). Without a PID column the parse fails.
3. Each later record that is not blank gives one `SnapshotProcess`: the PID as a decimal number (a record whose PID does not parse fails the parse with its line number), the name trimmed of spaces, and the address as decimal or `0x` hexadecimal when present and well formed, else 0.
4. `Confirm(p)` is true when some snapshot row has `p`'s PID and both of these hold: the row has no name, or its name equals `p.Name` ignoring case (D11), or `p.Name` is 14 bytes long and is the row name's first 14 bytes ignoring case (M8); and the row has no address, `p` has none, or they are equal.

### 4.10 Service hosts

1. Take the command lines (`processarguments.Run`); keep the processes the PID set names whose image name is `svchost.exe` ignoring case (D8, D11).
2. A host whose command line does not read is reported and left out.
3. Split the command line by D9: spaces and tabs separate arguments; double quotes group; a doubled quote inside quotes is one quote, except in the program name. The first argument is the program.
4. `Group` is the argument after the first `-k`, `Service` the one after the first `-s`, each matched ignoring case (M7). Either may be empty.
5. Rows are ordered by PID, then `_EPROCESS` address.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Windows scan: the S31 pool, header and type rules | S31 | refused and counted by the scan |
| Windows scan: the S17 process check on the body | D13, M5 | refused, counted per sentinel |
| Linux scan: both `ptrace` heads empty at their own direct-map address | K2 to K4, M9 | not a candidate |
| Linux scan: `pid`, `tgid` in 1 to `PID_MAX_LIMIT` − 1 | K6 | refused, counted ("ids") |
| Linux scan: leader rule | K5, M9 | refused, counted ("group leader") |
| Linux scan: parents in the kernel half | K8, M9 | refused, counted ("parents") |
| Linux scan: `exit_state` one of four values | K7, M9 | refused, counted ("exit state") |
| Linux scan: `comm` holds a NUL | K8, M10 | refused, counted ("name") |
| Environment: the block ends at its first empty string | D1, D2, M2 | nothing after it is read |
| Environment: a Windows name is the text before the first `=` after the first character | D1, D2, M4 | string skipped, counted |
| Environment: a Linux name is the text before the first `=` | K11, M11 | string skipped, counted |
| Environment: exited Windows processes are not read | M1 | skipped, counted |
| Environment: Linux bounds are user addresses | K10 | skipped, counted |
| WoW64: a PEB32 lies below 4 GiB | D4, M6 | no PEB32, reason given |
| Snapshot: names match ignoring case, or by the 14-byte kernel prefix | D11, M8 | not confirmed |

## 6. Failure modes

| Sentinel or diagnostic | Meaning |
|---|---|
| `processscan: no physical memory to scan` (`ErrNoPhysicalMemory`) | Either scan without a physical layer. |
| `processscan: symbol table lacks a task_struct member the scan needs` (`ErrNoTaskMember`) | K1 member missing. |
| `processscan: page_offset_base does not resolve or read` (`ErrNoDirectMap`) | K4. |
| `processscan: task scan needs 8-byte pointers` (`ErrPointerSize`) | 4.2 step 1. |
| `any.process.scan: <n> processes from <hits> tag hits (<counters>)` | 4.1 step 6. |
| `any.process.scan: <n> bodies refused by the process check: <sentinel> <count>, …` | 4.1 step 6. |
| `any.process.scan: <n> processes kept with a header TypeIndex of another type` | 4.1 step 6. |
| `any.process.scan: <n> tasks from <h> own-address list heads, <c> candidates; refused: …` | 4.2 step 7. |
| `any.process.scan: task at 0x<pa>: summary does not read: <err>` | 4.2 step 5; strict: error. |
| `any.process.scan: physical sweep incomplete: <err>` | 4.2 step 7; strict: error. |
| `processenvironment: symbol table lacks a member the environment needs` (`ErrNoEnvironmentMember`) | 4.4 step 1. |
| `any.process.read_environment: <n> exited processes not read` | 4.4 step 3. |
| `any.process.read_environment: _EPROCESS at 0x<addr>: pid <pid>: Peb does not read: <err>` | 4.4 step 4; strict: error. |
| `any.process.read_environment: _EPROCESS at 0x<addr>: pid <pid>: <what> …` | 4.4 steps 5 to 8. |
| `any.process.read_environment: <n> tasks …, first: …` | 4.5 step 8; strict: error for unread members. |
| `processlist: process column does not read` (`ErrColumnUnread`) | 4.7 in strict mode. |
| `<tool>: symbol table has no _EPROCESS.<member>: <column> unreadable for every process` | 4.7 `ReportAbsent`. |
| `<tool>: _EPROCESS at 0x<addr>: pid <pid> <name>: <columns> do not read, kept` | 4.7 `ReportUnread`. |
| `processlist: snapshot csv has no pid column` (`ErrSnapshotNoPID`) | 4.9 step 2. |
| `processlist: snapshot csv line <n>: pid "<text>" is not a decimal number` | 4.9 step 3. |
| `windows.service.find_candidates: _EPROCESS at 0x<addr>: pid <pid>: command line does not read, left out` | 4.10 step 2. |
| `wow64: …`, `_EPROCESS.<member> …` and `_EWOW64PROCESS.Peb …` reasons | 4.8, as text for the caller's diagnostics. |

## 7. Result schema

`processscan.Process` (Windows scan), in S31 order:

| Field | Type | Meaning |
|---|---|---|
| `PID` | uint64 | `UniqueProcessId`. |
| `Name` | string | `ImageFileName` up to its first NUL, not decoded (S17). |
| `Offset` | uint64 | Physical address of the `_EPROCESS` body. |
| `VirtualOffset` | uint64 | Kernel address of the body; 0 when the frame is not mapped. |
| `OtherCopy` | uint64 | Physical body address of another mapped copy; 0 when none. |
| `TypeIndexFailed` | bool | Kept although the header's TypeIndex is another type's (S31 4.5 step 4). |
| `Columns` | struct | 4.7. |

`processscan.LinuxTask` (Linux scan), in physical order:

| Field | Type | Meaning |
|---|---|---|
| `Offset` | uint64 | Physical address of the `task_struct`. |
| `Address` | uint64 | Its direct-map kernel address. |
| `PID`, `TID`, `PPID` | int64 | Thread-group ID, task ID, real parent's thread-group ID (S14). |
| `Comm` | string | `comm` up to its first NUL. |
| `ExitState` | `ExitState` | `""` (not exited), `EXIT_ZOMBIE`, `EXIT_DEAD` or `EXIT_TRACE` (K7). |

`processenvironment.EnvVar` (Windows): `PID`, `Process` (image name), `EPROCESS`, `Block` (block address in the process), `Variable`, `Value`. `processenvironment.LinuxEnvVar`: `PID`, `PPID`, `Comm`, `Key`, `Value`. Both in process order, then block order.

`servicecandidates.Service`: `PID`, `Process`, `EPROCESS`, `Group`, `Service`, `CommandLine`, ordered by PID then `EPROCESS`.

`processlist.Columns`: `PPID`; the counts `Threads` and `Handles`; the times `CreateTime` and `ExitTime`; then `SessionID` and `Wow64`; each but `SessionID` has its `…Unreadable` flag (S25 7).

`processlist.SnapshotProcess`: `PID`, `Name`, `EPROCESS`.

`wow64`: `Offsets` (opaque), `List` (`LoadOrder`, `MemoryOrder`, `InitOrder`), the bases map of 4.8 step 3.

## 8. Limits

- `Workers`: the pool sweep (S31).
- `MaxBufferBytes` (default 64 MiB): the most of one environment block or area read; real blocks are under 5 KB and areas under 7 KB (M2, M11), and D3 sets no upper bound.
- `MaxListEntries`: each 32-bit loader list (S03).
- The Linux sweep keeps one 1 MiB window and the list of own-address heads (about 0.5 million on a 2 GB capture, M10, 8 bytes each).

## 9. Acceptance

1. Synthetic fixtures: a pool page holding a valid `_EPROCESS` body and one the S17 check refuses; the absent type tag; the offset lookup with a match, an unmapped copy, a PID outside the set and no match; a physical image with a task, a thread, one candidate per Linux rule, a traced task and a sweep window edge; Windows blocks with `=C:`, stale bytes after the terminator, a string without `=`, a cut block, an odd byte; Linux areas with a title written over them, empty strings and a cut page; the exit, PEB, pointer and size paths of 4.4; each column, absent and unread, in strict mode; the PEB32 reasons, a 32-bit list read forward, recovered backward and with an unreadable `DllBase`; snapshot headers of each source, a byte-order mark, a `#TYPE` line, a bad PID, the 14-byte prefix; service-host command lines with quotes, `-k`, `-s` and neither.
2. Fuzz targets, 30 s each: `FuzzWindowsBlock` and `FuzzLinuxArea` (no panic; every variable's name is nonempty, a Windows name has no `=` after its first character and a Linux name none at all), `FuzzTaskScan` (arbitrary physical bytes around a fixed `task_struct` shape: no panic, every row satisfies every rule of 4.2 as recomputed), `FuzzSnapshotCSV` (no panic; no name keeps surrounding space), `FuzzCommandLine` (no panic; no argument of a line without quotes is empty or holds a space or tab), `FuzzLoader32` (arbitrary 32-bit loader bytes: no panic, no more bases than `MaxListEntries`, every base below 4 GiB). Runs on 2026-11-12: `FuzzSnapshotCSV` 1.94 million executions, `FuzzWindowsBlock` 5.58 million, `FuzzLinuxArea` 4.32 million, `FuzzTaskScan` 1,267 (each run sweeps a 4 MiB image), `FuzzLoader32` 3.73 million, `FuzzCommandLine` 2.00 million.
3. On the captures, `procscanfacts -tool` on 2026-11-12 (Windows in the order of 3.4, Linux mem3, mem4):

| Tool | mem1 | mem2 | mem5 | mem6 | mem7 | mem3 | mem4 |
|---|---|---|---|---|---|---|---|
| `any.process.scan` | 88 | 163 | 71 | 100 | 104 | 611 | 708 |
| of them `TypeIndexFailed` | 6 | 10 | 0 | 0 | 0 | | |
| `any.process.read_environment` | 2,348 | 4,557 | 2,054 | 2,573 | 2,018 | 3,134 | 2,687 |
| `windows.service.find_candidates` | 42 | 85 | 18 | 33 | 37 | | |

   - The Windows scan rows equal M5's accepted allocations; the S17 check refuses none. The Linux rows equal M10's accepted candidates and hold every listed task.
   - The Windows environment rows equal M2's variable counts; each capture reports its exited processes (4, 4, 3, 8, 9) in one diagnostic. On mem3 one string with nothing before its `=` is skipped, so 3,134 of M11's 3,135.
   - The service hosts are M7's svchost.exe processes less those whose command line does not read (0, 1, 0, 2, 0).
   - mem7's snapshot parses to 93 rows and confirms 81 of the 90 listed processes: the 81 of M8.

## 10. Open points

| # | Point | How to close it |
|---|---|---|
| O1 | Field names are kept so that callers do not change: `Offset`, `VirtualOffset`, `OtherCopy` (Windows scan), `Block`, `Variable`, `Key` (environment). `LinuxTask.Address` is new; `ExitState` values are now the kernel's macro names and `""` for a task that has not exited, in place of the previous names. `servicecandidates.Service` has new fields (`Process`, `EPROCESS`, `Group`, `Service`, `CommandLine`) in place of `ProcessName`, `Name`, `DisplayName`, `State`, `StartType` and `BinaryPath`. | Owner decision (Q2) |
| O2 | The Linux scan misses a task that traces another or is traced, since one of its `ptrace` heads is not empty (K3). No measured task was. | A capture with a traced process |
| O3 | The Linux scan reads `page_offset_base`, which exists on x86-64 kernels with a dynamic memory layout (both captures). A kernel without the variable, or a 32-bit kernel, is refused. | Owner decision, if such kernels join the support matrix (Q7) |
| O4 | The Windows scan no longer drops a name holding a control byte; the S17 check decides (S17 O4). None was seen (M5). | Owner decision |
| O5 | The environment tool skips exited processes (M1) and reads only the native block of a WoW64 process; the 32-bit process parameters have no type in the table (T2). | Owner decision; a table with `_RTL_USER_PROCESS_PARAMETERS32` |
| O6 | Linux strings without a `=` are skipped, not taken as the end of the area (M11); a title written over the area can leave later variables in place. | Owner decision |
| O7 | The snapshot header names are now those of D10 only. The previous aliases (`shortname`, `imagefilename`, `uniqueprocessid`, `virtaddr`, `address` and others, and the removal of `_`, `-`, `.` and spaces before comparing) are gone (S25 O6). Snapshot names compare ignoring case on Linux too. | Owner decision (Q2) |
| O8 | `windows.service.find_candidates` stays a placeholder: it lists service hosts from their command lines and reads no service records (S34 does). The `-k` and `-s` switches rest on M7, not on a Learn page. | Owner decision |
| O9 | `wow64` loses `Walk`, `WalkRecovering`, `Bases`, `Entry`, `Offsets.Is` and `Offsets.Available`, which no caller used; `processlist.ColumnReader` loses `KeepListed` and `Unread`. Old forms of the WoW64 member (`_WOW64_PROCESS.Wow64`, or a PEB32 pointer directly in `_EPROCESS`) are not read: no supported build has them. | Reviewer check |
| O10 | The Linux task scan lists copies of task_structs the task list also holds (3 on mem3, 2 on mem4). Owner decision 2026-11-12 (follow-up PQ2): keep 4.2. Done: recorded; every candidate that passes 4.2 step 4 is a row, copies included. No change. | Owner decision |
| O11 | `tools/wow64` (4.8) has no caller: no package outside its own tests imports it. Owner decision 2026-11-12: kept for v0.1.0; wired in or removed in v0.2.0. | v0.2.0 |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept |
| O2 | Defer to v0.2.0 |
| O3 | Keep refusing them |
| O4 | Let S17 decide |
| O5 | Skip exited, native block only |
| O6 | Skip them |
| O7 | D10 names only |
| O8 | Stay a placeholder |
| O9 | Accept removal |

## 11. Provenance

Author: the project, 2026-11-12. Sources: as cited in section 3, with access dates. Measurements: `procscanfacts` on the seven captures named in section 3, and the host process snapshot of mem7. Every rule rests on the sources and measurements above.
