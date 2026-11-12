# S25: Windows process list and active filter

Version 1, 2026-11-12.

## 1. Purpose

An examiner's first question about a Windows capture is which processes the kernel had. The kernel links every process object it has not yet deleted into one list, headed by the global `PsActiveProcessHead`. `any.process.list` walks that list and returns, for each process, its ID, image name, object address, page-table root and the columns other tools build on (parent, threads, handles, session, WoW64, creation and exit time).

The list holds processes that have exited but whose object is still referenced. Tools that look at a process's user space need the ones that still run. This specification also defines the active filter, which keeps only those, and the two optional filters of the tool: the sanity filter (the S17 process check) and the cross-check against a process snapshot taken outside the capture.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | Kernel virtual reads. |
| Symbol table | The kernel types and globals of section 3, the pointer size. |
| Physical memory | Optional. Only the S17 check uses it (its size). |
| `any.process.list.start_flink` | Unsigned. The `ActiveProcessLinks.Flink` of the System process, found by the session's bootstrap scan of physical memory. Used only when `PsActiveProcessHead` does not resolve to system space (4.2). |
| `any.process.list.sanity_filter` | Boolean. Drop entries that fail the S17 process check. |
| `any.process.list.active_only` | Boolean. Apply the active filter (4.5) to the list. |
| `any.process.list.cross_checker` | A `CrossChecker`. Drop entries the checker does not confirm. |
| `pid` | The project's PID set. `any.process.list` keeps only the processes it names; `pid` 0 names PID 0, and an empty set is an error (owner decisions). |
| `strict` | Turns an unreadable entry or a broken walk into an error. |
| Limits | `MaxListEntries` caps the walk (S03). |

A wrong option type is an error (owner decision 2026-11-03). The option keys are unchanged.

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | Terminating a process marks its remaining threads for termination, frees its resources, closes all its kernel objects, sets the exit code and signals the process object. "While open handles to kernel objects are closed automatically when a process terminates, the objects themselves exist until all open handles to them are closed." | Microsoft Learn, "Terminating a Process", dated 2025-07-14, accessed 2026-11-12. |
| D2 | A process runs until a thread calls `ExitProcess`, "the last thread of the process terminates", a thread calls `TerminateProcess` on it, or the user logs off or shuts down. | Microsoft Learn, "Terminating a Process", as D1. |
| D3 | `PsCreateSystemThread` "creates a system thread that executes in kernel mode". "Such a system thread has no TEB or user-mode context and runs only in kernel mode." Without a process handle "the thread will be created in the initial system process". | Microsoft Learn, "PsCreateSystemThread function (wdm.h)", dated 2023-01-12, accessed 2026-11-12. |
| D4 | `TokenSessionId`: "The buffer receives a DWORD value that indicates the Terminal Services session identifier that is associated with the token." | Microsoft Learn, "TOKEN_INFORMATION_CLASS (winnt.h)", dated 2023-07-24, accessed 2026-11-12. |
| D5 | A FILETIME counts 100-nanosecond intervals since 1601-01-01 UTC. | S17 F1. |
| D6 | A `LIST_ENTRY` walk, its recovery from the Blink side, and `CONTAINING_RECORD`. | S03 L1 to L7, section 4. |
| D7 | A 64-bit process's user space ends at 0x7FFF'FFFFFFFF; the kernel's addresses lie above it with bit 63 set; on 32-bit Windows system space starts at 0x80000000. | S17 F5 and 4.2 step 6. |
| D8 | CR3 bits 11:0 hold no address bits; bits M−1:12 hold the physical address of the top paging structure. | S17 F7. |

### Kernel types

Read with `processlistfacts` through the project's kernel tables for builds 26100 (mem1, GUID 0D960CE1…; mem6 and mem7, 953A8DE8…), 19045 (mem2, F57E740B…) and 14393 (mem5, 3DFC5F72…).

| # | Fact |
|---|---|
| T1 | `_EPROCESS` begins with `Pcb`, a `_KPROCESS`. `ActiveProcessLinks` is a `_LIST_ENTRY` that directly follows `UniqueProcessId` (`void*`): 0x1d0/0x1d8 on 26100, 0x440/0x448 on 19045, 0x2e8/0x2f0 on 14393. `ImageFileName` is `unsigned char[15]`. |
| T2 | `InheritedFromUniqueProcessId` is `void*`. `CreateTime` and `ExitTime` are `_LARGE_INTEGER`. `ActiveThreads` is `unsigned int`. `ObjectTable` is `_HANDLE_TABLE*`. `Peb` is `_PEB*`. `Token` is `_EX_FAST_REF`, whose `RefCnt` is bits 0..3 of the pointer. `_TOKEN.SessionId` is `unsigned int` at 0x78. |
| T3 | The WoW64 member is `WoW64Process` (`_EWOW64PROCESS*`) in all four tables; none has `Wow64Process`. |
| T4 | `_KPROCESS.DirectoryTableBase` is `unsigned long long` at 0x28 in all four. `_KPROCESS.UserDirectoryTableBase` (`unsigned long long`) exists on 19045 (0x388) and 26100 (0x158), not on 14393. No table has `_EPROCESS.DirectoryTableBase`. |
| T5 | `_EPROCESS.Session` is `_MM_SESSION_SPACE*` on 14393 and 19045, where `_MM_SESSION_SPACE.SessionId` is `unsigned int` at 0x8. On 26100 it is `_PSP_SESSION_SPACE*`, and neither `_PSP_SESSION_SPACE` nor `_MM_SESSION_SPACE` is in the table. |
| T6 | No table has `_HANDLE_TABLE.HandleCount`. |
| T7 | Every table has the globals `PsActiveProcessHead`, `PsInitialSystemProcess` and `PsIdleProcess`. |
| T8 | `ProcessExiting` and `ProcessDelete` are bits 2 and 3 of `_EPROCESS.Flags` in all four. |

### Measurements

M1 to M7 come from `processlistfacts -rows -views`, run on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100). Each walk uses the S03 recovering walk from `PsActiveProcessHead`.

| # | Measured |
|---|---|
| M1 | Lengths: 83, 153, 71, 101 and 90 processes (498). The walks of mem1 and mem6 close. On mem2 the forward walk stops at an entry whose Blink is 0, the predecessor's Flink not yet updated, and the Blink side then meets the forward walk with no entry missing. On mem5 both directions stop at a torn entry after 63 and 8 entries; no process is missing (the pool scan finds no unlisted process). On mem7 the forward walk stops at a link whose target is not a list entry and the Blink side recovers 1 entry: 13 running processes found by the pool scan, by thread owners and by csrss.exe handles are not walked (S26 M4). |
| M2 | No PID appears twice. PID 0 is never listed, and `PsIdleProcess` is never on the list. PID 4 is listed once, as the first entry, at the address `PsInitialSystemProcess` holds, on every capture. No listed process has a parent ID equal to its own ID. Every listed entry passes the S17 process check. |
| M3 | Exited but listed: 4, 4, 3, 8 and 9 processes (28) have a nonzero `ExitTime`. Every one of the 28 has `ActiveThreads` 0, a null `ObjectTable`, and `ProcessExiting` and `ProcessDelete` set. `ActiveThreads` is 0 in exactly one other process: Secure System on mem1 and mem2. |
| M4 | `Peb` is null for System on every capture, and for Registry (mem1, mem2, mem6, mem7), MemCompression and Secure System (mem1, mem2). `Session` is null for System, smss.exe (the running instance), Registry, MemCompression and Secure System where they exist. |
| M5 | The 32-bit value at `Session` + 8 equals `_TOKEN.SessionId` in 148 of 148 processes with a session on mem2, 67 of 69 on mem5, 77 of 78 on mem1, 98 of 98 on mem6 and 86 of 87 on mem7. The exceptions: on mem5 the two exited smss.exe copies that started sessions 1 and 2 (token session 0); on mem1 dwm.exe (session 1, token 0); on mem7 a WmiPrvSE.exe whose token reads as 760009701, not a session. On 14393 and 19045 that offset is the typed `SessionId` (T5). |
| M6 | `UserDirectoryTableBase` is 0 in every process on mem1, mem2, mem6 and mem7. `DirectoryTableBase` passes the S17 frame rule everywhere. |
| M7 | Bootstrap fallback, simulated on every capture: the System process's Blink is `PsActiveProcessHead`. Walking the ring that starts at System's Flink and counting that start entry gives the listed count plus one (84, 154, 72, 102, 91). Exactly one entry's enclosing record fails the S17 process check, and it is `PsActiveProcessHead` itself (`ErrBadID` or `ErrNoImageName`). |

## 4. Algorithm

### 4.1 Members

1. Resolve `_EPROCESS.ActiveProcessLinks`, `_EPROCESS.UniqueProcessId` and `_EPROCESS.ImageFileName` (15 bytes, T1). Without any one the tool fails (`ErrNoListMember`).
2. Resolve the native `_LIST_ENTRY` layout (S03).

### 4.2 Where the walk starts

1. Look up `PsActiveProcessHead`. If it resolves to a system-space address (D7), walk from it as the head of the list (4.3).
2. Otherwise, if `start_flink` is set, walk the ring that starts at that entry (4.4). This happens when the symbol table is not moved to the running kernel, so the global is an image offset.
3. Otherwise, if the global resolves to a nonzero address, walk from it: it is the only candidate, and the S03 rules reject a walk that does not find a list.
4. Otherwise fail with `ErrNoListHead`.

### 4.3 Walk from the head

Run the S03 recovering walk from the head with `MaxListEntries`. Each entry is an `ActiveProcessLinks`; its process is the entry minus that member's offset (D6). The walk reports its own breaks as diagnostics (S03). The listing is closed when the forward walk returns to the head, or when the Blink-side walk ends without an error (M1: mem2). A forward walk stopped by `MaxListEntries` is not closed.

### 4.4 Walk from a start entry

The start entry is the second process's links (M7), and the ring holds the head as one of its entries. Walk the ring with the start entry in the head's place, then put the start entry first. Run the S17 process check on each entry's enclosing record. Drop each entry that fails, with a diagnostic: the head lies in the kernel image, not in a process (M7). Entries come in ring order from the start entry, so System, whose links precede the start entry, comes last.

### 4.5 Each process

1. Read `UniqueProcessId` at the pointer width and `ImageFileName`. If either does not read, report a diagnostic and skip the entry; in strict mode fail.
2. `Name` is the name's bytes up to the first NUL (S17 4.2). An empty name stays empty.
3. Read the page-table roots: `_KPROCESS.DirectoryTableBase` is the kernel root (T4). `Process.DirectoryTableBase` is `UserDirectoryTableBase` when the table has it and its frame bits (63:12) are not all zero, else the kernel root, else 0 (open point O3). Because `Pcb` is at offset 0 (T1), a table that names either root as an `_EPROCESS` member describes the same bytes, and that member is used when the `_KPROCESS` one is absent.
4. Run the filters in this order, each only when its option is set: the sanity filter (S17 process check; a rejection is dropped with a diagnostic naming the S17 sentinel), the active filter (4.6), the cross-checker (a refusal drops the entry; a checker error keeps it with a diagnostic, or fails in strict mode).
5. Read the columns (4.7).

### 4.6 Active filter

A process is active when all four hold, tested in this order:

1. It passes the S17 process check.
2. It is not the initial system process: its address differs from the value of `PsInitialSystemProcess`. When that global does not read or holds 0, PID 4 stands in for it (M2). That process runs only kernel threads (D3), so it has no user space for a caller to examine. Its children stay: they are ordinary processes.
3. `ExitTime` is 0. A nonzero exit time is set only on processes that have terminated: every one measured has no threads, no handle table and both deletion flags (M3), which is what D1 describes.
4. `ActiveThreads` is not 0. A process with no thread has terminated (D2), or runs where its threads are not visible (Secure System, M3).

A member the table lacks drops its rule. A member that does not read rejects the process (`ErrMemberUnread`). The filter does not test the handle table, the PEB or the session: a running process's handle table can be paged out, and minimal processes such as Registry and MemCompression have no PEB but do have user space (M4, open point O2).

### 4.7 Columns

Kept from the project's column reader: the parent ID (`InheritedFromUniqueProcessId`), `ActiveThreads`, the handle count (always unreadable on the measured builds, T6), the session ID (4.8), WoW64 (`WoW64Process` or `Wow64Process` nonzero, T3), and `CreateTime` and `ExitTime` as UTC times (D5). A column whose member does not read is flagged unreadable; the tool keeps the row and reports it, and fails in strict mode.

### 4.8 Session ID

1. If `Session` is null, the process belongs to no session (`SessionIDNotApplicable`, M4).
2. The session ID is the 32-bit value at `Session` + the typed `SessionId` offset when the table has one (T5), else at `Session` + 8 (M5). The fixed offset is reported once per run.
3. A read that fails, or a table without `_EPROCESS.Session`, gives `SessionIDUnreadable`.

### 4.9 Result reuse

The Windows listing is kept in the context's options under `any.process.list.result_cache`, so the tools that call the list in one session walk it once. The Linux listing is filtered by PID during its walk, so its cache entry also records the PID set it was made with, and a listing narrowed to some PIDs never answers a wider request.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| The head is used when it is in system space or no start entry is set; else the start entry | D7, M7 | `ErrNoListHead` when neither exists |
| In a ring walk from a start entry, entries whose record fails the S17 check are not processes | M7 | dropped, diagnostic |
| PID and image name read | 4.5 | skipped, diagnostic; error in strict mode |
| Sanity filter: the S17 process check | S17 | dropped, diagnostic with the S17 sentinel |
| Active filter: S17 check, not the initial system process, no exit time, at least one thread | D1 to D3, M2, M3 | `Why` returns the sentinel |

## 6. Failure modes

| Sentinel or diagnostic | Meaning |
|---|---|
| `ErrNoListMember` | `ActiveProcessLinks`, `UniqueProcessId` or `ImageFileName` is not in the table. |
| `ErrNoListHead` | `PsActiveProcessHead` does not resolve and `start_flink` is unset. |
| `ErrSystemProcess`, `ErrExited`, `ErrNoThreads` | The active filter's rules 2 to 4. Rule 1 returns the S17 sentinels. |
| `any.process.list: _EPROCESS at 0x…: pid and image name do not read: …` | 4.5 step 1. |
| `any.process.list: _EPROCESS at 0x…: dropped by the sanity filter: …` | 4.5 step 4. |
| `any.process.list: _EPROCESS at 0x…: dropped by the active filter: …` | 4.5 step 4. |
| `any.process.list: _EPROCESS at 0x…: not confirmed by the cross-checker` | 4.5 step 4. |
| `any.process.list: _EPROCESS at 0x…: cross-checker failed, kept: …` | 4.5 step 4; an error in strict mode. |
| `any.process.list: list entry at 0x…: below the ActiveProcessLinks offset, skipped` | An entry address smaller than the member offset has no enclosing record. |
| `any.process.list: list entry at 0x…: not a process, dropped from the ring walk: …` | 4.4. |
| S03 walk diagnostics | A broken link; in strict mode the walk's error. |

## 7. Result schema

`processlist.Process`, one per listed process in walk order:

| Field | Type | Meaning |
|---|---|---|
| `PID` | uint64 | `UniqueProcessId`. |
| `Name` | string | `ImageFileName` bytes up to the first NUL, not decoded; empty when the name is empty. |
| `EPROCESS` | uint64 | Kernel virtual address of the `_EPROCESS`. |
| `DirectoryTableBase` | uint64 | The root to read the process's user space with (4.5 step 3); 0 when neither root reads. |
| `Columns` | struct | Kept: `PPID`; the counts `Threads` and `Handles`; the times `CreateTime` and `ExitTime`; `Wow64`; each with its unreadable flag. `SessionID` (int64) has no flag: it holds `SessionIDNotApplicable` (−1) or `SessionIDUnreadable` (−2) instead (4.8). |
| `Linux` | struct | Linux columns (S14). |

`RunListing` returns the rows and `Closed` (4.3). `KernelDirectoryTableBase` returns the kernel root of one process. The active filter's `Why` returns nil or a sentinel.

## 8. Limits

`MaxListEntries` bounds the walk (S03). No other loop depends on image data.

## 9. Acceptance

1. On the five captures, `processlistfacts -tool` on 2026-11-12: `any.process.list` returns 83, 153, 71, 101 and 90 rows, the counts of M1, with the walk closed on mem1, mem2 and mem6. The active filter keeps 77, 147, 67, 92 and 80: each list less System, its exited processes (M3) and Secure System where it exists.
2. Synthetic fixtures: a closed list; a list whose forward link breaks and whose Blink side closes it; a head outside system space with and without `start_flink`, the ring walk dropping exactly the head; an unreadable entry, kept out with a diagnostic and an error in strict mode; each filter; every active-filter rule with its sentinel, and a member that does not read; the session ID from the typed member, from the fixed offset, null and unreadable; both page-table roots.
3. `FuzzActiveListWalk` feeds arbitrary bytes as the bodies and links of a two-process list to the tool with the active filter on and the sanity filter on or off. It must not panic, and every row must satisfy every rule of 4.6 as recomputed by the test. 30 s on 2026-11-12: 1.08 million executions. `FuzzSnapshotCSV` (the kept snapshot parser): 1.74 million executions.

## 10. Open points

| # | Point | How to close it |
|---|---|---|
| O1 | On mem7 the walk loses 13 running processes to smear (M1). The tool reports the break but does not repair it from another list. | Owner decision: whether `any.process.list` should add processes found on the kernel's other process lists (S26 V2, V3) when its walk does not close. Owner decision 2026-11-12 (follow-up M4): accept; the diagnostics name the gap. Done: no change. On mem7 the S03 walk reports both ends of the gap: the forward walk stops at the entry 0xffff81012bc94258, whose Blink is 0x25568, and the Blink side stops at 0xffff81012bad3258 (`dllhost.exe` 4016), whose Flink is 0xffff81012b1f1258. A walk that follows Blink pointers without that check reaches 11 more processes (S29 O7). |
| O2 | The active filter keeps minimal processes (no PEB, M4). Callers that look for user-mode images find none in them. | Owner decision: keep, or drop processes with a null `Peb`. |
| O3 | No capture has a nonzero `UserDirectoryTableBase` (M6), so the choice of the user root for `DirectoryTableBase` rests on no measurement here. | A capture of a system with kernel virtual address shadowing enabled. Owner decision until then; the field keeps its earlier meaning. |
| O4 | The session ID at `Session` + 8 on 26100 rests on M5 alone; the table does not type the session space. | Measure on further 26100 updates and on builds after it. |
| O5 | The empty image name is now returned empty, not as a placeholder. | Owner decision (Q2: result values). |
| O6 | The snapshot CSV header aliases (`processid`, `imagefilename`, `virtaddr` and the others) are kept as they were. Whether any of them follows another tool's output format is not settled. | Owner decision (Q2). |
| O7 | `Name` is `ImageFileName` cut at its first NUL (4.5 step 2). The member is a NUL-padded byte array (T1), not a counted string, so bytes after the first NUL are padding or a stale name; S30 O6 shows an inner NUL only in counted object names. | Owner decision 2026-11-12 (follow-up D15): keep. Done: no change. |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Report the break only |
| O2 | Keep minimal processes |
| O3 | Keep the earlier meaning |
| O4 | Keep the M5 offset |
| O5 | Return empty |
| O6 | Keep the aliases |
| O7 | Keep |

## 11. Provenance

Author: the project, 2026-11-12. Sources: as cited in section 3, with access dates. Measurements: `processlistfacts` on the five captures named in section 3. Every rule rests on the sources and measurements above.
