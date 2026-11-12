# S26: Windows process comparison

Version 1, 2026-11-12.

## 1. Purpose

A rootkit can take its process off the kernel's active process list (S25) so that the list, and every tool built on it, no longer shows it. The process still exists: the kernel keeps other records of it, and its object still lies in pool memory. `windows.process.compare` gathers the processes that several independent views of the kernel know, matches them, and reports for each process which views hold it. A process that runs and is held by some view but not by the active list is the examiner's lead.

Most processes missing from the active list are not hidden. Exited processes leave it while their freed objects remain in pool; captures hold stale copies of live process objects; and a list walk broken by smear during acquisition misses running processes. This specification defines the views, the match, and the rules that tell these cases from a process that is hidden.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | Kernel virtual reads; it must translate kernel addresses to physical ones for the match (4.2). |
| Physical memory | Required: the pool scan reads it. |
| Symbol table | The members of S25 and S17, and those of section 3. |
| `pid` | The project's PID set. Rows whose PID it does not name are left out; `pid` 0 names PID 0. |
| `strict` | Turns a view that fails into an error. |
| Limits | `MaxListEntries` for each list walk; the pool scans' and handle walk's own limits. |

The tool takes no options of its own.

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | A terminated process's kernel objects are closed; "the objects themselves exist until all open handles to them are closed". | Microsoft Learn, "Terminating a Process", dated 2025-07-14, accessed 2026-11-12 (S25 D1). |
| D2 | CR3 holds the physical address of the top paging structure of the address space it translates. | S17 F7; Intel SDM Vol. 3A (253668-093US), chapter 5. |
| D3 | A `LIST_ENTRY` ring holds its head as one of its entries; `CONTAINING_RECORD` gives the structure around an entry. | S03 L1 to L7. |
| D4 | The process check: a candidate whose values no real process can hold is rejected. | S17. |

### Kernel types

Read with `processlistfacts` in the tables of S25 (builds 14393, 19045, 26100 client and server).

| # | Fact |
|---|---|
| T1 | Every table has the global `KiProcessListHead` and `_KPROCESS.ProcessListEntry` (`_LIST_ENTRY`): 0x110 on 26100, 0x350 on 19045, 0x240 on 14393. |
| T2 | Every table has `_EPROCESS.SessionProcessLinks` (`_LIST_ENTRY`): 0x230, 0x4a0, 0x340. `_MM_SESSION_SPACE.ProcessList` is typed at 0x10 on 14393 and 19045; 26100 does not type the session space (S25 T5). |
| T3 | Every table has `_KTHREAD.Process` and `_OBJECT_HEADER.Body`, which the thread scan and the handle walk use. |
| T4 | Every table has the global `PspCidTable`. No table has `MmProcessList`. |

### Measurements

M1 to M6 come from `processlistfacts -views` on 2026-11-12 over mem1_win11, mem2_win10, mem5_server2016, mem6_server2025 and mem7_server2025. "Unlisted" means not on the S25 walk of that capture.

| # | Measured |
|---|---|
| M1 | Kernel process list (`KiProcessListHead`): 78, 148, 68, 93 and 81 entries. Every entry is on the active list. The listed processes missing from it are exactly the exited ones (S25 M3) and Secure System. Its walk breaks at the same torn entries as the active list on mem2, mem5 and mem7. |
| M2 | Session rings: walking each session's ring from its first listed member, exactly one entry per ring fails the S17 check, and it lies at the session space + 0x10 on all four builds (14 rings). The other entries are the listed processes with a nonzero `Session`, with two differences, both on mem7: the ring holds ShellHost.exe (PID 6900), which the active walk lost (M4), and lacks a WmiPrvSE.exe whose links are torn. |
| M3 | Pool scan (`any.process.scan`): 88, 163, 71, 100 and 104 candidates, all of which pass the S17 check. Unlisted: mem1 6, of which 3 exited and 3 (two of PID 7580 svchost.exe, one of 10484 rdpinput.exe) share PID, name, `DirectoryTableBase` and `CreateTime` with a listed process; mem2 10, all exited; mem5 and mem6 none; mem7 15, of which 2 exited and 13 run. The scan finds no allocation for System on the three 26100 captures. |
| M4 | mem7's 13 running unlisted processes (PIDs 1684, 1752, 2340, 2408, 2972, 3532, 3780, 3988, 4016, 4692, 6056, 6900, 7552, among them the acquisition tool) are each found by the pool scan, by thread owners and by csrss.exe handles. The active walk of mem7 does not close (S25 M1). |
| M5 | Thread owners (`_KTHREAD.Process` of scanned threads): 85, 157, 69, 97 and 105 distinct owners, of which 79, 154, 68, 96 and 102 pass the S17 check. Unlisted owners: one exited process on mem1, five exited processes on mem2, the 13 of M4 on mem7, none elsewhere. Every unlisted owner that has exited has `ActiveThreads` 0. |
| M6 | csrss.exe handles: 2 csrss.exe on mem1 and 3 on the others hold `Process` handles to 71, 140, 62, 87 and 88 processes. None is unlisted except the 13 of M4 on mem7. They hold no handle to System, Registry, MemCompression, Secure System, smss.exe, any csrss.exe, LsaIso.exe, or most exited processes. |

## 4. Algorithm

### 4.1 Views

Each view yields candidate `_EPROCESS` addresses. A view that fails is reported and left out; in strict mode the tool fails.

| View | Candidates | Why it is independent of the active list |
|---|---|---|
| V1 active list | S25 `RunListing` (kernel virtual). | The baseline. |
| V2 kernel process list | The S03 recovering walk from `KiProcessListHead`; each entry minus `Pcb` + `ProcessListEntry` (T1). | Separate links in the `_KPROCESS` (M1). |
| V3 session rings | For each distinct nonzero `Session` of a V1 process: the S03 recovering walk of the `SessionProcessLinks` ring that starts at the first V1 process of that session, with that start entry included. Entries whose enclosing record fails the S17 check are dropped: that is the ring's head in the session space (M2). | Separate links, and needs no session type (T2). |
| V4 pool scan | `any.process.scan` rows (physical). | Finds objects by their pool allocation, linked or not (M3). |
| V5 thread owners | The distinct `_KTHREAD.Process` values of the thread scan's threads (kernel virtual). | A running process has threads, which the scan finds by their own allocations (M5). |
| V6 csrss.exe handles | The `Process` handles in the handle tables of every V1 process named `csrss.exe`: each object header plus `_OBJECT_HEADER.Body` (kernel virtual). | csrss.exe holds handles to the processes of its session (M6). |

`PspCidTable` (T4) is not a view in this version (open point O1).

### 4.2 Match

1. Run the S17 process check on each candidate, in the memory its view gave (physical for V4, kernel for the others). Count and drop each candidate that fails, per view.
2. A kernel address is matched by the physical address that kernel memory translates it to. A candidate whose address does not translate is a row of its own, keyed by its virtual address.
3. Each physical (or untranslated virtual) address is one row. A view that yields an address twice counts it once.

### 4.3 Each row

1. `PID` and `Name` come from the S17 check of the first view that found the row. `Name` is decoded for display (S00).
2. Read `ExitTime` from the memory that row came from. The process has exited when the value is in the S17 capture window (S17 4.1). A value of 0, outside the window, or unreadable is not an exit.
3. The verdict, in this order:
   - `listed`: V1 holds the row.
   - `exited`: the process has exited (D1; M3: every exited unlisted find).
   - `copy`: a V1 process has the same PID, name, `DirectoryTableBase` and `CreateTime`. A page-table root belongs to one address space (D2), so two running processes do not share it; the measured copies agree on all four (M3).
   - `unlisted`: the V1 walk did not close (S25 4.3), so the row may lie in the part it did not reach (M4).
   - `hidden`: otherwise.
4. `Hidden` is true for the verdict `hidden` only.
5. Each `hidden` row gets a diagnostic naming the views that hold it. When a V1 process has the row's PID and name but another root, a second diagnostic says so.

### 4.4 Order

Rows sort by PID, then name, then listed rows before unlisted ones, then physical address, then virtual address (`CompareRows`).

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| A candidate passes the S17 process check | D4 | dropped, counted per view |
| A session ring entry whose record fails the check is the ring's head | D3, M2 | dropped |
| Exited: an exit time inside the capture window | D1, S17 4.1, M3 | not an exit |
| Copy: same PID, name, kernel root and creation time as a listed process | D2, M3 | not a copy |
| Unlisted, not hidden: the active walk did not close | S25 M1, M4 | — |

## 6. Failure modes

| Sentinel or diagnostic | Meaning |
|---|---|
| `processcompare: session has no physical memory` (`ErrNoPhysicalMemory`) | The pool scan cannot run. |
| `processcompare: kernel memory does not translate addresses` (`ErrNoTranslation`) | Pointer views cannot be matched to the pool scan; reported once, rows keyed by virtual address. |
| `ErrViewUnavailable`, `ErrNoCsrss` | The table lacks a member a view needs, or no csrss.exe is listed. The view is left out with the diagnostic below, in strict mode too. |
| `windows.process.compare: active list: <err>` | The active list (V1) failed. The run fails, in every mode: V1 is the baseline. |
| `windows.process.compare: <view>: failed, left out: …` | A view other than V1 failed; an error in strict mode unless the cause is one of the two above. |
| `windows.process.compare: views: …` | One summary: candidates and rejections per view. |
| `windows.process.compare: active list walk did not close: …` | 4.3 step 3, with the count of `unlisted` rows. |
| `windows.process.compare: _EPROCESS at 0x…: pid …: hidden, held by …` | 4.3 step 5. |

## 7. Result schema

`processcompare.Row`:

| Field | Type | Meaning |
|---|---|---|
| `Physical` | uint64 | Physical address of the `_EPROCESS`; 0 when only an untranslated virtual address is known. |
| `Address` | uint64 | Kernel virtual address from the first pointer view that held it; 0 for a pool-scan-only row. |
| `PID` | uint64 | From the S17 check. |
| `Name` | string | Decoded image name. |
| `ActiveList`, `KernelList`, `SessionRing`, `PoolScan`, `ThreadOwner`, `CsrssHandle` | bool | The views V1 to V6 that hold the row. |
| `TypeIndexUnconfirmed` | bool | The pool scan could not confirm the object type index of its allocation. |
| `ExitTime` | time.Time | UTC; the zero time when the member is 0, unreadable or not a FILETIME. |
| `ExitTimeRead` | bool | The member read. |
| `Verdict` | `Verdict` | `listed`, `exited`, `copy`, `unlisted` or `hidden`. |
| `Hidden` | bool | `Verdict == hidden`. |

## 8. Limits

Each list walk is bounded by `MaxListEntries` (S03). The pool scans and the handle walk keep their own bounds. The match is linear in the candidates.

## 9. Acceptance

1. On the five captures, `processlistfacts -tool` on 2026-11-12:

| Capture | Rows | listed | exited | copy | unlisted | hidden | Active walk closed |
|---|---|---|---|---|---|---|---|
| mem1_win11 | 90 | 83 | 4 | 3 | 0 | 0 | yes |
| mem2_win10 | 165 | 153 | 12 | 0 | 0 | 0 | yes |
| mem5_server2016 | 71 | 71 | 0 | 0 | 0 | 0 | no |
| mem6_server2025 | 101 | 101 | 0 | 0 | 0 | 0 | yes |
| mem7_server2025 | 105 | 90 | 2 | 0 | 13 | 0 | no |

   The view counts of the summary diagnostic match M1 to M6: kernel process list 78, 148, 68, 93, 81; session rings 78, 148, 69, 98, 87; pool scan 88, 163, 71, 100, 104; csrss.exe handles 71, 140, 62, 87, 88.
2. Synthetic fixtures: one process in each view alone, each verdict, candidates that fail the check, a session ring whose head is dropped, a copy that differs only in root, a view that fails (diagnostic, and an error in strict mode), an untranslatable address, the PID option and the sort order.
3. `FuzzCompareViews` feeds arbitrary bytes as the body of one listed and one unlisted process, both on the kernel list and the session ring and found by the pool scan: no panic, every row holds at least one view, `Hidden` only with the verdict `hidden`, and the verdict `listed` exactly when `ActiveList`. 30 s on 2026-11-12: 71,784 executions.

## 10. Open points

| # | Point | How to close it |
|---|---|---|
| O1 | `PspCidTable` (T4) maps every process and thread ID to its object and would be a seventh view. It needs a specification of the ID table's entry format first. | A specification of the CID table from the PDB's `_HANDLE_TABLE` and `_HANDLE_TABLE_ENTRY` types, measured on the captures. |
| O2 | A walk that does not close turns live unlisted processes into `unlisted`, not `hidden` (M4). A rootkit that also tears the list would get the weaker verdict. | Owner decision: keep, or call them hidden and rely on the diagnostic. |
| O3 | The row fields are renamed: `Offset` → `Physical`, `VirtualOffset` → `Address`, `InProcessList` → `ActiveList`, `InProcessScan` → `PoolScan`, `InThreadScan` → `ThreadOwner`, `InCsrss` → `CsrssHandle`, `ScanTypeIndexFailed` → `TypeIndexUnconfirmed`, `ExitTimeKnown` → `ExitTimeRead`; `ExitTime` is now a time; `ListedCopy` and `Exited` give way to `Verdict`; `KernelList` and `SessionRing` are new. `NameIsLettersDotsAndSpaces` and the name-character diagnostic are removed. | Owner decision (Q2). |
| O4 | V3 starts from listed processes only, so a hidden process in a session with no listed member is not found by V3. | None needed while V4 to V6 cover it; revisit with O1. |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Defer to v0.2.0 |
| O2 | Unlisted |
| O3 | Accept the new fields |
| O4 | No action |

## 11. Provenance

Author: the project, 2026-11-12. Sources: as cited in section 3, with access dates. Measurements: `processlistfacts` on the five captures named in section 3. Every rule rests on the sources and measurements above.
