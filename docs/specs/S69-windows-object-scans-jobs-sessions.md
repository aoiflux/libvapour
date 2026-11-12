# S69: Windows mutant, symbolic link and file object scans, job and session lists

Version 1, 2026-11-12.

## 1. Purpose

Five tools answer questions an examiner asks about kernel objects a process list does not show:

- `windows.object.scan_mutants`: which named mutexes exist or existed, and which thread holds each. A named mutex is a common single-instance marker for programs, malware among them.
- `windows.object.scan_links`: which symbolic links the object namespace holds or held (drive letters, device aliases, callback links), with each target and creation time.
- `windows.file.scan`: which files were opened, including file objects that no handle table holds any more, with the device, the access the open was granted and whether a delete was pending.
- `windows.job.list`: which job objects group which processes, with the job's process counts.
- `windows.session.list`: which logon session each process runs in, with the user and session name its environment records.

The three scans find their objects by pool tag through `scan` (S31), so freed and unlinked objects are found too. The two lists start from the S25 process list and follow the structures it points to.

## 2. Inputs

| Input | Meaning |
|---|---|
| Physical memory | The scanned space of the three scans (`physical_memory`). The job and session lists do not need it. |
| Kernel memory | Name buffers, owner threads, devices, jobs, session spaces, image paths. |
| Symbol table | The kernel types of section 3. |
| Options | `pid` (job and session lists; S25), `windows.job.list.physical` (boolean: give each job row's `_EPROCESS` physical address). Strict mode applies to the job list's list walks (S03). |
| Limits | `Workers` (tag sweep, S31), `MaxListEntries` (a job's process list, S03). |

## 3. Facts from the sources

### Documentation

All accessed 2026-11-12.

| # | Fact | Source |
|---|---|---|
| D1 | "The state of a mutex object is signaled when it is not owned by any thread." A wait grants ownership and "the mutex's state changes to nonsignaled"; the owner "can specify the same mutex in repeated wait function calls without blocking" and "must call ReleaseMutex once for each time that the mutex satisfied a wait." The name "can have a "Global" or "Local" prefix … The remainder of the name can contain any character except the backslash character (\)." | Microsoft Learn, "CreateMutexW function (synchapi.h)", dated 2018-12-05. |
| D2 | "The mutex object is initialized with an initial state of signaled." | Microsoft Learn, "KeInitializeMutex function (wdm.h)", dated 2021-07-29. |
| D3 | Named kernel objects (mutexes, job objects and symbolic link objects among them) live in a global namespace and in one namespace per session; "Session zero is only used for hosting services"; "The first user to log on uses session one, the next user to log on uses session two". | Microsoft Learn, "Kernel object namespaces", dated 2018-05-31. |
| D4 | `FILE_OBJECT`: `Type` is 5 for a file object; `Size` is the size of the file object; `DeviceObject` is "the device object on which the file is opened"; `DeletePending`, `ReadAccess`, `WriteAccess`, `DeleteAccess`, `SharedRead`, `SharedWrite`, `SharedDelete` are BOOLEANs recording a pending delete and the access and sharing granted. "The file name in this string is valid only during the initial processing of an IRP_MJ_CREATE request." | Microsoft Learn, "FILE_OBJECT (wdm.h)", dated 2023-08-17. |
| D5 | `TotalProcesses`: "The total number of processes associated with the job during its lifetime, including those that have terminated." `ActiveProcesses`: "The total number of processes currently associated with the job." `TotalTerminatedProcesses`: "The total number of processes terminated because of a limit violation." | Microsoft Learn, "JOBOBJECT_BASIC_ACCOUNTING_INFORMATION (winnt.h)", dated 2018-12-05. |
| D6 | An environment block is `Var1=Value1\0…VarN=ValueN\0\0`; "The name of an environment variable cannot include an equal sign (=)." | Microsoft Learn, "Environment Variables", dated 2025-07-14. |
| D7 | The down-level logon name is "a domain and a user account in that domain, for example, DOMAIN\UserName", the separator a backslash. | Microsoft Learn, "User Name Formats", dated 2018-05-31. |
| D8 | `UNICODE_STRING`: `Length` and `MaximumLength` count bytes; `Length` does not exceed `MaximumLength`. | Microsoft Learn, "UNICODE_STRING (ntdef.h)". |
| D9 | Characters 1 to 31 are not allowed in file names. | Microsoft Learn, "Naming Files, Paths, and Namespaces". |

### Kernel types

Read through the project's kernel tables for builds 26100 (mem1, GUID 0D960CE1…; mem6 and mem7, 953A8DE8…), 19045 (mem2, F57E740B…) and 14393 (mem5, 3DFC5F72…) with `objectscanfacts -types`. Offsets are 26100 / 19045 / 14393 where they differ.

| # | Fact |
|---|---|
| T1 | `_KMUTANT` is 56 bytes: `Header` (`_DISPATCHER_HEADER`, 24 bytes) 0, `MutantListEntry` 0x18, `OwnerThread` (`_KTHREAD *`) 0x28, `Abandoned` at 0x30 (bit 0 of `MutantFlags` on 26100 and 19045, a whole `unsigned char` on 14393), `ApcDisable` 0x31. `_DISPATCHER_HEADER.Type` (`unsigned char`) 0, `SignalState` (`int`) 4. `_KOBJECTS.MutantObject` is 2. |
| T2 | `_ETHREAD.Tcb` 0; `_ETHREAD.Cid` (`_CLIENT_ID`, 16 bytes: `UniqueProcess` 0, `UniqueThread` 8) 0x508 / 0x478 / 0x630. `_KTHREAD.MutantListHead` 0x308. |
| T3 | `_OBJECT_SYMBOLIC_LINK` is 40 bytes: `CreationTime` (`_LARGE_INTEGER`) 0, `LinkTarget` (`_UNICODE_STRING`) 8, `DosDeviceDriveIndex` 0x18, `Flags` (`unsigned int`) 0x1c, `AccessMask` 0x20. 26100 and 19045 also have `Callback` (a function pointer) at 8 and `CallbackContext` at 0x10, over `LinkTarget`; 26100 adds `IntegrityLevel` 0x24. 14393 has neither callback member. |
| T4 | `_FILE_OBJECT` is 216 bytes on all builds: `Type` (`short`) 0, `Size` (`short`) 2, `DeviceObject` 8, `RelatedFileObject` 0x40, `DeletePending` 0x49, `ReadAccess` 0x4a, `WriteAccess` 0x4b, `DeleteAccess` 0x4c, `SharedRead` 0x4d, `SharedWrite` 0x4e, `SharedDelete` 0x4f (each `unsigned char`), `Flags` 0x50, `FileName` (`_UNICODE_STRING`) 0x58. `_DEVICE_OBJECT.DeviceType` 0x48. |
| T5 | `_EJOB` is 1,832 / 1,600 / 1,544 bytes: `Event` (`_KEVENT`) 0, `JobLinks` 0x18, `ProcessListHead` (`_LIST_ENTRY`) 0x28, `TotalProcesses` 0xd4, `ActiveProcesses` 0xd8, `TotalTerminatedProcesses` 0xdc (`unsigned int`), `SessionId` (`unsigned int`) 0x240 / 0x1e0 / 0x1e0, `ParentJob` 0x518 / 0x430 / 0x420. |
| T6 | `_EPROCESS`: `Job` (`_EJOB *`) 0x2a0 / 0x510 / 0x3b0, `JobLinks` 0x358 / 0x5c8 / 0x470, `Session` 0x2e8 / 0x558 / 0x400, `SessionProcessLinks` 0x230 / 0x4a0 / 0x340, `SeAuditProcessCreationInfo` 0x350 / 0x5c0 / 0x468, `CreateTime` 0x1f8 / 0x468 / 0x308. `_SE_AUDIT_PROCESS_CREATION_INFO.ImageFileName` (`_OBJECT_NAME_INFORMATION *`) 0, whose `Name` (`_UNICODE_STRING`) is at 0. |
| T7 | `_EPROCESS.Session` points to `_MM_SESSION_SPACE` on 19045 and 14393 (20,480 and 16,384 bytes; `SessionId` `unsigned int` 8, `ProcessList` 0x10) and to `_PSP_SESSION_SPACE` on 26100, a type the tables do not describe. |
| T8 | Globals in every table: `ObpRootDirectoryObject`, `PsActiveProcessHead`, `ObHeaderCookie`. |

### Measurements

`objectscanfacts -raw` and `-tool` on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100), in that order in every list of five. The ground truth does not use the S69 tools: the handle tables of every listed process (`windows.handle.list`, S30; 43,664, 51,796, 22,792, 36,064, 30,958 distinct objects), the object directory tree from `ObpRootDirectoryObject` walked through its hash buckets with each object's type decoded from its TypeIndex (S31 M2; 6,088, 2,575, 1,387, 2,157, 1,963 objects), and the active process list (83, 153, 71, 101, 90 processes). mem7 also has a process list with session ids taken on the live host 12 minutes before the capture.

| # | Measured |
|---|---|
| M1 | Mutants behind handles: 387, 662, 358, 435, 365 (2,207). `Header.Type` is 2 for all but 1 on mem1 (121; its header no longer holds a mutant, S31 M8). `OwnerThread` is null for 2,168 and their `SignalState` is 1; it is set for 39, and `SignalState` is 0 for 38 of them; the other, on mem1, holds a value above 1. No measured mutant has a `SignalState` below 0. `Abandoned` is set on 2, both unowned. |
| M2 | Every owner but the mem1 object's is in system space, its first byte (`Header.Type` of the `_KTHREAD`) is 6, and the mutant's `MutantListEntry` links back from its `Blink` (38 of 39). An unowned mutant's `MutantListEntry` is zero (628), holds stale links (1,539) or points to itself (1). |
| M3 | Named handle mutants: 176, 328, 101, 205, 173 (983). None of the names holds a backslash, a character below 0x20 or U+FFFD. |
| M4 | The scan accepts 989, 856, 365, 528, 617 `Muta` allocations; 600, 192, 6, 87, 128 only because their body is type 2 while their header's TypeIndex decodes to another type (kept, S31 4.5 step 4). Of those, 514, 152, 1, 65, 69 have a name whose descriptor or characters do not read or break D1; no handle reaches any of them. Every named handle mutant passes TypeIndex. |
| M5 | Symbolic links in the directory tree: 231, 313, 188, 210, 230 (1,172). `CreationTime` lies inside the capture window (S17) for all. Leaf names: none holds a backslash, a character below 0x20 or U+FFFD; 0, 1, 0, 1, 4 are empty. String targets: none holds a character below 0x20 or U+FFFD; all but 2 per capture begin with a backslash; one per capture is empty. `DosDeviceDriveIndex` is nonzero on 1, 4, 1, 1, 1 links, each a drive letter whose position in the alphabet it is. |
| M6 | `Flags` is 0 on 221, 306, 188, 199, 219 links, 0x20 on 3, 0, 0, 4, 4 and 0x10 on 7, 7, 0, 7, 7. On every link with 0x10 the pointer at `LinkTarget` lies inside a loaded kernel module and the `LinkTarget` bytes do not read as a string; on no other link does the pointer at `LinkTarget` lie inside a module. |
| M7 | File objects behind handles: 7,882, 2,685, 1,589, 1,838, 1,700 (15,694). `Type` is 5 and `Size` 216 for all but 3 on mem1 (S19 M1); for all 15,691, `DeviceObject` is a system-space address whose `Type` is 3 and whose object name reads. `FileName` is empty for 396, 650, 353, 435, 416, does not read for 11, 13, 0, 5, 8, holds a character below 0x20 for 146, 1, 0, 1, 5 and U+FFFD for 35, 0, 0, 0, 1 (D4: the name may be stale). |
| M8 | Jobs named by a process's `Job` or behind a `Job` handle: 14, 186, 21, 21, 11. The `ProcessListHead` walk closes with good back links for all but 2 on mem1, objects behind stale handles whose first byte is not 0 (`Event.Header.Type` is 0 for every other job), and its head `Blink` disagrees on 1 mem7 job. For every other job `TotalProcesses` ≥ `ActiveProcesses` + `TotalTerminatedProcesses` and ≥ the members on the list. `ActiveProcesses` equals the list's length for 9, 98, 18, 13, 6 jobs; for the rest it is larger, and 5, 90, 9, 8, 4 jobs have a `ParentJob`. |
| M9 | Every process on a job's list has `Job` equal to that job (none differs). Every process whose `Job` is set is on its job's list (6, 100, 17, 14, 8) except 1 on mem7. The job's `SessionId` equals each member's session id. |
| M10 | Processes without a session space (`Session` null): System, Secure System, Registry, smss.exe, MemCompression on mem1 and mem2; System and smss.exe on mem5; System, Registry and smss.exe on mem6 and mem7. On 19045 and 14393 every process on a session space's `ProcessList` points back to it but 1 on mem2 (148 of 149, 68 of 68). On mem7 the session id equals the live list's for all 77 processes both hold that have a session space; the 3 without one are session 0 in the live list; 10 processes of the capture are not in the live list. |
| M11 | Environment blocks: `USERNAME` is set for 74, 140, 59, 80, 64 processes and `USERDOMAIN` with it for 64, 127, 48, 69, 55; `SESSIONNAME` only for 2, 10, 8, 4, 2, all in an interactive session (1 on mem1, 2 on the others). |

## 4. Algorithm

### 4.1 Mutant scan

1. Resolve T1 and `_OBJECT_HEADER.Body`; a missing member is `ErrNoMutantType`. `_ETHREAD.Cid` and `_CLIENT_ID` are optional; without them owner ids are not read and a diagnostic says so.
2. The type tag is `_KMUTANT.Header` + `_DISPATCHER_HEADER.Type` = `MutantObject` (T1). Scan `scan.MutantFilter` through `ExecutiveScan` (S31), keeping TypeIndex mismatches when the tag resolves (S31 4.5 step 4).
3. **Body.** Read `_KMUTANT` from physical memory. An unowned mutant has `SignalState` 1; an owned one has an owner in system space and `SignalState` 0 or below (D1, D2, M1, M2). Any other combination refuses the body.
4. **Name.** `ObjectNamer` (S31 4.10) reads the name. A mutant without name information is counted and not listed. A name that does not read, or holds a backslash, a character below 0x20 or U+FFFD (D1, M3), sets `NameUnreadable`.
5. A row whose TypeIndex failed and whose name is unreadable is counted and not listed (M4).
6. **Owner.** For an owned mutant, read `Cid` at `OwnerThread` + `_ETHREAD.Cid` from kernel memory (T2); a read failure sets `OwnerUnreadable`.

### 4.2 Symbolic link scan

1. Resolve T3 (`LinkTarget` required; `CreationTime` and the callback members optional). Scan `scan.SymlinkFilter`; the type has no type member, so TypeIndex alone identifies the object. The scan is given kernel memory for names, so among equal object headers of one allocation the nearest whose name reads wins (S31 4.4 step 5, O10).
2. **Callback link.** When the table has `Callback`, `CallbackContext` and `Flags`, and `Flags` has bit 4 (0x10), the link is a callback link: the routine is the pointer at `Callback` and must be in system space, else the body is refused; the context is `CallbackContext` (M6).
3. **Target.** Otherwise `LinkTarget`: an odd `Length` or one above `MaximumLength` refuses the body (D8). A buffer that does not read, or a target holding a character below 0x20 or U+FFFD (M5), sets `TargetUnreadable`.
4. **Time.** `CreationTime` as a FILETIME; 0, a value past the last representable time, or a table without the member sets `CreateTimeUnreadable`.
5. **Name.** As 4.1 step 4 with the component rule (no backslash; M5). No name information leaves `Name` empty and not flagged.
6. A body with neither a readable target nor a readable name is refused: no row could show it.
7. **Attribution.** Callback routines are named with the kernel module list (S55 `Attributor`); a routine outside every module sets `CallbackUnowned`.

### 4.3 File object scan

1. Resolve T4 (`Size`, `DeviceObject`, `FileName` required; the BOOLEANs optional). The type tag is `_FILE_OBJECT.Type` = 5 (D4). Scan `scan.FileFilter`, keeping TypeIndex mismatches when the tag resolves.
2. **Body.** `Size` must equal the type's size (D4, M7) and `DeviceObject` must be a system-space address (D4, M7).
3. **Access.** Each BOOLEAN of T4 is true when its byte is nonzero (D4).
4. **Name.** `FileName` from the body, characters from kernel memory: an odd `Length`, one above `MaximumLength`, or a buffer that does not read sets `NameUnreadable` (D8). A name that reads is shown as found, trailing NULs dropped and embedded NULs made visible (`util.CountedText`): it may be stale (D4, M7). `PlausibleName` gives callers the D9 test.
5. **Device.** The device's object name, read from the header that precedes `DeviceObject` in kernel memory (S31 4.10); absent or unreadable sets `DeviceUnreadable`.

### 4.4 Job list

1. Resolve `_EPROCESS.Job`, `JobLinks` and `_EJOB.ProcessListHead` (required, `ErrNoJobType`); the four counters of T5 and the image path of T6 are optional. The process identity check of S17 must be usable.
2. Take the S25 process list. For each process the `pid` option keeps, in list order, read `Job`. A null job is skipped. A job already listed is skipped: each job is one group.
3. **Job row** (depth 0): the process's own columns (S25) with the job's address and counters; `Process` is `OriginalProcessLabel`. A job that does not read gives the row with every counter unreadable and no members.
4. **Members** (depth 1): walk `ProcessListHead` with the S03 walker (`MaxListEntries`, strict mode). Each entry minus `JobLinks` is an `_EPROCESS`. It must pass the S17 identity check and its `Job` must be this job (M9); otherwise it is left out with a diagnostic. Its row carries its columns (S25), `IsJobLink` and the image path from `SeAuditProcessCreationInfo` (T6). Members the `pid` option does not keep are left out.
5. **Physical.** With `windows.job.list.physical`, each row's `_EPROCESS` is translated through the kernel page tables; a failure sets `PhysicalUnknown`.

### 4.5 Session list

1. Take the S25 process list, keeping the processes the `pid` option names. The session id is the S25 one: `_EPROCESS.Session` to the session space and its `SessionId` (T7, M10); a null pointer is `SessionIDNotApplicable`, an unreadable one `SessionIDUnreadable`.
2. Read every environment block (S65 `processenvironment`). For each process take the first `USERNAME`, `USERDOMAIN` and `SESSIONNAME` in block order, names compared without regard to case (O7).
3. `UserName` is `DOMAIN\user` when both are set, the user alone when only it is (D7), else empty. `SessionType` is `SESSIONNAME`.
4. `CreateTime` is the S25 column.
5. Rows are ordered by session id, both absent markers first together, and otherwise in process list order.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Mutant body type 2 | T1, S31 | `TypeTagRejected` |
| Unowned ⇒ `SignalState` 1; owned ⇒ owner in system space and `SignalState` ≤ 0 | D1, D2, M1, M2 | `BodyRejected` |
| Mutant has name information | Purpose (named mutants) | Counted, not listed |
| Mutant name: no backslash, no character below 0x20, no U+FFFD | D1, M3 | `NameUnreadable` |
| TypeIndex failed and name unreadable | M4 | Counted, not listed |
| Callback routine in system space | M6 | `BodyRejected` |
| `LinkTarget` lengths (even, ≤ `MaximumLength`) | D8 | `BodyRejected` |
| Link target: no character below 0x20, no U+FFFD | M5 | `TargetUnreadable` |
| Link name: one component | M5 | `NameUnreadable` |
| A link has a readable target or name | 4.2 step 6 | `BodyRejected` |
| File `Type` 5, `Size` the type's | D4, M7 | `TypeTagRejected`, `BodyRejected` |
| `DeviceObject` in system space | D4, M7 | `BodyRejected` |
| `FileName` lengths and buffer | D8 | `NameUnreadable` |
| Job member passes S17 and names this job | S17, M9 | Left out, diagnostic |
| Job list back links | S03, M8 | Diagnostic; strict mode: error |

## 6. Failure modes

| Case | Result |
|---|---|
| Profile not Windows | `ErrNotWindows` of each package |
| No physical memory (scans) | `ErrNoPhysicalMemory` |
| Table lacks a required member | `ErrNoMutantType`, `ErrNoLinkType`, `ErrNoFileType`, `ErrNoJobType`, wrapped with the member's name |
| Table cannot locate object names | Mutant and link scans: error; file scan: diagnostic, `Device` unread |
| Pool scan prerequisites (S31, S70) | The `ExecutiveScan` error and diagnostics |
| Owner thread unreadable | `OwnerUnreadable`; diagnostic `windows.object.scan_mutants: mutant at 0x<addr>: owner thread at 0x<addr>: objectmutants: owner thread does not read: …` |
| Kernel module list fails | Diagnostic; callback links keep no module |
| `windows.job.list.physical` of the wrong form | `tools: option value of the wrong form` |
| Physical requested, kernel space cannot translate | `ErrNoFrames` |
| `Job` unreadable | Diagnostic `windows.job.list: process at 0x<addr>: Job: …`; process skipped |
| Job unreadable | Diagnostic `windows.job.list: job at 0x<addr>: joblist: job object does not read: …` |
| Member refused | Diagnostic `windows.job.list: job at 0x<addr>: process at 0x<addr>: <reason>` |
| Job list walk fails in strict mode | Rows so far and `windows.job.list: job at 0x<addr>: <walker error>` |
| Environment blocks fail | Diagnostic; `UserName`, `SessionType` empty |

Every scan ends with a diagnostic of its row count and the S31 statistics.

## 7. Result schema

`objectmutants.Mutant`: `Offset` (physical body), `VirtualOffset` (kernel address or 0), `OtherCopy` (S31 4.7), `Name`, `NameUnreadable` (new), `OwnerThread`, `OwnerPID`, `OwnerTID`, `OwnerUnreadable`, `Abandoned`, `TypeIndexFailed` (all new). Order: S31 4.9.

`objectlinks.Symlink`: `Offset`, `VirtualOffset`, `OtherCopy`, `Name`, `Target`, `NameUnreadable`, `TargetUnreadable`, `Callback`, `CallbackRoutine`, `CallbackContext`, `CallbackModule`, `CallbackSymbol`, `CallbackUnowned`, `CreateTime` (UTC; zero with `CreateTimeUnreadable`), `CreateTimeUnreadable`, `TypeIndexFailed` (new). A callback link has an empty `Target` that is not flagged. Order: S31 4.9.

`filescan.File`: `Offset`, `VirtualOffset`, `OtherCopy`, `Name`, `NameUnreadable`, `Device`, `DeviceUnreadable`, `ReadAccess`, `WriteAccess`, `DeleteAccess`, `SharedRead`, `SharedWrite`, `SharedDelete`, `DeletePending`, `TypeIndexFailed` (all but the first four new). Order: S31 4.9.

`joblist.Row`: `Depth` (0 job, 1 member), `EPROCESS`, `Physical`, `PhysicalUnknown`, `Job` (new), `Name`, `PID`, `PPID`, `PPIDUnreadable`, `SessionID` (S25 markers), `JobSessionID`, `JobSessionIDUnreadable`, `Wow64`, `Total`, `TotalUnreadable`, `Active`, `ActiveUnreadable`, `Terminated`, `TerminatedUnreadable` (counters on depth 0 only), `IsJobLink`, `Process` (image path on members, `OriginalProcessLabel` on the job row), `ProcessUnreadable`. Order: groups in process list order, members in list order.

`sessionlist.Row`: `SessionID`, `SessionType`, `PID`, `Process`, `EPROCESS`, `UserName`, `CreateTime`. Order: 4.5 step 5.

## 8. Limits

- `Workers`: tag sweep goroutines (S31).
- `MaxListEntries`: entries of one job's process list (S03); a longer list is cut with a diagnostic.
- Names and paths are read up to `util.MaxUnicodeStringBytes`, the largest `Length` a `UNICODE_STRING` holds.

## 9. Acceptance

1. Synthetic fixtures on the 26100 layouts of T1 to T6, except the `_EPROCESS` members of T6, which sit at their 19045 offsets, the build the process fixture lays out (S79 P1) (`internal/testsupport/s69_fixture.go`): named, unnamed, owned, recursively owned, abandoned and inconsistent mutants, a name outside D1, an owner that does not read; string, empty, unreadable, odd-length and control-character targets, callback links in a module, outside every module and outside system space, a table without the callback members, a zero creation time; file objects with access and pending delete, wrong `Size`, `Type` and device, names that do not read and names shown as found; a job group with members and image paths, the `pid` option, a list entry of another job, a member without a path, the physical option and its wrong form, a missing counter, a job that does not read, a table without job members; session order with absent sessions, the `pid` option, environment names in any case, account names. The private real-image test of the `pid` option passes.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzMutantBody` (accepted bodies keep the owner and state rule and the name rule), 3.42 million executions; `FuzzSymbolicLinkBody` (callback routines in system space, names and targets pass their rules, every row shows a name or target), 3.10 million; `FuzzFileObjectBody` (accepted bodies have the type's `Size` and a system-space device; names fit their `Length`), 4.24 million.
3. On the captures, `objectscanfacts -tool`, 2026-11-12:

| | mem1_win11 | mem2_win10 | mem5_server2016 | mem6_server2025 | mem7_server2025 |
|---|---|---|---|---|---|
| Mutant rows | 177 | 332 | 102 | 211 | 243 |
| Named handle mutants found | 176 of 176 | 328 of 328 | 101 of 101 | 205 of 205 | 173 of 173 |
| Not listed: unnamed; failed TypeIndex and name | 298; 514 | 372; 152 | 262; 1 | 252; 65 | 305; 69 |
| Link rows (callback links) | 231 (7) | 315 (7) | 190 (0) | 211 (7) | 234 (7) |
| Directory links found | 231 of 231 | 313 of 313 (312 before S31 O10) | 188 of 188 | 210 of 210 | 230 of 230 |
| File rows | 20,809 | 16,405 | 4,940 | 4,883 | 6,600 |
| Handle file objects found | 7,879 of 7,882 | 2,680 of 2,685 | 1,589 of 1,589 | 1,838 of 1,838 | 1,700 of 1,700 |
| File rows without a kernel address | 2,796 | 0 | 0 | 0 | 0 |
| Job rows (jobs, members) | 12 (6, 6) | 198 (98, 100) | 32 (15, 17) | 25 (11, 14) | 14 (6, 8) |
| Session rows | 83 | 153 | 71 | 101 | 90 |

   - Every callback link's routine is in a loaded module.
   - The 3 handle file objects not found on mem1 are those of M7 that are not file objects; the 5 on mem2 are not among the rows; why was not measured.
   - The job list reaches every process M9 counts on a job's list.
   - Scan times on mem1 (10.9 GB): mutants 21.5 s, links 7.9 s, files 18.4 s.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision (Q2): row fields kept from 0.1.0 where the meaning holds. New: `Mutant.NameUnreadable`, `OwnerThread`, `OwnerPID`, `OwnerTID`, `OwnerUnreadable`, `Abandoned`, `TypeIndexFailed`; `Symlink.TypeIndexFailed`; `File.NameUnreadable`, `Device`, `DeviceUnreadable`, the seven BOOLEANs, `TypeIndexFailed`; `joblist.Row.Job`. New sentinels: `ErrNotWindows` in each package, `objectmutants.ErrNoPhysicalMemory`, `ErrNoMutantType`, `ErrOwnerUnread`; `objectlinks.ErrNoPhysicalMemory`, `ErrNoLinkType`, `ErrTargetInvalid`, `ErrTargetUnread`; `filescan.ErrNoPhysicalMemory`, `ErrNoFileType`, `ErrNameInvalid`, `ErrNameUnread`; `joblist.ErrNoJobType`, `ErrJobUnread`, `ErrOtherJob`. | Owner review |
| O2 | Owner decision: the job list gives one group per job, headed by the first listed process naming it; a job named by no listed process (empty jobs behind handles, parent jobs; M8) is not listed. The job row's `Process` is a label, not the holder's path. Owner decision 2026-11-12: one group per job; reword O2 (the table below said one group per listed process; 4.4 step 2 holds). Done: no code change, the tool already gives one group per job. | Owner decision: list jobs from `Job` handles too; show the path |
| O3 | Owner decision: mutants without a name are counted, not listed (298 to 372 per capture), and mismatched rows whose name does not read are dropped (M4). | Owner decision: list them flagged |
| O4 | The callback bit 0x10 of `_OBJECT_SYMBOLIC_LINK.Flags` and the meaning of 0x20 rest on measurement (M6); no public document describes `Flags`. | Owner decision on a measured rule |
| O5 | File names are shown as found (D4); 2,870, 5,029, 671, 969, 1,627 scan rows hold names that fail `PlausibleName`. `filescan.PlausibleName`, `objectmutants.PlausibleName` and `objectlinks.Plausible` stay exported for their callers; the file scan does not apply its own. | Owner decision: flag such names |
| O6 | The image path of job members is `SeAuditProcessCreationInfo`, a member no public document describes (T6). | Owner decision |
| O7 | Environment variable names are compared without regard to case and the first occurrence wins; no Microsoft Learn page found states either. `USERNAME`, `USERDOMAIN` and `SESSIONNAME` are not documented on Microsoft Learn either; their values are the process's own claim, and `SESSIONNAME` is set on few processes (M11). | Owner decision: take the user from the token (S45) |
| O8 | Build 26100 does not type the session space; the session id there is S25's measured offset (T7, M10). | A table that types `_PSP_SESSION_SPACE` |
| O9 | x86 tables are covered only by the table-driven layouts; no 32-bit capture was measured. | A 32-bit capture (Q7) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Yes, as specified |
| O2 | One group per job, headed by the first listed process naming it (reworded 2026-11-12) |
| O3 | Count only |
| O4 | Keep measured rule |
| O5 | Show as found |
| O6 | Keep |
| O7 | Keep as is |
| O8 | Keep measured offset |
| O9 | Keep |

## 11. Provenance

Written from Microsoft Learn, the ntoskrnl types in the project's symbol tables, and the project's measurements with `objectscanfacts` on the five Windows captures. The author read the 0.1.0 files of these packages only for their exported names, callers, registered tool names and option keys before deleting them. Every rule rests on the sources and measurements above.
