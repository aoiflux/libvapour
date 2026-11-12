# S56: Windows loaded libraries, registry autostart locations and the process tree

Version 1, 2026-11-12.

## 1. Purpose

Three questions an examiner asks early about a Windows capture, answered by three tools.

- `windows.library.list`: which DLLs each process had loaded. The user-mode loader keeps one record per loaded module in the process's own memory and links every record into three lists headed in the PEB's loader data. The tool walks all three lists, so that a record cut out of one list, or a list broken by a page that is not in the capture, still shows, and says in which lists each record was found.
- `windows.registry.list_autostart`: which programs the registry starts at boot or logon. The tool reads the autostart locations that Microsoft documents, in the machine hives and in every loaded user hive, and returns one row per value found there.
- `any.process.tree`: which process started which. Each process records the ID of the process that created it. The tool arranges the listed processes by that link, on Windows and on Linux, and refuses a link that cannot be true: a self-parented process, and a parent whose process ID was reused after the real parent ended.

## 2. Inputs

| Input | Tool | Meaning |
|---|---|---|
| Kernel memory, symbol table | all | Kernel virtual reads; the kernel types of 3.2. |
| Process spaces | library list, tree | `tools.Context.ProcessSpace` for the process's page-table root from the process list. |
| Process list | library list, tree | `processlist.Run` (S25): every listed process, with PID, image name, `_EPROCESS` address, page-table root and the S25 columns (parent PID, creation and exit time). |
| Registry hives | autostart | `registryhive.OpenEveryHive` (S49): the loaded hives with their file and registry paths. |
| `windows.library.list.base` | library list | Unsigned. Keep the rows whose DLL base is this address (the `modulelist` base rule, S55). |
| `windows.library.list.name` | library list | Regular expression. Keep the rows whose `BaseDllName` or `FullDllName` matches. |
| `windows.library.list.ignore_case` | library list | Boolean. Match the name pattern without case. |
| `windows.library.list.offset` | library list | Unsigned. List only the process that the process scan finds at this physical offset (`processscan.ProcessesAtOffset`). |
| `pid` | library list, tree | The project's PID set (owner decisions). |
| `strict` | all | Turns a broken list, an unreadable record or an unread hive location into an error. |
| Limits | library list | `MaxListEntries` per loader list (S03). |

A wrong option type is an error (owner decision 2026-11-03). Tool names and option keys are unchanged.

## 3. Facts from the sources

### 3.1 Documentation

| # | Fact | Source |
|---|---|---|
| D1 | `PEB` begins `BYTE Reserved1[2]; BYTE BeingDebugged; BYTE Reserved2[1]; PVOID Reserved3[2]; PPEB_LDR_DATA Ldr; PRTL_USER_PROCESS_PARAMETERS ProcessParameters; ...`. `Ldr` is "a pointer to a PEB_LDR_DATA structure that contains information about the loaded modules for the process". With 4-byte pointers `Ldr` is at 0x0C; with 8-byte pointers at 0x18. | Microsoft Learn, "PEB structure (winternl.h)", updated 2024-05-29, accessed 2026-11-12. |
| D2 | `PEB_LDR_DATA` is `BYTE Reserved1[8]; PVOID Reserved2[3]; LIST_ENTRY InMemoryOrderModuleList;`. `InMemoryOrderModuleList` is "the head of a doubly-linked list that contains the loaded modules for the process. Each item in the list is a pointer to an LDR_DATA_TABLE_ENTRY structure." | Microsoft Learn, "PEB_LDR_DATA structure (winternl.h)", updated 2025-08-15, accessed 2026-11-12. |
| D3 | `LDR_DATA_TABLE_ENTRY` is `PVOID Reserved1[2]; LIST_ENTRY InMemoryOrderLinks; PVOID Reserved2[2]; PVOID DllBase; PVOID Reserved3[2]; UNICODE_STRING FullDllName; BYTE Reserved4[8]; PVOID Reserved5[3]; union { ULONG CheckSum; PVOID Reserved6; }; ULONG TimeDateStamp;`. With 4-byte pointers: `InMemoryOrderLinks` at 0x08, `DllBase` at 0x18, `FullDllName` at 0x24, the 8 reserved bytes at 0x2C. | Same page as D2. |
| D4 | A `UNICODE_STRING` is `USHORT Length; USHORT MaximumLength; PWSTR Buffer;`, the lengths in bytes. | Microsoft Learn, "UNICODE_STRING structure (ntdef.h)", accessed 2026-11-12. |
| D5 | `RTL_USER_PROCESS_PARAMETERS` is `BYTE Reserved1[16]; PVOID Reserved2[10]; UNICODE_STRING ImagePathName; UNICODE_STRING CommandLine;`. | Microsoft Learn, "RTL_USER_PROCESS_PARAMETERS structure (winternl.h)", accessed 2026-11-12. |
| D6 | A FILETIME counts 100-nanosecond intervals since 1601-01-01 UTC. | Microsoft Learn, "FILETIME structure (minwinbase.h)", accessed 2026-11-12. |
| D7 | A process identifier "uniquely identifies the process throughout the system"; "the identifier is valid from the time the process is created until the process has been terminated". `Process32First` gives the identifier of the parent process. | Microsoft Learn, "Process Handles and Identifiers", dated 2025-07-14, accessed 2026-11-12. |
| D8 | The four Run and RunOnce keys are `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`, `...\RunOnce`, `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` and `...\RunOnce`. Each entry is a value `description-string=commandline`; "the data value for a key is a command line no longer than 260 characters"; the order in which several programs under one key run "is indeterminate". A RunOnce value name prefixed with `!` has its deletion deferred until after the command runs; a RunOnce value name prefixed with `*` runs even in Safe Mode; otherwise the keys are ignored in Safe Mode. | Microsoft Learn, "Run and RunOnce Registry Keys", dated 2024-07-19, accessed 2026-11-12. |
| D9 | `HKEY_LOCAL_MACHINE\SOFTWARE` is redirected for 32-bit applications on 64-bit Windows, to `Wow6432Node`; `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies`, `...\Windows NT\CurrentVersion\Image File Execution Options` and `HKEY_CURRENT_USER\SOFTWARE` are shared on Windows 7 and later. `HKEY_CURRENT_USER` is a link to `HKEY_USERS\[SID]`, and `HKEY_USERS\[SID]\SOFTWARE\Classes` to `HKEY_USERS\[SID]_Classes`. | Microsoft Learn, "Registry Keys Affected by WOW64", dated 2021-01-23, accessed 2026-11-12. |
| D10 | Recommended registry items to monitor "based on known attack patterns" include `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `RunOnce`, `RunServicesOnce`, the `Wow6432Node` Run and RunOnce keys, and the values `AppInit_DLLs`, `LoadAppInit_DLLs` and `IconServiceLib` of `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows` (and `AppInit_DLLs`, `LoadAppInit_DLLs` of its `Wow6432Node` copy). | Microsoft Learn, "Overview of file integrity monitoring in Microsoft Defender for Cloud", dated 2026-03-22, accessed 2026-11-12. |
| D11 | "Run these programs at user logon" (policies Run_1 for the user and Run_2 for the computer) has the registry key `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`; the computer's list runs just before the user's. The same key holds `DisableLocalMachineRun`, `DisableCurrentUserRun`, `DisableLocalMachineRunOnce` and `DisableCurrentUserRunOnce`. | Microsoft Learn, "ADMX_Logon Policy CSP", dated 2026-10-14, accessed 2026-11-12. |
| D12 | The Winlogon key is `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`; its values are REG_SZ unless noted. Userinit.exe runs when the user has logged on and then executes the shell programs named in `Shell`, which separates them with commas. | Microsoft Learn, "MSGina.dll Features", accessed 2026-11-12; "Can't log on to Windows" (KB 555648), dated 2026-02-12, which names the `Shell` and `Userinit` values of that key. |
| D13 | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image>` with a REG_SZ value `Debugger` starts the named debugger for that image. | Microsoft Learn, "Debugging a Service", accessed 2026-11-12. |
| D14 | `HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute`, a MULTI_SZ, "contains the names and arguments of programs that are executed by Session Manager". | Microsoft Learn (Sysinternals), "Inside Native Applications", accessed 2026-11-12. |
| D15 | The `HKEY_CURRENT_USER` hive's file is `Ntuser.dat`; `HKEY_USERS\.DEFAULT` is the file `Default`; user profile hives are under `HKEY_USERS`. | Microsoft Learn, "Registry Hives", accessed 2026-11-12. |
| D16 | A `LIST_ENTRY` walk, its recovering mode and `CONTAINING_RECORD`; `LIST_ENTRY32` has width 4. | S03 L1 to L7, 4.1 to 4.6. |

### 3.2 Kernel types

Read with `libraryfacts` through the project's kernel tables for builds 26100 (mem1 GUID 0D960CE1...; mem6 and mem7 953A8DE8...), 19045 (mem2, F57E740B...) and 14393 (mem5, 3DFC5F72...). T1 to T5 hold in all four tables.

| # | Fact |
|---|---|
| T1 | `_PEB.Ldr` is `_PEB_LDR_DATA*` at 0x18; `_PEB.ProcessParameters` is `_RTL_USER_PROCESS_PARAMETERS*` at 0x20; `_PEB.ImageBaseAddress` at 0x10. |
| T2 | `_PEB_LDR_DATA` (0x58 bytes): `Length` 0x0, `Initialized` 0x4, `SsHandle` 0x8, `InLoadOrderModuleList` 0x10, `InMemoryOrderModuleList` 0x20, `InInitializationOrderModuleList` 0x30, each a `_LIST_ENTRY`. |
| T3 | `_LDR_DATA_TABLE_ENTRY` (0x120 bytes on 14393 and 19045, 0x138 on 26100): `InLoadOrderLinks` 0x0, `InMemoryOrderLinks` 0x10, `InInitializationOrderLinks` 0x20, `DllBase` 0x30 (`void*`), `EntryPoint` 0x38, `SizeOfImage` 0x40 (`unsigned int`), `FullDllName` 0x48 and `BaseDllName` 0x58 (`_UNICODE_STRING`), `ObsoleteLoadCount` 0x6c (`unsigned short`), `DdagNode` 0x98 (`_LDR_DDAG_NODE*`), `LoadTime` 0x100 (`_LARGE_INTEGER`). No table has `_LDR_DATA_TABLE_ENTRY.LoadCount`. `_LDR_DDAG_NODE.LoadCount` is `unsigned int` at 0x18. |
| T4 | `_EPROCESS.WoW64Process` is `_EWOW64PROCESS*`; `_EWOW64PROCESS.Peb` is `void*` at 0. `_PEB32.Ldr` is `unsigned int` at 0x0c (agrees with D1). `LIST_ENTRY32` is `{ unsigned int Flink at 0; unsigned int Blink at 4 }`; `_STRING32` is `{ Length 0, MaximumLength 2, Buffer 4 (unsigned int) }`, 8 bytes. No table has `_PEB_LDR_DATA32` or `_LDR_DATA_TABLE_ENTRY32`. |
| T5 | `_EPROCESS.InheritedFromUniqueProcessId` is `void*`; `CreateTime` and `ExitTime` are `_LARGE_INTEGER`; `Peb` is `_PEB*`; `SeAuditProcessCreationInfo` is `_SE_AUDIT_PROCESS_CREATION_INFO` whose `ImageFileName` is `_OBJECT_NAME_INFORMATION*`, whose `Name` is a `_UNICODE_STRING` at 0. `_RTL_USER_PROCESS_PARAMETERS.ImagePathName` is at 0x60 and `CommandLine` at 0x70 (agrees with D5). The global `PsInitialSystemProcess` is in every table. |

### 3.3 The 32-bit loader layout

No table describes the 32-bit loader data or records (T4). L1 lays the 64-bit member order of T2 and T3 out again with 4-byte pointers and 8-byte `LIST_ENTRY32`, and checks every offset that Learn's declarations fix (D1, D2, D3).

| # | Layout | Learn check |
|---|---|---|
| L1 | Loader data: `InLoadOrderModuleList` 0x0C, `InMemoryOrderModuleList` 0x14, `InInitializationOrderModuleList` 0x1C. Record: `InLoadOrderLinks` 0x00, `InMemoryOrderLinks` 0x08, `InInitializationOrderLinks` 0x10, `DllBase` 0x18, `SizeOfImage` 0x20, `FullDllName` 0x24, `BaseDllName` 0x2C, strings as `_STRING32` (T4). | 0x14 (D2), 0x08, 0x18, 0x24 and the 8 bytes at 0x2C (D3) |

M8 confirms L1 on the captures. `LoadCount` and `LoadTime` have no 32-bit layout and are not read for 32-bit records.

### 3.4 Measurements

M1 to M14 come from `libraryfacts -v`, run on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 and mem7_server2025 (26100). Counts are given in that order. Each list is walked with the S03 recovering walk.

| # | Measured |
|---|---|
| M1 | Listed processes 83, 153, 71, 101, 90. `_EPROCESS.Peb` is 0 for 4, 4, 1, 2, 2 (the System, Registry, Secure System and memory compression processes); the PEB page does not read for 4, 5, 3, 11, 10; `Ldr` is 0 for 1, 1, 0, 0, 0; 74, 143, 67, 88, 78 have loader data. |
| M2 | In-load-order walks: complete 74, 142, 67, 86, 73; ended at an unreadable record 0, 1, 0, 2, 3; at a back-link break 0, 0, 0, 0, 2. Records reached: in load order 4,351, 7,995, 3,458, 4,668, 4,117; in memory order 4,351, 7,995, 3,458, 4,667, 4,118; in initialization order 4,276, 7,851, 3,385, 4,578, 4,039. The backward walk recovered 0, 28, 0, 0, 40 load-order records. The union of the three lists has 4,351, 7,995, 3,458, 4,668, 4,119 records. |
| M3 | Where both walks read, the load-order and memory-order lists hold the same records in the same order in every process (74, 143, 67, 87, 77). |
| M4 | Membership of the union: in all three lists 4,276, 7,851, 3,385, 4,578, 4,037; in load and memory order but not initialization order, the process image itself (its `DllBase` equals `_PEB.ImageBaseAddress`) 74, 143, 67, 87, 78 and other records 1, 1, 6, 2, 2 (resource-only DLLs such as `TipRes.dll`); only in load order 0, 0, 0, 1, 0; in memory and initialization order 0, 0, 0, 0, 1; only in initialization order 0, 0, 0, 0, 1. The process image is the first load-order record in every process. |
| M5 | `DllBase` does not read for 1 record (mem6); it is 0 for 1 (mem7). `BaseDllName` does not read for 0, 126, 1, 101, 132 records; `FullDllName` for 0, 107, 0, 84, 93. Re-measured 2026-11-12 with `windows.library.list` after O8: rows 4,351, 8,038, 3,524, 4,695 and 4,158 (24,766); the mem6 record (PID 528 `fontdrvhost.exe`, entry 0x171e3bc7ff0, on the load-order list only) is a flagged row with every field unread, and the tool's unread-name diagnostic on mem6 counts 103 `BaseDllName` and 86 `FullDllName` of 4,695 (102 and 85 of 4,694 before). |
| M6 | `DdagNode->LoadCount`: 0xFFFFFFFF in 777, 1,061, 445, 772, 674 records; 1 in 2,022, 3,981, 1,699, 2,204, 1,964; 2 to 99 in 1,539, 2,932, 1,306, 1,676, 1,468; 100 or more 13, 11, 8, 10, 11; 0 once (mem7); unreadable 0, 10, 0, 5, 1. |
| M7 | `LoadTime` read as a FILETIME is at or after the process's `CreateTime` less one second in every record where both read (4,351, 7,995, 3,458, 4,666, 4,117); it does not read for 0, 0, 0, 1, 2. |
| M8 | WoW64 processes 0, 1, 2, 2, 1. Their 32-bit lists by L1: 0, 43, 66, 27, 39 load-order records; 6 of the 7 walks complete, 1 ends at an unreadable record (mem6); load and memory order agree in every process; the 32-bit process image is first in load order and absent from initialization order in each; every one of the 40 image headers at a 32-bit `DllBase` that reads starts with `MZ`; `BaseDllName` does not read for 3 of 175 records. |
| M9 | Of the image headers at a native `DllBase` that read, 4,341, 4,807, 3,453, 2,112, 719 start with `MZ` and 0, 13, 0, 0, 1 do not (all on pages filled with zeros or other data); 10, 3,175, 5, 2,555, 3,399 do not read. |
| M10 | Every listed process has a distinct PID on all five captures; none is self-parented; no chain of parent links forms a cycle; the parent PID of 3, 7, 3, 10, 8 processes names no listed process (System's 0 among them). |
| M11 | A listed process holding the parent PID was created after the child for 4, 2, 0, 3, 1 processes. On mem1: `Secure System` and `Registry` are 50.4 s older than their parent `System`, and `csrss.exe` 1276 and `wininit.exe` 1436 are 1.5 s older than `svchost.exe` 944 that holds their parent PID. On mem2 and mem7 `Registry` (and on mem2 `Secure System`) are older than `System` by 0.4 to 1.1 s; on mem6 `Registry` by 0.4 s, and `csrss.exe` 704 and `winlogon.exe` 768 are 6.6 s older than `svchost.exe` 688. |
| M12 | mem7 has a process snapshot taken on the host after the capture (`proc_after.csv`, `ParentProcessId` per `ProcessId`). Of the 90 listed processes 81 are in it under the same name, and the parent PID agrees for all 81; the other 9 had exited. |
| M13 | Autostart values per capture (section 7.2 locations): see section 9.3. Hives: every capture has `\REGISTRY\MACHINE\SOFTWARE` and `\REGISTRY\MACHINE\SYSTEM`, the user hives `\REGISTRY\USER\.DEFAULT` (file `DEFAULT`), `S-1-5-19` and `S-1-5-20` (`ServiceProfiles\...\NTUSER.DAT`), and one profile hive `\REGISTRY\USER\S-1-5-21-...` (`C:\Users\<name>\ntuser.dat`); the `_Classes` hives are separate. |
| M14 | No `Wow6432Node` Image File Execution Options key has a subkey (0 on all five); none of the four `Disable...Run...` policy values exists in any hive; no Policies `Run` key exists in any hive. |

## 4. Algorithm

### 4.1 Library list

1. The process rows are the process list (S25) narrowed by the PID set, or the processes the process scan finds at `windows.library.list.offset`.
2. For each process, read `_EPROCESS.Peb` in kernel memory. A PEB of 0 is a process with no user-mode loader (M1) and gives no rows, silently. Then open the process space. If it does not open, report and go on.
3. Read `_PEB.Ldr` in the process space (T1). If it does not read, or is 0, report and go on (M1).
4. Walk each of the three lists of T2 with the S03 recovering walk (a table that describes only the in-load-order list, as a hand-built test table may, walks that one and says so), in the process space, with the native `_LIST_ENTRY` layout. The record of a list entry is its container by that list's link member (T3, D16). A link whose container would fall below address 0 is skipped silently: it is not counted and gives no diagnostic (O10). A head that does not read is reported; the other lists still walk.
5. The rows are the records of the in-load-order list in walk order, then those found only by the in-memory-order walk, then those found only by the in-initialization-order walk (M2, M4). Each row says in which of the three lists its record was found.
6. For each record read `DllBase` (pointer width), `SizeOfImage`, `BaseDllName` and `FullDllName` (D4, T3). A record whose `DllBase` does not read is listed with `Base` 0 and `BaseUnreadable` set, and counted (M5); its other fields are still read. A field that does not read is flagged. A base filter cannot match such a row and drops it.
7. `LoadCount` is `DdagNode->LoadCount` (T3). A table without `DdagNode` or `_LDR_DDAG_NODE.LoadCount` gives no load counts, reported once. `LoadTime` is the record's FILETIME (D6, M7); 0 or a value with the top bit set is no time.
8. If `_EPROCESS.WoW64Process` is not 0, read `_EWOW64PROCESS.Peb`, then `_PEB32.Ldr` (T4), and walk the three 32-bit lists with `LIST_ENTRY32` and L1, steps 4 to 6 the same. These rows are marked WoW64 and carry no load count or time.
9. Apply the base and name filters, then report the counts of section 6.

### 4.2 Autostart list

1. Open every loaded hive (S49). Pick the machine SOFTWARE hive (registry path `\REGISTRY\MACHINE\SOFTWARE`), the machine SYSTEM hive (`\REGISTRY\MACHINE\SYSTEM`) and every user hive: a registry path `\REGISTRY\USER\<name>` that does not end in `_Classes` (D9, D15). A hive whose registry path did not read is picked by its file name instead: `SOFTWARE`, `SYSTEM`, `NTUSER.DAT` or `DEFAULT` (D15, M13). When two hives qualify as the machine SOFTWARE or SYSTEM hive, the first in list order is used and the others are reported.
2. In each picked hive, open each location of the table below for its hive kind. A key that does not exist gives no rows. A key that does not read is reported.
3. A key location gives one row per value, in stored order (D8: order has no meaning). A value location gives a row for each named value present. The Image File Execution Options location gives a row for each subkey that has a `Debugger` value.
4. RunOnce rows take the `!` and `*` prefixes of the value name as flags (D8); the name is kept as stored.
5. BootExecute is read from the current control set of SYSTEM (`Select\Current`, S49). If that does not read, the location is reported and skipped.

| Location | Hive | Key | What | Source |
|---|---|---|---|---|
| `Run` | SOFTWARE | `Microsoft\Windows\CurrentVersion\Run` | every value | D8, D10 |
| `RunOnce` | SOFTWARE | `Microsoft\Windows\CurrentVersion\RunOnce` | every value | D8, D10 |
| `RunServicesOnce` | SOFTWARE | `Microsoft\Windows\CurrentVersion\RunServicesOnce` | every value | D10 |
| `Run`, 32-bit view | SOFTWARE | `Wow6432Node\Microsoft\Windows\CurrentVersion\Run` | every value | D9, D10 |
| `RunOnce`, 32-bit view | SOFTWARE | `Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce` | every value | D9, D10 |
| `PolicyRun` | SOFTWARE | `Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` | every value | D11, O4 |
| `Winlogon` | SOFTWARE | `Microsoft\Windows NT\CurrentVersion\Winlogon` | `Shell`, `Userinit` | D12 |
| `AppInit` | SOFTWARE | `Microsoft\Windows NT\CurrentVersion\Windows` | `AppInit_DLLs`, `LoadAppInit_DLLs`, `IconServiceLib` | D10 |
| `AppInit`, 32-bit view | SOFTWARE | `Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows` | `AppInit_DLLs`, `LoadAppInit_DLLs` | D10 |
| `ImageDebugger` | SOFTWARE | `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image>` | `Debugger` | D13 (shared, D9) |
| `BootExecute` | SYSTEM | `<current control set>\Control\Session Manager` | `BootExecute` | D14 |
| `Run` | user | `Software\Microsoft\Windows\CurrentVersion\Run` | every value | D8 |
| `RunOnce` | user | `Software\Microsoft\Windows\CurrentVersion\RunOnce` | every value | D8 |
| `PolicyRun` | user | `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` | every value | D11, O4 |

### 4.3 Process tree

1. Windows: the rows are every process of the process list, with its parent PID (`InheritedFromUniqueProcessId`), creation and exit time (S25), and the details of 4.4. Linux: every task the process list gives, with the parent's thread-group ID from `linuxobj` (`ParentPID`, S14); Linux rows have no creation time. The process list is taken without the PID set; the set applies in step 7.
2. A row whose parent PID does not read, or equals its own PID (self-parented, owner decision), is a root. A self-parented row takes no children.
3. The candidates for a row's parent are the other rows that hold its parent PID. With several, the one whose lifetime holds the row's creation (created at or before it, and not exited before it) is taken; else the first in list order (D7).
4. On Windows a candidate created after the row cannot have created it (D7): the parent PID names a process that ended and whose PID was reused. The row becomes a root and is flagged. The initial system process (`PsInitialSystemProcess`) is exempt: its `CreateTime` is set after the processes the kernel itself starts (M11).
5. If the parent links still form a cycle, the row of the cycle first in list order becomes a root.
6. Children and roots are ordered by PID, then list order. Depth is the number of parent links above a row.
7. With a PID set, a row is kept when the set names it or one of its descendants.

### 4.4 Process details (Windows)

1. `AuditImageName`: `SeAuditProcessCreationInfo.ImageFileName` (T5) is a pointer to an `_OBJECT_NAME_INFORMATION` in kernel memory; its `Name` is read. A null pointer gives an empty name.
2. `ImagePathName` and `CommandLine`: `_EPROCESS.Peb`, then `_PEB.ProcessParameters` in the process space (T1, D1), then the two `UNICODE_STRING`s (D5, T5). Each string is read on its own.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Loader list links agree (S03 4.3) | D16 | The walk breaks, is reported, and the backward walk recovers what it can |
| Record container not below 0 | D16 | The entry is skipped silently: no count, no diagnostic, no strict-mode error (O10) |
| `DllBase` reads | M5 | Row flagged `BaseUnreadable`, `Base` 0; counted |
| A parent created after its child is not its parent, except the initial system process | D7, M11 | The child is a root, flagged `ParentPIDReused` |
| A self-parented process is a root without children | Owner decision | As stated |

No rule tests an image header, a name or a count: M9 shows `MZ` missing only where the page is not the image, and no measured value of a field is out of its type's range.

## 6. Failure modes

| Case | Result |
|---|---|
| Not a Windows profile (library list, autostart) | Run error `<tool>: unsupported profile os "<os>"` |
| Process list fails | Run error `<tool>: process list: <error>` |
| Symbol table lacks `_PEB.Ldr`, `_EPROCESS.Peb`, the in-load-order head or link, or a record field of T3 | Run error `windows.library.list: <type>.<member>: librarylist: symbol table lacks a loader member: ...` |
| `_EPROCESS.WoW64Process` or `_EWOW64PROCESS.Peb` does not read | Diagnostic `windows.library.list: process <pid> at 0x<eprocess>: ...: does not read`; strict: error |
| Process space does not open | Diagnostic `windows.library.list: process <pid> at 0x<eprocess>: no process space, no libraries listed: <error>` |
| PEB pointer or `Ldr` does not read, or `Ldr` is 0 | Diagnostic `windows.library.list: process <pid> at 0x<eprocess>: PEB pointer does not read: <error>`, `windows.library.list: process <pid> at 0x<eprocess>: PEB at 0x<peb>: loader data does not read: <error>` or `…: PEB at 0x<peb>: loader data pointer is 0`; in strict mode the run returns the error |
| List break | The S03 diagnostic; in strict mode the run returns it |
| A loader link whose record container falls below 0 | The entry is skipped; no diagnostic, no count, no strict-mode error (O10) |
| Records flagged for an unreadable `DllBase` | Diagnostic `windows.library.list: process <pid> at 0x<eprocess>: <n> loader records flagged: librarylist: DllBase does not read`; strict: error |
| Names unreadable | One diagnostic with the counts; rows flagged |
| No 32-bit layout in the table | Diagnostic `windows.library.list: librarylist: symbol table lacks _PEB32 or LIST_ENTRY32: ...: no 32-bit libraries listed` |
| Hive location key unreadable, value list incomplete, subkey list incomplete, a named value that may be among the unread values, `Select\Current` unread | Diagnostic `windows.registry.list_autostart: <hive> key <path>: <what> does not read: <error>` (`registryautostart: an autostart location did not read in full` when the hive layer gives no error); strict: all rows and the first error |
| No user hive | Diagnostic `windows.registry.list_autostart: no user hive is loaded; no per-user locations read` |
| No SOFTWARE or SYSTEM hive | Diagnostic; that hive's locations give no rows |
| A tree row's columns unreadable | The S25 column diagnostic per row; strict: error |
| Tree: profile neither Windows nor Linux | Run error `any.process.tree: unsupported profile os "<os>"` |
| Tree: no `SeAuditProcessCreationInfo.ImageFileName` or no `ProcessParameters` strings in the table | One diagnostic; the fields are flagged unreadable |

## 7. Result schema

### 7.1 `librarylist.DLL`

One row per loader record, in process-list order, then the order of 4.1 step 5.

| Field | Type | Meaning |
|---|---|---|
| `PID`, `ProcName`, `EPROCESS`, `DirectoryTableBase` | | The process (S25) |
| `Entry` | uint64 | Address of the loader record in the process space |
| `Base`, `BaseUnreadable`, `Size`, `SizeUnreadable` | uint64, bool, uint64, bool | `DllBase` (0 when it does not read), `SizeOfImage` |
| `Name`, `NameUnreadable` | string, bool | `BaseDllName` |
| `FullPath`, `FullPathUnreadable` | string, bool | `FullDllName` |
| `LoadCount`, `LoadCountUnreadable` | uint32, bool | `DdagNode->LoadCount`; unreadable on 32-bit rows |
| `LoadTime`, `LoadTimeUnreadable` | time.Time (UTC), bool | Zero when there is no time; unreadable on 32-bit rows |
| `Wow64` | bool | Found in the 32-bit lists |
| `InLoadOrder`, `InMemoryOrder`, `InInitializationOrder` | bool | The lists in which the record was found |

### 7.2 `registryautostart.Entry`

One row per value, in hive list order, then the location order of 4.2, then stored order.

| Field | Type | Meaning |
|---|---|---|
| `Location` | `Location` | `Run`, `RunOnce`, `RunServicesOnce`, `PolicyRun`, `Winlogon`, `AppInit`, `ImageDebugger`, `BootExecute` |
| `Wow64View` | bool | The `Wow6432Node` copy (D9) |
| `User` | bool | Read from a user hive |
| `Hive`, `HiveFile` | string | The hive's registry path and file path (S49) |
| `Key`, `KeyLastWrite` | string, time.Time | Key path inside the hive; its last write time (zero when it does not read) |
| `Image`, `ImageUnreadable` | string, bool | The Image File Execution Options subkey name |
| `ValueName`, `ValueNameUnreadable` | string, bool | As stored |
| `ValueType` | uint32 | Registry value type |
| `Data`, `DataUnreadable` | string, bool | S49 text form; a MULTI_SZ has one line per string |
| `DeferredDeletion`, `RunInSafeMode` | bool | RunOnce name prefixes `!` and `*` (D8) |

### 7.3 `processtree.Entry`

| Field | Type | Meaning |
|---|---|---|
| `PID`, `Name`, `EPROCESS`, `Columns` | | The process list row (S25); `Columns.PPID` is the recorded parent PID |
| `Depth`, `Children` | int, []*Entry | Place in the tree |
| `ParentPIDReused` | bool | The process holding the parent PID was created after this one (4.3 step 4) |
| `AuditImageName`, `AuditImageNameUnreadable` | string, bool | 4.4 step 1 |
| `ImagePathName`, `ImagePathNameUnreadable`, `CommandLine`, `CommandLineUnreadable`, `ParametersUnreadable` | string, bool | 4.4 step 2 |

`Flatten` lists a tree depth first.

## 8. Limits

- `MaxListEntries` caps each loader list (S03). The longest measured list has fewer than 400 records.
- The tree is built and flattened without recursion, so its depth needs no cap; the deepest measured chain is 7 links.
- Strings are `UNICODE_STRING`s, whose length is a USHORT; they are read in full.

## 9. Acceptance

1. Synthetic fixtures: loader lists that agree; a record cut from the load-order list but on the other two; a record only on the initialization-order list; a broken link recovered backward; an unreadable `DllBase` flagged, not dropped; unreadable names; `DdagNode` load count and `LoadTime`; a table without `DdagNode`; a WoW64 process by L1; a PEB of 0, an unreadable PEB and `Ldr` 0; the base, name and ignore-case filters; strict mode. Autostart over fake hives: each location, the RunOnce prefixes, the 32-bit view, user and `.DEFAULT` hives picked by registry path and by file name, `_Classes` hives skipped, Image File Execution Options, BootExecute from the current control set and its absence, unreadable keys and incomplete value lists with the strict error. Tree: self-parented, missing parent, reused PID, the system-process exemption, duplicate PIDs, a cycle, order, depth, the PID set, details, and Linux tasks.
2. Fuzz targets, 30 s each: `FuzzLoaderLists` (arbitrary process memory under a fixed layout: no panic, no duplicate record, no more records than the three capped walks reach, every row in at least one list), `FuzzTree` (arbitrary PID and parent pairs: no panic, every row placed once, depth consistent, no self-parented row with children) and `FuzzRunOncePrefixes` (a flag only from a leading `!` or `*`).
3. On the captures: see 9.3.
4. M12: the tree places every mem7 process present in the host snapshot under the parent the snapshot gives.

### 9.3 Tool results on the captures

From `libraryfacts -tool -v`, 2026-11-12, in the order of 3.4.

| Tool | mem1 | mem2 | mem5 | mem6 | mem7 |
|---|---|---|---|---|---|
| `windows.library.list` rows | 4,351 | 8,038 | 3,524 | 4,694 (measured before O8; M5 gives 4,695 after it) | 4,158 |
| of them WoW64 | 0 | 43 | 66 | 27 | 39 |
| of them not in load order | 0 | 0 | 0 | 0 | 2 |
| of them with `BaseDllName` unreadable | 0 | 127 | 2 | 102 | 132 |
| `windows.registry.list_autostart` rows | 8 | 11 | 8 | 8 | 6 |
| machine Run / RunOnce | 0 / 0 | 1 / 1 | 0 / 0 | 2 / 0 | 0 / 0 (Run key does not read) |
| user Run | 0 | 4 | 0 | 0 | 0 |
| Winlogon / AppInit / AppInit 32-bit / BootExecute | 2 / 3 / 2 / 1 | 2 / 3 / 0 / 0 | 2 / 3 / 2 / 1 | 2 / 3 / 0 / 1 | 2 / 3 / 0 / 1 |
| `any.process.tree` rows | 83 | 153 | 71 | 101 | 90 |
| roots | 5 | 7 | 3 | 12 | 8 |
| `ParentPIDReused` | 2 | 0 | 0 | 2 | 0 |
| deepest row | 4 | 5 | 7 | 4 | 4 |
| command line unreadable | 4 | 7 | 3 | 15 | 10 |

The library rows equal the union of M2 plus the WoW64 records of M8, with the one record of M5 whose `DllBase` does not read as a row flagged `BaseUnreadable`. mem2 has no BootExecute row because its `Select\Current` does not read (reported). The `ParentPIDReused` rows are the `csrss.exe` and `wininit.exe` (mem1) and `csrss.exe` and `winlogon.exe` (mem6) of M11; `Registry` and `Secure System` stay under `System`. On mem7 every tree row that is in the host snapshot sits under the parent the snapshot gives (M12).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Row and field names. `DLL` keeps its fields so that its callers do not change; `InLoadOrder`, `InMemoryOrder` and `InInitializationOrder` are new. `registryautostart.Entry` and `processtree.Entry` have new detail fields (`Location`, `ValueName`, `AuditImageName`, `ImagePathName`, `CommandLine`, `ParentPIDReused` and others) in place of the previous ones. | Owner decision (Q2) |
| O2 | The 32-bit loader layout L1 has no type source; it rests on Learn's declarations and M8. | A table with `_LDR_DATA_TABLE_ENTRY32`, or the 32-bit ntdll PDB |
| O3 | Load counts and load times of 32-bit records are not read: no source gives their offsets. | Same as O2 |
| O4 | The policy `Run` subkey under `Policies\Explorer` is the list key of D11 by its policy name; Learn gives the key, not the subkey, and no capture has it (M14). The `Disable...Run...` values that switch Run and RunOnce off are not applied to the rows (none exists on the captures). | A capture with the policy set |
| O5 | Locations the previous tool read and that no Learn page found here documents are not read: the Winlogon values `Taskman`, `AppSetup`, `GinaDLL`, `System`, `VmApplet`, `Ueventinit`. Also not read: `RunServices`, `RunOnceEx`, `SetupExecute`, `Execute`, startup folders, services. | Owner decision |
| O6 | The previous autostart tool dropped named values with empty data; this one returns them (`AppInit_DLLs` is empty on all five captures). | Owner decision |
| O7 | The tree exempts only the initial system process from the creation-time rule (M11). A kernel-started process other than those of M11 whose parent's `CreateTime` is late would be cut from its parent. | More captures |
| O8 | A record whose `DllBase` does not read is left out (one of 24,593 records, M5). Owner decision 2026-11-12: list with a flag. Done: 4.1 step 6, 5, 6, 7.1 (`DLL.BaseUnreadable`), 9; the record is kept with `Base` 0 and its other fields read (`tools/windows/librarylist/loader.go`, `library_list.go`, test in `s56_test.go`); M5 re-measured. Callers that read at `Base` pass such rows over: `windows.library.compare` leaves them out of its index (fuzz target extended), `windows.pe.dump` skips them with `DllBase does not read`, `windows.pe.read_version` counts them in a new diagnostic `<n> process modules passed over: DllBase does not read`; `windows.pe.list_imports`, `windows.pe.resolve_symbols` and `windows.process.dump` already pass over a `Base` of 0. S55 4.6 and S66 name the flag (S55 O12, owner decision 2026-11-12, follow-up D14). | Owner decision |
| O9 | The shared test fixture `internal/testsupport/processfixture.go` linked its loader lists by Flink only and had no `_PEB32` or `LIST_ENTRY32`; it now writes Blinks and declares both types, so that the S03 walk accepts its lists. | Reviewer check |
| O10 | A loader list link whose record container falls below 0 is skipped silently: `walkLoader` (`tools/windows/librarylist/loader.go`) adds no count and reports no diagnostic, so strict mode does not fail on it. Owner decision 2026-11-12: kept for v0.1.0; count the entry and report it in a diagnostic (strict: error) in v0.2.0. | v0.2.0 |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept |
| O2 | Defer to v0.2.0 |
| O3 | Stay unread |
| O4 | Defer to v0.2.0 |
| O5 | Stay unread |
| O6 | Return them |
| O7 | Defer to v0.2.0 |
| O8 | List with a flag |
| O9 | Schedule review now |

## 11. Provenance

Author: the project, 2026-11-12. Sources: as cited in section 3, with access dates. Measurements: `libraryfacts` on the five captures named in section 3, and the host process snapshot of mem7. Every rule rests on the sources and measurements above.
