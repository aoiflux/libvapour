# S37: Windows scheduled tasks from the registry task cache

Version 1, 2026-11-12.

## 1. Purpose

The Task Scheduler keeps a copy of every registered task in the SOFTWARE hive, under `Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`. A task's definition there survives in memory after the task's XML file is gone, and its run state tells when the task last ran and how it ended. An examiner wants, per task: where it is registered, who it runs as, what starts it, what it runs, and its last run.

The registration text is stored as plain registry strings. The principal, settings, triggers, actions and run state are stored as binary values that Microsoft does not document. This specification defines those binary layouts from the project's own measurements on the captures, cross-checked against copies of the same tasks' XML definitions found in the same captures, and names each emitted field after the documented XML task definition. A field whose meaning could not be tied to a documented property and a measurement is not emitted (section 10).

## 2. Inputs

| Input | Meaning |
|---|---|
| SOFTWARE hive | Opened through the project's `registryhive` package (`OpenHive(ctx, "SOFTWARE", nil)`). |
| `TaskCache\Tasks` | One subkey per task, named by its GUID. Values: the strings of 3.1 and the binary values `Triggers`, `Actions` and `DynamicInfo`. |
| `TaskCache\Tree` | One subkey per folder and task; a task's key holds its GUID in the string value `Id`. |
| Options | None of the tool's own. Strict mode (`strict`) as in every tool. |
| Limits | `MaxRowsPerObject` (records per binary value), `MaxRecursionDepth` (Tree depth). |

## 3. Facts from the sources

### 3.1 Documentation

| # | Fact | Source |
|---|---|---|
| D1 | The task definition has the parts RegistrationInfo, Triggers, Settings, Data, Principals and Actions. RegistrationInfo holds URI ("the path in the task store for this task"), SecurityDescriptor (SDDL), Source, Date ("the creation or modification date"), Author, Version (free text of the task owner), Description and Documentation. | [MS-TSCH] v20240423, 2.5 and 2.5.2. |
| D2 | Common trigger elements: an Id attribute, StartBoundary and EndBoundary (xs:dateTime), Enabled ("if the field is not present or the value is TRUE, the trigger is enabled"), ExecutionTimeLimit, and Repetition with Interval (1 minute to 31 days), Duration and StopAtDurationEnd. Time and calendar triggers have RandomDelay; CalendarTrigger has ScheduleByDay with DaysInterval (1 to 365) and ScheduleByWeek with WeeksInterval (1 to 52) and DaysOfWeek. EventTrigger has a Subscription, an XPath event query. LogonTrigger and SessionStateChangeTrigger have a UserId. | [MS-TSCH] 2.5.3.1 to 2.5.3.9. |
| D3 | xs:dateTime and xs:duration follow ISO 8601. | [MS-TSCH] 2.5.1.1. |
| D4 | `TASK_TRIGGER_TYPE` (mstask.h): `TASK_TIME_TRIGGER_ONCE` 0, `_DAILY` 1, `_WEEKLY` 2, `_MONTHLYDATE` 3, `_MONTHLYDOW` 4, `TASK_EVENT_TRIGGER_ON_IDLE` 5, `_AT_SYSTEMSTART` 6, `_AT_LOGON` 7. `WEEKLY` is `{ WORD WeeksInterval; WORD rgfDaysOfTheWeek; }`. | Microsoft Learn, "TASK_TRIGGER_TYPE (mstask.h)" and "WEEKLY (mstask.h)", updated 2024-02-22, accessed 2026-11-12. |
| D5 | Day-of-the-week flags: bit 0 Sunday through bit 6 Saturday. | [MS-TSCH] 2.4.2.11.3. |
| D6 | `TASK_TRIGGER_TYPE2` (taskschd.h): EVENT 0, TIME 1, DAILY 2, WEEKLY 3, MONTHLY 4, MONTHLYDOW 5, IDLE 6, REGISTRATION 7, BOOT 8, LOGON 9, SESSION_STATE_CHANGE 11, CUSTOM_TRIGGER_01 12. | Microsoft Learn, "TASK_TRIGGER_TYPE2 (taskschd.h)", updated 2024-02-22, accessed 2026-11-12. |
| D7 | `TASK_SESSION_STATE_CHANGE_TYPE`: CONSOLE_CONNECT 1, CONSOLE_DISCONNECT 2, REMOTE_CONNECT 3, REMOTE_DISCONNECT 4, SESSION_LOCK 7, SESSION_UNLOCK 8. | Microsoft Learn, "TASK_SESSION_STATE_CHANGE_TYPE (taskschd.h)", updated 2024-02-22, accessed 2026-11-12. |
| D8 | Settings: Enabled (default true), Hidden, ExecutionTimeLimit, Priority (1 to 10; 7 when absent), RestartOnFailure with Interval and Count (1 to 255). Principal: an id attribute, UserId, LogonType, DisplayName, RunLevel. Actions: a Context attribute naming a principal; Exec has Command, Arguments, WorkingDirectory; ComHandler has ClassId (a GUID) and Data. | [MS-TSCH] 2.5.4, 2.5.6, 2.5.7. |
| D9 | The task version attribute is "X.Y". | [MS-TSCH] 2.5 and 2.5.1.2. |
| D10 | A FILETIME counts 100-nanosecond intervals since January 1, 1601 (UTC). | Microsoft Learn, "FILETIME structure (minwinbase.h)", accessed 2026-11-12. |
| D11 | SID wire form: Revision (1), SubAuthorityCount, a 6-byte big-endian IdentifierAuthority, then the 32-bit sub-authorities; text form `S-1-<authority>-<sub>...`, the authority in hexadecimal when it is 2^32 or more. GUID text form `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` with the first three fields little-endian. | [MS-DTYP] 2.4.2.1, 2.4.2.2, 2.3.4. |

### 3.2 Measurements

M1 to M15 come from `taskcachefacts` (with `-xml -tool`), run on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 and mem7_server2025 (26100). The SOFTWARE hives hold 109, 141, 128, 76 and 58 task keys (512). Many cells of mem1, mem6 and mem7 are paged out: a value whose data does not read in full is "cut".

| # | Measured |
|---|---|
| M1 | `Triggers`: present in 87, 128, 128, 66, 45 keys; cut in 13, 5, 0, 2, 2; the 432 that read are 160 to 2,256 bytes (33, 41, 43, 27, 19 distinct lengths). `Actions`: present in 84, 126, 128, 66, 45; cut in 2, 1, 0, 1, 1; 42 to 564 bytes. `DynamicInfo`: present in 49, 125, 128, 66, 44; cut in 2, 1, 0, 1, 0; every one that reads is 36 bytes. |
| M2 | The `Triggers` value is a sequence of fields, each starting on an 8-byte boundary counted from the start of the record that holds it; the bytes between are filler (0x48 where the writer pads, other bytes inside copied structures) and carry nothing. The value is a header (L2) followed by trigger records (L5 to L7) back to back. Each record restarts the 8-byte count, so a record that follows a WNF record (L7) may start on any byte. All 432 values decode end to end with this layout and no bytes left over. |
| M3 | Every `Triggers` value starts with the 32-bit value 23. |
| M4 | Strings in the header and in accounts are "slotted": a 32-bit byte count in its own slot, then UTF-16LE bytes that include a terminating NUL. A trigger's Id is "packed": a 32-bit byte count immediately followed by UTF-16LE bytes without a NUL. |
| M5 | The settings block (L3) is 0 (54 values), 44 (268) or 88 (110) bytes. All 58 tasks listed under `TaskCache\Maintenance` have 88. Priority values seen: 1 to 10, and 0 only where the block is empty. |
| M6 | Record kinds, as the 16-bit value at a record's start (451 records): 0x6666 206, 0x7777 19, 0x8888 5, 0xAAAA 67, 0xCCCC 14, 0xDDDD 95, 0xEEEE 9, 0xFFFF 36. No other value occurs. |
| M7 | Task flags (L2): over the 23 XML copies of 16 tasks (M13), bit 22 is set exactly when the copy's Settings Enabled is true or absent in 22 copies (12 false, 10 true). The 23rd says true; it is the older of two copies of mem2's `Reboot_AC`, and the newer copy says false and agrees. |
| M8 | Records 0xDDDD carry a 32-bit schedule field (L6) of 0 (60 records), 1 (32) or 2 (3). Every XML TimeTrigger compared has 0 (10), the CalendarTrigger with ScheduleByDay has 1 and its DaysInterval in the next 16 bits. The three records with 2 carry 16-bit pairs (1, 0x01), (1, 0x40) and (4, 0x41). |
| M9 | Boundaries (L4): a marker byte of 0 or 1, seven filler bytes, a FILETIME. XML StartBoundary values with a zone (Z or an offset) have marker 0 and the FILETIME is that instant in UTC; values without a zone have marker 1 and the FILETIME holds the written wall-clock time. 11 boundaries compared, each within 60 s of its copy; FILETIMEs hold whole seconds where the XML gives a fraction. A FILETIME of 0 or with the top bit set marks an absent boundary. |
| M10 | `Actions` starts with a 16-bit format: 2 on 14393 (128 values), 3 on the others (316). Then a packed context string, then records back to back without filler: 0x6666 (190 records) holds packed Id, Command, Arguments and WorkingDirectory, and in format 3 two more bytes (0 in all 130); 0x7777 (256) holds a packed Id, a 16-byte GUID and packed Data. No other record kind occurs. All 444 values decode end to end. |
| M11 | `DynamicInfo`: 32-bit 3, then FILETIMEs at 4 and 12, 32-bit words at 20 and 24, a FILETIME at 28. The FILETIME at 12 is 0 in 202 values and set in 206. The word at 24 holds values such as 0x8007042B, 0x800710E0, 0x80070002, 0x1 and 0x420: HRESULTs and exit codes; it is nonzero in 22 of the 206 that ran and in 4 that did not. The word at 20 is 0 in all 408. |
| M12 | `TaskCache\Boot` and `TaskCache\Logon` list task GUIDs. Every one of the 28 Boot tasks that decodes has a 0xFFFF record, and every one of the 61 Logon tasks has a 0xAAAA record. No task listed under `TaskCache\Plain` has either. |
| M13 | Physical memory holds UTF-16 task XML: 57 copies over the five captures; 15 are damaged and do not parse, 19 name no task key that reads. The other 23 copies of 16 tasks agree with the decoded values on: principal id (23 of 23), principal UserId given as a SID (23), action context (23), action count (23), Exec command and arguments (21), ComHandler ClassId (2), task version attribute against `Schema` (20), ExecutionTimeLimit (10), Priority (9), RestartOnFailure (3), trigger kind (Time 10, WnfStateChange 5, CalendarTrigger 1, EventTrigger 1), trigger Enabled (17), StartBoundary zone form and time (11), Repetition Interval (4) and Duration (1), RandomDelay (3), DaysInterval (1), WNF StateName (5) and Data (5), event Subscription (1). Task flag bits 4, 5, 6, 9, 23 and 30 agree in all 23 copies with DisallowStartIfOnBatteries (6 false, 17 true), StopIfGoingOnBatteries (7, 16), StartWhenAvailable (6, 17), WakeToRun (21, 2), Hidden (22, 1) and AllowHardTerminate (1 false, 22 true). |
| M14 | Every task whose `Path` value and `Tree` path both read has them equal: 57, 48, 128, 24 and 16 tasks; none differ. |
| M15 | The script's own walk of L2 to L8, written apart from the tool, ends exactly at the end of all 432 `Triggers` values. It counts the fields of section 10: the second header string is empty in all 432; the event-driven words at +0x28, +0x2C and +0x30 (356 records), the timed words at +0x28, +0x40 and +0x50 (95 records), the settings words +0x0C and +0x1C, the format-3 Exec bytes, the `DynamicInfo` word at 20, and the account class words. |

### 3.3 Layouts

Offsets are from the start of the record (the value for L2 and L8 to L9). "Slot" means a field padded to the next 8-byte boundary (M2).

| # | Layout |
|---|---|
| L1 | Slot rules of M2 and M4. |
| L2 | Trigger set header: slot format (M3); boundary at 0x08 and at 0x18 (L4; not emitted, O4); slot task flags (bit 22 Enabled, M7); slot 32-bit word (not emitted); slotted principal id; slotted string, empty in all 432 (not emitted, O5); account (L3a); slotted settings block (L3). |
| L3a | Account: slot byte, 1 for no account (nothing follows) or 0; slot byte; slot 32-bit class (not emitted, O6); slotted SID bytes (D11); slotted account name. |
| L3 | Settings block, 32-bit little-endian words: +0x08 ExecutionTimeLimit seconds, +0x10 Priority, +0x14 RestartOnFailure Interval seconds, +0x18 RestartOnFailure Count. 0xFFFFFFFF is an absent duration. Words +0x00, +0x04, +0x0C, the 16 bytes at +0x1C and the second 44 bytes of an 88-byte block are not emitted (O7). |
| L4 | Boundary: 16 bytes, marker byte 0 or 1 at +0, FILETIME at +8 (M9). |
| L5 | Event-driven record (kinds other than 0xDDDD): slot kind; start boundary +0x08; end boundary +0x18; 24 bytes not emitted (O8); 16 bytes whose first byte is Enabled (0 or 1); packed Id at +0x50; then the kind's tail: 0x6666 L7; 0x7777 a 32-bit session state change (D7) in an 8-byte field, then an account (L3a); 0xAAAA an account (L3a); 0xCCCC a 64-bit character count, the UTF-16 subscription, a 16-bit NUL, filler to the slot, and 24 bytes that are zero in all 14 records; 0x8888, 0xEEEE and 0xFFFF nothing. |
| L6 | Timed record (0xDDDD): slot kind; boundaries at +0x08 and +0x18; 16 bytes, zero in all 95 (not emitted); at +0x38 32-bit Repetition Interval and Duration seconds; +0x40 32-bit word not emitted (O9); +0x44 schedule (D4, M8); +0x48 8 bytes of schedule data (DAILY: 16-bit DaysInterval; WEEKLY: 16-bit WeeksInterval and 16-bit days, D4, D5); +0x50 8 bytes whose second byte is Enabled (the first is 0 in all 95, O10); +0x58 32-bit RandomDelay seconds; packed Id at +0x60. |
| L7 | WNF tail: 8-byte state name in the slot after the Id (+0x58 when the Id is empty); 32-bit data length; 4 filler bytes; the data bytes, with no filler after them. |
| L8 | Actions value of M10. |
| L9 | DynamicInfo value of M11: emitted are the FILETIME at 12 and the word at 24. |

## 4. Algorithm

1. Open `TaskCache\Tasks`. A failure fails the run (6).
2. Walk `TaskCache\Tree` from its root, depth-first, each key once by cell. A key with a readable string `Id` maps that GUID (case folded) to the key's path below Tree, with a leading backslash.
3. For each subkey of `Tasks`, one row:
   1. `GUID` is the key name; `KeyLastWrite` the key's last write time (D10).
   2. The REG_SZ values of D1 that read in full are copied: `Path`, `URI`, `Author`, `Description`, `Date`, `Source`, `Version`, `Documentation`, `SecurityDescriptor`. The REG_DWORD `Schema` gives `SchemaVersion` as "high word.low word" (D9, M13).
   3. `TreePath` is the path step 2 found for the GUID.
   4. `Triggers` is decoded by L2 to L7: header, then records until the value ends. The task's `Enabled`, `Principal`, `Settings` and `Triggers` come from it.
   5. `Actions` is decoded by L8: `ActionContext` and `Actions`.
   6. `DynamicInfo` is decoded by L9: `LastRunTime` and `LastTaskResult`.
4. Kinds. Record 0xDDDD takes its kind from the schedule: 0 Time, 1 Daily, 2 Weekly (D4, D6, M8). 0x6666 is WnfStateChange (M13), 0xCCCC Event (M13), 0xFFFF Boot (M12), 0xAAAA Logon (M12), 0x7777 SessionStateChange (D7: every state value seen is a documented one, and Ids such as `LocalConsoleConnectTrigger` sit with value 1). 0x8888 and 0xEEEE, and schedules other than 0 to 2, have no kind (O1, O2).
5. Rows are sorted by `Path` (else `TreePath`), case folded, then by `GUID`.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Triggers format 23 | M3 | `ErrFormat`; state undecoded |
| Actions format 2 or 3 | M10 | `ErrFormat`; state undecoded |
| DynamicInfo 36 bytes of format 3 | M1, M11 | `ErrFormat`; state undecoded |
| Every field inside the value | M2 | `ErrTruncated` |
| Strings of even length | M4 | `ErrField` |
| SID of revision 1 and length 8 + 4 × count | D11 | `ErrField` |
| Settings block 0, 44 or 88 bytes | M5 | `ErrField` |
| Account marker, boundary marker and Enabled byte 0 or 1 | M9, L3a, L5, L6 | `ErrField` |
| Days of the week only in bits 0 to 6 | D5 | `ErrField` |
| Event record tail zero and subscription NUL-terminated | L5 | `ErrField` |
| Record kind in M6 (triggers) or M10 (actions) | M6, M10 | `ErrRecordKind` |
| At most `MaxRowsPerObject` records per value | 8 | `ErrLimit` |

A failure inside a record keeps the header and the records before it: the value is "partial". A failure before the first record leaves it "undecoded", with nothing from it emitted.

## 6. Failure modes

| Case | Result |
|---|---|
| Profile not Windows | Run error `windows.task.list: unsupported profile os "<os>"` |
| No SOFTWARE hive | Run error `windows.task.list: SOFTWARE hive: ...` |
| `Tasks` key missing or unreadable | Run error `windows.task.list: task cache Tasks key: ...` |
| `Tasks` subkey list incomplete | Diagnostic `windows.task.list: task cache Tasks key at 0x<addr>: subkey list not read in full: tasklist: task cache not read in full`; `ErrIncomplete` in strict mode |
| `Tree` incomplete or unreadable | Diagnostic `windows.task.list: task cache Tree key not read in full; some tasks have no tree path`; `ErrIncomplete` in strict mode |
| A value cut, or missing from an incomplete value list | Its state is `unreadable` and its name is in `UnreadableValues` |
| A value that fails section 5 | State `partial` or `undecoded`; diagnostic `windows.task.list: task key <GUID> at 0x<addr>: <value> value decoded in part: <error>` or `... not decoded: <error>`; in strict mode the run returns all rows and the first such error |

## 7. Result schema

One `tasklist.Task` per task key:

| Field | Type | Meaning |
|---|---|---|
| `GUID`, `GUIDUnreadable` | string, bool | Key name; whether it did not read |
| `KeyLastWrite` | time.Time (UTC) | Task key last write; zero when it did not read |
| `Path`, `TreePath` | string | `Path` value; path from Tree |
| `URI`, `Author`, `Description`, `Date`, `Source`, `Version`, `Documentation`, `SecurityDescriptor` | string | RegistrationInfo strings (D1), verbatim |
| `SchemaVersion` | string | "X.Y" |
| `Enabled` | *bool | Task flag bit 22; nil when the Triggers header did not decode |
| `Principal` | `ID`, `UserID` (SID string), `UserName` | L2, L3a |
| `Settings` | `ExecutionTimeLimit`, `RestartInterval` (xs:duration, "" absent), `Priority` (0 absent), `RestartCount` | L3 |
| `Triggers` | []`Trigger` | Record order |
| `ActionContext`, `Actions` | string, []`Action` | L8 |
| `LastRunTime` | time.Time (UTC) | Zero when the task never ran |
| `LastTaskResult` | uint32 | Valid when `DynamicInfoState` is decoded |
| `TriggersState`, `ActionsState`, `DynamicInfoState` | `decoded`, `absent`, `unreadable`, `partial`, `undecoded` | Section 6 |
| `UnreadableValues` | []string | Value names that did not read |

`Trigger`: `Kind` (`Event`, `Time`, `Daily`, `Weekly`, `Boot`, `Logon`, `SessionStateChange`, `WnfStateChange`, or empty), `Record` (the stored kind value), `ID`, `Enabled`, `Start`/`End` (time.Time, zero when absent) with `StartLocal`/`EndLocal` (true: the time is wall-clock time with no zone, M9), `RepetitionInterval`, `RepetitionDuration` and `RandomDelay` (xs:duration; "" when the interval or delay is 0), `DaysInterval`, `WeeksInterval`, `DaysOfWeek` (day names), `StateChange` (D7 names), `UserID`, `UserName`, `Subscription`, `StateName` and `StateData` (upper-case hex of the stored bytes).

`Action`: `Kind` (`Exec` or `ComHandler`), `Record`, `ID`, `Command`, `Arguments`, `WorkingDirectory`, `ClassID` (D11 text form), `Data`.

The decoders `DecodeTriggers`, `DecodeActions` and `DecodeDynamicInfo` are exported, so that the measurement script and other callers decode a value the same way.

## 8. Limits

- `MaxRowsPerObject`: records per `Triggers` or `Actions` value. The most seen is 6 trigger records and 3 actions in one value; the default is far above.
- `MaxRecursionDepth`: Tree depth. Registry folders are a few levels deep.
- The value data itself is bounded by `registryhive` (`MaxBufferBytes`).

## 9. Acceptance

1. Synthetic fixtures (`tools/windows/tasklist/s37_fixture_test.go`, from L2 to L9; tests in `triggerset_test.go`, `actionset_test.go` and `task_list_test.go`): every record kind of M6 with its tail, both settings lengths, an empty settings block, every refusal of section 5, the record limit, both Actions formats, both action kinds, DynamicInfo with and without a run; the tool over a fake hive with a Tree path, registration strings, `Schema`, unreadable and incomplete values, an undecodable value of each kind with its diagnostic, the strict-mode error, a missing Tasks key, a Tree cycle and the sort order.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzDecodeTriggers` (no panic; no more records than the limit; every returned record of a kind in M6; tied kinds always named; no local marker on an absent boundary; only package errors) 3.30 million executions; `FuzzDecodeActions` 3.26 million; `FuzzDecodeDynamicInfo` 3.07 million.
3. On the captures (M1 to M15): 432 of 432 `Triggers`, 444 of 444 `Actions` and 408 of 408 `DynamicInfo` values that read decode whole; none is partial or undecoded. The tool returns 109, 141, 128, 76 and 58 rows with no run error.
4. The XML cross-checks of M13 all agree, apart from the one older copy of M7.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Record kinds 0x8888 (5 records) and 0xEEEE (9) decode by L5 but have no kind. 0xEEEE sits with tasks under `TaskCache\Maintenance` and with an Id `SyncThemeFODStateOnIdle`; it may be IdleTrigger, and 0x8888 RegistrationTrigger. No XML copy of either was found. | A capture holding XML of a task with an IdleTrigger or RegistrationTrigger |
| O2 | Schedules 3 and 4 (`MONTHLYDATE`, `MONTHLYDOW`) were not seen; such records decode with no kind and no schedule data. | A capture with a monthly task |
| O3 | Action kinds other than 0x6666 and 0x7777 (SendEmail, ShowMessage) were not seen and are refused. | A capture with such an action |
| O4 | The header's two boundaries behave as the earliest start and latest end over the task's triggers (an empty task has the maximum then 0); no document states it, so they are not emitted. | Owner decision |
| O5 | The second header string is empty in all 432 values; by position it may be the principal DisplayName (D8). Not emitted. | A task with a DisplayName |
| O6 | The principal's account class word is 5 for 393 accounts (all well-known SIDs), 4 for 33 (all `S-1-5-32-…`), 1 for 2 and 8 for 4 (all `S-1-5-21-…`); trigger accounts have 1 and 8 once each. LogonType and RunLevel were not located. Not emitted. | More XML copies with each LogonType and RunLevel |
| O7 | Settings words not emitted: +0x00 and +0x04 sit where IdleSettings Duration and WaitTimeout would be by order, and were not compared; +0x0C is 0xFFFFFFFF in all 378 blocks (DeleteExpiredTaskAfter by order); the 16 bytes at +0x1C are zero in all 378 (a NetworkSettings Id by order); the second half of the 88-byte blocks (58 Maintenance tasks and 52 others) may hold MaintenanceSettings. The task flag bits of M13 are not emitted: they rest on 16 tasks, and Hidden (bit 23) and AllowHardTerminate (bit 30) change together in the one copy where either differs from its default, so the two are not separated. | Owner decision on emitting the measured flag bits |
| O8 | In event-driven records the first word at +0x28 is nonzero in 93 of 356 records (300 in a mem1 boot trigger); by position it may be Delay; the second is 0xFFFFFFFF except 300 and 1800 once each; the word at +0x30 is nonzero in 15. No XML copy of an event-driven trigger has a Delay, ExecutionTimeLimit or Repetition, so none is emitted. | A capture holding XML of a boot or logon trigger with a Delay |
| O9 | The timed record's word at +0x40 is 0xFFFFFFFF in 92 records and 300 or 14400 in 3; by position it may be the trigger's ExecutionTimeLimit. Not emitted. | XML of a time trigger with an ExecutionTimeLimit |
| O10 | StopAtDurationEnd: the first byte at +0x50 of timed records is 0 in all 95, and the one XML copy that states it says false. Not emitted. | XML with StopAtDurationEnd true |
| O11 | `DynamicInfo` FILETIMEs at 4 and 28 are not emitted. The one at 4 equals the key's last write in 175 of 202 tasks that never ran, and on mem6 and mem7 equals a common time near the capture for most tasks; the one at 28 is at or after the last run for most tasks that succeeded, and earlier for some that failed. Neither matches a documented property. | Owner decision |
| O12 | The `Hash` value (32 bytes), the Tree values `Index` and `SD`, the task key value `Data` (one task) and the format-3 two bytes after an Exec record are not emitted. Tree entries whose GUID has no task key produce no row. | Owner decision |
| O13 | A boundary with marker 1 is wall-clock time without a zone (`StartLocal`); it is not converted to UTC, because the machine's time zone is outside this tool. | Owner decision (Q2 contract says UTC) |
| O14 | Row and field names are new (`Task` replaces `Entry`; one row per task with nested triggers and actions instead of one row per action and trigger). | Owner decision (Q2) |
| O15 | The kind name `WnfStateChange` comes from the element name in the captures' own XML; no published document lists that trigger. | Owner decision |
| O16 | Follow-up R2: with O14 a trigger is fields, not text: `Kind`, `UserID`, `UserName`, `StateChange`, `StateName` and `Subscription` hold what a one-line trigger description would say, and the tool renders no such line. Owner decision 2026-11-12: keep the fields; no row field changed. | Closed |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Leave without a kind |
| O2 | Defer; decode with no kind |
| O3 | Keep refusing |
| O4 | Do not emit |
| O5 | Do not emit |
| O6 | Do not emit |
| O7 | Do not emit |
| O8 | Do not emit |
| O9 | Do not emit |
| O10 | Do not emit |
| O11 | Do not emit |
| O12 | Do not emit |
| O13 | Keep StartLocal, not converted |
| O14 | Accept the new rows |
| O15 | Keep WnfStateChange |

## 11. Provenance

Author: the project, 2026-11-12. Sources: [MS-TSCH] v20240423 (PDF from the Microsoft Open Specifications site, accessed 2026-11-12); [MS-DTYP]; the Microsoft Learn pages cited in 3.1, accessed 2026-11-12; the project's measurements with `taskcachefacts` on the five captures named in 3.2, including task XML found in those captures' physical memory. Every rule rests on the sources and measurements above.
