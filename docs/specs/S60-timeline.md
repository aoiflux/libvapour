# S60: Timeline of dated events from other tools' rows

Version 1, 2026-11-12.

## 1. Purpose

Many tools report a time with each row: when a process or thread was created or exited, when a library was loaded, when a socket was created, when a file record was written, when a program was launched through the shell, when a shell command was entered. Each tool reports its own rows in its own order. An examiner reconstructing what happened wants all of these times on one line in time order, with each time tied to the tool, the row field it came from and the object it belongs to, and wants the same list in a plain text form that other timeline programs can merge with file-system times.

`any.timeline.list` runs a fixed set of source tools for the image's operating system, turns every present time of every row into one dated entry, and returns the entries in time order. On request it also writes the entries as a body file (section 7.2). It reads no memory of its own: every fact comes from the source tools' rows as their specifications define them.

## 2. Inputs

| Input | Use |
|---|---|
| Profile | `OS()` selects the source table (section 3.2): `windows` or `linux`, case folded. Any other value is a run error. |
| Source tools | Run through `tools.Execute` by their registered names (section 3.2). Their rows are read through the exported row types of their packages, as their specifications define them. |
| Options | `any.timeline.list.tool_filter` (list of strings; the option reader trims each word and drops empty ones): run only the sources whose tool name contains at least one of the words. `any.timeline.list.create_bodyfile` (bool): also write the body file. `any.timeline.list.record_config` (bool): refused when true (O1). `output_dir`: the body file directory. `max_dump_size`: through `tools.Context.DumpLimit`. `strict` and `diagnostics` as for every tool. A value of the wrong type is an error wrapping `tools.ErrOptionType` (owner decision 2026-11-03). |
| `pid` | Not applied (4 step 2, O7). |
| Limits | `NameAttempts` (body file name collisions, through `extract.CreateUnique`), `MaxArtifactBytes` (body file size, through `DumpLimit`). Every other bound is a source tool's own. |

## 3. Facts from the sources

### 3.1 Documents

All accessed 2026-11-12.

| # | Fact | Source |
|---|---|---|
| D1 | Seconds since the Epoch: a UTC time name with integer `tm_sec`, `tm_min`, `tm_hour`, `tm_yday`, `tm_year` relates to seconds by `tm_sec + tm_min*60 + tm_hour*3600 + tm_yday*86400 + (tm_year-70)*31536000 + ((tm_year-69)/4)*86400 - ((tm_year-1)/100)*86400 + ((tm_year+299)/400)*86400`; every day is exactly 86400 seconds. "If the year is <1970 or the value is negative, the relationship is undefined." | POSIX.1-2024 (IEEE Std 1003.1-2024), Base Definitions 4.19 |
| D2 | `struct stat` carries three times: `st_atim` "Last data access timestamp", `st_mtim` "Last data modification timestamp", `st_ctim` "Last file status change timestamp"; "Times shall be given in seconds since the Epoch." | POSIX.1-2024, Base Definitions `<sys/stat.h>` |
| D3 | `FILE_BASIC_INFORMATION` carries four times: `CreationTime` "the time that the file was created", `LastAccessTime`, `LastWriteTime` "the time that the file was last written to", `ChangeTime` "the last time the file was changed"; all in 100-nanosecond intervals since 1601. | Microsoft Learn, "FILE_BASIC_INFORMATION structure (wdm.h)", ms.date 2021-05-18 |
| D4 | `date-time = full-date "T" full-time`, `full-time = partial-time time-offset`, `time-offset = "Z" / time-numoffset`, `time-secfrac = "." 1*DIGIT`. A date-time without an offset is not an Internet date-time. | RFC 3339, section 5.6 |
| D5 | UTF-8 encodes U+0000 to U+007F as one byte equal to the code point; bytes C0, C1 and F5 to FF never appear; a valid sequence is defined by the table of section 4. | RFC 3629, sections 1, 3 and 4 |

The body file follows a line format that timeline programs commonly read: one line per entry, eleven fields separated by `|`, the last four being times in seconds since the Epoch. No OS-level or standards document defines that line. Section 7.2 defines it from D1 to D3 and the field list there, and the choice is O2.

### 3.2 Source tools

The row fields read, the event class each time field gives, the subject text and the address fields. "Absent when" lists the source's own absent rule for that field (section 5). The specification named is the one that defines the field; a source with no specification yet is read by its current exported row type.

Windows (`windows`), run in this order:

| Tool | Row | Field: event | Absent when | Subject | Address / Physical |
|---|---|---|---|---|---|
| `any.process.list` (S25) | `processlist.Process` | `CreateTime`: `created`; `ExitTime`: `exited` | zero, or `CreateTimeUnreadable` / `ExitTimeUnreadable` | `process <Name> pid <PID>` (`process pid <PID>` when the name is empty) | `EPROCESS` / 0 |
| `any.process.scan` (S26) | `processscan.Process` | as above | as above | as above | `VirtualOffset` / `Offset` |
| `windows.thread.list` (S50) | `threadlist.Thread` | `CreateTime`: `created`; `ExitTime`: `exited` | zero, or the `…Unreadable` flag | `thread tid <TID> pid <PID>` and the process name when known | `ETHREAD` / 0 |
| `windows.thread.scan` (S50) | `threadscan.Thread` | as above | as above | `thread tid <TID> pid <PID>` | `VirtualOffset` / `Offset` |
| `windows.thread.find_orphaned` (S51) | `threadscan.Thread` | as above | as above | as above | as above |
| `windows.library.list` (S56) | `librarylist.DLL` | `LoadTime`: `loaded` | zero, or `LoadTimeUnreadable` | `library <FullPath, else Name, else "unnamed library"> in process <ProcName> pid <PID>` | `Base` / 0 |
| `windows.session.list` (S69) | `sessionlist.Row` | `CreateTime`: `created` | zero (the S25 column; an unreadable time is zero) | `process <Process> pid <PID>[ of <UserName>] in session <SessionID>` | `EPROCESS` / 0 |
| `windows.network.list` (S28) | `network.Endpoint` | `CreateTime`: `created` | zero (`TimeProblem` set) | `<Kind> <Family> <local address:port>`, then ` to <remote address:port> <State>` for a connection or ` listening` for a listener, then ` owned by process <OwnerImage> pid <OwningPID>` when `OwnerProblem` is empty; an unread address is written `unread:<port>` | `ObjectAddress` / `ObjectPhysical` |
| `windows.network.scan` (S28) | `network.Endpoint` | as above | as above | as above | as above |
| `windows.object.scan_links` (S69) | `objectlinks.Symlink` | `CreateTime`: `created` | zero, or `CreateTimeUnreadable` | `symbolic link <Name> to <Target>`; a callback link's target is `callback 0x<CallbackRoutine>`; an unread name is `unread name`, an unread target `unread target` | `VirtualOffset` / `Offset` |
| `windows.module.list_unloaded` (S64) | `moduleunloaded.Module` | `Time`: `unloaded`, on either clock (S64 4.8 step 6: an interrupt-time value is placed at boot plus the value) | zero (`Clock` `unknown`, or the shared times do not read) | `kernel module <Name>`; an unread or empty name is `with unread name` | `StartAddress` / 0 |
| `windows.task.list` (S37) | `tasklist.Task` | `LastRunTime`: `ran`; `KeyLastWrite`: `written` | zero | `scheduled task <Path, else TreePath, else GUID, else "unnamed">` | 0 / 0 |
| `windows.execution.list_compat_cache` (S41) | `executioncompatcachememory.CacheEntry` | `FileLastWrite`: `modified` | zero | `compat cache entry <Key>`; an unread or empty key is `with unread key` | `Address` / 0 |
| `windows.execution.read_userassist` (S44) | `executionuserassist.CountValue` | `LastLaunch`: `launched`; `CountKeyLastWrite`: `written`, once per (`HiveAddress`, `Key`) | zero | `UserAssist <ExpandedName> at <Key>, count <LaunchCount>` (`unread name` for an unread or empty name; S44 O10); for the key, `UserAssist key <Key>` | 0 / 0; the key: `HiveAddress` / 0 |
| `windows.execution.read_amcache` (S63 T10) | `executionamcache.InventoryRecord` | `KeyLastWrite`: `written`; `LinkTime`: `linked`. The zoneless text `LinkDate` and `InstallDate` give no entry (D4, S63 O8) | zero | `amcache <Category>[ <Path>, else <Name>][ program <ProgramID>]` (M4) | `HiveAddress` / 0 |
| `windows.ntfs.scan_records` (S42) | `ntfsrecord.Row` | `CreationTime`: `created`; `LastWriteTime`: `modified`; `ChangeTime`: `changed`; `LastAccessTime`: `accessed` (D3) | zero | `<AttributeType> of <Name, else "unnamed file">[ in record <SegmentNumber>]`, then for `$FILE_NAME` ` under directory record <ParentSegmentNumber>` (hard links repeat one name in one record, M4) | 0 / `RecordPhysical` |

Linux (`linux`), run in this order:

| Tool | Row | Field: event | Absent when | Subject | Address / Physical |
|---|---|---|---|---|---|
| `any.process.list` (S14, S25), with `any.process.list.threads` true | `processlist.Process`, `Linux` columns | `CreationTime`: `created` | `Linux.Read` false, or `CreationTimeErr` set | `task <Comm> pid <PID>`; a thread: `thread <Comm> tid <TID> pid <PID>`; unread: `task pid <PID>` | `EPROCESS` / 0 |
| `linux.boot.read_time` (S46) | `boottime.Row` | `BootTime`: `booted` | zero (never in a row, S46) | `boot`, or `boot of time namespace <Namespace>` | `NamespaceAddress` / 0 |
| `linux.shell.read_history` (S15c) | `shellhistory.Command` | `CommandTime`: `entered` | `CommandTimeOK` false | `<Process> pid <PID> history entry <Index>: <Command>` | `EntryAddress` (user space) / 0 |
| `linux.file.list_open` (S39) | `fileopen.File` | `Accessed`: `accessed`; `Modified`: `modified`; `Changed`: `changed` (D2) | `InodeOK` false, or the field's `…OK` false | `<Path, else "unnamed file"> open as fd <FD> by <Process> pid <PID> tid <TID>` | 0 / 0 |
| `linux.pagecache.list_files` (S12) | `pagecache.File` | as above (D2) | the field's `…OK` false | `cached inode <InodeNumber> <Path, else "unnamed">` | `InodeAddress` / 0 |

### 3.3 Measurements

M1 to M6 come from `timelinefacts`, run on 2026-11-12 over the seven captures. Capture times are `_KUSER_SHARED_DATA.SystemTime` (Windows, through `windows.kernel.read_info`) and the timekeeper's last update (Linux, `linuxobj.BootClock.Updated`, S46).

Capture times: mem1_win11 2026-05-06T18:24:25Z, mem2_win10 2026-05-26T20:50:39Z, mem5_server2016 2026-01-30T08:27:03Z, mem6_server2025 2026-09-27T19:18:15Z, mem7_server2025 2026-10-29T19:09:32Z, mem3_ubuntu24 2026-08-22T13:28:13Z, mem4_fedora40 2026-08-22T13:59:46Z.

| # | Measured |
|---|---|
| M1 | Rows / entries / absent times per Windows source, mem1, mem2, mem5, mem6, mem7: `any.process.list` 83/87/79, 153/157/149, 71/74/68, 101/109/93, 90/99/81; `any.process.scan` 88/95/81, 163/177/149, 71/74/68, 100/108/92, 104/115/93; `windows.thread.list` 1,123/1,219/1,027, 1,974/2,133/1,815, 1,303/1,321/1,285, 1,298/1,457/1,139, 1,210/1,346/1,074; `windows.thread.scan` 2,216/3,374/1,058, 2,294/2,734/1,854, 1,326/1,351/1,301, 1,345/1,544/1,146, 1,441/1,639/1,243; `windows.thread.find_orphaned` 0 rows on all five; `windows.library.list` 4,351/4,351/0, 8,038/7,995/43, 3,524/3,458/66, 4,695/4,666/29, 4,158/4,117/41 (mem6 includes the row flagged for an unread `DllBase`, S56 O8); `windows.session.list` 83/83/0, 153/153/0, 71/71/0, 101/101/0, 90/90/0; `windows.network.list` 43/43/0, 54/54/0, failed on mem5 (the measured layout has no endpoint tables for 14393, S28), 44/44/0, 61/61/0; `windows.network.scan` 68/68/0, 66/66/0, 62/62/0, 51/51/0, 76/76/0; `windows.object.scan_links` 231/231/0, 315/312/3, 190/190/0, 211/211/0, 234/234/0; `windows.module.list_unloaded` 8/8/0, 9/9/0, 9/9/0, 20/20/0, 13/13/0 (on mem1, mem6 and mem7 the interrupt clock, placed at boot plus the value, S64 4.8 step 6); `windows.task.list` 109/121/97, 141/225/57, 128/201/55, 76/100/52, 58/71/45; `windows.execution.list_compat_cache` 140/89/51, 811/549/262, 256/241/15, 237/171/66, 272/199/73; `windows.execution.read_userassist` 13/5/10, 68/47/23, 58/39/21, 22/12/12, 24/16/10; `windows.execution.read_amcache` failed on mem1 and mem7 (no Amcache hive opens), 1,263/1,642/884, 372/662/82, 670/1,050/290 (`KeyLastWrite` on every row, `LinkTime` on the 379, 290 and 380 `driver_binary` rows); `windows.ntfs.scan_records` 72,823/291,292/0, 98,952/395,795/13, 65,815/263,260/0, 33,520/134,080/0, 41,540/166,160/0. Totals: 301,066, 412,048, 271,013, 143,724 and 174,236 entries. Re-measured 2026-11-12 with `timelinefacts` after S60 O6. |
| M2 | Linux, mem3 and mem4: `any.process.list` with threads 557/557/0 and 573/573/0; `linux.boot.read_time` 1/1/0 each (boot 2026-08-22T13:26:36Z and 13:51:04Z); `linux.shell.read_history` 0 rows each; `linux.file.list_open` 8,530/25,590/0 and 8,865/26,595/0; `linux.pagecache.list_files` 24,231/72,693/0 and 23,753/71,259/0. Totals 98,841 and 98,428 entries. Times in the first second of 1970: `linux.file.list_open` 10,809 and 10,875, `linux.pagecache.list_files` 105 and 187, all exactly 1970-01-01T00:00:00Z (inode times the kernel left at 0, for example `socket:[10036]`); none on Windows. |
| M3 | Times before 1970: `windows.thread.list` and `windows.thread.scan` 5 each on mem6 and mem7 (the first system threads, 1601-01-01T00:00:00.15Z: created before the system time was set), `windows.ntfs.scan_records` 2 on mem2 (1601-01-01), `windows.object.scan_links` 1 on mem5 (1601-06-12, a stale object); none elsewhere. Times after the capture time, per capture: threads up to 30 s after (mem1 14 listed, 68 scanned), sockets and links up to 3 s except 2 stale links on mem5 (up to the year 27950), libraries up to 12 on mem6 and 15 on mem5, compat cache 13 on mem6 (up to 2026-09-28T00:27:28Z, 5 h after), amcache 199 on mem2 and 176 on mem6 (`LinkTime` up to 2106-02-04, near 2^32 seconds), NTFS 116, 34, 96, 172 and 232 (up to the years 24222, 60056 and 37855). Times after the capture are the sources' data; they are kept (section 5). |
| M4 | Order: every result is sorted by `Compare` (checked pairwise); 5 of 5 shuffled copies re-sort to the identical result on all seven captures; a second run on mem6, mem7, mem3 and mem4 gives an identical result. Adjacent pairs sharing a time: 242,076, 377,064, 261,688, 125,628, 152,675 (Windows, re-measured 2026-11-12 after O6), 84,129 and 82,259. Adjacent pairs equal in every field: 0 on all five Windows captures (the 4 on mem5 were amcache `Program` entries, which S63 T10 no longer lists). Before `$FILE_NAME` subjects named the directory, mem6 had 11,165 such pairs from hard links; before amcache subjects named the program identifier, mem2 had 3 and mem5 29. |
| M5 | Body file lines / bytes / entries not written: mem1 301,058 / 60,584,943 / 0; mem2 412,047 / 76,540,662 / 2; mem5 271,233 / 45,617,139 / 0; mem6 143,694 / 24,650,681 / 10; mem7 174,213 / 29,628,068 / 10; mem3 87,927 / 13,174,782 / 10,914; mem4 87,366 / 13,513,115 / 11,062. Entries not written are those of M2 and M3 before 1970 or in its first second. |
| M6 | Run time of `Collect`, one capture at a time: mem1 84 s (process scan 33 s, thread scan 13 s, orphaned threads 12 s, network scan 9 s), mem2 30 s, mem5 30 s, mem6 16 s; with three captures measured in parallel, mem7 25 s, mem3 4.3 s, mem4 7.3 s. The process list is walked once per run and shared by the sources that need it (4 step 2). |

## 4. Algorithm

1. Read the options (section 2). Refuse `record_config` true, `create_bodyfile` without `output_dir`, and a profile OS other than Windows or Linux, before any source runs. Choose the sources of section 3.2 for the OS; with filter words, keep a source when its tool name contains at least one word, in table order. A word that is empty or matches no source of the OS is an error naming the OS's sources.
2. Build the source context once: the caller's context without the `pid` option and without the timeline's own three options; every other option, the diagnostics sink and the tool result caches are shared, so a tool that several sources need (the process list) is walked once. With a `pid` option set, add one diagnostic that it was not applied.
3. For each chosen source, in table order: apply the source's own overrides on a copy of the source context (only the Linux process list has one, `threads` true, so that thread creation times are included); run the tool through `tools.Execute`; check that the result is a slice of the row type of 3.2, else `ErrRowType`.
4. For each row, for each time field of 3.2: when the field is absent (section 5) count it and give no entry. Otherwise give one entry: the time converted to UTC, the event of 3.2, the tool name, the field name, the subject and the addresses. No source gives a time as text: a text without a time offset is not an Internet date-time (D4) and cannot be placed in UTC.
5. Record per source: rows, entries, absent times, entries before 1970 (D1), run time and failure.
6. Sort all entries by time, then tool name, field name, subject, address, physical address and event, with a stable sort, so that entries equal in every field keep the order their sources gave them (M4).
7. With `create_bodyfile`, write the sorted entries as a body file (section 7.2) into `output_dir` under the name `timeline.body` (`BodyfileName`), or `timeline-<n>.body` when that name exists (S00 failure modes). The name does not follow the S00 scheme: the body file is a text export, not recovered evidence (S00 section 1, owner decision 2026-11-12). Then add one diagnostic with the file name, the lines written and the entries left out.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| A time that is zero, or that its source flags as unreadable or not present, is absent. | Each source specification's own absent rule (3.2); a zero `time.Time` is the absent value of the result contract. | No entry; counted in `Absent`. |
| A time without a time offset is not placed. | D4; the amcache `LinkDate` and `InstallDate` texts carry no zone (S63 O8). | Not read; no entry. |
| A time before 1970-01-01T00:00:00Z is kept in the entries but not written to the body file. | D1: seconds since the Epoch are undefined before 1970. | Entry kept; counted in `BeforeEpoch`; left out of the body file and counted in its diagnostic. |
| A time in the first second of 1970 is kept in the entries but not written to the body file. | Its seconds value is 0, which the body file uses for "no time" (7.2); on the captures such times are unset inode times (M2). | Entry kept; left out of the body file and counted in its diagnostic. |
| The timeline does not judge a time against the capture time. | A time after the capture is a property of the source's data (a skewed clock, a carved stale object), not of the timeline; M3 reports how often it occurs. | None. |
| Every source row type is the one of 3.2. | The timeline reads fields by type. | `ErrRowType`: the source fails (section 6). |

## 6. Failure modes

| Case | Result |
|---|---|
| Option of the wrong type | Run error wrapping `tools.ErrOptionType` |
| `record_config` true | Run error `any.timeline.list: timeline: recording the run configuration is not supported` (`ErrRecordConfig`) |
| `create_bodyfile` without `output_dir` | Run error `any.timeline.list: timeline: a body file needs output_dir` (`ErrNoOutputDir`) |
| Filter word empty or matching no source | Run error `any.timeline.list: timeline: tool filter word matches no source: "<word>" (<os> sources: <names>)` (`ErrToolFilter`) |
| Profile OS other than Windows or Linux | Run error `any.timeline.list: unsupported profile os "<os>"` |
| `pid` option set | Diagnostic `any.timeline.list: pid option not applied: every source covers every process` |
| A source fails (its error, or `ErrRowType`) | The rows it returned are kept; diagnostic `any.timeline.list: source <tool>: run failed, <n> rows kept: <error>`; `Failure` in its summary |
| Body file name taken `NameAttempts` times, or not creatable | Run error `any.timeline.list: body file: <error>` |
| Body file larger than `DumpLimit` | The file is removed; run error wrapping `ErrBodyTooLarge` |
| Strict mode | The first source failure ends the run with `any.timeline.list: source <tool>: run failed: <error>` and no entries |

Source tools write their own diagnostics to the shared sink; the timeline does not repeat them.

## 7. Result schema

### 7.1 Entries

`Run` returns `[]timeline.Entry` in the order of 4 step 6. `Collect` returns `timeline.Result` with the same `Entries` and one `SourceSummary` per source run.

| Field | Type | Meaning |
|---|---|---|
| `Time` | `time.Time` | UTC; never zero (an absent time gives no entry); may be before 1970 |
| `Event` | `Event` | One of `created`, `exited`, `loaded`, `unloaded`, `modified`, `accessed`, `changed`, `written`, `ran`, `launched`, `linked`, `entered`, `booted` (3.2) |
| `Tool` | string | Registered name of the source tool |
| `Field` | string | Name of the source row field the time came from |
| `Subject` | string | The object, by the subject rule of 3.2 |
| `Address`, `Physical` | uint64 | Virtual and physical address of the object by 3.2; 0 when the source has none |

`SourceSummary`: `Tool`, `Rows`, `Entries`, `Absent`, `BeforeEpoch` (counts), `Elapsed` (run time), `Failure` (error, nil when the source succeeded).

Exported helpers: `Compare` and `Sort` (4 step 6), `BeforeEpoch` (D1), `BodyLine` and `BodyName` (7.2), `Sources` (the tool names of 3.2 for an OS).

### 7.2 Body file

UTF-8 text, one line per entry in timeline order, each line ended by LF. A line has eleven fields separated by `|`:

| # | Field | Value |
|---|---|---|
| 1 | Content digest | `0` (no digest is computed) |
| 2 | Name | `<Tool> <Event> <Field>: <Subject>`, then ` at 0x<Address>` when the address is not 0, else ` physical 0x<Physical>` when that is not 0; escaped as below |
| 3 | Inode or record number | `0` |
| 4 | Mode | `0` |
| 5 | Owner | `0` |
| 6 | Group | `0` |
| 7 | Size | `0` |
| 8 | Last access | seconds, or `0` |
| 9 | Last modification | seconds, or `0` |
| 10 | Status change | seconds, or `0` |
| 11 | Creation | seconds, or `0` |

Fields 8 to 10 are the three `struct stat` times (D2); field 11 is the creation time of D3. Exactly one of them is set per line: the column of the entry's event.

| Column | Events |
|---|---|
| 8 Last access | `accessed`, `launched`, `ran` |
| 9 Last modification | `modified`, `written`, `exited`, `unloaded` |
| 10 Status change | `changed` |
| 11 Creation | `created`, `loaded`, `booted`, `entered`, `linked` |

Seconds are the whole seconds since the Epoch of D1: the fraction is dropped toward the earlier second (the `tm_sec` of D1 is an integer). An entry before 1970 has no defined value and gets no line, and neither does an entry whose seconds value is 0 (section 5): `0` in a time field means no time (O5).

Escaping of the name: the separator `|` (0x7C), every C0 control byte 0x00 to 0x1F (LF and CR included), 0x7F, and every byte that is not part of a valid UTF-8 sequence (D5) is written as `\x` and two lowercase hex digits. Every other character is written as is, backslash included (O4).

## 8. Limits

| Limit | Use | Reason |
|---|---|---|
| `NameAttempts` | Body file name collisions | An existing file is never replaced (S00). |
| `DumpLimit` (`max_dump_size`, else `MaxArtifactBytes`) | Body file size | The body file is an artefact; the largest measured body file is 76,540,662 bytes (M5). |

No cap on the number of entries: each source is bounded by its own limits.

## 9. Acceptance

1. Unit tests from sections 3.2 to 7 (`tools/any/timeline/*_test.go`): every source mapping of 3.2 with present, absent and unreadable times; scan rows placed by physical address; the UserAssist key time once per key and per run; amcache key and link times, and zoneless `LinkDate` and `InstallDate` giving no entry; Linux unread tasks, threads and missing inode times; the catalogue has no repeated source per OS; option type errors, the refusals of 4 step 1 before any source runs, filter words by substring; gathering across sources with sort, a failed source's rows kept with its diagnostic, the strict error; the source context without the timeline's options and `pid`, with overrides not leaking to the caller; a run on an empty image for both OSes; the body file written through `Run` with its diagnostic; `Compare` over every key, `Sort` independent of input order and stable for equal entries; every event with one body column; each column, whole seconds, the 11 fields; times before 1970 and unknown events give no line, nor does second 0, second 1 does; name escaping; an existing body file kept and the name `timeline-1.body` used; a file over the limit removed.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzBodyLine` (any time, event and text; a line exactly for a known event from second 1 of 1970 on; no line break, valid UTF-8, 11 fields, exactly one time field set to the whole seconds, the others `0`) 655,777 executions, run while the captures were measured.
3. On the captures, `timelinefacts` (M1 to M6): every capture gives entries from every source that has rows; the order check of M4 holds; the body file of M5 has one line per entry from 1970 on.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | `record_config` is kept as an option key and refused when true: the project has no run-configuration record to write. | Owner decision |
| O2 | The body file line (7.2) is defined here from D1 to D3 and the field order that timeline programs commonly read; no standards document defines it, and none is cited. Fields 1 and 3 to 7 are written as `0`; the source rows of files (NTFS segment numbers, Linux inode numbers, modes, owners and sizes) are not carried into them. | Owner decision |
| O3 | The event-to-column table of 7.2 is this specification's choice for events that are not file times (`exited`, `launched`, `ran`, `loaded`, `booted`, `entered`, `linked`, `unloaded`). The event name is in field 2 of every line, so a reader can tell them apart. Owner decision 2026-11-12: drop `installed`, edit O3. Done: no source gives it (O6), so the event `installed` and its constant `Installed` are removed from 7.2, the column table and O3 (`tools/any/timeline/entry.go`, `body.go`, test `TestEveryEventHasOneBodyColumn`). | Owner decision |
| O4 | Escaping is not reversible for a subject that already holds `\x` followed by two hex digits; a backslash is not escaped, so that Windows paths stay readable. | Owner decision |
| O5 | An entry in the first second of 1970 gets no body line, because `0` means "no time" there. On the captures every such entry is an inode time the kernel left at 0 (M2); the entries keep them. Whether the timeline should treat a Linux inode time of exactly 0 as absent is a source question (S12, S39). | Owner decision |
| O6 | The amcache tool has no specification of its own yet. Its four UTC text fields are read as named: `LastModifyTime` and `LastModifyTime2` as `modified`, `InstallTime` as `installed`, `CompileTime` as `linked`. Its zoneless `InstallDate` and `LinkDate` are not read: without an offset they are not Internet date-times (D4) and cannot be placed in UTC. The same holds for `windows.session.list`, `windows.object.scan_links` and `windows.module.list_unloaded`: their rows are read by their current types. Owner decision 2026-11-12: schedule now. Done: checked each source against its specification. Amcache (S63 T10) rows are `InventoryRecord`s with no text times: the timeline reads `KeyLastWrite` (`written`) and the driver `LinkTime` (`linked`, seconds since 1970 UTC, S63 D12); `LinkDate` and `InstallDate` stay unread, as S63 emits them as stored without a zone (S63 O8), test `TestAmcacheZonelessDatesGiveNoEntry`. Session list (S69 4.5 step 4: the S25 `CreateTime`), scan_links (S69 4.2 step 4: `CreateTimeUnreadable`) and list_unloaded (S64 4.8 step 6: `Time` zero only when the clock is unknown) match the code as it stood. With no text-time source left, `ParseTextTime`, `ErrTextTime`, `SourceSummary.Malformed`, the malformed diagnostic and `FuzzParseTextTime` are removed (`tools/any/timeline/collect.go`, `entry.go`, `tool.go`); 3.2, 4, 5, 6, 7.1, 9 and M1, M3 updated and re-measured. The event `installed` remained in the event set with no source; it is removed (O3). | Specifications of those tools |
| O7 | The `pid` option is not applied: the timeline covers the image, and several sources (sockets, sessions, libraries) resolve owners through the full process list. | Owner decision |
| O8 | Result and API changes (Q2). `Entry` is now one dated event: `Time`, `Event`, `Tool`, `Field`, `Subject`, `Address`, `Physical` replace `Tool`, `Description`, `Created`, `Modified`, `Accessed`, `Changed`. `Stamp`, `Kind` (`NotYielded`, `Datetime`, `Absent`), `Type` (`Created`, `Modified`, `Accessed`, `Changed` as `Type` values) and `Entry.Stamp` are removed; `Created`, `Modified`, `Accessed` and `Changed` are now `Event` values. New: `Event` and its 13 values, `Result`, `SourceSummary`, `Collect`, `Compare`, `Sort`, `BeforeEpoch`, `BodyName`, `Sources`, `ErrRowType`, `ErrBodyTooLarge` (`ParseTextTime`, `ErrTextTime` and the event `installed` were added and later removed, O3 and O6). `BodyLine` keeps its signature. Times keep their full precision instead of whole seconds. Addresses are written in full, not masked. Orphaned-thread entries carry their own tool name. Entries with no time are no longer listed; they are counted per source. The body file is written in timeline order. Subjects are this specification's wording. | Owner decision (Q2) |
| O9 | The timeline does not flag times after the capture time (section 5); M3 counts them per source. | Owner decision |
| O10 | Registry key last-write times are taken only where a source reports them (`windows.task.list`, `windows.execution.read_userassist`); no source lists every key of every hive with its time. | A registry key source and an owner decision on its volume |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep, refuse when true |
| O2 | Accept |
| O3 | Accept |
| O4 | Do not escape backslash |
| O5 | Keep entry, no body line |
| O6 | Schedule now |
| O7 | Keep ignoring pid |
| O8 | Accept |
| O9 | Do not flag; count per source |
| O10 | Defer to v0.2.0 |

## 11. Provenance

Author: the project, 2026-11-12. Sources: POSIX.1-2024 Base Definitions 4.19 and `<sys/stat.h>`, Microsoft Learn "FILE_BASIC_INFORMATION", RFC 3339 and RFC 3629, accessed 2026-11-12; the project's specifications of the source tools named in 3.2; the project's measurements with `timelinefacts` on the seven captures of 3.3. Every rule rests on the sources and measurements above.
