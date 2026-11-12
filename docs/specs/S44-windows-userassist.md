# S44: Windows Explorer program-launch counts in user hives

Version 1, 2026-11-12.

## 1. Purpose

Explorer keeps, in each user's registry hive, a count of the programs, shortcuts and applications the user started through the shell, with the time of the latest start. The data sits under `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` of the user hive, one value per program, the value name letter-rotated. It survives after the program and its files are gone. An examiner wants, per user hive: which programs were started through the shell, how often, and when last.

`windows.execution.read_userassist` lists every value under every `Count` key of every user hive in memory: its subkey, decoded name, the known folder its name starts with, the launch count and last launch time where the value layout is measured, and the value data as stored.

Microsoft does not document the value layout (D3). This specification defines it from the project's own census of the captures' user hives, and ties each emitted field to a meaning by cross-checks against the same captures' process list and against the pairing of shortcut and program values. A field no measurement ties to a meaning is not emitted (section 10).

## 2. Inputs

| Input | Use |
|---|---|
| Registry hives | Every hive `registryhive.OpenEveryHive` opens, through the project's `registryhive` reader. A hive is a user hive when the last component of its file path (else its name) is `NTUSER.DAT`, any case (D2, M1). |
| Kernel symbol table | Pointer size only, for the 64-bit folder paths of D5. |
| Options | `strict` and `diagnostics` only. The tool has no option of its own. |
| Limits | None of its own. Value and subkey lists are bounded by `registryhive` (`MaxRowsPerObject`), value data by `MaxBufferBytes`. |

## 3. Facts from the sources

### 3.1 Documentation

All pages accessed 2026-11-12.

| # | Fact | Source |
|---|---|---|
| D1 | A FILETIME counts 100-nanosecond intervals since January 1, 1601 (UTC). | Microsoft Learn, "FILETIME (minwinbase.h)", ms.date 2018-12-05 |
| D2 | A user profile hive is loaded for each user who logs on, under `HKEY_USERS`; the supporting files of `HKEY_CURRENT_USER` are `Ntuser.dat` and `Ntuser.dat.log`. | Microsoft Learn, "Registry Hives", ms.date 2018-05-31 |
| D3 | The key `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` exists and regenerates itself at the next logon when deleted; the data in it is undocumented. | Microsoft Learn Q&A, question 2629999 ("FIX: Start Screen items erroneously highlighted as NEW", 2013-11-03) and question 889897 ("Windows 10 'Top Apps', how do I get them with code?", answer of 2022-06-15). Community answers on Microsoft Learn, not product documentation. |
| D4 | KNOWNFOLDERID: 126 constants. Each lists a GUID, a display name, a folder type, a Default Path in environment-string form (for example `%windir%\system32`) or "Not applicable" for a virtual folder, and legacy values. `FOLDERID_RecordedTV` and `FOLDERID_TreeProperties` have no GUID ("not used" as of Windows 7). | Microsoft Learn, "KNOWNFOLDERID", ms.date 2020-07-27 |
| D5 | The Remarks of KNOWNFOLDERID: for a 64-bit application on a 64-bit system, `FOLDERID_ProgramFilesX86` is `%SystemDrive%\Program Files (x86)`, `FOLDERID_ProgramFilesCommonX86` is `%ProgramFiles(x86)%\Common Files`, and `FOLDERID_SystemX86` is `%windir%\syswow64`. Example paths: `%windir%` C:\Windows, `%ProgramFiles%` C:\Program Files, `%APPDATA%` C:\Users\username\AppData\Roaming, and so on. | Same page, "Remarks" |
| D6 | ROT13, as this spec uses it: each letter A to Z and a to z becomes the letter 13 places on in its own case, wrapping after Z; every other character stays. Applying it twice gives the input back. | The project's own definition; M10 shows that the stored names decode with it. |

### 3.2 Measurements

M1 to M12 come from `userassistfacts`, run on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 and mem7_server2025 (26100). Capture times are `_KUSER_SHARED_DATA.SystemTime` through the project's `windows.kernel.read_info`: 2026-05-06T18:24:25Z, 2026-05-26T20:50:39Z, 2026-01-30T08:27:03Z, 2026-09-27T19:18:15Z and 2026-10-29T19:09:32Z.

| # | Measured |
|---|---|
| M1 | Hives found: 24, 29, 19, 29 and 24 open (125). 15 are named `NTUSER.DAT` (3 per capture): the key is present in 5 (one per capture, `C:\Users\<profile>\ntuser.dat`), absent in 4 (the service-profile hives of mem2 and mem5) and does not read in 6 (the service-profile hives of mem1, mem6 and mem7, paged out). In the other 110 hives the key is absent (89) or does not read (21); it is present in none. |
| M2 | Each of the 5 UserAssist keys has no values and the same 9 GUID subkeys: `{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}`, `{A3D53349-6E61-4557-8FC7-0028EDCEEBF6}`, `{B267E3AD-A825-4A09-82B9-EEC22AA3B847}`, `{BCB48336-4DDD-48FF-BB0B-D3190DACB3E2}`, `{CAA59E3C-4792-41A5-9909-6A6A8D32490E}`, `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}`, `{F2A1CB5A-E3CC-4A2E-AF9D-505A7009D442}`, `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}`, `{FA99DFC7-6AC2-453A-A5E2-5E2AFF4507BD}`. Each GUID subkey holds one value, `Version`, and one subkey, `Count`. |
| M3 | `Version` is REG_DWORD 5 in 36 of the 45 GUID subkeys; in the other 9 (mem1 1, mem6 3, mem7 5) the value list does not read in full. No other version occurs. |
| M4 | Count values per subkey: `{CEBFF5CD-…}` 10, 56, 43, 19 and 22; `{F4E57C4B-…}` 3, 12, 15, 3 and 2; the other seven subkeys 0 in every hive (185 values). All 185 are REG_BINARY and all names read. The value lists of both non-empty `Count` keys of mem7 do not read in full; the other 43 lists do. |
| M5 | Value sizes: 72 bytes 175 values; 1,612 bytes 9 values (the value `UEME_CTLSESSION`, once per non-empty subkey; on mem7 only under `{CEBFF5CD-…}`); data not read in full 1 (mem1). No other size occurs. |
| M6 | The 72-byte layout, over 175 values: 32-bit word +0x00 is 0 in 165 and 0xFFFFFFFF in 10 (all `UEME_CTLCUACount:ctor`, two per capture); 32-bit words +0x04, +0x08, +0x0C (largest per capture: +0x04 1, 47, 25, 14, 14; +0x08 2, 143, 204, 21, 23; +0x0C 117,985 to 12,905,353); ten 32-bit words +0x10 to +0x34, each the IEEE 754 single -1.0 (0xBF800000) in all 1,750; word +0x38 0xFFFFFFFF in all 175; 64-bit word +0x3C a FILETIME (M7); word +0x44 0 in all 175. Word +0x3C is 0 exactly when word +0x04 is 0 (175 of 175). Under `{F4E57C4B-…}` (31 values) word +0x08 is 0 and word +0x0C equals word +0x04 in all 31. |
| M7 | Word +0x3C is nonzero in 109 values (3, 45, 37, 10, 14). Every one is a valid FILETIME, at or before its `Count` key's last write, and at or before the capture time. 94 are at or after the earliest last write among the hive's UserAssist keys; the other 15 (mem2 9, mem5 4, mem6 1, mem7 1) are 100 to 107 s before it, and name programs a new profile starts with (Snipping Tool, Paint, Get Started, Feedback Hub, Maps, People, Sticky Notes). In each `{F4E57C4B-…}` key the newest value time is within 1 ms of the key's last write (0.3 to 0.9 ms); in `{CEBFF5CD-…}` it is 9.5 s to 124 s before. |
| M8 | Process cross-check (project's `windows.process.list`): of the programs whose name ends `.exe` and matches a running process image, 3 have word +0x3C within 2 s of a matching process's create time (the capture program on mem1, 58 ms; on mem2, 1.5 s; on mem6, 6 ms), each with word +0x04 ≥ 1 (mem6: 1). 4 more on mem5 (SearchUI, ShellExperienceHost and two MicrosoftEdgeUpdate) run with word +0x04 = 0 and word +0x3C = 0: system-started programs. 4 have word +0x04 ≥ 1 and no running copy started within 60 s of word +0x3C. |
| M9 | Shortcut pairing: 26 values name a `.lnk` file, all under `{F4E57C4B-…}`, all with word +0x3C set. 21 have a value under `{CEBFF5CD-…}` with the identical FILETIME (to the 100 ns), and in all 21 that value's word +0x04 is at least the shortcut's (for example `Microsoft Edge.lnk` 1 and taskbar `Microsoft Edge.lnk` 11, against `MSEdge` 12). 5 have no such partner. |
| M10 | Names, ROT13-decoded (D6): 80 start with a `{GUID}` and a backslash, and all 80 GUIDs are KNOWNFOLDERID GUIDs (D4); 31 are drive-letter paths; 29 are application identities containing `!`; 26 others are names such as `Microsoft.Windows.Explorer`, `MSEdge` or `Microsoft.AutoGenerated.{…}`; 19 start `UEME_` (`UEME_CTLCUACount:ctor` 10, `UEME_CTLSESSION` 9). |
| M11 | File cross-check (project's `windows.file.scan`): the 111 path names (80 with a known folder, all with a Default Path, and 31 drive paths), expanded with the example paths of D5, give 16 that name a file object exactly and 8 more whose last component does; 87 have none. File objects exist only for files open or cached at capture time. |
| M12 | The 1,612-byte value is a 32-bit word (0 in all 9), three 32-bit words, then three slots of three 32-bit words and 260 UTF-16 code units (1,612 = 4 + 12 + 3 × 532). Every one of the 27 slots names a 72-byte value under the same subkey, and its three words equal that value's words +0x04, +0x08 and +0x0C (27 of 27). |

### 3.3 Layout

| # | Layout |
|---|---|
| L1 | Key path, in a user hive: `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`, then GUID subkeys, each with `Version` (REG_DWORD) and a subkey `Count` (D3, M2). |
| L2 | A `Count` value's name is ROT13 of the program name: letters A to Z and a to z rotate, every other character stays (D6, M10). |
| L3 | A 72-byte value under a subkey whose `Version` is 5: +0x04 launch count (32-bit), +0x3C last launch time (FILETIME, 0 when never launched). The words +0x00, +0x08, +0x0C, +0x10 to +0x34, +0x38 and +0x44 are not emitted (O1 to O3). |
| L4 | A name that starts with a KNOWNFOLDERID GUID in braces, followed by a backslash or the end, names a path below that folder (M10, M11). |

## 4. Algorithm

1. Open every hive (`registryhive.OpenEveryHive`). Keep the user hives (section 2). None opens: diagnostic, no rows, no error.
2. In each user hive, open the key of L1. Absent: next hive. Not readable: diagnostic, next hive.
3. Read its subkeys. For each GUID subkey:
   1. Read `Version` from its values: a 4-byte REG_DWORD gives the version; otherwise the version is unknown.
   2. Find its `Count` subkey. Absent: no rows. Not readable: diagnostic.
   3. Read the `Count` key's values. Each value gives one row: the name is ROT13-decoded (L2), split into folder and rest (L4) and expanded (step 4); the data is decoded by L3 when it reads in full, is 72 bytes and the version is 5 or unknown (M3, M5).
4. Expansion: a name with a known-folder prefix whose folder has a Default Path becomes the path with the rest appended (`{1AC14E77-…}\cmd.exe` becomes `%windir%\system32\cmd.exe`). On a 64-bit kernel the three paths of D5 replace the Default Path. Otherwise the expanded name is the name.
5. Rows are sorted by hive path, hive address, subkey name (case folded), then name, a name that did not read last.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Data of exactly 72 bytes | M5, M6 | `DataState` `unmeasured`; no counts; data still emitted |
| Version 5, or not readable | M3 | Version other than 5: `unmeasured` and a diagnostic with `ErrVersion` |
| FILETIME below 2^63 | D1 (FileTimeToSystemTime range, S17) | `LastLaunch` zero; diagnostic with `ErrTime` |

The launch count is emitted as stored: every value is in range by type, and M7 to M9 found nothing implausible.

## 6. Failure modes

| Case | Result |
|---|---|
| Profile not Windows | Run error `windows.execution.read_userassist: unsupported profile os "<os>"` |
| No user hive opens | Diagnostic `windows.execution.read_userassist: no NTUSER.DAT hive opens` |
| UserAssist key not readable | Diagnostic `windows.execution.read_userassist: hive <path> at 0x<addr>: UserAssist key not read: <error>` |
| Subkey list of the UserAssist key not read in full | Diagnostic `windows.execution.read_userassist: UserAssist key at 0x<addr>: subkey list not read in full: executionuserassist: user hive not read in full` |
| `Count` not found for certain | Diagnostic `windows.execution.read_userassist: subkey <GUID> at 0x<addr>: Count key not read: executionuserassist: user hive not read in full` |
| `Count` value list not read in full | Diagnostic `windows.execution.read_userassist: Count key of <GUID> at 0x<addr>: value list not read in full: executionuserassist: user hive not read in full` |
| Values whose data did not read | `DataState` `unreadable`, `Data` holds the bytes that read; diagnostic `windows.execution.read_userassist: Count key of <GUID> at 0x<addr>: <n> values not read in full: executionuserassist: user hive not read in full` |
| Version other than 5, with values | Diagnostic `windows.execution.read_userassist: subkey <GUID> at 0x<addr>: values not decoded: executionuserassist: subkey version not measured` |
| Launch time of 2^63 or more | Diagnostic `windows.execution.read_userassist: Count key of <GUID> at 0x<addr>: value "<name>": last launch 0x<filetime>: executionuserassist: last launch is not a time` |
| Strict mode | Every diagnostic above except "no user hive opens" also records its error (`ErrIncomplete`, `ErrVersion` or `ErrTime`); the run returns all rows and the first error. |

## 7. Result schema

One `executionuserassist.CountValue` per value:

| Field | Type | Meaning |
|---|---|---|
| `HivePath`, `HiveAddress` | string, uint64 | The hive's file path (else its name) and its `_CMHIVE` address |
| `Key` | string | Path of the `Count` key within the hive |
| `GUID`, `GUIDUnreadable` | string, bool | The GUID subkey's name; whether it did not read |
| `Version`, `VersionKnown` | uint32, bool | The subkey's `Version`; whether it read |
| `CountKeyLastWrite` | time.Time (UTC) | Zero when it did not read |
| `Name`, `NameUnreadable` | string, bool | ROT13-decoded value name (L2) |
| `KnownFolder`, `KnownFolderPath` | string | The KNOWNFOLDERID constant and path of the name's prefix (D4, D5); empty when none |
| `ExpandedName` | string | Step 4 |
| `DataState` | `decoded`, `unmeasured`, `unreadable` | Section 5 and 6 |
| `DataLength` | uint32 | Stored data length in bytes |
| `Data` | []byte | Data bytes that read, as stored |
| `LaunchCount` | uint32 | L3; 0 unless `decoded` |
| `LastLaunch` | time.Time (UTC) | L3; zero when never launched or not `decoded` |

`DecodeCountData` (L3) and `LookupKnownFolder` (D4, D5) are exported so that callers decode a value the same way. The package errors are `ErrIncomplete`, `ErrDataLength`, `ErrVersion` and `ErrTime`.

## 8. Limits

No limit of the tool's own. The registry reader caps subkey and value lists by `MaxRowsPerObject` and reports a list it stops as incomplete, which the tool reports by section 6. The largest measured `Count` key has 56 values.

## 9. Acceptance

1. Synthetic fixtures (`tools/windows/executionuserassist/s44_fixture_test.go`, from L1 to L4; tests in `execution_read_userassist_test.go` and `countdata_test.go`): a hive with both populated subkeys, a session value, a never-launched value, a known-folder name on a 32-bit and a 64-bit kernel, an unknown GUID prefix, a drive path, an unreadable name, cut data, version 6, an unreadable `Version`, an incomplete subkey list, a `Count` key that cannot be searched, an incomplete value list, a FILETIME of 2^63, a missing key, an unreadable key, strict mode, and the sort order. The KNOWNFOLDERID table: 124 GUIDs, unique, each a GUID in braces, and the three 64-bit paths of D5.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzDecodeCountData` (no panic; only `ErrDataLength`, and only for a length other than 72; the count and time are the words at +0x04 and +0x3C) 3.46 million executions; `FuzzDecodeName` (no panic; ROT13 applied twice is the identity; a folder found only for a braced GUID prefix followed by a backslash or the end; prefix plus rest is the name; the expanded name is the folder path plus the rest, else the name) 3.45 million.
3. On the captures (`userassistfacts -tool`, 2026-11-12): the tool returns 13, 68, 58, 22 and 24 rows (185): 175 `decoded`, the 9 session values `unmeasured`, the one cut value of M5 `unreadable`; 80 names with a known folder; 109 with a launch count above 0; no run error. Its diagnostics are the 6 unreadable keys of M1, the cut value of M5 and the 2 incomplete value lists of M4.
4. The cross-checks of M7 to M9 and M12 hold as measured.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Words +0x08 and +0x0C of the 72-byte value are not emitted. Both grow with use; +0x08 is nonzero for system-started programs that were never launched (M8: SearchUI 14, ShellExperienceHost 11), and +0x0C looks like a duration in milliseconds under `{CEBFF5CD-…}` but equals the launch count under `{F4E57C4B-…}` (M6). No measurement ties either to a meaning such as focus count or focus time. They remain in `Data`. | A controlled capture: start one program once, keep its window in front for a measured time, capture |
| O2 | Word +0x00 (0, or 0xFFFFFFFF in `UEME_CTLCUACount:ctor`), the ten -1.0 singles, +0x38 and +0x44 are constant over 175 values and are not emitted. | A document or a capture where they vary |
| O3 | The 1,612-byte `UEME_CTLSESSION` value has a measured layout (M12) but its header words have no meaning tied by measurement; it is `unmeasured` with its data. | Owner decision |
| O4 | The two populated subkeys hold programs (`{CEBFF5CD-…}`) and shortcuts (`{F4E57C4B-…}`) by the names they hold (M9); no document names them, so no label is emitted. | A Microsoft document of the subkeys |
| O5 | Only hives named `NTUSER.DAT` are read (D2, M1). A mandatory profile (`NTUSER.MAN`) was not measured. | A capture with a mandatory profile |
| O6 | Value layouts other than 72 bytes under version 5 (for example older Windows versions) were not measured; such values are `unmeasured`. | Captures of other Windows versions |
| O7 | Names that are not paths (application identities, `UEME_` names) are emitted as decoded, without interpretation. | Owner decision |
| O8 | Row and field names are new: `CountValue` replaces `Entry`; there are no key or subkey rows (`Type` and its constants are gone); `LaunchCount` replaces `Count`, `LastLaunch` (time) replaces `LastUpdated` and `LastUpdatedUTC`; `Data` replaces `RawData`; `FocusCount`, `FocusTime`, `FocusTimeMillis`, `ID`, `Unparsed`, `PathUnreadable`, `LastWriteUnreadable`, `RawDataUnreadable` and `NoHiveName` are gone (`DataState` carries the data state); `HivePath` and `HiveAddress` replace `Hive` and `HiveOffset`; `Key` (a path within the hive, without the hive's file name) replaces `Path`; `CountKeyLastWrite` (a time) replaces `LastWriteTime` and `LastWriteTimeUTC`; `GUID`, `GUIDUnreadable`, `Version`, `VersionKnown`, `KnownFolder`, `KnownFolderPath`, `ExpandedName`, `DataState` and `DataLength` are new. | Owner decision (Q2) |
| O9 | Launches through the shell are told from other starts only by M8 and M9: the system-started programs of M8 have a launch count of 0. Whether a launch by a script or a service is ever counted was not measured. | A controlled capture that starts a program from a script |
| O10 | The timeline line for a value now names the key path within the hive (`UserAssist <name> at Software\...\{GUID}\Count, count <n>`), without the hive file name in front. | Owner decision (Q2) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep in Data only |
| O2 | Do not emit |
| O3 | Keep unmeasured |
| O4 | No label |
| O5 | Defer; only NTUSER.DAT is read |
| O6 | Defer; mark unmeasured |
| O7 | Emit as decoded |
| O8 | Accept the new names |
| O9 | Defer |
| O10 | Key path without hive file name |

## 11. Provenance

Author: the project, 2026-11-12. Sources: the Microsoft Learn pages and Microsoft Learn Q&A answers of 3.1, accessed 2026-11-12; the project's definition of ROT13 in D6, confirmed by M10; the project's measurements with `userassistfacts` on the five captures of 3.2, through the project's `registryhive`, `windows.kernel.read_info`, `windows.process.list` and `windows.file.scan`. Every rule rests on the sources and measurements above.
