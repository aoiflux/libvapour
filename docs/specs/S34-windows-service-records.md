# S34: Windows service records in services.exe memory, and their comparison with the registry

Version 1, 2026-11-12.

## 1. Purpose

The service control manager (SCM) runs in services.exe. It holds one record per service it knows: the service's name and display name, its status, its start type and, for a running service, the process that hosts it or the driver object that implements it. It links the records on one list. The registry's `CurrentControlSet\Services` keys hold the configuration the SCM read at boot and any written since.

An examiner wants the services the SCM held at capture time, with the process each ran in. They also want the differences between three views: records on the SCM's list, records still in services.exe memory that the list does not reach, and services the registry describes. A service that is running but has no key, a record that was unlinked, and a key that the SCM never loaded can each mark tampering.

This specification defines how the records are found in services.exe's private memory, how the SCM's own list is walked, the checks a record must pass, and the comparison with the registry.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory and symbol table | The process list (S25), the VAD walk of each services.exe (S24) and the SYSTEM hive (registryhive). |
| Process memory | Each services.exe's address space, through `tools.Context.ProcessSpace`. |
| services.exe PDB | Optional, through `tools.Context.LoadPDB` with the fingerprint from the image's CodeView record. Two publics are used (P1, P2). |
| Kernel build | `winkernel.ReadBuild`, for the diagnostic of 4.3 step 4 only. |
| Options | None of the tool's own. `strict` (4.3 step 4, 4.5 step 5). |
| Limits | `MaxRegionScanBytes` (bytes scanned per private VAD), `MaxMatchesPerChunk` (tag hits kept per VAD), `MaxListEntries` (list walk), `MaxNameBytes` (image paths and driver object names). |

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | `SERVICE_STATUS` is seven DWORDs in order: `dwServiceType`, `dwCurrentState`, `dwControlsAccepted`, `dwWin32ExitCode`, `dwServiceSpecificExitCode`, `dwCheckPoint`, `dwWaitHint`. `dwCurrentState` is one of `SERVICE_STOPPED` 1, `SERVICE_START_PENDING` 2, `SERVICE_STOP_PENDING` 3, `SERVICE_RUNNING` 4, `SERVICE_CONTINUE_PENDING` 5, `SERVICE_PAUSE_PENDING` 6, `SERVICE_PAUSED` 7. `dwServiceType` values: `SERVICE_KERNEL_DRIVER` 0x1, `SERVICE_FILE_SYSTEM_DRIVER` 0x2, `SERVICE_WIN32_OWN_PROCESS` 0x10, `SERVICE_WIN32_SHARE_PROCESS` 0x20, `SERVICE_USER_OWN_PROCESS` 0x50, `SERVICE_USER_SHARE_PROCESS` 0x60, and `SERVICE_INTERACTIVE_PROCESS` 0x100 with a Win32 type. | Microsoft Learn, "SERVICE_STATUS structure (winsvc.h)", updated 2024-02-22, accessed 2026-11-12. |
| D2 | `SERVICE_STATUS_PROCESS` adds `dwProcessId`, "the process identifier of the service", and `dwServiceFlags`: "If the service is not running, dwProcessId is zero." | Microsoft Learn, "SERVICE_STATUS_PROCESS structure (winsvc.h)", updated 2024-02-22, accessed 2026-11-12. |
| D3 | `lpServiceName`: "The maximum string length is 256 characters … service name comparisons are always case insensitive. Forward-slash (/) and backslash (\\) are not valid service name characters." `lpDisplayName` "has a maximum length of 256 characters". `dwServiceType` adds `SERVICE_ADAPTER` 0x4 and `SERVICE_RECOGNIZER_DRIVER` 0x8, both "Reserved". Start types: `SERVICE_BOOT_START` 0, `SERVICE_SYSTEM_START` 1, `SERVICE_AUTO_START` 2, `SERVICE_DEMAND_START` 3, `SERVICE_DISABLED` 4. Error control: `SERVICE_ERROR_IGNORE` 0, `_NORMAL` 1, `_SEVERE` 2, `_CRITICAL` 3. For a kernel or file system driver, `lpServiceStartName` "is the driver object name that the system uses to load the device driver". CreateService creates "a key with the same name as the service" under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services` and stores `DisplayName`, `ErrorControl`, `Group`, `ImagePath` ("Name of binary file, as specified by lpBinaryPathName"), `ObjectName`, `Start`, `Tag` and `Type` there. | Microsoft Learn, "CreateServiceW function (winsvc.h)", updated 2025-07-01, accessed 2026-11-12. |
| D4 | The Services tree "stores information about each service on the system". `Start`, `Type` ("a combination of" 0x1, 0x2, 0x10, 0x20) and `ErrorControl` carry the values of D3; `ImagePath` "specifies the path to the service binary". A driver keeps its own data under the `Parameters` subkey. | Microsoft Learn, "HKLM\SYSTEM\CurrentControlSet\Services Registry Tree", dated 2024-09-18, accessed 2026-11-12. |
| D5 | Per-user services are created from templates at sign-in and deleted at sign-out; the instance name is `<service name>_LUID`. The service type of a per-user service includes the bit 64 (0x40). `sc qc` shows "whether the service is a user-service template or user-service instance". | Microsoft Learn, "Per-user services", dated 2024-10-01, accessed 2026-11-12. |

### services.exe PDB publics

Read through the project's symbol tables (`symbols/autoload`) for the services.pdb builds 4509DF9E72555CCA35D35E7C3C7E954A-1 (mem1, 26100), 121C32360C557C5DDB87D17B3D79ED1F-1 (mem2, 19045), CD7AE52400CA4919B133DD7F364CA8C2-1 (mem5, 14393) and 41B29DC06C87FC4EE8D1C1FF85E12EDB-1 (mem7, 26100). The PDBs carry publics only, no types (`servicefacts -pdb`).

| # | Fact |
|---|---|
| P1 | On 26100 and 19045 the public `?ServiceDatabase@@3VCServiceDatabase@@A` is a global of class `CServiceDatabase`; related publics name the class `CServiceRecord` (for example `?AddToStartSet@CServiceRecord@@…`). RVAs 0xc6488 (mem1), 0xa04b0 (mem2), 0xc54f8 (mem7). |
| P2 | On 14393 the public `?ServiceDatabase@@3U_SERVICE_RECORD@@A` is a global of struct `_SERVICE_RECORD` (RVA 0x64de0), and `?ScTotalNumServiceRecs@@3KA` a `DWORD` global (RVA 0x64db4). |
| P3 | On every build, `?ImageDatabase@@3U_IMAGE_RECORD@@A` is a global of struct `_IMAGE_RECORD`. |

### Measurements

M1 to M11 come from `servicefacts` on 2026-11-12 over mem1_win11 (build 26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100). Each capture has one services.exe. `-discover` measures offsets from the tags with no layout assumed; `-census` applies the layouts of 4.2 and counts each rule; `-anchor` dumps the PDB globals.

| # | Measured |
|---|---|
| M1 | The PDB globals begin with a four-byte tag: `CServiceDatabase` "Sc27" (0x37326353) on 26100 and 19045; the 14393 `_SERVICE_RECORD` sentinel "Sc17" (0x37316353); `_IMAGE_RECORD` "Sc18" (0x38316353) everywhere. Their pointers lead to heap objects tagged "Sc19" (0x39316353) at +8 behind a pointer into the services.exe image (26100, 19045), "sErv" (0x76724573) at +0 (14393), and "Sc16" (0x36316353) at +0 for image records. |
| M2 | Tag census in the private VADs: "Sc19" 689, 674, 633, 635 hits on mem1, mem2, mem6, mem7, every one at address ≡ 8 (mod 16); "sErv" 500 hits on mem5, every one ≡ 0 (mod 16); no capture has the other family's tag. Records sit in 1 or 2 heap VADs of 1 to 16 MB (mem1: all 689 in one 16 MB VAD; mem2: 664 and 10; mem5: 498 and 2). The largest private VAD on 26100 and 19045, 0x100020000 bytes, holds none. |
| M3 | Offsets measured from the record start (the tag on 14393, the pointer before the tag otherwise), counted over all hits. Name pointer to a string equal to a registry key name: +0x38 on 26100 and 19045 (689, 673, 633, 635 of the hits), +0x10 on 14393 (500). Display name: the next pointer (+0x40, +0x18). A DWORD equal to the key's `Type`: +0x50 (26100: 689, 633, 635), +0x48 (19045: 589), +0x40 (14393: 500); the next DWORD is in 1..7 in every hit. `ErrorControl`: +0x28 (26100, 19045), +0x60 (14393), equal in 689, 670, 500, 633, 635. `Start`: +0x24, +0x5c, equal in 666, 618, 449, 567, 569 (the registry value can change after boot, M10). A DWORD unique per record and running 1..n: +0x20 in all three. Pointers to another record's start: +0x10 and +0x18 (26100, 19045), +0x08 and +0x98 (14393), one fewer than the records each. A pointer to an "Sc16" object or to a driver object name: +0x150 (26100), +0x128 (19045), +0x38 (14393). |
| M4 | Fit: decoded with the 19045 offsets, every 26100 hit fails the state rule (689, 633, 635 of 689, 633, 635), and every 19045 hit fails with the 26100 offsets (674 of 674). With its own layout every hit passes all rules of 5.1 (689, 674, 500, 633, 635). |
| M5 | List: on 26100 and 19045 `CServiceDatabase` +8 is the first record and +0x10 the last; each record's +0x18 is the next and +0x10 the previous, null at both ends. The walk reaches 680, 673, 633, 635 records with every back link agreeing; the last walked is +0x10 each time; the DWORD at +0x24 equals the walked count each time; the DWORD at +0x20 (680, 674, 637, 635) is at or above every walked sequence number (680, 674, 634, 635). On 14393 the sentinel's +0x98 is the first record, whose +0x08 points back to the sentinel; the walk reaches 500 records, all back links agree, and `ScTotalNumServiceRecs` is 500. |
| M6 | The head tag occurs once in each services.exe image at an 8-aligned offset where the pointers lead to records ("Sc27" with first and last records; "Sc17" whose +0x98 record points back), and that one place is the PDB global on the four captures that have the PDB. mem6's CodeView page is not resident, so its PDB does not load; the image search finds its head. |
| M7 | Records not on the list: mem1 9, each with the sequence number and name of a listed record; mem2 1, sequence 367, whose name pointer leads to the one-character string "ā", with no registry key; none elsewhere. |
| M8 | Image records ("Sc16", 48, 98, 28, 46, 51 hits): +0x18 points to the command line in every hit; a DWORD equal to a listed process ID at +0x28 (26100, 19045: 48 of 48, 93 of 98, 46, 45 of 51) or +0x20 (14393: 27 of 28). For listed records of a Win32 type, the union of M3 is null when stopped; for the running ones it leads to a tagged image record whose process is listed and named in its command line: 81, 104, 80, 99, 103; on mem7 5 more name a process the process list does not hold. |
| M9 | Driver union: for listed driver records it leads to a string beginning `\Driver\` or `\FileSystem\` in 151, 100, 75, 109, 97 records whose last component is the service name; on mem7 13 more lead to text that is not a driver object name and 3 to memory that is not text. |
| M10 | Registry against the list: every listed record has a key. `Type` differs in 84 records on mem2 (memory holds 0x30, own and share, in 78) and nowhere else. `Start` differs in 23, 55, 51, 66, 66 records. Keys with no `Type` value: 48, 52, 52, 46, 46. Keys with a service type and no listed record: `Fs_Rec` (type 0x8) on all five, and the key of the acquisition driver loaded to take the capture (type 0x2, start 3) on mem2, mem6 and mem7. |
| M11 | Values in accepted records. Types: 0x1, 0x2, 0x10, 0x20, 0x50, 0x60, 0x110, 0x120, 0xd0, 0xe0 everywhere, and 0x30 and 0xf0 on 19045; no other value. States: only 1 and 4, except one record in state 3 on mem2. mem1: 353 kernel drivers, 40 file system drivers, 296 Win32; 455 stopped, 234 running. |

## 4. Algorithm

### 4.1 Targets

1. List processes without the PID filter (S25). Each process whose image name is `services.exe` (case-insensitive) is a target. None → `ErrNoServicesProcess`.
2. The symbol table's pointer size must be 8; the layouts are measured only for 64-bit services.exe (`ErrPointerSize`).
3. Per target: its address space; its VADs (S24 `ProcessVADs`); the private VADs (`PrivateMemoryKnown` and `PrivateMemory`); the image VAD whose file name ends in `\services.exe` (`memoryranges.FileNames`). A target whose space or VADs do not read is reported and skipped; in strict mode the run fails.

### 4.2 Layouts

Each layout gives the tag, its offset, and the members of M3. Names are the builds they were measured on.

| Member | 14393 | 19041 | 26100 |
|---|---|---|---|
| Tag, offset | "sErv", +0 | "Sc19", +8 | "Sc19", +8 |
| Image pointer at +0 | no | yes | yes |
| Previous, next | +0x08, +0x98 | +0x10, +0x18 | +0x10, +0x18 |
| Service name, display name | +0x10, +0x18 | +0x38, +0x40 | +0x38, +0x40 |
| Sequence | +0x20 | +0x20 | +0x20 |
| `SERVICE_STATUS` | +0x40 | +0x48 | +0x50 |
| Start type, error control | +0x5c, +0x60 | +0x24, +0x28 | +0x24, +0x28 |
| Process or driver | +0x38 | +0x128 | +0x150 |
| Image record process ID | +0x20 | +0x28 | +0x28 |
| Head | "Sc17" sentinel, first at +0x98 | "Sc27", first +8, last +0x10, count +0x24, counter +0x20 | as 19041 |

An image record carries "Sc16" at +0 and its command line pointer at +0x18 (M8).

### 4.3 Record scan (`windows.service.scan`)

1. In each private VAD, read page by page up to `MaxRegionScanBytes`; a longer VAD is scanned to that bound and reported. Unread pages are skipped.
2. Each layout tag at a 4-aligned offset gives a candidate at the tag's address less its offset. The candidate start must be 16-aligned (M2). More than `MaxMatchesPerChunk` hits in one VAD stop that VAD's scan and are reported.
3. **Fit.** Decode every candidate with every layout of its tag (5.1). The layout that accepts the most candidates is chosen (M4). None accepts any → `ErrNoServiceRecords`. Two layouts accepting the same nonzero number → `ErrLayoutAmbiguous`.
4. The kernel build (`winkernel.FileSetBuild`) is compared with the layout's name. A build that is not one of the three, or whose layout is not the one chosen, is reported (`ErrUnmeasuredBuild`); strict mode fails the run.
5. Each accepted record becomes a row (4.6). `Listed` is set from the list walk of 4.4 when it succeeds.

### 4.4 List walk (`windows.service.list`)

1. **Head.** If the PDB loads (fingerprint from the image's CodeView record), the public of P1 or P2 gives the head. Otherwise search the image VAD at 8-aligned offsets for "Sc27" and "Sc17". A "Sc27" place counts when its +8 and +0x10 pointers decode as records under one layout whose previous (first) and next (last) links are null; a "Sc17" place when its +0x98 pointer decodes as a record whose previous link is that place (M5, M6). No place → `ErrNoServiceList`; more than one → `ErrNoServiceList` naming the count.
2. **Layout.** The head's tag gives the family. Within the family, walk with each layout and keep the one that reaches the most records.
3. **Walk.** From the first record follow the next link until it is null. Stop on a record that fails 5.1, on a repeat, or at `MaxListEntries` (`ErrServiceListIncomplete`). A previous link that is not the record before (null before the first on 19041 and 26100, the sentinel on 14393) is counted and reported.
4. **Head checks** (19041, 26100): the last record must be the head's last; the count at +0x24 must equal the walked records; the counter at +0x20 must be at or above every sequence. On 14393 with the PDB, `ScTotalNumServiceRecs` must equal the walked records. A failure is a diagnostic.
5. A cut walk returns the records before the cut and reports the cut; strict mode fails the run.

### 4.5 Comparison (`windows.service.compare`)

1. Run 4.3 and 4.4 on each target with the scan's layout.
2. **Unlinked.** An accepted record that the walk did not reach is a `unlinked` row, unless a listed record has its sequence number and, case-insensitively, its name (a copy, M7); copies are counted in a diagnostic.
3. **No registry key.** A listed or unlinked record whose name has no subkey under `CurrentControlSet\Services` is a `no registry key` row (D3 says each service has a key). When the subkey list is incomplete, no record is judged and that is reported.
4. **Registry only.** A subkey whose `Type` has one of the low six bits (D3) and that no listed record names is a `registry only` row. Keys without `Type` are not services (M10). When the list walk was cut, no key is judged.
5. A target whose fit or list walk fails, or whose walk was cut, gives no rows and is reported; strict mode fails the run. When no target is compared, the run fails.

### 4.6 Row values

1. Strings are NUL-terminated UTF-16 read through the target's space. The name and display name hold at most 256 characters (D3); the image path and driver object name at most `MaxNameBytes` bytes.
2. Status, start type and error control come from their members (D1, D3).
3. **Process.** For a Win32 type (0x10 or 0x20 set) not in state stopped: the union must point to an object tagged "Sc16"; its process ID and command line are read (M8). A null pointer or a missing tag sets `ProcessIDUnreadable`. A stopped service has process ID 0 (D2).
4. **Driver.** For a driver type (0x1 or 0x2): a non-null union must lead to a string beginning `\Driver\` or `\FileSystem\` (D3, M9); other text sets `DriverObjectNameUnreadable`.
5. **Registry.** The key with the service's name, compared case-insensitively (D3), supplies `ImagePath` and `Parameters\ServiceDll` (D4). Without the SYSTEM hive every row is `RegistryUnreadable`.

## 5. Validity rules

### 5.1 Record

| Rule | Justification | On failure |
|---|---|---|
| Tag at its offset; start 16-aligned | M1, M2 | Not a candidate |
| On 19041 and 26100 the pointer at +0 lies in the services.exe image | M1 | Rejected: `image pointer` |
| Name pointer reads a string of 1 to 256 characters without `/` or `\` | D3, M3 | Rejected: `name` |
| State 1 to 7 | D1, M4 | Rejected: `state` |
| Type has one of the low six bits and no bit above 0x1ff | D1, D3, D5, M11 | Rejected: `type` |
| Start type 0 to 4, error control 0 to 3 | D3 | Rejected: `start type`, `error control` |
| Sequence not 0 | M3 | Rejected: `sequence` |

A display name that does not read sets `DisplayNameUnreadable`; it does not reject.

### 5.2 List

| Rule | Justification | On failure |
|---|---|---|
| Head tag at the PDB global, or one validated image place | P1, P2, M5, M6 | `ErrNoServiceList` |
| Every walked record passes 5.1; no repeat; within `MaxListEntries` | M5 | Walk cut, `ErrServiceListIncomplete` |
| Previous link is the record before | M5 | Counted, reported |
| Head last, count and counter agree | M5 | Reported |

## 6. Failure modes

| Case | Result |
|---|---|
| No services.exe | `ErrNoServicesProcess` |
| 32-bit symbol table | `ErrPointerSize` |
| A target's space or VADs do not read | `windows.service.<verb>: services.exe pid <n> at 0x<eprocess>: <what> not read: %w`; target skipped; strict mode fails |
| No layout accepts a record | `ErrNoServiceRecords` |
| Two layouts tie | `ErrLayoutAmbiguous` |
| Build not measured, or another layout fits | Diagnostic wrapping `ErrUnmeasuredBuild`; strict mode fails |
| VAD longer than `MaxRegionScanBytes`, or tag hits past `MaxMatchesPerChunk` | Diagnostic; rest of that VAD not scanned |
| No head | `ErrNoServiceList` |
| Walk cut | Records before the cut; diagnostic `windows.service.<verb>: service record at 0x<addr>: walk stopped after <n> records: %w`; strict mode fails; a cut before the first record fails the run |
| SYSTEM hive or `Services` key not read | Rows marked `RegistryUnreadable`; compare reports no registry findings and says so |

## 7. Result schema

All three tools return `[]servicerecord.Service`:

| Field | Type | Meaning |
|---|---|---|
| `RecordAddress` | uint64 | Record start in services.exe; 0 for `registry only` rows |
| `SCMProcessID` | uint64 | The services.exe process |
| `Listed` | bool | The record is on the SCM's list (scan: when the walk succeeded; list: always) |
| `Finding` | `Finding` | Compare only: `unlinked`, `no registry key`, `registry only` |
| `Sequence` | uint32 | The record's sequence number |
| `ServiceName`, `DisplayName` | string | |
| `ServiceType` | `ServiceType` | Bit names joined by `|`: `kernel driver`, `file system driver`, `adapter`, `recognizer driver`, `own process`, `share process`, `user service`, `user service instance`, `interactive`; other bits as `0x…` |
| `CurrentState` | `CurrentState` | `stopped`, `start pending`, `stop pending`, `running`, `continue pending`, `pause pending`, `paused` |
| `StartType` | `StartType` | `boot`, `system`, `auto`, `demand`, `disabled` |
| `ErrorControl` | `ErrorControl` | `ignore`, `normal`, `severe`, `critical` |
| `ControlsAccepted`, `Win32ExitCode`, `ServiceSpecificExitCode` | uint32 | As read (D1) |
| `ProcessID` | uint32 | 0 when stopped or a driver |
| `ImagePath` | string | The image record's command line |
| `DriverObjectName` | string | |
| `RegistryKeyFound` | bool | |
| `RegistryImagePath`, `RegistryServiceDll` | string | |
| `DisplayNameUnreadable`, `ProcessIDUnreadable`, `ImagePathUnreadable`, `DriverObjectNameUnreadable`, `RegistryUnreadable` | bool | |

`registry only` rows take `ServiceType`, `StartType` and `ErrorControl` from the key's values and leave the state empty. Sort: scan by target, then address; list by target, then walk order; compare by target, finding in the order above, then address, then name.

## 8. Limits

- `MaxRegionScanBytes`: bytes of one private VAD scanned. The default (1 GiB) covers the measured heap VADs (at most 16 MB, M2) and bounds the 4 GiB reservation.
- `MaxMatchesPerChunk`: tag hits kept per VAD.
- `MaxListEntries`: records walked.
- `MaxNameBytes`: bytes of an image path or driver object name.

## 9. Acceptance

1. Synthetic fixtures (`tools/windows/servicerecord/s34_fixture_test.go`) build each of the three layouts in a sparse address space: every rule of 5.1, the fit and its tie, the 16-byte alignment, each head form with and without a PDB global, a walk cut by a failing record, a repeat and the entry cap, a wrong back link, head counts, copies and unlinked records, the registry findings with complete and incomplete key lists, process and driver values, and the value names of 7.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzDecodeRecord` (arbitrary record and string bytes under each layout; an accepted record obeys 5.1): 2.43 million executions. `FuzzWalkList` (arbitrary heap and head bytes; the walk ends within the cap and never repeats a record; the head search runs on the same bytes): 1.76 million executions.
3. On the captures, `servicefacts -tool` on 2026-11-12 (online, so the PDB loads where the CodeView page is resident):

| Capture | Build | Keys (with `Type`) | Scan rows (listed) | List rows | Compare rows |
|---|---|---|---|---|---|
| mem1_win11 | 26100 | 729 (681) | 689 (680) | 680 | 1: registry only `Fs_Rec` |
| mem2_win10 | 19045 | 727 (672) | 674 (673) | 673 | 4: unlinked and no registry key for the record "ā" at 0x1d95da66500; registry only the acquisition driver and `Fs_Rec` |
| mem5_server2016 | 14393 | 553 (501) | 500 (500) | 500 | 1: registry only `Fs_Rec` |
| mem6_server2025 | 26100 | 681 (635) | 633 (633) | 633 | 2: registry only the acquisition driver and `Fs_Rec` |
| mem7_server2025 | 26100 | 683 (637) | 635 (635) | 635 | 2: registry only the acquisition driver and `Fs_Rec` |

   - The list's head comes from the PDB global on mem1, mem2, mem5 and mem7, and from the image search on mem6 (M6). Every list matches M5: no back link disagrees and no head check fails.
   - List rows with a process ID: 81, 104, 80, 99, 108; with a driver object name: 151, 100, 75, 109, 84, and 16 marked unreadable on mem7 (M9); with a registry `ServiceDll`: 229, 214, 161, 193, 191. 32 display names on mem7 do not read.
   - Every scan row has a registry key except the mem2 record "ā" (M7).
   - mem1 compare reports its 9 copies (M7) in a diagnostic.
   - The 0x100020000-byte private VAD is scanned to `MaxRegionScanBytes` and reported on the four captures that have it (M2).
   - The layout the fit chose is the one measured for the capture's build on all five; no build diagnostic is given.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The record and head layouts, the tags, the 16-byte alignment and the image record's members rest on measurements only (M1 to M8); the PDBs have no types. | Owner decision on measured constants |
| O2 | Builds other than 14393, 19041-19045 and 26100 are read with whichever measured layout fits and are reported. A build whose layout moved fits none and fails. | Captures of 17763, 22621 and later builds |
| O3 | Copies of listed records (M7) are counted, not shown. | Owner decision: show them as their own finding |
| O4 | `Fs_Rec` (type 0x8, "Reserved" in D3) has a key and no record on all five captures and is reported as `registry only` every time. | Owner decision: leave recognizer drivers out |
| O5 | `ServiceDll` under `Parameters` is read by the registry join; Microsoft Learn documents `Parameters` for drivers only (D4). | Owner decision |
| O6 | Row field names, finding names and value names are new (Q2); 0.1.0's `Offset`, `Order`, `PID`, `Start`, `State`, `Type`, `Name`, `Display`, `Binary`, `BinaryRegistry`, `Dll` and their `…Unreadable` flags are renamed or split (7). | Owner decision |
| O7 | The type bit 0x80 is named `user service instance` from D5's wording and M11 (instances 0xd0, 0xe0); no page gives the value. 0x200 is not admitted. | A Learn page with the value |
| O8 | 32-bit services.exe is not measured. | A 32-bit capture (Q7) |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep the measured constants |
| O2 | Defer; fit and report |
| O3 | Count only |
| O4 | Keep reporting registry only |
| O5 | Keep reading it |
| O6 | Accept the new names |
| O7 | Keep the name |
| O8 | Defer |

## 11. Provenance

Written from Microsoft Learn's service documentation, the public symbols of the captures' services.pdb read through the project's symbol tables, the project's registry reader and the project's measurements. Every rule rests on the sources and measurements above.
