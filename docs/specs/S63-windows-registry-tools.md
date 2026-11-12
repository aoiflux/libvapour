# S63: Windows registry tools

Version 1, 2026-11-12.

## 1. Purpose

Ten tools answer an examiner's questions from the registry hives held in memory. Each reads the hives through the S49 reader (`registryhive`): its cell map, its key and value decoding and its hive selection.

| # | Tool | Package | Question |
|---|---|---|---|
| T1 | `windows.registry.scan_hives` | registryhivescan | Which hive objects are in kernel pool, including any no longer on the kernel's hive list? |
| T2 | `windows.registry.check_cell_routine` | registrycellroutine | Does each hive's cell lookup and release routine point into the kernel image, as Windows sets it, or somewhere else? |
| T3 | `windows.registry.read_key` | registrykey | What subkeys and values does a key hold, in one hive or in every hive? |
| T4 | `windows.registry.read_system_profile` | registrysystemprofile | Which Windows product and build is this, when was it installed, what is the computer called and what time zone does it keep? |
| T5 | `windows.registry.list_mounted_devices` | registrymounteddevices | Which drive letters, mount points and volume names has the mount manager recorded, and which of them name the same volume? |
| T6 | `windows.service.read_registry` | serviceregistry | How is each service configured in the current control set? |
| T7 | `windows.service.list_sids` | servicesids | What is the service SID of each service key? |
| T8 | `windows.software.list` | softwarelist | Which programs are registered for removal in the machine and user hives? |
| T9 | `windows.execution.read_compat_cache` | executioncompatcache | What did the compatibility cache hold the last time it was written to the SYSTEM hive? |
| T10 | `windows.execution.read_amcache` | executionamcache | Which program files, applications and drivers does the Amcache hive inventory? |

T9 is the on-disk counterpart of S41 (`windows.execution.list_compat_cache`, the cache in kernel memory); S41's code facts give the value's record format, and the two are cross-checked (M24).

## 2. Inputs

| Input | Use |
|---|---|
| Hives | `registryhive.GatherHives`, `OpenHive`, `OpenEveryHive`, `SelectHives`, `CellReader`, `CurrentControlSet` and `CurrentControlSetChecked` (S49 4.7, 4.8). T1 is the pool scan `registryhive` gathers from, so it reads kernel memory itself. |
| Kernel symbol table | `_CMHIVE`, `_HHIVE` (P1 to P3), `_UNICODE_STRING`, `CmpHiveListHead`; the pointer size. |
| Big-pool table | S52 `poolbig.ReadTable` (T1). |
| Loaded modules | S55 `modulelist.Run` and `Placed` (T2). |
| Options | T3: `windows.registry.read_key.hive` (string, S49 4.7 step 6 selection), `.path` (string, key path in the hive), `.recurse` (bool), `.validate_bins` (bool, S49 4.3 step 6). The other tools have no option of their own. All take `strict` and `diagnostics`. |
| Limits | `MaxListEntries` (T1 hive list walk), `MaxNameBytes` (T1 path strings). Key and value lists are bounded inside `registryhive` (`MaxListEntries`, `MaxBufferBytes`). |

## 3. Facts from the sources

### 3.1 Documentation

Microsoft Learn pages, accessed 2026-11-12.

| # | Fact | Source |
|---|---|---|
| D1 | Value type numbers: `REG_NONE` 0, `REG_SZ` 1, `REG_EXPAND_SZ` 2, `REG_BINARY` 3, `REG_DWORD` 4, `REG_DWORD_BIG_ENDIAN` 5, `REG_LINK` 6, `REG_MULTI_SZ` 7, `REG_RESOURCE_LIST` 8, `REG_QWORD` 11. No number is given for any other type. | [MS-RPRN] "Registry Type Values", updated 2025-08-11; [MS-RRP] 2.2.5 (S49 D1, D2) |
| D2 | "A registry tree can be 512 levels deep." Key names are not case sensitive; each subkey's name is unique under its parent. | "Registry element size limits", 2022-07-22; "Structure of the Registry", updated 2025-04-15 (S49 D4, D5) |
| D3 | A FILETIME counts 100-nanosecond intervals since January 1, 1601 (UTC). | "FILETIME (minwinbase.h)", ms.date 2018-12-05 |
| D4 | `TIME_ZONE_INFORMATION.Bias` is "the difference, in minutes, between Coordinated Universal Time (UTC) and local time": "UTC = local time + bias"; `StandardBias` and `DaylightBias` are added to `Bias` during standard and daylight time. | "TIME_ZONE_INFORMATION (timezoneapi.h)", ms.date 2018-12-05, updated 2024-02-22 |
| D5 | The mount manager keeps its persistent name database in the `MountedDevices` key of the SYSTEM hive. Each persistent symbolic link name is a value name under the key, "accompanied by a unique ID", which the volume's driver supplies; all names of one volume share the unique ID. Names are unique volume names `\??\Volume{GUID}`, drive letters such as `\DosDevices\D:` and mount points such as `\DosDevices\C:\mymount`. | "Supporting Mount Manager Requests in a Storage Class Driver", ms.date 2024-06-05, updated 2025-03-25 |
| D6 | Service types `SERVICE_KERNEL_DRIVER` 0x1, `SERVICE_FILE_SYSTEM_DRIVER` 0x2, `SERVICE_ADAPTER` 0x4, `SERVICE_RECOGNIZER_DRIVER` 0x8, `SERVICE_WIN32_OWN_PROCESS` 0x10, `SERVICE_WIN32_SHARE_PROCESS` 0x20, `SERVICE_USER_OWN_PROCESS` 0x50, `SERVICE_USER_SHARE_PROCESS` 0x60, `SERVICE_INTERACTIVE_PROCESS` 0x100; start types `SERVICE_BOOT_START` 0 to `SERVICE_DISABLED` 4; error control 0 to 3. CreateService makes a key named after the service under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services` holding `DisplayName`, `ErrorControl`, `Group`, `ImagePath`, `ObjectName`, `Start`, `Tag` and `Type`. Service names compare without case. | "CreateServiceW function (winsvc.h)", updated 2025-07-01; "SERVICE_STATUS structure", updated 2024-02-22 (S34 D1, D3) |
| D7 | A per-user service's type includes the bit 64 (0x40); templates live under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`, instances are named `<service name>_LUID`. | "Per-user services", ms.date 2024-10-01, updated 2025-09-24 |
| D8 | A service SID is `S-1-5-80-` and the five 32-bit words of the SHA-1 of the upper-cased UTF-16 service name; example `ALG` gives `S-1-5-80-2387347252-3645287876-2469496166-3824418187-3586569773`. | [MS-LSAT] 3.1.1.1.2, updated 2024-05-01 (S45 D7) |
| D9 | Values under `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\<product code>` include `DisplayName`, `DisplayVersion`, `Publisher`, `InstallDate` ("the last time this product received service", else the install time), `InstallLocation` and `UninstallString`. | "Windows Installer Properties for the Uninstall Registry Key", ms.date 2018-05-31, updated 2025-04-15 |
| D10 | `HKEY_LOCAL_MACHINE\SOFTWARE` is redirected for WOW applications; `Wow6432Node` is "the redirected registry location for x86 processes running on AMD64 Windows installations". | "Registry Keys Affected by WOW64", ms.date 2021-01-23, updated 2025-10-23 |
| D11 | A GUID's packet form is `Data1` (4 bytes), `Data2` and `Data3` (2 bytes each), in little-endian byte order, then `Data4` (8 bytes); its curly braced string form is `{` UUID `}`, for example `{f81d4fae-7dec-11d0-a765-00a0c91e6bf6}`. | [MS-DTYP] 2.3.4.2 "GUID--Packet Representation" and 2.3.4.3 "GUID--Curly Braced String Representation", updated 2024-10-30 |
| D12 | The PE file header's `TimeDateStamp` is "the low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value)". | "PE Format", section "COFF File Header", accessed 2026-11-12 |

No Microsoft document describes the AppCompatCache value, the Amcache hive, the `CurrentVersion` values of T4 or the form of a mount manager unique ID. Those facts are measured.

### 3.2 Kernel PDB types

Read through the project's symbol tables for the captures' ntkrnlmp.pdb (S49 3, GUIDs 0D960CE1 mem1, F57E740B mem2, 3DFC5F72 mem5, 953A8DE8 mem6 and mem7), with `registrytoolfacts -scan -routine`.

| # | Fact |
|---|---|
| P1 | `_CMHIVE` is 0x12d8 bytes on 26100, 0x12e8 on 19045 and 0x17a8 on 14393, and begins with `Hive` (`_HHIVE`, +0). Its `FileFullPath`, `FileUserName`, `HiveRootPath` and `HiveList` members are those of S49 P1. |
| P2 | `_HHIVE` has `Signature` (+0), `GetCellRoutine` (+0x8), `ReleaseCellRoutine` (+0x10), `Allocate` (+0x18), `Free` (+0x20), `FileWrite` (+0x28) and `FileRead` (+0x30) on all three builds. |
| P3 | `HvpGetCellPaged`, `HvpGetCellFlat`, `HvpReleaseCellPaged` and `HvpReleaseCellFlat` are public symbols of every kernel. |

### 3.3 Measurements

`registrytoolfacts`, 2026-11-12, over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100). Counts are given in that order. The script reads keys through `registryhive`, the pool through `poolbig`, modules through `modulelist`, SCM records through S34 `servicerecord.List`, token SIDs through S45 `tokensids.Run` and the kernel cache through S41.

Hive objects (T1, T2):

| # | Measured |
|---|---|
| M1 | Every hive on the hive list (24, 29, 19, 29, 24) is the start address of an in-use big-pool allocation tagged `CM10`; no listed hive lies inside an allocation of any other tag except freed allocations that a later one reused. In-use `CM10` allocations: 24, 29, 19, 29, 24, each with `_HHIVE.Signature` 0xbee0bee0 and each on the list. Freed `CM10` allocations: 12, 16, 0, 0, 24; none holds the signature (10, 16, 24 hold other values, 2 on mem1 do not read). |
| M2 | `CM10` allocation sizes: 0x12e0 (26100), 0x12f0 (19045), 0x17b0 (14393), 8 bytes above `sizeof(_CMHIVE)` on every build. |
| M3 | `GetCellRoutine` is `HvpGetCellPaged` and `ReleaseCellRoutine` is `HvpReleaseCellPaged` in all 125 hives, each inside the kernel image (the loaded module that holds `CmpHiveListHead`). |

Keys and values (T3):

| # | Measured |
|---|---|
| M4 | All keys of all hives, walked from each root: 189,968, 102,750, 305,637, 71,418 and 44,907 keys; the deepest key lies 12, 24, 17, 13 and 13 levels below its root. Volatile keys (cell index bit 31): 405, 1,849, 244, 4,442, 4,149. |
| M5 | Value types outside D1 occur on every capture: 9, 10, 14, 18, 23, 24 and others, numbers from 500 to 583 in the SAM hive, and large numbers such as 0x10000000x and 0xFFFF00xx (mem1: 0xFFFF0012 1,047 values). |

System profile (T4):

| # | Measured |
|---|---|
| M6 | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` reads whole on all five, with REG_SZ `ProductName`, `EditionID`, `CurrentBuild`, `CurrentBuildNumber`, `BuildLabEx`, `InstallationType`, `RegisteredOwner`, `RegisteredOrganization`, `ProductId`, REG_DWORD `UBR` and `InstallDate`, and REG_QWORD `InstallTime`; `DisplayVersion` on 26100 and 19045, `ReleaseId` on all. |
| M7 | `CurrentBuild` equals the kernel's `NtBuildNumber` (S03 build reader) on all five (26100, 19045, 14393, 26100, 26100). |
| M8 | `InstallDate`, read as seconds since 1970 UTC, and `InstallTime`, read as a FILETIME (D3), name the same second on all five (`InstallTime` 0.38 to 0.71 s later). |
| M9 | `TimeZoneInformation` holds REG_DWORD `Bias` and `ActiveTimeBias`: -330 and -330 on mem1, mem2, mem5; 480 and 420 on mem6, mem7. `ActiveTimeBias` × 600,000,000 equals `_KUSER_SHARED_DATA.TimeZoneBias` (100 ns units) on all five. |
| M10 | `Select\Current` reads 1 on mem1, mem5, mem6 and mem7; on mem2 it does not read and `ControlSet001` is used (S49 9.3). `ComputerName\ComputerName` and `ComputerName\ActiveComputerName` hold the same `ComputerName`. |

Mounted devices (T5):

| # | Measured |
|---|---|
| M11 | `MountedDevices` values: 1, 5, 3, 1; on mem7 the key does not read (the root's subkey list is incomplete). Names: drive letters 1, 4, 2, 1; `\??\Volume{…}` names 0, 1, 1, 0. All values are REG_BINARY. |
| M12 | Unique IDs are of two forms: 24 bytes beginning with the ASCII bytes `DMIO:ID:` (1, 4, 1, 1) and UTF-16LE text beginning `\??\SCSI#` (0, 1, 2, 0; 180 and 206 bytes). No other form occurs. On mem5 one `\??\Volume{…}` name and `\DosDevices\D:` share a unique ID (D5). |

Services (T6, T7):

| # | Measured |
|---|---|
| M13 | `<current control set>\Services` holds 729, 727, 553, 681 and 683 subkeys, each list read whole; no name is outside ASCII. Keys with no `Type` value: 48, 55, 52, 46, 46. Value lists not read whole: 0, 6, 0, 1, 0. |
| M14 | `Type`, `Start` and `ErrorControl` are REG_DWORD wherever present; `ImagePath` is REG_EXPAND_SZ or REG_SZ; `DisplayName` REG_SZ or REG_EXPAND_SZ; `ObjectName` and `Group` REG_SZ. Two `Group` values on mem2 do not read. |
| M15 | `Type` values: 0x1, 0x2, 0x8, 0x10, 0x20, 0x50, 0x60, 0x110, 0x120 (D6) and 0xd0, 0xe0 (1 and 22 on mem1, 1 and 19 on mem2, 0 and 6 on mem5, 1 and 18 on mem6 and mem7): the bit 0x80 with a per-user type (D7). No Microsoft page names 0x80. |
| M16 | Every service record on the SCM's list (680, 673, 500, 633, 635) has a key of the same name. |
| M17 | Distinct `S-1-5-80-` SIDs in process tokens: 163, 95, 122, 158, 153; the D8 SID of a service key matches 162, 94, 122, 157 and 152 of them. The D8 derivation reproduces the `ALG` example. |

Uninstall keys (T8):

| # | Measured |
|---|---|
| M18 | SOFTWARE `Microsoft\Windows\CurrentVersion\Uninstall` subkeys: 13, 24, 24, 17, 18 (with `DisplayName` 1, 10, 11, 1, 2); `Wow6432Node\…\Uninstall`: 13, 18, 17, 16, 16 (2, 6, 3, 2, 2). Every `InstallDate` that reads is eight digits `yyyymmdd`; `DisplayName`, `DisplayVersion`, `Publisher` are REG_SZ; `InstallLocation` and `UninstallString` REG_SZ or REG_EXPAND_SZ. On mem6 one value of each list does not read. |
| M19 | `NTUSER.DAT` hives hold `Software\Microsoft\Windows\CurrentVersion\Uninstall` with 0, 2, 2, 0, 1 subkeys (the user profiles of mem2, mem5 and mem7), each with `DisplayName`; the key does not read in 3, 0, 0, 2, 2 service-profile hives. |

AppCompatCache value (T9):

| # | Measured |
|---|---|
| M20 | `<current control set>\Control\Session Manager\AppCompatCache` holds REG_BINARY `AppCompatCache`, `CacheMainSdb` and `SdbTime`. `AppCompatCache` is 29,162 and 76,540 bytes and reads whole on mem1 and mem5; on mem2, mem6 and mem7 (205,386, 51,240, 66,610 bytes) none of its data is resident (S41 M4). |
| M21 | The first 32-bit word is 0x34 on mem1 (26100) and 0x30 on mem5 (14393), and is the offset of the first record. |
| M22 | From that offset the value is a run of records, each the 32-bit signature 0x73743031 (bytes `10ts`), a 32-bit CRC and a 32-bit payload length, then the payload (S41 C7, C8). Each payload is a 16-bit key length, the key (UTF-16LE), a 64-bit FILETIME, a 32-bit data size and the data (S41 C9, C10); the data ends the payload exactly. Records: 139 and 256; the CRC-32 (IEEE polynomial) of the payload matches in all; the records end exactly at the value's end. |
| M23 | The FILETIME is 0 in 49 and 15 records (the package keys of S41 M7). |
| M24 | Against S41's in-memory cache: mem5 256 of 256 records match an entry by key, with the same time, the same data and the same position; mem1 137 of 139 match by key, 136 with the same time, 129 with the same data (the cache changed after the value was written). |

Amcache hive (T10):

| # | Measured |
|---|---|
| M25 | One hive whose file path contains `amcache` is loaded on mem2, mem5 and mem6 (`\??\C:\Windows\AppCompat\Programs\Amcache.hve`, mounted under `\REGISTRY\A\{…}`); none on mem1 and mem7. |
| M26 | `Root\InventoryApplicationFile` keys: 785, 52, 237. On 19045 and 26100 each key is named `<file name>|<16 hex digits>` and holds REG_SZ `LowerCaseLongPath` (lower case in all), `Name`, `FileId`, `ProgramId`, `Publisher`, `ProductName`, `Version`, `LinkDate` and REG_QWORD `Size`; on 14393 each key is a 44-digit identifier and holds only `BinaryType`, `FileId`, `LongPathHash`, `LowerCaseLongPath`, `ProgramId` and `Size`. `FileId` is `0000` and 40 lower-case hexadecimal digits in 785, 52 and 235 keys (2 empty on mem6). `LinkDate` is `MM/DD/YYYY HH:MM:SS` in 784 and 233 keys (1 empty, 4 other). `ProgramId` names an `InventoryApplication` key in 522, 52 and 53. |
| M27 | `Root\InventoryApplication` keys: 99, 30, 53, each named `0000` and 40 hexadecimal digits, with `ProgramId` equal to the key name in all; REG_SZ `Name`, `Publisher`, `Version`, `RootDirPath`, `InstallDate` (`MM/DD/YYYY HH:MM:SS` or empty). |
| M28 | `Root\InventoryDriverBinary` keys: 379, 290, 380. On 19045 and 26100 each key is the driver's path with forward slashes (`c:/windows/system32/drivers/1394ohci.sys`) and holds `DriverId` (`0000` and 40 hexadecimal digits); on 14393 the key is a 44-digit identifier and `DriverName` holds the file name. `DriverTimeStamp` is REG_DWORD in all; for the drivers loaded at capture time it equals the PE `TimeDateStamp` (D12) at the module's base in 136 of 136 (mem2) and 102 of 102 (mem6). |
| M29 | On 14393 the hive also holds `Root\File` and `Root\Programs`, whose values have numeric names (`0`, `1`, `15`, `101`, …) and no measured meaning. |

## 4. Algorithm

### 4.1 T1 hive objects in pool

1. Read the big-pool table (S52). Keep allocations tagged `CM10` (M1). Freed ones are counted and skipped (M1); an allocation smaller than `sizeof(_CMHIVE)` is counted and skipped (M2).
2. Read the 32-bit `_HHIVE.Signature` at the allocation's address + `_CMHIVE.Hive` (P1, P2). 0xbee0bee0 (S49 M1): a row, `Verified`. Another value: counted and skipped. Not readable: a row, not `Verified`.
3. Read `FileFullPath`, `FileUserName` and `HiveRootPath` (`_UNICODE_STRING`, at most `MaxNameBytes`). `FilePath` is the first of the three that is not empty (S49 4.7 step 3); `RegistryPath` is `HiveRootPath`.
4. Walk `CmpHiveListHead` with the S03 recovering walker; an entry less `_CMHIVE.HiveList` is a listed hive. `OnHiveList` is `listed` or `not_listed`; `unknown` when the symbol, the member or the walk is missing.
5. Rows by address.

### 4.2 T2 cell routines

1. Gather the hives (S49 4.7 step 7). None: `ErrNoHive`.
2. List the loaded modules (S55) and keep those with a range. The kernel image is the module that holds the address of `CmpHiveListHead`, else the module whose base is the session's kernel base.
3. For each hive and each of `GetCellRoutine` and `ReleaseCellRoutine` that the table has (P2), read the pointer at hive + `_CMHIVE.Hive` + the member. Place it: `null`, `kernel_image` (inside the kernel image; the kernel symbol at that address is named, P3), `other_module`, `no_module`, or `unreadable`.
4. One row per hive and routine, in gathering order then member order. A routine outside the kernel image is reported in one diagnostic (M3 finds none).

### 4.3 T3 key listing

1. Read the options. Gather the hives and select them with the `hive` option (S49 4.7 step 6). No hive: `ErrNoHive`; none selected: `ErrNoMatch`.
2. For each selected hive: open it (S49 `NewHiveLayer`, the Registry process reader, bin checking when `validate_bins`). A hive that does not open is reported and gives no row.
3. Resolve the root and each component of `path` (S49 4.8). The root or a component that does not read, or a component that does not exist: one row of kind `key` for the requested path with `KeyNotRead` and the reason, a diagnostic, and the next hive. A key that does not read, but not one that is absent, makes strict mode return `ErrIncomplete`.
4. List the key: one `key` row per subkey, then one `value` row per value. With `recurse`, each subkey's listing follows its row, depth first. A subkey is not entered when its name did not read, when it is the listing key or one of its ancestors, when it was listed before (D2: one parent), or when it lies 512 levels below the root (D2).
5. A subkey or value list that did not read whole is reported; strict mode then returns the rows and `ErrIncomplete`.
6. Hives in gathering order; rows in list order within a hive.

### 4.4 T4 system profile

1. Open `SOFTWARE` and `SYSTEM` by exact name (S49 4.7). Neither: `ErrNoHive`.
2. From `SOFTWARE\Microsoft\Windows NT\CurrentVersion` read, in this order: `ProductName`, `EditionID`, `DisplayVersion`, `ReleaseId`, `CurrentBuild`, `CurrentBuildNumber`, `UBR`, `BuildLabEx`, `InstallationType`, `InstallDate`, `InstallTime`, `RegisteredOwner`, `RegisteredOrganization`, `ProductId` (M6).
3. From `SYSTEM`: `Select\Current` (S49 4.8 step 4); then from the current control set `Control\ComputerName\ComputerName` and `Control\ComputerName\ActiveComputerName` value `ComputerName` (M10), and `Control\TimeZoneInformation` values `TimeZoneKeyName`, `StandardName`, `DaylightName`, `Bias`, `ActiveTimeBias` (M9).
4. One row per value found. String types give the text as stored; REG_DWORD and REG_QWORD give decimal. `InstallDate` also gives a time as seconds since 1970 UTC and `InstallTime` as a FILETIME (M8). `Bias` and `ActiveTimeBias` are signed minutes and also give the UTC offset of local time, −bias (D4, M9), as `UTC+hh:mm`.
5. A value whose list or data did not read gives a row with `Unreadable` and a diagnostic. A key that does not read is reported. A value that is absent gives no row. When `Select\Current` does not read, the facts read from `ControlSet001` say so in a diagnostic.

### 4.5 T5 mounted devices

1. Open `SYSTEM`; open `MountedDevices`. Either fails: the tool fails with `ErrUnreadable`.
2. One row per value. The name's kind (D5): `\DosDevices\` and a letter and a colon is `drive_letter`; a longer `\DosDevices\` name is `mount_point`; `\??\Volume{` … `}` is `volume_name`; anything else `other`.
3. The unique ID is the value's data. Its form (M12): 24 bytes beginning `DMIO:ID:` is `dmio_id` and its last 16 bytes are written as a GUID (D11); UTF-16LE text whose first character is a backslash and that holds no control character is `device_path`; any other `other`, written as hexadecimal.
4. Each row also names the `volume_name` rows that have the same unique ID (D5).
5. Sort: drive letters, mount points, volume names, other; then by name ignoring case.

### 4.6 T6 service configuration

1. Open `SYSTEM`; take the current control set (S49 4.8 step 4); open `Services`. Failure: `ErrServicesUnread`.
2. One row per subkey: its name, last write time, and the values of D6: `Type`, `Start`, `ErrorControl`, `Tag` (REG_DWORD), `ImagePath`, `DisplayName`, `ObjectName`, `Group` (string types).
3. Each value is present, absent or unreadable. A value list that did not read whole leaves every value it did not find unreadable, not absent. A numeric value of another type or length is unreadable.
4. `Type` is named by its D6 bits (`kernel_driver`, `file_system_driver`, `adapter`, `recognizer_driver`, `win32_own_process`, `win32_share_process`, `user_service` for 0x40 (D7), `interactive_process`); other bits are written in hexadecimal (M15). `Start` and `ErrorControl` are named by D6.
5. Sort by name ignoring case (D6).

### 4.7 T7 service SIDs

1. As 4.6 step 1.
2. For each subkey whose name read, the SID of D8: upper-case the name by Unicode simple case mapping one UTF-16 unit to one, hash its UTF-16LE bytes with SHA-1, write `S-1-5-80` and the five little-endian 32-bit words in decimal.
3. Names that did not read are counted in a diagnostic. Sort by service name ignoring case.

### 4.8 T8 uninstall entries

1. Take the first hive in load order whose name is `SOFTWARE` exactly (S49 4.7 step 6 exact match, as `OpenHive` picks it). Read `Microsoft\Windows\CurrentVersion\Uninstall` (view `native`, D9) and `Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall` (view `wow64`, D10).
2. Every hive whose file name is `NTUSER.DAT`: `Software\Microsoft\Windows\CurrentVersion\Uninstall` (view `user`, M19).
3. One row per subkey: its name and last write time and the D9 values `DisplayName`, `DisplayVersion`, `Publisher`, `InstallDate`, `InstallLocation`, `UninstallString`, as stored. A value that did not read is named in `Unread`.
4. A key that is absent is skipped; one that does not read is reported. SOFTWARE not opening: `ErrNoHive`.
5. Sort by `DisplayName` ignoring case, then key name, view and hive path.

### 4.9 T9 compatibility cache value

1. Open `SYSTEM`; read `<current control set>\Control\Session Manager\AppCompatCache` value `AppCompatCache` (M20). Not found: `ErrNoValue`. Its list incomplete and the value not found: `ErrIncomplete`. No data byte read: `ErrValueUnread`.
2. The first 32-bit word is the header size; 0x30 and 0x34 are accepted (M21), any other is `ErrHeader`.
3. From the header size, decode records (M22): signature 0x73743031, CRC, payload length. Each payload: key length, key (UTF-16LE, even length), FILETIME, data size, data. A payload past the data read, a payload whose parts do not fit, or bytes left after the last record end the walk with `ErrRecord`. The CRC-32 of the payload is compared and the result kept on the row.
4. Rows in record order; `Position` counts from 0 (the record order is the cache's most-recent-first order, S41 C8).
5. When the data read is shorter than the value, or the walk stops before the end, a diagnostic reports it; strict mode returns the rows and the error.

### 4.10 T10 Amcache inventory

1. Open the first listed hive whose file path or registry path contains `amcache`, ignoring case (`registryhive.OpenEveryHive`, M25). None: `ErrNoHive`.
2. For each of `Root\InventoryApplicationFile` (`application_file`), `Root\InventoryApplication` (`application`) and `Root\InventoryDriverBinary` (`driver_binary`) that exists, one row per subkey: its name and last write time, and the values of M26 to M28 by name:

| Field | application_file | application | driver_binary |
|---|---|---|---|
| `Path` | `LowerCaseLongPath` | `RootDirPath` | the key name when it holds `/`, else empty |
| `Name` | `Name` | `Name` | `DriverName` |
| `FileID` | `FileId` | none | `DriverId` when the key name holds `/`, else the key name |
| `ProgramID` | `ProgramId` | `ProgramId` | none |
| `Publisher` | `Publisher` | `Publisher` | `DriverCompany` |
| `Product` | `ProductName` | none | `Product` |
| `Version` | `Version` | `Version` | `DriverVersion` |
| `LinkDate` | `LinkDate` as stored | none | none |
| `InstallDate` | none | `InstallDate` as stored | none |
| `LinkTime` | none | none | `DriverTimeStamp` as seconds since 1970 UTC (D12, M28) |
| `Service` | none | none | `Service` |

3. `FileIDHash` is the 40 digits after `0000` when `FileID` is `0000` and 40 lower-case hexadecimal digits (M26 to M28). String values must be REG_SZ or REG_EXPAND_SZ; another type is unread.
4. A value that did not read is named in `Unread`. `Root\File` and `Root\Programs` are not decoded (M29); their presence is reported.
5. Rows in category order of step 2, then key list order.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| T1: tag `CM10`, in use | M1 | Skipped, counted |
| T1: allocation at least `sizeof(_CMHIVE)` | M2 | Skipped, counted |
| T1: `_HHIVE.Signature` 0xbee0bee0 | S49 M1, M1 | Skipped, counted; unreadable gives an unverified row |
| T2: routine inside the kernel image | M3 | Row `other_module` or `no_module`; diagnostic |
| T3: depth below the root under 512 | D2 | Subtree not entered; diagnostic |
| T3: a key under one parent only; no cycle | D2 | Subtree not entered again; diagnostic |
| T4: REG_DWORD of 4 bytes, REG_QWORD of 8 | D1 | Row `Unreadable` |
| T5: name forms | D5 | Kind `other` |
| T5: unique ID forms | M12 | Form `other` |
| T6: numeric values REG_DWORD of 4 bytes | D6, M14 | Unreadable |
| T9: header size 0x30 or 0x34 | M21 | `ErrHeader` |
| T9: record signature 0x73743031; parts fit the payload; key length even | M22, S41 C7 to C10 | Walk ends; `ErrRecord` |
| T9: CRC-32 of the payload | M22 | `ChecksumValid` false |
| T10: `FileId`/`DriverId` `0000` and 40 lower-case hexadecimal digits | M26 to M28 | `FileIDHash` empty |
| T10: `DriverTimeStamp` REG_DWORD of 4 bytes | M28 | `LinkTime` zero, `Unread` |

## 6. Failure modes

| Case | Result |
|---|---|
| Profile not Windows | Run error `<tool>: unsupported profile os "<os>"` |
| T1: no big-pool table | Run error `windows.registry.scan_hives: <poolbig error>` |
| T1: `_CMHIVE.Hive` or `_HHIVE.Signature` missing | Run error wrapping `registryhivescan: _CMHIVE or _HHIVE members missing from the symbol table` |
| T1: allocation counts, every run | Diagnostic `windows.registry.scan_hives: <n> CM10 allocations in use, <f> freed, <s> smaller than _CMHIVE, <b> without the hive signature, <u> unverified` |
| T1: hive list not walked | Diagnostic `windows.registry.scan_hives: CmpHiveListHead at 0x<addr>: hive list not walked: %w`; `OnHiveList` `unknown` |
| T2: no `GetCellRoutine` nor `ReleaseCellRoutine` | Run error `registrycellroutine: _HHIVE has no cell routine members` |
| T2: no hive | Run error `registrycellroutine: no hive found` |
| T2: module list fails | Run error `windows.registry.check_cell_routine: loaded modules: …` |
| T2: kernel image not found | Diagnostic; every routine is placed `other_module` or `no_module` |
| T2: routine pointer unreadable | Row `unreadable`; diagnostic `windows.registry.check_cell_routine: hive at 0x<addr>: <member> not read: %w`; strict mode error |
| T3: option of the wrong type | Run error |
| T3: no hive, none selected | `registrykey: no hive found`, `registrykey: no hive matches the hive option` |
| T3: hive does not open | Diagnostic `windows.registry.read_key: hive at 0x<addr>: not opened: %w` |
| T3: key not read or absent | `KeyNotRead` row; diagnostic `windows.registry.read_key: hive at 0x<addr>: key "<path>" not read: %w` |
| T3: list incomplete, subtree skipped | Diagnostic `windows.registry.read_key: key at 0x<addr>: <what>: registrykey: key not read in full`; strict mode returns rows and `ErrIncomplete` |
| T4: neither hive opens | `registrysystemprofile: neither SOFTWARE nor SYSTEM opens` |
| T4: key or value not read | Diagnostic `windows.registry.read_system_profile: key <hive>\<path> not read: %w` or a row `Unreadable` and `… value <name> at 0x<key>: registrysystemprofile: value not read`; strict mode error |
| T5: SYSTEM or `MountedDevices` not read | `registrymounteddevices: MountedDevices key not read` wrapping the cause |
| T5: value list incomplete, value data not read | Diagnostic; row `DataUnreadable`; strict mode `ErrIncomplete` |
| T6, T7: Services not read | `serviceregistry: Services key not read`, `servicesids: Services key not read`, wrapping the cause |
| T6, T7: subkey or value list incomplete | Diagnostic `<tool>: key at 0x<addr>: <list> not read in full: <pkg>: services not read in full`; strict mode `ErrIncomplete` |
| T8: SOFTWARE does not open | `softwarelist: SOFTWARE hive does not open` |
| T8: Uninstall key not read, list incomplete, values unread | Diagnostic; strict mode `ErrIncomplete` |
| T9: value absent, not resident, header | Run error `executioncompatcache: AppCompatCache value not found`, `… value data not resident`, `… header size not measured` |
| T9: record | Diagnostic `windows.execution.read_compat_cache: value at 0x<key>: offset 0x<n>: …: executioncompatcache: record does not decode`; the rows before it; strict mode error |
| T9: data short | Diagnostic `windows.execution.read_compat_cache: value at 0x<key>: <n> of <m> bytes read: executioncompatcache: value not read in full`; strict mode error |
| T10: no Amcache hive | `executionamcache: no Amcache hive opens` |
| T10: inventory key not read, list incomplete, values unread | Diagnostic; strict mode `ErrIncomplete` |

## 7. Result schema

T1 `registryhivescan.Hive`: `Address` (the `_CMHIVE`), `PoolSize` (bytes), `Verified` (bool), `FilePath`, `RegistryPath` (string), `OnHiveList` (`listed`, `not_listed`, `unknown`).

T2 `registrycellroutine.Routine`: `HiveAddress`, `HivePath`, `Member` (`GetCellRoutine` or `ReleaseCellRoutine`), `Address`, `Placement` (`kernel_image`, `other_module`, `no_module`, `null`, `unreadable`), `Module`, `ModuleUnreadable`, `Symbol`.

T3 `registrykey.Item`: `HivePath`, `HiveAddress`, `Path` (the holding key's path in the hive, components as stored), `Depth` (levels below the requested key), `Kind` (`key`, `value`), `Name`, `NameUnreadable`, `Type` (D1 name, else `type 0x<n>`), `TypeCode`, `TypeUnreadable`, `Data` (S49 4.6 text), `Raw`, `Length`, `DataUnreadable`, `LastWrite` (time, UTC; the key's own, or the holding key's for a value), `LastWriteUnreadable`, `Volatile`, `KeyNotRead`, `Reason`.

T4 `registrysystemprofile.Setting`: `Hive`, `Key`, `ValueName`, `Type`, `Text`, `Time` (UTC, zero unless 4.4 step 4 gives one), `UTCOffset`, `Unreadable`.

T5 `registrymounteddevices.MountedName`: `Name`, `NameUnreadable`, `Kind`, `UniqueID` (bytes), `Form` (`dmio_id`, `device_path`, `other`), `Identifier` (GUID, path or hexadecimal), `Volumes` ([]string), `DataUnreadable`.

T6 `serviceregistry.ServiceKey`: `Name`, `NameUnreadable`, `LastWrite`, `Type`, `TypeNames`, `Start`, `StartName`, `ErrorControl`, `ErrorControlName`, `Tag`, `ImagePath`, `DisplayName`, `ObjectName`, `Group`, `Absent`, `Unread` ([]string of value names). A number is meaningful only when its value name is in neither list.

T7 `servicesids.ServiceSID`: `Service`, `SID`. `servicesids.SID(name)` is exported (D8).

T8 `softwarelist.Program`: `HivePath`, `HiveAddress`, `View` (`native`, `wow64`, `user`), `Key`, `KeyUnreadable`, `KeyLastWrite`, `DisplayName`, `DisplayVersion`, `Publisher`, `InstallDate`, `InstallLocation`, `UninstallString`, `Unread`.

T9 `executioncompatcache.CacheRecord`: `Position`, `Offset` (in the value), `Key`, `FileLastWrite` (UTC; zero when 0), `DataSize`, `Data`, `ChecksumValid`.

T10 `executionamcache.InventoryRecord`: `HivePath`, `HiveAddress`, `Category`, `Key`, `KeyUnreadable`, `KeyLastWrite`, and the fields of 4.10, and `Unread`.

## 8. Limits

T1 reads each path string up to `MaxNameBytes` and walks the hive list up to `MaxListEntries`. T3's recursion is bounded by D2's 512 levels, by `registryhive`'s list caps and by listing each key once. The other tools read fixed keys; their lists are bounded inside `registryhive`.

## 9. Acceptance

1. Synthetic fixtures per package (T1 `s63_fixture_test.go`; the others in each package's `_test.go`) build memory and symbol tables by hand, or hives with `registryhive/registrytest`: T1 a pool table with in-use, freed, small and unsigned allocations and a hive list; T2 routines in the kernel, another module, no module, null and unreadable; T3 listings with recursion, a cycle, a repeat, the depth limit, missing and unreadable keys, strict mode; T4 every value kind, biases and times; T5 every name kind and form, shared IDs; T6 types, start and error names, absent and unreadable values; T7 the D8 examples; T8 three views; T9 the record walk, CRC, a cut value and header errors; T10 the three categories on both layouts.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzScan` (T1; one row at most per allocation, none verified below `sizeof(_CMHIVE)`) 167,000 executions; `FuzzTypeName` (T3; never empty) 4.22 million; `FuzzDecode` (T4; numbers only at their exact size) 2.33 million; `FuzzUniqueID` (T5; each form keeps its length rule) 4.43 million; `FuzzTypeNames` (T6; no names only for 0) 3.98 million; `FuzzServiceSID` (T7; always `S-1-5-80-` and five words) 3.01 million; `FuzzDecodeRecords` (T9; only `ErrHeader` or `ErrRecord`, records in order inside the value with their data size) 4.05 million; `FuzzInventoryValues` (T10; a hash only from the measured identifier form, each value unread at most once) 1.31 million.
3. On the captures (`registrytoolfacts -tool`), see 9.1.

### 9.1 Tool runs

`registrytoolfacts -tool`, 2026-11-12, after the last code change. Counts per capture in the order mem1, mem2, mem5, mem6, mem7.

| Tool | Rows | Notes |
|---|---|---|
| T1 | 24, 29, 19, 29, 24 | All verified and on the hive list; freed `CM10` allocations skipped: 12, 16, 0, 0, 24 (M1). |
| T2 | 48, 58, 38, 58, 48 | Every routine `kernel_image`: `HvpGetCellPaged` and `HvpReleaseCellPaged` (M3). |
| T3 `SYSTEM`, `Select` | 4, 3, 4, 4, 4 | Value rows; on mem2 one value of `Select` does not read (M10). |
| T3 `SOFTWARE`, `Microsoft\Windows NT\CurrentVersion`, recursive | 9,010, 8,732, 9,518, 4,017, 3,979 | Lists not read in full are reported (193, 74, 0, 103, 87 diagnostics of the tool's own). |
| T3 every hive, `Software\Microsoft\Windows\CurrentVersion\Run` | 23, 29, 17, 28, 23 | One `KeyNotRead` row per hive where the key is absent or not read; mem2 lists 4 values. |
| T4 | 20, 22, 21, 20, 20 | `CurrentBuild` 26100, 19045, 14393, 26100, 26100 (M7); `ActiveTimeBias` gives UTC+05:30 on mem1, mem2, mem5 and UTC-07:00 on mem6, mem7 (M9); `ReleaseId` on mem1 and `Select\Current` on mem2 unreadable. |
| T5 | 1, 5, 3, 1, error | mem5's `\DosDevices\D:` names the one volume name with its unique ID; mem7 fails with `ErrUnreadable` (M11). |
| T6 | 729, 727, 553, 681, 683 | Keys with the bit 0x80: 23, 20, 6, 19, 19; keys with an unread value: 0, 8, 0, 1, 0. |
| T7 | 729, 727, 553, 681, 683 | One SID per named key (M13, M17). |
| T8 | 26, 44, 43, 33, 35 | native 13, 24, 24, 17, 18; wow64 13, 18, 17, 16, 16; user 0, 2, 2, 0, 1 (M18, M19). |
| T9 | 139, error, 256, error, error | Every checksum valid; mem2, mem6 and mem7 fail with `ErrValueUnread` (M20). |
| T10 | error, 1,263, 372, 670, error | application_file 785, 52, 237; application 99, 30, 53; driver_binary 379, 290, 380, each with `LinkTime`; mem1 and mem7 fail with `ErrNoHive` (M25). |

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Row types and fields are new (Q2): `registryhivescan.Hive` `Offset`, `Bytes`, `Name` become `Address`, `PoolSize`, `FilePath` with `RegistryPath`, `Verified`, `OnHiveList`; `registrycellroutine.Hive` becomes `Routine` with one row per hive and member, not only flagged hives; `registrykey.Row` becomes `Item` (`Hive`/`HiveOffset` to `HivePath`/`HiveAddress`, `LastWrite` a time, `Unlisted` to `KeyNotRead` with `Reason`, `TypeCode` new); `registrysystemprofile.Info` (`Category`, `Field`, `Value`) becomes `Setting` with one row per registry value and no merged fields (`Build`, `ReleaseVersion`, `UTCOffset` rows are gone); `registrymounteddevices.Mount` becomes `MountedName` (`Drive` and the MBR form are gone, `Form`, `Identifier`, `UniqueID`, `Volumes` new); `serviceregistry.Service` becomes `ServiceKey` with numbers and names; `servicesids.List` and `Listing` are gone; `softwarelist.Program` gains `View`, `HivePath`, `KeyLastWrite`, `UninstallString` and loses the key-name fallback for `Name`; `executioncompatcache.Entry` becomes `CacheRecord`; `executionamcache.Entry` becomes `InventoryRecord` with no file-to-program grouping and no legacy layout. | Owner decision (Q2) |
| O2 | T2 emits a row for every hive and routine; the old tool emitted only hives whose routine lay outside the kernel. | Owner decision |
| O3 | T5 does not decode unique IDs beyond their measured forms. A 12-byte form (disk signature and offset) is said to exist on MBR disks; no capture holds one, so it is `other`. | A capture with an MBR basic disk |
| O4 | T6 names the bit 0x80 (M15) only in hexadecimal: no Microsoft page names it. | A Learn page |
| O5 | T7 upper-cases by Unicode simple case mapping; Windows' own table may differ for some non-ASCII characters. No measured name is outside ASCII (M13). | A capture with such a name |
| O6 | T8 reads user hives' Uninstall keys (M19); D9 names only the machine key. | Owner decision |
| O7 | T9 accepts header sizes 0x30 and 0x34 only; the other header words (S41 O2) are not emitted. | Captures of other builds |
| O8 | T10's value meanings rest on their names and measurement: `FileIDHash` is 40 hexadecimal digits, the length of a SHA-1, but no measurement ties it to a file's hash; `LinkDate` and `InstallDate` carry no time zone and are emitted as stored. | A controlled capture with known files |
| O9 | T10 does not decode `Root\File` and `Root\Programs` (M29), which the old tool read on 14393. | A document or a controlled capture |
| O10 | T4 emits each value as stored; which values make up "the build" (CurrentBuild, UBR) is left to the reader. `processdump` now reads `CurrentBuild`. | Owner decision |
| O11 | The tool names and option keys are kept (Q2). | Owner decision |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept |
| O2 | Row for every routine |
| O3 | Defer to v0.2.0 |
| O4 | Hexadecimal only |
| O5 | Accept simple mapping |
| O6 | Read user keys too |
| O7 | Only 0x30 and 0x34 |
| O8 | Defer to v0.2.0 |
| O9 | Do not decode |
| O10 | Emit values as stored |
| O11 | Keep them |

## 11. Provenance

Author: the project, 2026-11-12. Sources: the Microsoft Learn pages and open specifications of 3.1, accessed 2026-11-12; the PE/COFF specification; the captures' ntkrnlmp.pdb types through the project's symbol tables; S41's code facts for the AppCompatCache record format; the project's measurements with `registrytoolfacts` on the five captures. Every rule rests on the sources and measurements above.
