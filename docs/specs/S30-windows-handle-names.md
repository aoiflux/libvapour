# S30: Windows handle names

Version 1, 2026-11-12.

## 1. Purpose

`windows.handle.list` lists every handle a process holds. For each it gives the object's type and a name an examiner can search for: the path a named event or section has in the object manager's namespace, the device and path of a file, the registry path of a key, and which process or thread a process or thread handle opens. This specification defines how that name is read and written for each object type, and when a name that exists is reported as not read.

The handle table walk itself (levels, entry decoding, ceilings) is unchanged by this specification; section 4.7 records only the comment and message pass on it.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | Object headers, bodies, name strings, key control blocks. |
| Symbol table | The types of section 3 and the global `ObpRootDirectoryObject`. |
| Object | The `_OBJECT_HEADER` address a handle entry decodes to, and the type name the TypeIndex gives (S31 4.5). |
| Limits | `MaxPathSteps`: directories walked for one namespace path, key control blocks walked for one key. |

No option key is added; `windows.handle.list.offset` and `pid` are unchanged.

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | "Named objects are organized into a hierarchy. Each object is named relative to a parent object. Each component of the object's name begins with a backslash character. For example, **\KernelObjects** is the parent object for **\KernelObjects\LowMemoryCondition**." "If an object is unnamed, a user-mode component cannot open a handle to it." | Microsoft Learn, "Object Names", dated 2017-06-16, accessed 2026-11-12. |
| D2 | "An object directory is a named object that is used solely to contain other named objects. For example, the **\Device** object directory contains the named device objects created by drivers." | Microsoft Learn, "Object Directories", dated 2017-06-16, accessed 2026-11-12. |
| D3 | `FILE_OBJECT.DeviceObject` is "a pointer to the device object on which the file is opened". `FileName` "holds the name of the file opened on the volume. If the volume is being opened, the Length member … will be zero." `RelatedFileObject` indicates "the current file object has been opened relative to an already open file object" and "is only valid during the processing of the IRP_MJ_CREATE requests". | Microsoft Learn, "FILE_OBJECT (wdm.h)", dated 2023-08-17, accessed 2026-11-12. |
| D4 | "The root for all registry keys is the **\Registry** object." HKEY_LOCAL_MACHINE corresponds to **\Registry\Machine**, HKEY_USERS to **\Registry\User**. "Every key has an object name." | Microsoft Learn, "Registry Key Object Routines", dated 2017-06-16, accessed 2026-11-12. |
| D5 | "A temporary object can be accessed by name only as long as its handle count is nonzero. Once the handle count decrements to zero, the object's name is removed from the object manager's namespace." | Microsoft Learn, "Life Cycle of an Object", dated 2017-06-16, accessed 2026-11-12. |

### Kernel types

Builds 26100 (mem1, mem6), 19045 (mem2), 14393 (mem5), through `poolfacts -types`.

| # | Fact |
|---|---|
| T1 | `_OBJECT_HEADER_NAME_INFO` (32 bytes): `Directory` (`_OBJECT_DIRECTORY *`) 0, `Name` (`_UNICODE_STRING`) 8. Its place in front of the header is S31 4.10. |
| T2 | `_FILE_OBJECT`: `DeviceObject` 8, `RelatedFileObject` 0x40, `FileName` (`_UNICODE_STRING`) 0x58. |
| T3 | `_EPROCESS.UniqueProcessId` (`void *`) and `ImageFileName` (`unsigned char [15]`); `_ETHREAD.Cid` (`_CLIENT_ID`: `UniqueProcess` 0, `UniqueThread` 8). Offsets differ per build (for example `UniqueProcessId` 0x1d0 on 26100, 0x440 on 19045). |
| T4 | `_CM_KEY_BODY.KeyControlBlock` 8. `_CM_KEY_CONTROL_BLOCK`: `ParentKcb` and `NameBlock` (0x48, 0x50 on 26100 and 19045; 0x40, 0x48 on 14393), `Flags` (bits 16..31 of the word at 0xb8, 0xb0 on 14393), `TotalLevels` (bits 21..30 of the word at 8, 4 on 14393), and on 26100 `FullKCBName` (`_UNICODE_STRING *`, bit 0 a stale flag). `_CM_NAME_CONTROL_BLOCK`: `Compressed` bit 0 of the word at 0, `NameLength` (`unsigned short`) 0x18, `Name` (`wchar_t [1]`) 0x1a. |

### Measurements

From `poolfacts -handles` on 2026-11-12 over mem1_win11, mem2_win10, mem5_server2016, mem6_server2025: 170,047 handles walked by the script's own table reader (46,853, 57,560, 25,562, 40,072).

| # | Measured |
|---|---|
| M1 | Namespace: for objects with a name, the `Directory` chain reaches `ObpRootDirectoryObject` with every directory named, up to 5 levels and more (`\Sessions\2\AppContainerNamedObjects\S-1-15-2-…\RPC Control\…`). Each capture also has chains that end at a directory with no name info that is not the root: one `KernelObjects` directory and what it holds (`KernelObjects\LowMemoryCondition`), and on mem1 a few sections (`!PrivacIE!SharedMem!Settings`). |
| M2 | Every named `Desktop` (73, 149, 63, 91) has a null `Directory`: its parent is the window station, not a directory. A few events and mutants have a name and a null `Directory` (2 on mem6), the state D5 describes. |
| M3 | Files (7,893, 2,708, 1,618, 1,859): `FileName` begins with a backslash for 7,296, 2,034, 1,252 and 1,408; is empty for 402, 652, 362 and 444 (a device or volume open, D3); is relative for 184, 9, 4 and 2; does not read for 11, 13, 0 and 5. Every file with a readable device has a device whose namespace path is rooted (`\Device\HarddiskVolume3`, `\Device\Harddisk0\DR0`, `\clfs`). Relative names occur with and without a `RelatedFileObject` (184 without on mem1). |
| M4 | Keys (2,927, 4,385, 1,600, 3,012): following `ParentKcb` from the key's control block to the end, every chain ends at `REGISTRY`. A hive's root control block has `Flags` bit 0x4 and repeats the name of the key that mounts it (`\REGISTRY\MACHINE\SYSTEM\SYSTEM\CONTROLSET001`). Keeping the outermost control block and dropping every other one with bit 0x4, the number of levels equals `TotalLevels` for 11,914 of 11,924 keys; the 10 others are 8 name blocks that do not read and 1 null control block on mem1, and 1 freed block of garbage on mem2. |
| M5 | Name blocks hold upper-case names: no kept name has a lower-case letter. Where `FullKCBName` is set and not stale (220, 414, 123, 274), it equals the built path ignoring case (`\REGISTRY\MACHINE\SYSTEM\ControlSet001`). Uncompressed name blocks occur only on mem1 (82 keys). |
| M6 | Processes behind handles (835, 1,565, 507, 1,041) have a readable `ImageFileName` and `UniqueProcessId`, one on mem1 an empty name. Threads (1,203, 2,173, 1,544, 1,397) have readable `Cid` values, multiples of 4 for all but 1 on mem2. Neither type has name info. |

## 4. Algorithm

The form is chosen by the handle's type name: `File`, `Key`, `Process`, `Thread`, or the namespace form for every other type. A name is reported as text, empty (the object has none), or not read (`NameUnreadable`).

### 4.1 Namespace form

1. Locate the name info (S31 4.10). None: the name is empty (D1). The root directory itself is named `\`.
2. Read `Name` as a counted string. Characters show as stored; a NUL shows as `␀`.
3. Walk `Directory`: each directory's own name info gives the next component (D1, D2, M1).
   - The chain reaches `ObpRootDirectoryObject`: the name is `\` and the components joined by `\`, outermost first.
   - The chain ends at a null `Directory` or at a directory with no name info: the components so far, joined by `\`, with no leading backslash. The missing leading backslash says the path is not anchored at the root (M1, M2).
   - A directory seen twice, a step past `MaxPathSteps`, or a component that does not read: not read.
4. A table without `_OBJECT_HEADER_NAME_INFO.Directory` gives the leaf name alone.

### 4.2 File form

1. Read `FileName`. Not readable: not read.
2. Not empty and not starting with `\`: the name is `FileName` alone. It was relative to a `RelatedFileObject` that is valid only while the open is processed (D3, M3).
3. Otherwise the name is the device's namespace path (4.1, from `DeviceObject`'s header) followed by `FileName`, which may be empty (a device or volume open, D3). A device path that does not read leaves `FileName` alone; with an empty `FileName`, the name is not read.

### 4.3 Key form

1. Follow `KeyControlBlock`, then `ParentKcb` until null. A null `KeyControlBlock` gives an empty name.
2. For each control block, unless it has `Flags` bit 0x4 and a parent (the root of a mounted hive, M4), take the name block's name: `NameLength` bytes, one character per byte when `Compressed` is set, UTF-16LE otherwise.
3. The name is `\` and the kept names joined by `\`, outermost first: `\REGISTRY\MACHINE\SYSTEM\CONTROLSET001` (D4, M4). Names keep the case the name block stores (M5).
4. When the table has `TotalLevels`, the number of kept names must equal it (M4); otherwise the name is not read.
5. A control block seen twice, a step past `MaxPathSteps`, or a member that does not read: not read.

### 4.4 Process form

`<ImageFileName> pid <UniqueProcessId>`, the image name cut at its first NUL, the ID in decimal: `System pid 4` (T3, M6).

### 4.5 Thread form

`tid <UniqueThread> pid <UniqueProcess>`, both in decimal: `tid 64 pid 4` (T3, M6).

### 4.6 Unreadable names

Each name not read is counted per form; at the end of the run one diagnostic per form gives the count and the first object's reason.

### 4.7 Handle table walk

Unchanged in behaviour. Its diagnostics now name the object and address in the form `windows.handle.list: <object> at 0x<addr>: <what failed>`: `process <pid> at 0x<eprocess>: ObjectTable does not read, its handles are unknown: …`, and for the table `handle table of process <pid> at 0x<table>:` followed by `TableCode does not read, its handles are unknown: …`, `TableCode 0x<code>: <reason>`, `<n> of <m> entry pages do not start at the handle value of their place, their entries are not listed: …`, `<n> of <m> entry pages and <p> of <q> pointer pages do not read, its handles are incomplete: …`, `<n> page pointers at or past <ceiling> are not followed`, or `stopped at <ceiling>, its rows may be a prefix`. A table level other than 0, 1 or 2 is `handlelist: handle table level not 0, 1 or 2`, and a table page that is not page-aligned is `handlelist: handle table page is not page-aligned`.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Namespace chain without a repeated directory, within `MaxPathSteps` | M1 | Not read |
| Key chain without a repeated block, within `MaxPathSteps` | M4 | Not read |
| Kept key levels equal `TotalLevels` | M4 | Not read (`handlelist: key path length disagrees with TotalLevels`) |
| A relative `FileName` is not joined to the device | D3, M3 | Name is `FileName` alone |

## 6. Failure modes

| Case | Result |
|---|---|
| Table lacks `_OBJECT_HEADER.Body` | Every name empty. Namespace names come back empty only. File, Key, Process and Thread names are flagged not read and counted in the end-of-run diagnostic, with the missing member as the reason |
| Table cannot place name info | Namespace names empty, not "not read" |
| Table lacks a member of 4.2 to 4.5 | That form's names are not read; counted |
| Unreadable string, pointer or block | Not read; counted |
| End of run | `windows.handle.list: <n> <form> handle names did not read; first: object at 0x<addr>: <reason>` |

Sentinels: `handlelist: object name not readable`, `handlelist: name path past MaxPathSteps`, `handlelist: key path length disagrees with TotalLevels`.

## 7. Result schema

`handlelist.Handle` is unchanged: `PID`, `ProcessName`, `HandleValue`, `Object` (the `_OBJECT_HEADER` address), `GrantedAccess`, `TypeIndex`, `TypeName`, `ObjectName` (sections 4.1 to 4.5), `NameUnreadable`. Row order is unchanged: process order, then handle value.

## 8. Limits

- `MaxPathSteps`: directories per namespace path, control blocks per key. Measured chains are below 16 levels.

## 9. Acceptance

1. Synthetic fixtures (`tools/windows/handlelist/names_test.go`): a rooted path, a path under an unnamed directory, a leaf with no directory, the root itself, a cycle, `MaxPathSteps`; a file with an absolute, an empty and a relative `FileName`; a key across a mounted hive, a compressed and a wide level, a `TotalLevels` mismatch, a key chain past `MaxPathSteps`; process and thread forms; the per-form diagnostic.
2. Fuzz target `FuzzKeyLevel` (arbitrary name block bytes, either compression: no panic, compressed output has one character per byte), 30 s on 2026-11-12: 3.09 million executions.
3. On the captures, `windows.handle.list` through `poolfacts -handles`, 2026-11-12:

| Capture | Handles | Full path | Relative | Empty | Not read |
|---|---|---|---|---|---|
| mem1_win11 | 46,853 | 12,706 | 2,309 | 30,187 | 1,651 |
| mem2_win10 | 57,560 | 10,125 | 4,026 | 43,210 | 199 |
| mem5_server2016 | 25,190 | 4,805 | 2,121 | 18,262 | 2 |
| mem6_server2025 | 40,072 | 7,317 | 2,618 | 30,092 | 45 |

   "Relative" includes the process and thread forms. Keys: every key name but 9 on mem1 and 1 on mem2 is a full path starting `\REGISTRY`. Of the not-read names on mem1, 1,588 belong to handles whose type does not resolve (their headers no longer hold objects).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | The process and thread forms (`System pid 4`, `tid 64 pid 4`) are this specification's own; they are new row values. | Owner decision (Q2) |
| O2 | Key names are the name blocks' upper-case forms. The stored case is in the hive's key node; `FullKCBName` has it on 26100 but only for some keys (M5). Follow-up 2026-11-12: on mem1 8 Key names do not read; 4.3 steps 4 and 5 flag those handles `NameUnreadable`. Owner decision 2026-11-12: keep the flag; FullKCBName fallback in v0.2.0. Done: no library change. A `FullKCBName` fallback on 26100 is deferred to v0.2.0 (owner decision 2026-11-12). | Owner decision: read key nodes through the registry reader |
| O3 | Bit 0x4 of the control block `Flags` as the mark of a hive root rests on measurement (M4); no public document states it. | Owner decision on measured rules |
| O4 | A path under an unnamed directory has no leading backslash (M1). The unnamed directories may be a silo's root; the reader does not name the silo. | A source for silo namespaces |
| O5 | A relative `FileName` is shown alone (4.2). | Owner decision: join it to the related file's name when that object still reads |
| O6 | NUL shows as `␀` in handle names (owner decision of 2026-11-11), while `scan.ObjectNamer` cuts at a NUL (S31 O6). Owner decision 2026-11-12: show NUL visibly everywhere. Done: `scan.ObjectNamer` now drops only terminating NULs and shows an inner NUL as `␀` (S31 4.10, `scan/names.go`); the handle list already did (4.1 step 2). The process form keeps `ImageFileName` cut at its first NUL: that member is a NUL-padded byte array (S25), not a counted object name; owner decision 2026-11-12 (follow-up D15): keep. Measured 2026-11-12 on the five Windows captures with every caller (handle list, file, driver, mutant, link and pool scans, device tree, GUI): row counts unchanged; mem2, mem5 and mem6 give identical rows; mem1 shows the hidden suffix of one stale driver object name (1 row each in `windows.driver.scan` and `windows.pool.scan`, 4 in `windows.device.tree`); mem7 shows it for 6 stale mutant names in `windows.pool.scan`, and one `windows.object.scan_mutants` name read before as `df` is now flagged `NameUnreadable`, its suffix holding a backslash (S69 4.1 step 4). | Owner decision on one rule |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Use the new forms |
| O2 | Keep upper-case name block form |
| O3 | Keep the measured rule |
| O4 | Keep no leading backslash |
| O5 | Show it alone |
| O6 | Show NUL visibly everywhere |

## 11. Provenance

Written from Microsoft Learn's WDK documentation, the ntoskrnl types in the project's symbol tables, and the project's measurements with `poolfacts`. Every rule rests on the sources and measurements above.
