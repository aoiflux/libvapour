# S27: Windows kernel callback registrations

Version 1, 2026-11-12.

## 1. Purpose

Drivers ask the kernel to call them back when a process or thread starts, an image loads, a registry operation runs, the system bug-checks or shuts down, a file system registers, a power setting changes, or a handle to a process, thread or desktop is opened. A rootkit uses the same registrations to watch or hide activity, and a registration whose routine lies outside every loaded module is a classic sign of code loaded without a module entry.

`windows.callback.list` lists every registration it can find in eleven kernel stores, with the routine the kernel will call, the module that holds it, and the store's own detail (slot, altitude, component, device, setting). It does not judge a registration. The examiner decides what is unexpected.

## 2. Inputs

| Input | Use |
|---|---|
| Kernel memory | Every store and record. |
| Kernel symbol table | The symbols of 4.1, the types `_LIST_ENTRY`, `_EX_FAST_REF`, `_UNICODE_STRING`, `_DEVICE_OBJECT`, `_DRIVER_OBJECT`, `_OBJECT_TYPE`, `_KUSER_SHARED_DATA`, and the build symbol `NtBuildNumber`. |
| Loaded modules | `windows.module.list`, unfiltered by PID, for the owner of each routine (`modulelist.Attributor`). |
| Options | `strict` and `diagnostics` only. The tool has no option of its own. |
| Limits | `MaxListEntries` (each list walk), `MaxNameBytes` (each string). |

The image is untrusted. Every pointer and count can hold any value.

## 3. Facts from the sources

| # | Fact | Source |
|---|---|---|
| F1 | `PsSetCreateProcessNotifyRoutineEx` returns `STATUS_INVALID_PARAMETER` when "the operating system has reached its limit for registering process-creation callback routines", and `STATUS_ACCESS_DENIED` when the image lacks `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`. | Microsoft Learn, "PsSetCreateProcessNotifyRoutineEx function (ntddk.h)", accessed 2026-11-12. |
| F2 | "The maximum number of drivers that can be simultaneously registered to receive load-image notifications is eight"; an update for Windows 8.1 raised it "from eight to 64". `PsSetCreateThreadNotifyRoutine` returns `STATUS_INSUFFICIENT_RESOURCES` when registration fails. | Microsoft Learn, "PsSetLoadImageNotifyRoutine function" and "PsSetCreateThreadNotifyRoutine function" (ntddk.h), accessed 2026-11-12. |
| F3 | `CmRegisterCallbackEx(Function, Altitude, Driver, Context, Cookie, Reserved)`: Altitude is a `UNICODE_STRING` holding the altitude of the caller; Cookie identifies the registration for `CmUnRegisterCallback`. `CmRegisterCallback` registers the same kind of routine. | Microsoft Learn, "CmRegisterCallbackEx function (wdm.h)", accessed 2026-11-12. |
| F4 | `KeRegisterBugCheckCallback(CallbackRecord, CallbackRoutine, Buffer, Length, Component)`: Component is "a null-terminated ANSI string that identifies the caller", usually the driver's name. `KeRegisterBugCheckReasonCallback` registers the other kinds. | Microsoft Learn, "KeRegisterBugCheckCallback function (wdm.h)", accessed 2026-11-12. |
| F5 | `_KBUGCHECK_CALLBACK_RECORD` is `{ LIST_ENTRY Entry; PKBUGCHECK_CALLBACK_ROUTINE CallbackRoutine; PVOID Buffer; ULONG Length; PUCHAR Component; ULONG_PTR Checksum; UCHAR State; }`. `_KBUGCHECK_REASON_CALLBACK_RECORD` is `{ LIST_ENTRY Entry; PKBUGCHECK_REASON_CALLBACK_ROUTINE CallbackRoutine; PUCHAR Component; ULONG_PTR Checksum; KBUGCHECK_CALLBACK_REASON Reason; UCHAR State; }`. `KBUGCHECK_CALLBACK_REASON` runs `KbCallbackInvalid` (0) to `KbCallbackReserved3` (9). | WDK 10.0.28000.0 `km/wdm.h` (NuGet `Microsoft.Windows.WDK.x64` 10.0.28000.1839), lines 25194, 25229, 25258. |
| F6 | On x64 a pointer is 8 bytes and 8-aligned, `ULONG` and an enumeration 4 bytes and 4-aligned, `UCHAR` 1 byte; a structure member is placed at the next multiple of its alignment. So F5 gives `CallbackRoutine` at 0x10 and `Component` at 0x28 in the first record, and `CallbackRoutine` 0x10, `Component` 0x18, `Reason` 0x28 in the second. | Microsoft Learn, "x64 ABI conventions", section "Types and storage", accessed 2026-11-12. |
| F7 | `IoRegisterShutdownNotification(DeviceObject)` registers the driver to receive `IRP_MJ_SHUTDOWN` for that device in its DispatchShutdown routine. `IoRegisterLastChanceShutdownNotification` does the same after the file systems are flushed. | Microsoft Learn, "IoRegisterShutdownNotification function (wdm.h)", accessed 2026-11-12. |
| F8 | `IRP_MJ_SHUTDOWN` is 0x10; `IO_TYPE_DEVICE` is 3 and `IO_TYPE_DRIVER` is 4. | WDK 10.0.28000.0 `km/wdm.h`, lines 32109, 32110, 32144. |
| F9 | `IoRegisterFsRegistrationChange(DriverObject, DriverNotificationRoutine)` registers a file system filter's routine, called when a file system registers or unregisters. | Microsoft Learn, "IoRegisterFsRegistrationChange function (ntifs.h)", accessed 2026-11-12. |
| F10 | `PoRegisterPowerSettingCallback(DeviceObject, SettingGuid, Callback, Context, Handle)` registers a routine for one power setting, named by a GUID. `GUID_LIDSWITCH_STATE_CHANGE` is `{BA3E0F4D-B817-4094-A2D1-D56379E6A0F3}`. | Microsoft Learn, "PoRegisterPowerSettingCallback function (wdm.h)", accessed 2026-11-12; WDK 10.0.28000.0 `km/wdm.h`, line 11267. |
| F11 | `ObRegisterCallbacks` "registers a list of callback routines for thread, process, and desktop handle operations". `OB_CALLBACK_REGISTRATION` begins `{ USHORT Version; USHORT OperationRegistrationCount; UNICODE_STRING Altitude; ... }`; `OB_FLT_REGISTRATION_VERSION` is 0x0100; `OB_OPERATION_HANDLE_CREATE` is 1 and `OB_OPERATION_HANDLE_DUPLICATE` is 2. | Microsoft Learn, "ObRegisterCallbacks function (wdm.h)", accessed 2026-11-12; WDK 10.0.28000.0 `km/wdm.h`, lines 44869 to 44971. |
| F12 | In all four kernel tables (GUIDs 0D960CE1, F57E740B, 3DFC5F72, 953A8DE8): `_EX_FAST_REF` has `Object`, `RefCnt` (bits 0 to 3 of an 8-byte integer) and `Value`, all at 0; `_OBJECT_TYPE.Name` is at 0x10 and `_OBJECT_TYPE.CallbackList` (a `_LIST_ENTRY`) at 0xc8; `_DEVICE_OBJECT.DriverObject` is at 0x8; `_DRIVER_OBJECT.DriverName` is at 0x38 and `MajorFunction` at 0x70. No table describes `_KBUGCHECK_CALLBACK_RECORD`, `_KBUGCHECK_REASON_CALLBACK_RECORD`, a shutdown packet, a callback routine block or any `ObRegisterCallbacks` record. | Measured with `callbackfacts` on 2026-11-12 in the project's symbol cache. |
| F13 | Every table has the symbols `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, `PspLoadImageNotifyRoutine`, `CallbackListHead`, `KeBugCheckCallbackListHead`, `KeBugCheckReasonCallbackListHead`, `IopNotifyShutdownQueueHead`, `IopNotifyLastChanceShutdownQueueHead`, `IopFsNotifyChangeQueueHead`, `PopRegisteredPowerSettingCallbacks`, `PsProcessType`, `PsThreadType`, `ExDesktopObjectType` and `ExGetCallBackBlockRoutine`. None has `CmCallbackListHead`. | Measured as F12. |
| F14 | `MOV r64, r/m64` is REX.W 8B /r; `RET` is C3. | Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 2, instruction reference for MOV and RET. |
| F15 | Builds 19041 to 19045 share one set of system files, and layouts keyed by build use the file-set build. | S03, B7, B8 and 4.9. |

### Measurements

M1 to M8 come from `callbackfacts` (`-raw` dumps every record; `-tool` runs this tool), run on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393) and mem6_server2025 (26100).

| # | Measured |
|---|---|
| M1 | Each of the three notify arrays is followed by the next public symbol 0x200 bytes later, on every capture: 64 eight-byte slots. Each nonzero slot has its low 4 bits set (57 slots, all value 15). Clearing them gives a record whose qword at +8 lies in a loaded module in every case. `ExGetCallBackBlockRoutine` begins `48 8B 41 08 C3` on all four captures: `mov rax, [rcx+8]; ret` (F14), so the routine is the qword at +8 of the record. |
| M2 | Every entry on `CallbackListHead` (3 per capture) holds a routine in a loaded module at +0x28, and a `UNICODE_STRING` at +0x30 whose text is a decimal altitude (425000, 385250.8, 189900 and others). |
| M3 | Every entry on `KeBugCheckCallbackListHead` (1, 1, 1, 0) and `KeBugCheckReasonCallbackListHead` (166, 174, 60, 142) holds a routine in a loaded module at +0x10, as F5 and F6 place it. Components read as ANSI names (`fvevol`, `WUDFRd`); one each on mem1 and mem6 lies in an unmapped kernel page. |
| M4 | Every entry on `IopNotifyShutdownQueueHead` (6, 8, 5, 7) and `IopNotifyLastChanceShutdownQueueHead` (1, 2, 2, 2) holds at +0x10 a pointer to an object whose first `USHORT` is 3 (F8). |
| M5 | The one entry on `IopFsNotifyChangeQueueHead` of each capture holds at +0x10 a pointer to an object of type 4 and at +0x18 a routine in `FLTMGR.SYS`. |
| M6 | Every entry on `PopRegisteredPowerSettingCallbacks` (47, 29, 26, 22) holds a routine in a loaded module at +0x50, the four bytes `PSet` at +0x10, and a GUID at +0x24, such as `GUID_LIDSWITCH_STATE_CHANGE` (F10). |
| M7 | Each entry on an `_OBJECT_TYPE.CallbackList` (mem1: 1 on each of the three types; others: 1 on Process and Desktop) holds the operation mask at +0x10 (3), a pointer at +0x18 to a record that starts with `Version` 0x100 (F11) and has a `UNICODE_STRING` altitude at +0x10, the object type itself at +0x20, a pre-operation routine in a loaded module at +0x28 and a post-operation routine at +0x30 (0 on every capture). |
| M8 | M1 to M7 give the same offsets on 14393, 19045 and 26100. |

## 4. Algorithm

### 4.1 Stores, in output order

| Kind | Store | Record |
|---|---|---|
| `process_create` | `PspCreateProcessNotifyRoutine`, 64 `_EX_FAST_REF` slots (F1, F12, M1) | routine block: routine at +8 (M1) |
| `thread_create` | `PspCreateThreadNotifyRoutine`, same (F2) | same |
| `image_load` | `PspLoadImageNotifyRoutine`, same (F2) | same |
| `registry` | list `CallbackListHead` (F3, M2) | routine +0x28, altitude `UNICODE_STRING` +0x30 |
| `bugcheck` | list `KeBugCheckCallbackListHead` | `_KBUGCHECK_CALLBACK_RECORD` (F5, F6) |
| `bugcheck_reason` | list `KeBugCheckReasonCallbackListHead` | `_KBUGCHECK_REASON_CALLBACK_RECORD` (F5, F6) |
| `shutdown` | list `IopNotifyShutdownQueueHead` (F7, M4) | device object +0x10 |
| `shutdown_last_chance` | list `IopNotifyLastChanceShutdownQueueHead` (F7, M4) | device object +0x10 |
| `filesystem_change` | list `IopFsNotifyChangeQueueHead` (F9, M5) | driver object +0x10, routine +0x18 |
| `power_setting` | list `PopRegisteredPowerSettingCallbacks` (F10, M6) | setting GUID +0x24, routine +0x50 |
| `object_handle` | `CallbackList` of the types `PsProcessType`, `PsThreadType`, `ExDesktopObjectType` (F11, F12, M7) | as M7 |

### 4.2 Steps

1. Refuse a profile that is not Windows, and a table with 4-byte pointers (`ErrNot64Bit`): no 32-bit kernel was measured.
2. Read the loaded modules. If they do not read, every routine is listed without an owner, with a diagnostic; strict mode fails.
3. Read the kernel build (S03 4.7). Look up the measured layout by file-set build (F15). Without a kernel build or a measured layout, only the two bug-check kinds are listed, because their layout comes from the WDK header (F5, F6), and a diagnostic names the build.
4. For each store of 4.1 in order:
   1. A missing symbol drops that kind with a diagnostic, in every mode: the kernel has no such store to misread.
   2. **Arrays.** Read the 64 slots in one read. A slot of 0 after clearing the `RefCnt` bits is empty. The `RefCnt` width comes from the table's `_EX_FAST_REF.RefCnt` bit field (F12); without it the kind is dropped. Each other slot is one registration; read its routine.
   3. **Lists.** Walk forward with the S03 walker, capped at `MaxListEntries`. Each entry walked is one registration.
   4. **Bug-check records.** If the table describes the record type with `CallbackRoutine` and `Component` (and `Reason` for the reason record), its offsets win over F6. Read the routine, the reason (named from F5), and the component: a pointer to a NUL-terminated ANSI string, read until NUL or `MaxNameBytes`.
   5. **Shutdown packets.** Read the device object. Its `Type` must be 3, and its `DriverObject`'s `Type` must be 4 (F8). The routine is the driver's `MajorFunction[IRP_MJ_SHUTDOWN]` (F7): the routine the kernel calls for this registration.
   6. **File system packets.** Read the routine; the driver object's `Type` must be 4.
   7. **Power settings.** Read the routine and the 16-byte GUID.
   8. **Object types.** For each of the three type symbols, read the type object and its `Name`. Walk its `CallbackList`. An entry whose object type (+0x20) is not this type does not belong to the list (M7). Read the operation mask and the altitude from the registration record. A nonzero pre-operation routine and a nonzero post-operation routine each give a row.
5. Attribute each nonzero routine to the first loaded module whose range holds it, and to a kernel symbol when the module is the kernel (`modulelist.Attributor`).

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| The table's pointer size is 8 | No 32-bit capture (section 10) | `ErrNot64Bit`, no rows |
| A record reads | Section 2 | Row with `Damage`, routine 0 where unread; `ErrRecordUnread` |
| A name string reads (component, altitude) | F3, F4, F11 | Row keeps its routine, `Damage`; `ErrStringUnread` |
| A shutdown packet names a device object of type 3 whose driver object has type 4 | F7, F8, M4 | Row with routine 0, `Damage`; `ErrNotDevice` or `ErrNotDriver` |
| A file system packet names a driver object of type 4 | F8, M5 | Row keeps its routine, `Damage`; `ErrNotDriver` |
| An object callback entry names its own object type | M7 | Row with routine 0, `Damage`; `ErrOtherType` |
| A registration's routine is nonzero | F1 to F11: every registration passes a routine | Row with `Damage`; `ErrNullRoutine` |

A routine outside every module is not a failure: it is a finding, shown by an empty `Module`.

## 6. Failure modes

| Case | Non-strict | Strict |
|---|---|---|
| Not Windows, or 4-byte pointers | error | error |
| Modules do not read | diagnostic; no owners | error |
| No kernel build, or no measured layout | diagnostic; bug-check kinds only | same |
| Symbol missing (`ErrSymbolMissing`) | diagnostic; kind dropped | same |
| Array or list head does not read (`ErrRecordUnread`, `winkernel.ErrListUnreadable`) | diagnostic; kind dropped | error |
| List break (S03) | diagnostic; entries before it listed | error |
| Damaged record (section 5) | row with `Damage` plus diagnostic | error |

Diagnostics have the form `windows.callback.list: <object> at 0x<addr>: <what failed>: <sentinel>: <cause>`.

## 7. Result schema

`callbacklist.Entry`, one per registration and routine:

| Field | Type | Meaning |
|---|---|---|
| `Kind` | `Kind` (typed string) | One of the eleven values of 4.1. |
| `Routine` | uint64 | The routine the kernel calls. 0 when it could not be read. |
| `Module` | string | Display name of the module that holds `Routine`; empty when none does. |
| `ModuleUnreadable` | bool | The owner's name did not read. |
| `Symbol` | string | Kernel symbol at `Routine`, when the owner is the kernel. |
| `Record` | uint64 | Address of the record the routine was read from: the routine block for arrays, the list entry otherwise. |
| `Detail` | string | Arrays: `slot N`. Registry: `altitude A`. Bug-check: `component C`. Reason: `<reason name> component C`. Shutdown kinds: `device 0x<addr> driver <DriverName>`. File system: `driver <DriverName>`. Power: `setting {GUID}`. Object: `<type name> pre|post <create,duplicate> altitude A`. A part that did not read is left out. |
| `Damage` | string | Empty, or the failed rule of section 5 in words. |

Rows come in the kind order of 4.1, then slot order or walk order, then type order and pre before post. The order is deterministic.

## 8. Limits

`MaxListEntries` bounds every walk (S03). `MaxNameBytes` bounds every string. The arrays have a fixed 64 slots (M1). No other loop depends on image data.

## 9. Acceptance

1. Synthetic fixtures (`tools/windows/callbacklist/s27_fixture_test.go`, `callback_list_test.go`) on the layouts of M1 to M7: one registration of every kind, in order, owned; a routine outside every module; a 3-bit `RefCnt`; an unmeasured build (bug-check kinds only); builds 19041 and 19045 (one layout); a non-device object in a shutdown packet, also in strict mode; an object entry naming another type; an unreadable component, also in strict mode; an unreadable array, also in strict mode; a missing symbol in strict mode; a table record type that wins over F6; a 4-byte table refused.
2. `FuzzCollect` writes arbitrary bytes over the fixture's records. It must not panic or fail in non-strict mode, every row has a kind of 4.1, and every row without `Damage` has a routine. 30 s on 2026-11-12: 1.13 million executions.
3. On the captures, `callbackfacts -tool`, 2026-11-12. Every row has an owner. Damaged rows: the two unmapped components of M3.

| Kind | mem1_win11 | mem2_win10 | mem5_server2016 | mem6_server2025 |
|---|---|---|---|---|
| `process_create` | 10 (CI, UCPD, appid, cng, dxgkrnl, iorate, ksecdd, peauth, tcpip, wtd) | 10 (CI, KslD, WdFilter, cng, dxgkrnl, iorate, ksecdd, ntoskrnl, peauth, tcpip) | 8 (CI, WdFilter, cng, dxgkrnl, ksecdd, ntoskrnl, peauth, tcpip) | 8 (CI, MpKslDrv, WdFilter, cng, dxgkrnl, ksecdd, peauth, tcpip) |
| `thread_create` | 1 (mmcss) | 5 (KslD 2, WdFilter 2, mmcss) | 1 (WdFilter) | 5 (MpKslDrv 2, WdFilter 2, mmcss) |
| `image_load` | 1 (ahcache) | 3 (KslD, WdFilter, ahcache) | 2 (WdFilter, ahcache) | 3 (MpKslDrv, WdFilter, ahcache) |
| `registry` | 3 (UCPD, applockerfltr, bfs) | 3 (UCPD, WdFilter, ntoskrnl) | 3 (WdFilter, ntoskrnl, registry) | 3 (WdFilter, bfs, ntoskrnl) |
| `bugcheck` | 1 (fvevol) | 1 (fvevol) | 1 (hal) | 0 |
| `bugcheck_reason` | 166, 1 damaged | 174 | 60 | 142, 1 damaged |
| `shutdown` | 6 | 8 | 5 | 7 |
| `shutdown_last_chance` | 1 (volmgr) | 2 (spaceport, volmgr) | 2 (spaceport, volmgr) | 2 (spaceport, volmgr) |
| `filesystem_change` | 1 (FLTMGR) | 1 (FLTMGR) | 1 (FLTMGR) | 1 (FLTMGR) |
| `power_setting` | 47 | 29 | 26 | 22 |
| `object_handle` | 3 (UCPD) | 2 (WdFilter) | 2 (WdFilter) | 2 (WdFilter) |
| Rows | 240 | 238 | 111 | 195 |

## 10. Open points

| # | Point | How to close it |
|---|---|---|
| O1 | Owner decision (Q2): the kind values, the row field names (`Kind`, `Routine`, `Record`, `Detail`, `Damage` replace the 0.1.0 names) and the `Detail` wording. | Owner review. |
| O2 | Owner decision (O2, 2026-11-12, open): the measured layout keyed to 19041 serves 19042 to 19045 through the file-set build (F15). The default chosen here follows KB5015684; it was measured on 19045 (mem2) only. | Owner decision; a 19041 to 19044 capture. |
| O3 | Owner decision (Q3): the measured offsets of M1, M2 and M4 to M7 have no type source, so their Go member names are the project's own. The PDB-wins rule applies to the two WDK records only, because no source names the private types. | A table that names the private types. |
| O4 | `CallbackListHead`'s role rests on M2 alone; no public document names it. The 64-slot size of the process and thread arrays rests on M1 and F2's image-load figure. | Disassembly of `CmUnRegisterCallback` and of the array writers on each build. |
| O5 | Owner decision: the tool reads the kernel's own stores only, with no pool scan for unlinked records. Every store is a public symbol on the measured builds (F13), and a record unlinked from its store is not called by the kernel. Debug-print callbacks (`RtlpDebugPrintCallbackList`) are not listed: the list was empty on every capture, so its records could not be measured. | Owner decision; a capture with a debug-print callback registered. |
| O6 | The process array does not tell `PsSetCreateProcessNotifyRoutine` from its `Ex` and `Ex2` forms; the qword at +0x10 of the block varies (0, 2, 6) and has no source. | A controlled capture registering each form. |
| O7 | x86 kernels are refused: no 32-bit capture (Q7). F5 and F6 would give the 4-byte offsets of the bug-check records. | A 32-bit capture. |
| O8 | A routine outside the kernel image has no symbol (S55 4.4 step 4). Owner decision 2026-11-12: keep full scope, recheck those rows once. Result of the recheck on mem1, mem2 and mem5: 3, 2 and 2 rows, every routine inside another module (CLASSPNP, cng, ksecdd on mem1; ksecdd, KslD on mem2; crashdmp, dxgkrnl on mem5). The kernel symbol table names no symbol at any of these routines, so they stay unnamed. Done: no change. | None. |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept the new names |
| O2 | Serve through file-set build |
| O3 | Accept project names |
| O4 | Defer to v0.2.0 |
| O5 | Read kernel stores only |
| O6 | Leave undistinguished |
| O7 | Refuse x86 |
| O8 | Keep full scope, recheck those rows once |

## 11. Provenance

Author: the project, 2026-11-12. Sources: Microsoft Learn pages and the WDK 10.0.28000.0 headers as cited in section 3, accessed 2026-11-12; the Intel SDM; the ntoskrnl types and symbols in the project's symbol tables. Measurements: `callbackfacts` on the four captures named in section 3. Every rule rests on the sources and measurements above.
