# S64: Windows driver, device and kernel-state tools

Version 1, 2026-11-12.

## 1. Purpose

An examiner of a Windows kernel asks a group of related questions. Which driver objects exist, including ones no list holds, and does each one's code lie in a loaded module? Where do the drivers' dispatch routines point? Which devices did each driver create and which filters sit above them? Which kernel modules were loaded or unloaded? What does the kernel's own address-space map say, which processors exist, which timers will run code and whose, where do the system services lead, and has anyone patched the user-mode ETW entry points? This specification defines fourteen tools that answer them, one section group per tool, over shared rules for reading kernel objects.

| Tool | Package | Question |
|---|---|---|
| `windows.driver.scan` | driverscan | Which driver objects do the pool allocations hold? |
| `windows.driver.find_unbacked` | driverunbacked | Which driver objects start in no loaded module? |
| `windows.driver.check_irp` | driverirp | Which module holds each dispatch routine? |
| `windows.device.tree` | devicetree | Which devices belong to each driver, and what is attached above them? |
| `windows.module.scan` | modulescan | Which loader entries do the pool allocations hold? |
| `windows.module.list_drivers` | moduledrivers | Placeholder: loaded modules named `.sys`. |
| `windows.module.list_unloaded` | moduleunloaded | Which kernel modules were unloaded, and when? |
| `windows.kernel.list_regions` | kernelregions | How did the memory manager lay out system space? |
| `windows.kernel.read_info` | kernelinfo | Kernel identity and the shared clock. |
| `windows.kernel.find_pattern` | kernelpattern | Where in system space does a regular expression match? |
| `windows.cpu.list` | cpulist | Each processor's control region and control block. |
| `windows.timer.list` | timerlist | Which timers queue a DPC, and whose code is it? |
| `windows.syscall.list` | syscalllist | Where does each native system service lead? |
| `windows.etw.check_patches` | etwpatches | Which ntdll ETW entry points return at once or jump out of ntdll? |

`windows.module.list_drivers` stays a placeholder: it defines no analysis of its own (section 4.6).

## 2. Inputs

| Input | Use |
|---|---|
| Kernel memory | `tools.Context.Memory`, kernel virtual reads. |
| Physical memory | `tools.OptionPhysicalMemory`, for the pool scans (S31) and the pattern search. |
| Page tables | `tools.OptionKernelDTB` and `tools.OptionPagingMode`, for the pattern search's own walk (S53 `layers.IntelTranslator`). |
| Process spaces | `tools.Context.ProcessSpace`, for the ETW check. |
| Symbol table | The ntoskrnl types and globals of section 3. |
| Shared code | `winkernel` list walker and build reader (S03); `modulelist` module list, address rules, attribution and filters (S55); `scan` pool scans (S31); `memoryranges` (S24) and `pesymbols.Exports` (S18 reader) for the ETW check. |
| Options | `windows.module.scan.base`, `windows.module.scan.name` (S55 4.5 rules); `windows.kernel.find_pattern.pattern` (RE2 text), `windows.kernel.find_pattern.maxsize` (unsigned); `pid` through the memory ranges; `strict`; `diagnostics`. |
| Limits | `MaxListEntries`, `MaxTableEntries`, `MaxMatchesPerChunk`, `RowPreviewBytes`, `MaxBufferBytes`, `PTECacheEntries`, `Workers`; `util.MaxUnicodeStringBytes` per string. |

The image is untrusted: every count, pointer and name can hold any value.

## 3. Facts from the sources

### Documentation and headers

| # | Fact | Source |
|---|---|---|
| W1 | `DRIVER_OBJECT` begins `CSHORT Type; CSHORT Size; PDEVICE_OBJECT DeviceObject; ULONG Flags; PVOID DriverStart; ULONG DriverSize; PVOID DriverSection; PDRIVER_EXTENSION DriverExtension; UNICODE_STRING DriverName; …` and ends `PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];`, with the comment that the dispatch table "must be the last field in the object". `DRIVER_EXTENSION` begins with the "Back pointer to Driver Object" and holds `UNICODE_STRING ServiceKeyName`. | WDK 10.0.28000.0 `km/wdm.h` (NuGet Microsoft.Windows.WDK.x64 10.0.28000.1839), lines 33240 to 33350, accessed 2026-11-12. |
| W2 | `IO_TYPE_DEVICE` is 3 and `IO_TYPE_DRIVER` is 4. `IRP_MJ_CREATE` 0x00 to `IRP_MJ_PNP` 0x1b; `IRP_MJ_MAXIMUM_FUNCTION` is 0x1b. | `km/wdm.h`, lines 32107 to 32157. |
| W3 | `DEVICE_TYPE` values `FILE_DEVICE_BEEP` 0x01 to `FILE_DEVICE_CXL_TYPE3` 0x67 (95 names); "Values … used by Microsoft Corporation are in the range 0-32767, and 32768-65535 are reserved for use by customers." `FILE_DEVICE_IS_MOUNTED`, `FILE_DEVICE_SECURE_OPEN`, `FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL` and `FILE_DEVICE_REQUIRE_SECURITY_CHECK` are characteristics, not types. | `km/wdm.h`, line 7398 and the `FILE_DEVICE_` defines. |
| W4 | `DEVICE_OBJECT.Type`: "For device objects, the value of this member is 3." `DriverObject`: the driver object "that represents the loaded image of the driver". `NextDevice`: "the next device object, if any, that was created by the same driver". `AttachedDevice`: "the attached device object … typically … the device object of a filter driver, which intercepts I/O requests originally targeted to the device". `DeviceType` is set by `IoCreateDevice`. | Microsoft Learn, "DEVICE_OBJECT structure (wdm.h)", dated 2024-02-09, accessed 2026-11-12. |
| W5 | `UNICODE_STRING` is `{ USHORT Length; USHORT MaximumLength; PWSTR Buffer; }`, lengths in bytes. | Microsoft Learn, "UNICODE_STRING structure (ntdef.h)" (S55 D7). |
| W6 | `KeNumberProcessors` is declared `extern NTSYSAPI volatile CCHAR KeNumberProcessors;` on x86 and AMD64. | `km/wdm.h`, line 176. |
| W7 | `KSYSTEM_TIME` is `{ ULONG LowPart; LONG High1Time; LONG High2Time; }`. `KeQueryTickCount` reads `High1Time`, then `LowPart`, and repeats until `High1Time` equals `High2Time`. `KUSER_SHARED_DATA.InterruptTime` is "Current 64-bit interrupt time in 100ns units" and `SystemTime` "Current 64-bit system time in 100ns units"; `NtSystemRoot` is `WCHAR[260]`; `NtProductType` is `NT_PRODUCT_TYPE`. `KI_USER_SHARED_DATA` is 0xFFFFF78000000000 on AMD64 (S03). | `km/wdm.h`, lines 276 to 280, 19891 to 19899, 2957; `km/ntddk.h`, lines 9104 to 9140, 9201. |
| W8 | A DPC object's `Type` is `DpcObject` or `ThreadedDpcObject` (the header's DPC assertion). | `km/wdm.h`, lines 19084 to 19094. |
| W9 | FILETIME counts 100-nanosecond intervals since January 1, 1601 (UTC). | Microsoft Learn, "FILETIME structure (minwinbase.h)", accessed 2026-11-12. |
| W10 | A processor group holds up to 64 logical processors; 64-bit Windows supports more than 64 logical processors. | Microsoft Learn, "Processor Groups", dated 2026-11-02, accessed 2026-11-12. |
| W11 | Encodings: `RET` `C3`, `RET imm16` `C2 iw`, `JMP rel8` `EB cb`, `JMP rel32` `E9 cd`, `JMP r/m` `FF /4`; with ModRM `25`, `FF 25` is `JMP [RIP+disp32]` in 64-bit mode and `JMP [disp32]` in 32-bit mode. | Intel SDM Vol. 2 (S29 F2). |
| W12 | Paging and canonical addresses (S55 D3, D4); `MappedRun` listings of a page-table root (S53). | S55, S53. |
| W13 | The image's headers: the signature offset at 0x3c, the COFF file header with `Machine` at 0 (2 bytes) and `TimeDateStamp` at 4 (4 bytes), and the optional header with `MajorOperatingSystemVersion` and `MinorOperatingSystemVersion` at 40 and 42 (2 bytes each) in PE32 and PE32+ alike. `TimeDateStamp` is "the low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), which indicates when the file was created"; `MajorOperatingSystemVersion` and `MinorOperatingSystemVersion` are "the major version number of the required operating system" and the minor one; `IMAGE_FILE_MACHINE_AMD64` is 0x8664. | Microsoft Learn, "PE Format" (S72 P1, P2, P4), accessed 2026-11-12. |

### Kernel types

Read with `drivertoolfacts -types` from the kernel tables of mem1_win11 (26100, GUID 0D960CE103763A6097E839406D8B369F), mem2_win10 (19045, F57E740B088E5056E8AF0772F1CC5BEB), mem5_server2016 (14393, 3DFC5F7228304C26859E55E481700385), mem6_server2025 and mem7_server2025 (26100, 953A8DE880B0818C32DA2DEC1D79C2D9).

| # | Fact |
|---|---|
| K1 | `_DRIVER_OBJECT` is 0x150 bytes in all five: `Type` (short) 0, `Size` (short) 2, `DeviceObject` 8, `DriverStart` 0x18, `DriverSize` (unsigned int) 0x20, `DriverExtension` 0x30, `DriverName` 0x38, `MajorFunction` (`[28]` pointers) 0x70. `_DRIVER_EXTENSION`: `DriverObject` 0, `ServiceKeyName` 0x18 (0x58 bytes on 26100, 0x50 on the others). |
| K2 | `_DEVICE_OBJECT` is 0x150 bytes: `Type` 0, `DriverObject` 8, `NextDevice` 0x10, `AttachedDevice` 0x18, `DeviceType` (unsigned int) 0x48, `DeviceObjectExtension` 0x138. `_DEVOBJ_EXTENSION`: `DeviceObject` 8, `AttachedTo` 0x30. `_OBJECT_DIRECTORY.HashBuckets` is `[37]` pointers to `_OBJECT_DIRECTORY_ENTRY` {`ChainLink` 0, `Object` 8}. |
| K3 | `_KPCR`: `Self` 0x18, `CurrentPrcb` 0x20, `Prcb` (embedded `_KPRCB`) 0x180. `_KPRCB.Number` (unsigned int) 0x24; `_KPRCB.TimerTable` 0x4100 (26100), 0x3940 (19045), 0x3600 (14393). |
| K4 | `_KTIMER_TABLE.TimerEntries` is `[2][256]` `_KTIMER_TABLE_ENTRY` at 0x200 on 26100 and 19045 and `[256]` on 14393; `_KTIMER_TABLE_ENTRY` is 0x20 bytes with `Entry` (`_LIST_ENTRY`) at 8. `_KTIMER` is 0x40 bytes: `Header` 0, `DueTime` (`_ULARGE_INTEGER`) 0x18, `TimerListEntry` 0x20, `Dpc` 0x30, `Period` (unsigned int) 0x3c. `_DISPATCHER_HEADER.Type` 0, `SignalState` 4. `_KDPC`: `Type` 0, `DeferredRoutine` 0x18. |
| K5 | `_KOBJECTS` gives `TimerNotificationObject` 8, `TimerSynchronizationObject` 9, `DpcObject` 19 and `ThreadedDpcObject` 26 in all five. |
| K6 | `_KAFFINITY_EX` holds `StaticBitmap[32]` 64-bit words on 26100 and `Bitmap[20]` on 19045 and 14393. |
| K7 | `_MI_VISIBLE_STATE.SystemVaRegions` is `[18]`, `[13]` and `[14]` `_MI_SYSTEM_VA_ASSIGNMENT` {`BaseAddress` 0, `NumberOfBytes` 8} on 26100, 19045 and 14393, and `_MI_ASSIGNED_REGION_TYPES` has `AssignedRegionMaximum` 18, 13 and 14. `SystemVaType` is `[256]` unsigned char on 26100 and 19045 and absent on 14393. `_MI_SYSTEM_VA_TYPE` and `_MI_ASSIGNED_REGION_TYPES` number their values differently on each build. |
| K8 | `_DBGKD_GET_VERSION64`: `MajorVersion` 0, `MinorVersion` 2, `MachineType` 8, `KernBase` 0x10, `PsLoadedModuleList` 0x18. |
| K9 | No table describes `_UNLOADED_DRIVERS`, `_KDDEBUGGER_DATA64` or `_KSERVICE_TABLE_DESCRIPTOR`; none types a global. The globals `KiProcessorBlock`, `KeNumberProcessors`, `KiServiceTable`, `KiServiceLimit`, `KiArgumentTable`, `KeServiceDescriptorTable`, `MmUnloadedDrivers`, `MmLastUnloadedDriver`, `KiWaitNever`, `KiWaitAlways`, `KdVersionBlock`, `KdDebuggerDataBlock`, `KdpDataBlockEncoded`, `MiVisibleState`, `NtBuildLab`, `NtBuildLabEx`, `ObpRootDirectoryObject` and `MmPfnDatabase` exist in all five. |

### Measurements

All rows come from `drivertoolfacts` on 2026-11-12, over mem1_win11, mem2_win10, mem5_server2016, mem6_server2025 and mem7_server2025, in that order. `-raw` reads the structures directly with its own code; `-tool` runs the tools of this specification. Every capture is x64 with 4-level paging and 8-byte pointers.

**Drivers and devices** (`-raw -only driver`: the driver objects named in `\Driver`, `\FileSystem` and `\FileSystem\Filters`, found through `ObpRootDirectoryObject`, which the pool scan does not use).

| # | Measured |
|---|---|
| D1 | 162, 157, 109, 124 and 131 driver objects are named in the directories; the other directory entries are 10 device objects and 1 directory per capture. |
| D2 | Every one has `Type` 4 and `Size` 0x150 (sizeof `_DRIVER_OBJECT`), a `DriverExtension` whose `DriverObject` is the driver, and a readable `ServiceKeyName`. `DriverName` starts `\Driver\` (138, 130, 83, 96, 103) or `\FileSystem\` (24, 27, 26, 28, 28); its last part is the object name except for 2 drivers on mem1. |
| D3 | `DriverStart` is a loaded module's base for all but one per capture; `DriverSize` equals that module's `SizeOfImage` for 152, 148, 100, 114 and 121. No `DriverStart` lies in no module. |
| D4 | The one driver per capture with `DriverStart` 0 and `DriverSize` 0 is `\FileSystem\RAW`. |
| D5 | `MajorFunction` slots: inside the driver's own image 1,125, 1,149, 922, 896, 876; in the kernel image 2,005, 1,934, 1,488, 1,709, 1,757; in another module 1,406, 1,313, 642, 867, 1,035; in no module 0. |
| V1 | 308, 386, 267, 263 and 255 devices hang off the drivers' `DeviceObject`/`NextDevice` chains; every one has `Type` 3, names its own driver in `DriverObject`, and has a `DeviceObjectExtension` whose `DeviceObject` is the device. No chain cycles. |
| V2 | 95, 171, 75, 69 and 68 devices sit on `AttachedDevice` chains, at most 4, 5, 2, 2 and 2 deep; each attached device has `Type` 3 and its extension's `AttachedTo` is the device below it. |
| V3 | `DeviceType` values outside the wdm.h names: 0x100 and 0x7d00 on all five, 0x8fff on mem2 and mem7 (3, 4, 3, 3, 4 devices). |

**Processors, timers, services** (`-raw`).

| # | Measured |
|---|---|
| C1 | `KeNumberProcessors` is 16, 8, 8, 4 and 4, read as one byte or as four; `KeMaximumProcessors` equals it; the `KiProcessorBlock` slots after the count are 0. For every processor, `_KPCR.Self` is the control region, `CurrentPrcb` is the embedded block, `_KPRCB.Number` is the slot index, and the region is page-aligned. |
| C2 | The processor capacity of K6 is 2,048 on 26100 and 1,280 on 19045 and 14393. |
| T1 | The timer lists hold 135, 204, 251, 173 and 140 distinct timers (8,192, 4,096, 2,048, 2,048, 2,048 lists). No timer is reached from two lists. |
| T2 | 46, 62, 66, 42 and 55 lists break on the forward walk; 21, 25, 20, 19 and 17 break at the first entry, whose `Blink` is another list head of the same table. The S03 recovering walk finds 34, 53, 28, 22 and 14 entries through `Blink`. |
| T3 | Every listed timer's `Header.Type` is 8 or 9 (91/44, 139/65, 199/52, 128/45, 111/29). |
| T4 | No stored `_KTIMER.Dpc` value reads as an address. |
| T5 | The candidate transform `bswap64(rotl64(stored ^ KiWaitNever, KiWaitNever & 0xFF) ^ timer) ^ KiWaitAlways` gives 0 for 100, 171, 208, 141 and 104 timers and a `_KDPC` of `Type` 19 for all the others (35, 33, 43, 32, 36); no decoded value is anything else. |
| T6 | The decoded `DeferredRoutine`s lie in the kernel image (11, 9, 10, 10, 10) or another module (24, 24, 33, 21, 26), except one on mem6 in no module. |
| T7 | Links with low bits set: 0, 1, 0, 1, 2. The mem6 one is the timer of T6 whose routine lies in no module, at an unaligned pool address. |
| T8 | Every listed DPC timer's `DueTime` is at or after the capture's `InterruptTime`. |
| T9 | `timerwalkfacts`, 2026-11-12: the forward walk breaks on 46, 62, 66 and 55 lists of mem1, mem2, mem5 and mem7, and the backward walk on 42, 57, 65 and 49 of those; a Flink walk without the back-link test reaches 68, 87, 84 and 55 entries before another list head that the recovering walk does not list. Each such entry lies past a link that does not point back. On mem2 five DPC timers sit there (0xffff8b8885ee1540, 0xffff8b8885ee3540, 0xffff8b8885fa7108, 0xffff8b8885fa72a0, 0xffff8b8885fa7c30): the first two form a pair that links to the head of list 485 of processor 0, whose own links make it empty, and are reached from the heads of lists 283 and 287 only across 1 and 3 such links; the other three are a run reached from the head of list 328 only across one, whose back end leads to an address that does not read. The timers 0xffff8b88891771d0 (mem2, list 272) and 0xffff9e03faf31710 (mem1, list 402) are linked both ways and reached by the backward walk with every link pointing back; no Flink walk from a head reaches them. |
| S1 | `KeServiceDescriptorTable` holds `KiServiceTable`, 0, `KiServiceLimit` and `KiArgumentTable` in its first four pointer-wide slots. |
| S2 | `KiServiceLimit` is 489, 473, 450, 489 and 489. Each entry read as a signed 32-bit value shifted right by 4 and added to `KiServiceTable` lands in the kernel image at an address with an `Nt` symbol, for every entry. |
| S3 | The low 4 bits of each entry are `KiArgumentTable`'s byte for it divided by 4 (302/187, 295/178, 286/164, 302/187, 302/187 entries with 0/nonzero bits). |
| S4 | The second descriptor of `KeServiceDescriptorTableShadow` names a table in `win32k.sys` with 1,493, 1,318, 1,138, 1,477 and 1,477 entries; it reads through the kernel space on mem1, mem6 and mem7 only. |

**Modules, regions, kernel identity, ETW**.

| # | Measured |
|---|---|
| U1 | `MmUnloadedDrivers` points into a pool allocation tagged `MmDT` of 0x800, 0x800, 0x7e0, 0x800 and 0x800 bytes; 0x7e0 is a 0x10-byte header and 50 records of 0x28 bytes. |
| U2 | `MmLastUnloadedDriver` is 8, 9, 9, 20 and 13; the slots at and after it are zero. With a 0x28 stride every record has a `.sys` name (UNICODE_STRING at 0, except `pme9533.tmp` on mem2), a page-aligned start (0x10) in system space, and an end (0x18) a whole number of pages above it. |
| U3 | The 8-byte value at 0x20 is below the capture's `InterruptTime` on the three 26100 captures (all records), and between the boot time and `SystemTime` as a FILETIME on 19045 and 14393 (within 2 s before `SystemTime − InterruptTime` for the earliest records). |
| R1 | `MiVisibleState` points to `_MI_VISIBLE_STATE` in all five. |
| R2 | The PFN database pointer, the `MmUnloadedDrivers` pool array, the paged root directory object and the kernel image lie in the `SystemVaRegions` elements whose `_MI_ASSIGNED_REGION_TYPES` names are `AssignedRegionPfnDatabase`, `AssignedRegionNonPagedPool`, `AssignedRegionPagedPool` and `AssignedRegionSystemImages`, on every capture; and, where `SystemVaType` exists, in slots whose `_MI_SYSTEM_VA_TYPE` names are `MiVaPfnDatabase`, `MiVaNonPagedPool`, `MiVaPagedPool` and `MiVaDriverImages`. |
| R3 | Unused elements: `AssignedRegionKasan` with size 0 on 26100, `AssignedRegionCfg` with base 0 on 14393. `AssignedRegionCfg` has a base that is not page-aligned on 26100 and 19045, and overlaps `AssignedRegionSystemDataViews` on mem6. |
| R4 | `SystemVaType` has 256 slots of 0x8000000000 bytes (the upper half split in 256), with 16, 11, 16 and 16 runs of one nonzero type on the four captures that have it; every byte is a `_MI_SYSTEM_VA_TYPE` value. |
| I1 | `KUSER_SHARED_DATA` gives NT 10.0, builds 26100, 19045, 14393, 26100, 26100, product types 1, 1, 3, 3, 3, and `NtSystemRoot` `C:\Windows`. |
| I2 | `NtBuildLab` reads `26100.ge_release.240331-1435`, `19041.vb_release.191206-1406`, `14393.rs1_release.161220-1747` and the 26100 string again; `CmNtCSDVersion` is 0. |
| I3 | `_DBGKD_GET_VERSION64` at `KdVersionBlock` gives `KernBase` equal to the session's kernel base and `PsLoadedModuleList` equal to the symbol, `MachineType` 0x8664, version 15.<build>. |
| I4 | `KdpDataBlockEncoded` is 1 on all five and the bytes at `KdDebuggerDataBlock + 0x10` are not `KDBG`: the debugger data block is stored encoded. |
| I5 | The kernel image's headers at the session's kernel base read on all five (`-tool -only info`): `Machine` 0x8664, `MajorOperatingSystemVersion` 10 and `MinorOperatingSystemVersion` 0 on every one. `TimeDateStamp` read as W13 says is 2043-05-03 22:39:25 UTC, 1985-02-02 23:04:03, 2016-12-21 06:50:57, and 2085-08-29 17:06:46 on mem6 and mem7: on the 26100 kernels it is later than the capture's `SystemTime`, and on 19045 it is before the build's `NtBuildLab` date, so on those builds the field does not hold the link time (O15). |
| E1 | The ETW exports of the 64-bit ntdll are the `Etw` functions and `NtTraceEvent`, `NtTraceControl` (and `Zw` aliases on 14393): 42, 42, 82, 84 and 42 names across the System32 and SysWOW64 copies. |
| E2 | ntdll mappings 78, 149, 70, 95, 81; first bytes read 2,822, 3,458, 1,949, 1,792, 673 and unread 408, 1,348, 835, 314, 197; export tables unread 1, 34, 2, 44, 60. First bytes over all reads: `33`, `40`, `48`, `4c`, `4d`, `65`, `66`, `8b`, `b8` and `e9`; no `C3`, `C2` or `EB`. |
| E3 | Every `E9` (75, 21, 10, 50, 20 reads) is `EtwpGetCpuSpeed` and jumps inside its own ntdll mapping. |

## 4. Algorithm

### 4.1 Shared rules

1. **Profile.** Every tool refuses a profile whose OS is not Windows.
2. **Strings.** A `UNICODE_STRING` is read with `util.ReadUnicodeString` when it lies in kernel virtual memory. A string inside a body found in physical memory is decoded from the body's bytes, with its buffer read through the kernel space: Length 0 is the empty string; odd, above `MaximumLength`, above `util.MaxUnicodeStringBytes` or a null buffer with a nonzero length is unreadable (W5).
3. **Attribution.** Routines are attributed with the S55 attributor over `modulelist.Placed`: the first attribution gives `Module`, `Symbol` and `ModuleUnreadable`; none sets `Unowned`. A module list that does not read is an error in strict mode and a diagnostic otherwise, except where noted.
4. **Object names.** An object header name is read with `scan.ObjectNamer` (S31); a table that cannot locate names gives one diagnostic and empty names.

### 4.2 `windows.driver.scan`

1. Resolve `_DRIVER_OBJECT` (size, `Size`, `DriverStart`, `DriverSize`, `DriverName`, `DriverExtension`), `_DRIVER_EXTENSION.ServiceKeyName` and `_OBJECT_HEADER.Body` (K1). A missing one is `ErrNoDriverType` naming it.
2. Scan with the S31 executive-object scan, filter `scan.DriverFilter`, type tag `_DRIVER_OBJECT.Type` = `IO_TYPE_DRIVER` (W2). An unresolved tag gives a diagnostic.
3. **Body rule.** The body's `Size` must equal sizeof `_DRIVER_OBJECT` (D2); otherwise the hit is not a driver object.
4. Read `DriverStart` and `DriverSize` (4 bytes, W1), `DriverName` by 4.1 step 2, `ServiceKeyName` through `DriverExtension` (null or unread: flagged), and the object header name.
5. Each row carries the S31 placement: physical body, kernel address (0 when unmapped), other mapped copy, and whether the TypeIndex check failed.
6. One diagnostic gives the count and the scan statistics. Order: S31 placement order.

`PlausibleName` is true for a name with at least one character, valid UTF-8, no replacement character and only printable characters: a reused or unread buffer decodes to control or replacement characters. `Identified` is true when any of the three names is plausible.

### 4.3 `windows.driver.find_unbacked`

1. Read the module list; failure is an error, since without it every driver would look unbacked.
2. Keep each scanned driver whose `DriverStart` is 0 or lies in no placed module.
3. `NoImage` is set when both `DriverStart` and `DriverSize` are 0 (D4).

### 4.4 `windows.driver.check_irp`

1. `_DRIVER_OBJECT.MajorFunction` must be an array; its length gives the slots (28 on every table, W2). A length other than the 28 wdm.h names gives a diagnostic; extra slots are named by number.
2. For each scanned driver with a kernel address, once per address: read each slot through the kernel space. A copy the kernel does not map is left out and counted.
3. Each slot is a row: driver address, driver name (`DriverName`, else the object name), code, `IRP_MJ_` name (W2), handler, attribution (4.1 step 3), and `InImage` when the handler lies in `[DriverStart, DriverStart + DriverSize)`.
4. A slot that does not read gives a diagnostic and no row; strict mode then fails. Handlers in no module are counted in one diagnostic.

### 4.5 `windows.device.tree`

1. Resolve the members of K1 and K2 (`ErrNoDeviceType` when one is missing).
2. For each scanned driver with a kernel address, once per address: a `driver` row at level 0.
3. Follow `DeviceObject`, then `NextDevice` (W4). Each device must have `Type` `IO_TYPE_DEVICE` and name this driver in `DriverObject` (V1); one that does not stops that driver's chain (`ErrNotDevice`, `ErrOtherDriver`). A repeated device is `ErrCycle`; more than `MaxListEntries` devices is `ErrTooLong`. Each device is a `device` row at level 1 with its index in the chain, address, object name and type (W3; unknown values as hex, V3).
4. Above each device follow `AttachedDevice` (W4): each must have `Type` 3; each is an `attached` row at levels 2, 3, … carrying the attached device's own driver's `DriverName` and object name. Cycles and length are bounded as in step 3.
5. A broken chain is an error in strict mode and a diagnostic otherwise; the rows before it stay.

### 4.6 `windows.module.list_drivers` (placeholder)

The S55 module list filtered to modules whose base name ends in `.sys`, compared without case; a module whose name did not read is kept. The tool reads no driver object; `windows.driver.scan` does.

### 4.7 `windows.module.scan`

1. Read the base and name options with `modulelist.ReadFilter` (S55 4.5).
2. The loader entry type is the one `scan.ModuleFilterFor` names (S55 T1, T2); `DllBase`, `SizeOfImage` and `BaseDllName` are required (`ErrNoLoaderEntry`), `FullDllName` optional with a diagnostic.
3. Scan with the S31 structure scan for that filter.
4. **Entry rule.** `DllBase` at or above system space start (S55 4.3), page-aligned, and `SizeOfImage` nonzero and a whole number of pages (S55 M2, M3); otherwise the hit is not a loader entry.
5. Names by 4.1 step 2. Rows the filter keeps, in placement order, with physical body, kernel address and other mapped copy; one diagnostic with the counts and the S55 filter report.

### 4.8 `windows.module.list_unloaded`

1. `MmUnloadedDrivers` and `MmLastUnloadedDriver` are required (`ErrNoSymbols`); a 4-byte table is `ErrUnsupportedLayout` (no measured layout, O5).
2. The array pointer 0 means nothing was unloaded: a diagnostic and no rows.
3. **Record layout** (U1, U2; no type, K9): 0x28 bytes, name `UNICODE_STRING` at 0, start 0x10, end 0x18, time 0x20; 50 records.
4. `MmLastUnloadedDriver` above 50 is `ErrIndexTooLarge` in strict mode, otherwise capped with a diagnostic.
5. **Order.** The slots before `MmLastUnloadedDriver`, oldest first. If the slot at `MmLastUnloadedDriver` holds a nonzero name length the array has wrapped, and the slots from it to 49 come first (O6).
6. **Clock** (U3, W7, W9). With `SystemTime` and `InterruptTime` read from the shared data (4.10 step 4): a value at or below `InterruptTime` is interrupt time (`Clock` `interrupt`, `SinceBoot` the value, `Time` boot plus the value); a value at or below `SystemTime` is a FILETIME (`Clock` `system`, `Time` the value, `SinceBoot` from boot when not negative); otherwise `unknown`. Boot is `SystemTime − InterruptTime`. The two ranges cannot meet on a running system: interrupt time counts from boot, system time from 1601.
7. An end below the start gives a diagnostic; the row stays.

### 4.9 `windows.kernel.list_regions`

1. `MiVisibleState` and an array `_MI_VISIBLE_STATE.SystemVaRegions` are required (`ErrNoVisibleState`); the pointer must read (`ErrStateUnread`).
2. **Assigned regions** (R2). Element *i* is named by the `_MI_ASSIGNED_REGION_TYPES` value *i*; a table without the enum names elements by number with a diagnostic. An element with base 0 or size 0 is unassigned and gives no row (R3). One that passes the top of the address space gives a diagnostic.
3. **Slot types** (R4). When `SystemVaType` exists, its *n* bytes split the upper half (S55 4.3) into *n* equal slots; runs of equal nonzero bytes are rows named by `_MI_SYSTEM_VA_TYPE`. A count that does not divide the half gives a diagnostic and no slot rows.
4. Rows sorted by start, then table name.

### 4.10 `windows.kernel.read_info`

Rows of name and value, in this order, each present when its source reads (an unread member gives a diagnostic):

1. Session: `KernelBase`, `DirectoryTableBase`, `PagingMode`, `SymbolTable`, `PointerSize`.
2. Version block (K8, I3): `KdVersionBlock`, `MajorVersion`, `MinorVersion`, `MachineType`, `KernBase`, `PsLoadedModuleList`. A `KernBase` other than the session's gives a diagnostic.
3. `NtBuildLab`, `NtBuildLabEx`: NUL-terminated text of at most 256 bytes; `KeNumberProcessors`: one byte (W6).
4. Shared data (W7): `KUSER_SHARED_DATA` address; `NtMajorVersion`, `NtMinorVersion`, `NtBuildNumber`, `ActiveProcessorCount`, `NumberOfPhysicalPages`; `NtProductType` named by `_NT_PRODUCT_TYPE`; `NtSystemRoot` (260 WCHARs); `SystemTime` as UTC in `SystemTimeLayout`; `InterruptTime` as a duration. A `KSYSTEM_TIME` whose two high parts differ is torn (`ErrTimeTorn`, W7).
5. Kernel image header (W13, I5): with a session kernel base, the image's headers are read there with the S72 parser (`extract.ReadHeaders`). Rows `Machine` (hexadecimal), `TimeDateStamp` (the W13 time_t as UTC in `SystemTimeLayout`, shown as read whatever it holds, O15), `MajorOperatingSystemVersion` and `MinorOperatingSystemVersion` (decimal). Headers that do not read give the diagnostic `windows.kernel.read_info: kernel image at 0x<base>: pe header does not read: <err>` and none of these rows; no kernel base gives none either.

The debugger data block is not read: it is stored encoded on every capture (I4) and no table types it (O3).

### 4.11 `windows.kernel.find_pattern`

1. The pattern option is required (`ErrNoPattern`) and must compile under RE2 (`tools.Context.PatternOption`); it is compiled as `(?s:<text>)`. The match-size option defaults to `RowPreviewBytes`, must be above 0 and at most `MaxBufferBytes` (a kept match is a buffer in a row).
2. Walk the kernel page-table root with the S53 translator and keep the runs in the upper half (S55 4.3): the kernel's page tables also map the user half of the process they came from.
3. **Blocks.** Consecutive runs whose virtual addresses touch form one block, whatever their frames; a block reads across its frames in order.
4. **Chunks.** A block is read in chunks of `ChunkSize` (16 MiB) plus `Overlap` (4 KiB) of lookahead. A match is reported by the chunk in which it starts: one starting in the lookahead belongs to the next chunk. A chunk that does not read is skipped and counted.
5. **Bytes.** Matching is one character per byte: data with a byte at or above 0x80 is matched as Latin-1, each byte the code point of its value, and offsets are mapped back. A match is cut to the match size; `Text` is its UTF-8 decoding with replacement characters.
6. At most `MaxMatchesPerChunk` matches per chunk; the chunks that reach it are counted in a diagnostic. Unread tables and uncaptured pages are reported once.
7. `Translator`, `Section`, `SectionBlocks`, `MappedBlocks`, `Block`, `ScanBlock`, `Scanner` (`Matches`, `Chunk`), `CompilePattern`, `PatternOption`, `MaxSizeOption`, `Truncate` and `ReportMapping` are the same machinery for the process pattern tools, `linux.memory.find_pattern` (S61 4.12) among them: sections are compared with runs on their masked addresses and a block keeps the section's form. Steps 1 and 3 to 6 hold for every caller. `Scanner.Limit` is the step 6 cap (0 is none) and `Scanner.Capped` the chunks that reached it; each caller sets `Limit` to `MaxMatchesPerChunk` and reports `Capped` as step 6 says.

### 4.12 `windows.cpu.list`

1. `KiProcessorBlock` and `KeNumberProcessors` are required (`ErrNoProcessorBlock`), and `_KPCR.Prcb` (`ErrNoPcrType`).
2. The count is one byte (W6); unread is `ErrCountUnread`, 0 is `ErrNoProcessors`. A count above the capacity (64 times the words of `_KAFFINITY_EX`'s bitmap, K6, C2; `MaxProcessors` 2,048 without the type) is `ErrCountTooLarge` in strict mode and capped otherwise.
3. Each slot below the count holds a `_KPRCB` address; 0, an address below the `Prcb` offset, or an unread slot gives a diagnostic and no row (strict mode fails on an unread slot). The control region is the block minus the `Prcb` offset (K3).
4. `Number` is `_KPRCB.Number`; `PointsBack` is true when `_KPCR.Self` is the region and `CurrentPrcb` the block (C1). False gives a diagnostic; the row stays.

### 4.13 `windows.timer.list`

1. Resolve K4 and K5 (`ErrNoTimerTable`, `ErrNoTimerType`, `ErrNoDpcType`); the bucket count is the product of `TimerEntries`' dimensions.
2. For each processor of 4.12, each bucket's `Entry` is a list head walked with the S03 recovering walk (T2) up to `MaxListEntries`. A head that does not read fails strict mode and is counted otherwise. Breaks are counted, not reported one by one: every capture has them (T2), so strict mode does not refuse them.
3. Each link must be pointer-aligned (T7); the timer is the link minus `TimerListEntry`. A timer reached again is listed once.
4. `Header.Type` must be a timer type of `_KOBJECTS` (K5, T3).
5. **DPC.** With 8-byte pointers and both `KiWaitNever` and `KiWaitAlways`, the stored `Dpc` is decoded with the transform of T5; otherwise it is taken as stored. A decoded 0 is a timer without a DPC; a DPC whose `Type` is not `DpcObject` or `ThreadedDpcObject` (W8) is counted. Only timers with a DPC are rows.
6. Row: processor, timer address, `DueTime` (100-ns interrupt time, T8), `Period` (ms), `Signaled` (`SignalState` nonzero), DPC address, `DeferredRoutine` and its attribution. One diagnostic gives every count.

### 4.14 `windows.syscall.list`

1. **Table.** `KeServiceDescriptorTable`'s first descriptor (S1) when its base and limit read: it is what the system-call path uses. Otherwise `KiServiceTable` with the 4-byte `KiServiceLimit`. A descriptor naming another table than `KiServiceTable` gives a diagnostic. Neither: `ErrNoServiceTable`.
2. A limit above `MaxTableEntries` is `ErrTableTooLarge` in strict mode and capped otherwise.
3. **Entries.** 4 bytes each. With 8-byte pointers the routine is the table address plus the signed entry shifted right by 4 (S2) and `ArgumentBytes` is 4 times the low 4 bits (S3); with 4-byte pointers the entry is the routine address (O8).
4. Attribution anchored at the table (S55 4.4 step 4). Unread entries are left out with a diagnostic (strict mode fails); unowned routines are counted.

### 4.15 `windows.etw.check_patches`

1. Take the memory ranges (S24, which apply `pid`). An ntdll mapping is an `image` range whose file name is `ntdll.dll` without case; the System32 and SysWOW64 copies are separate mappings.
2. Read its exports (`pesymbols.Exports`); an unread table gives a diagnostic and the mapping is skipped, even when its code reads (11 processes on mem2, 29 on mem7, O14). Keep the non-forwarder exports whose name starts with `Etw`, `NtTrace` or `ZwTrace` (E1), in RVA order.
3. Read the first 6 bytes of each in the process's own space; unread entry points are counted.
4. **Patch rule** (W11, E2, E3). `C3` and `C2` are patches. `EB`, `E9` and `FF 25` are patches when the jump target lies outside the mapping; the `FF 25` target is the 8-byte slot at RIP + disp32 in a 64-bit image and the 4-byte slot at disp32 in a SysWOW64 image, and a slot that does not read is a patch with target 0. Any other first byte is not a patch.
5. Row per patch: PID, process, module file name, path, function, address, opcode, instruction name, target. One diagnostic gives the counts.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Driver body `Size` is sizeof `_DRIVER_OBJECT` | W1, D2 | hit refused |
| Driver body `Type` is `IO_TYPE_DRIVER` (scan tag) | W2, D2 | hit refused |
| Device `Type` is 3 and `DriverObject` is the owner | W4, V1 | chain stopped, diagnostic |
| Attached device `Type` is 3 | W4, V2 | chain stopped, diagnostic |
| Device and stack chains are acyclic and within `MaxListEntries` | V1, V2 | chain stopped, diagnostic |
| Loader entry base in system space, page-aligned, size in whole pages | S55 M2, M3 | hit refused |
| `UNICODE_STRING` length even, within `MaximumLength` and the cap | W5 | flagged unreadable |
| Unloaded record layout 0x28 bytes, 50 records, 64-bit only | U1, U2 | `ErrUnsupportedLayout` on 4-byte tables |
| Unload time placed by its range | U3, W7, W9 | `unknown` clock |
| `SystemVaRegions` indexed by `_MI_ASSIGNED_REGION_TYPES` | K7, R2 | numbered names |
| Zero base or size is unassigned | R3 | no row |
| `KSYSTEM_TIME` high parts agree | W7 | `ErrTimeTorn` |
| Processor count within the affinity capacity | K6, C2, W10 | capped, strict error |
| `_KPCR.Self` and `CurrentPrcb` point back | C1 | flag false, diagnostic |
| Timer link pointer-aligned | T7 | skipped, counted |
| Timer `Header.Type` is a timer type | K5, T3 | skipped, counted |
| Decoded DPC has a DPC type | W8, T5 | skipped, counted |
| Service entry decode | S2, S3 | — |
| ETW jump target outside the mapping | E3 | not a patch |

## 6. Failure modes

| Case | Result |
|---|---|
| Profile not Windows | `<tool>: unsupported profile os "<os>"` |
| Required member or symbol missing | the package sentinel: `driverscan.ErrNoDriverType`, `devicetree.ErrNoDeviceType`, `driverirp.ErrNoMajorFunction`, `modulescan.ErrNoLoaderEntry`, `moduleunloaded.ErrNoSymbols`, `kernelregions.ErrNoVisibleState`, `cpulist.ErrNoProcessorBlock`, `cpulist.ErrNoPcrType`, `timerlist.ErrNoTimerTable`, `timerlist.ErrNoTimerType`, `timerlist.ErrNoDpcType`, `syscalllist.ErrNoServiceTable` |
| No physical memory for a scan | `driverscan.ErrNoPhysicalMemory`, `modulescan.ErrNoPhysicalMemory`, `kernelpattern.ErrNoPhysical` |
| Pool scan unsupported or unresolved | the S31 and `tools.Context` errors and diagnostics |
| Module list fails | find_unbacked: error; others: strict error, otherwise diagnostic `<tool>: loaded modules not read, so no routine has an owner: <err>` |
| Device chain broken | `windows.device.tree: <object> at 0x<addr>: <cause>`; strict: error |
| Dispatch slot unread | `windows.driver.check_irp: driver object at 0x<drv>: MajorFunction[<i>] at 0x<addr>: does not read: <err>`; strict: error |
| Processor slot unread | `windows.cpu.list: KiProcessorBlock slot <i> at 0x<addr>: does not read: <err>`; strict: error |
| Count out of range | `cpulist.ErrNoProcessors`, `ErrCountTooLarge`, `moduleunloaded.ErrIndexTooLarge`, `syscalllist.ErrTableTooLarge` (strict), else capped with a diagnostic |
| Shared time torn or unread | `kernelinfo.ErrTimeTorn`, `ErrTimeUnread`; read_info gives a diagnostic, list_unloaded places no time |
| Kernel image header unread | `windows.kernel.read_info: kernel image at 0x<base>: pe header does not read: <err>` diagnostic, no header rows |
| Pattern option | `kernelpattern.ErrNoPattern`, the RE2 option error, `ErrMaxSizeNotAbove`, `ErrMaxSizeTooLarge`; no kernel DTB `ErrNoKernelDTB`; unknown paging mode `ErrPagingMode` |
| ETW export table or space unavailable | `windows.etw.check_patches: <process> (<pid>): …` diagnostic, mapping skipped |

## 7. Result schema

- `driverscan.Driver`: `Offset` (physical body), `VirtualOffset`, `OtherCopy`, `Start`, `Size` (bytes), `Name`, `NameUnreadable`, `ServiceKey`, `ServiceKeyUnreadable`, `ObjectName`, `ObjectNameUnreadable`, `TypeIndexFailed`.
- `driverunbacked.Driver`: `driverscan.Driver` and `NoImage`.
- `driverirp.Entry`: `Offset` (driver address), `Driver`, `DriverNameUnreadable`, `Major`, `MajorName`, `Handler`, `Module`, `ModuleUnreadable`, `Symbol`, `Unowned`, `InImage`. Order: driver, then code.
- `devicetree.Row`: `Level`, `Kind` (`driver`, `device`, `attached`), `DriverOffset` (driver address), `DriverName` (object name), `DriverFullName` (`DriverName` member), `DeviceIndex`, `DeviceAddress`, `DeviceName`, `AttachedDriverName`, `AttachedDriverHeaderName`, `DeviceType`, `DeviceTypeCode`. Depth-first order.
- `modulescan.Module`: `Offset`, `VirtualOffset`, `OtherCopy`, `Base`, `Size`, `Name`, `NameUnreadable`, `Path`, `PathUnreadable`.
- `moduledrivers.Driver`: `Base`, `Size`, `Name`, `NameUnreadable`, `BaseUnreadable`, `SizeUnreadable`.
- `moduleunloaded.Module`: `Name`, `NameUnreadable`, `StartAddress`, `EndAddress`, `CurrentTime` (raw), `Clock` (`system`, `interrupt`, `unknown`), `Time` (UTC; zero when unknown), `SinceBoot`.
- `kernelregions.Region`: `Table` (`SystemVaRegions` or `SystemVaType`), `Type` (enum name or number), `Start`, `Size` (bytes).
- `kernelinfo.Row`: `Variable`, `Value` (decimal counts and versions, `MajorOperatingSystemVersion` and `MinorOperatingSystemVersion` among them; `0x` hexadecimal for addresses, `MachineType` and `Machine`; `SystemTime` and `TimeDateStamp` in `SystemTimeLayout`; text); `SystemTimeLayout`; `SharedTime`, `FiletimeUTC`.
- `kernelpattern.Match`: `Offset` (canonical address), `Text`, `Hex` (the cut bytes).
- `cpulist.Entry`: `Index`, `Offset` (`_KPCR`), `PRCB`, `Number`, `PointsBack`; `MaxProcessors`, `Capacity`.
- `timerlist.Entry`: `Processor`, `Offset`, `DueTime` (100 ns), `Period` (ms), `Signaled`, `Dpc`, `Routine`, `Module`, `ModuleUnreadable`, `Unowned`, `Symbol`.
- `syscalllist.Entry`: `Index`, `Address`, `ArgumentBytes`, `Module`, `ModuleUnreadable`, `Unowned`, `Symbol`.
- `etwpatches.Row`: `PID`, `Process`, `Module`, `Path`, `Function`, `Offset`, `Opcode`, `Instruction`, `Target`; `OpcodeString()`; `Opcodes`; `IsETWFunction`.

## 8. Limits

`MaxListEntries` bounds every list and device chain; `MaxTableEntries` the service table; `MaxMatchesPerChunk` the matches per chunk; `RowPreviewBytes` the default match size and `MaxBufferBytes` its ceiling; `PTECacheEntries` the pattern walk's cache; `Workers` the pool scans; `util.MaxUnicodeStringBytes` each string. The fixed sizes are measured or declared: 28 dispatch slots (W2, K1), 50 unloaded records (U1), 256 slot types (K7), 6 bytes of ETW entry code (W11), `ChunkSize` 16 MiB and `Overlap` 4 KiB (a page of lookahead per chunk).

## 9. Acceptance

1. Synthetic fixtures (`internal/testsupport/s64_fixture.go`, a 64-bit kernel with page tables on the K1 to K4 offsets, pooled objects with name headers): driver objects with and without names, a refused `Size` and `Type`, an unreadable name buffer, a missing member, no physical memory; unbacked drivers and `NoImage`, strict mode over a broken module list; dispatch slots inside the image, in the kernel and in no module; device chains with a stack two deep, an unknown type, a device of another driver and a cycle, strict mode; loader entries refused by base, alignment and size, the name and base filters and a wrong option type; the `.sys` placeholder; processors with a broken back link, a zero count, a count above the capacity in strict and lenient mode; timers with and without DPC, a non-timer, a plain stored pointer, a misaligned link; service entries with argument bytes and negative offsets, a descriptor naming another table; shared data rows and a torn time; kernel image header rows, last in 4.10 order, and an unread header; assigned regions and slot runs, a table without `SystemVaType`; unloaded records on both clocks, a wrapped array, a capped index, a null array; byte matching, lookahead ownership, the match cap, a match across two frames, the option rules; ETW returns, jumps in and out of the image, `FF 25` slots for 64-bit and SysWOW64 images, forwarders.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzReadSplit`, `FuzzDecode` (modulescan), `FuzzProcessorBlock`, `FuzzDpcKey`, `FuzzServiceTable`, `FuzzSharedTime`, `FuzzSlotRuns`, `FuzzRecords`, `FuzzPatternMatches`, `FuzzClassify`, `FuzzDeviceChain`; executions in section 9.4.
3. On the captures (`drivertoolfacts -tool`, 2026-11-12):

| | mem1_win11 | mem2_win10 | mem5_server2016 | mem6_server2025 | mem7_server2025 |
|---|---|---|---|---|---|
| driver.scan rows (mapped objects) | 162 | 157 | 109 | 124 | 131 |
| directory drivers found (D1) | 162 of 162 | 157 of 157 | 109 of 109 | 124 of 124 | 131 of 131 |
| find_unbacked rows | 1 (`\FileSystem\RAW`, `NoImage`) | 1 (same) | 1 (same) | 1 (same) | 1 (same) |
| check_irp rows: own image / kernel / other / no module | 1,125 / 2,005 / 1,406 / 0 | 1,149 / 1,934 / 1,313 / 0 | 922 / 1,488 / 642 / 0 | 896 / 1,709 / 867 / 0 | 876 / 1,757 / 1,035 / 0 |
| device.tree driver / device / attached | 162 / 308 / 95 | 157 / 386 / 171 | 109 / 267 / 75 | 124 / 263 / 69 | 131 / 255 / 68 |
| module.scan rows; listed modules found; unlisted bases | 206; 195 of 195; 1 | 195; 195 of 195; 0 | 142; 142 of 142; 0 | 158; 158 of 158; 0 | 166; 165 of 165; 1 |
| module.list_drivers rows of modules | 186 of 195 | 187 of 195 | 132 of 142 | 149 of 158 | 156 of 165 |
| module.list_unloaded rows, clock | 8 interrupt | 9 system | 9 system | 20 interrupt | 13 interrupt |
| kernel.list_regions assigned / slot runs | 17 / 16 | 13 / 11 | 13 / 0 | 17 / 16 | 17 / 16 |
| kernel.read_info rows | 28 | 28 | 28 | 28 | 28 |
| find_pattern `ntoskrnl.exe` matches, read back equal | 188, 188 | 232, 232 | 161, 161 | 157, 157 | 161, 161 |
| cpu.list rows (all point back, Number = index) | 16 | 8 | 8 | 4 | 4 |
| timer.list rows (kernel / other module) | 35 (11 / 24) | 32 (8 / 24) | 43 (10 / 33) | 31 (10 / 21) | 34 (8 / 26) |
| syscall.list rows, all in the kernel image; first symbol `Nt` | 489; 470 | 473; 455 | 450; 445 | 489; 470 | 489; 470 |
| etw.check_patches rows | 0 | 0 | 0 | 0 | 0 |

   - The driver scan finds exactly the directory drivers on every capture.
   - The unlisted module-scan bases are loader entries the module list no longer links.
   - The read_info rows reproduce I1 to I3 and I5: `KernBase` and `PsLoadedModuleList` equal the session's and the symbol's, and `Machine` equals `MachineType`.
   - Every pattern match reads back through the kernel reader with the same bytes, so the block frame map agrees with the kernel's translation.
   - The timer rows are the DPC timers of T5 less the misaligned links of T7 (1 on mem2, 1 on mem6, 2 on mem7); every `DueTime` is at or after the capture (T8).
   - The syscall rows whose first symbol is not `Nt` carry an `Nt` alias at the same address (S2); the table gives another name first.
   - The patch rule gives no row on the captures: no entry point starts with a return, and the only jump stays in ntdll (E2, E3).

4. Fuzz executions (2026-11-12, 30 s each, no failure): `FuzzReadSplit` 4,258,561 (a body string never reads as text when flagged); `FuzzDecode` 4,541,466 (an accepted loader entry always meets the entry rule); `FuzzProcessorBlock` 3,256,133 (no more rows than the count, region and block one `Prcb` offset apart); `FuzzDpcKey` 4,891,522 (the decode inverts the transform); `FuzzServiceTable` 3,799,063 (argument bytes a multiple of 4 up to 60); `FuzzSharedTime` 3,717,220 (torn exactly when the high parts differ); `FuzzSlotRuns` 4,262,342 (runs ordered, disjoint, whole slots); `FuzzRecords` 1,821,086 (at most 50 rows, no flagged name with text); `FuzzPatternMatches` 1,055,039 (matches ordered, inside the data, equal to its bytes); `FuzzClassify` 1,879,542 (no patch jumps inside the image; patches only on the listed opcodes); `FuzzDeviceChain` 2,543 (no device listed twice at one level, bounded rows; each execution runs a full pool scan).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision (Q3): the row field names of 0.1.0 are kept where the meaning holds (`Offset`, `VirtualOffset`, `OtherCopy`, `DriverName`/`DriverFullName`, …). New fields: `driverscan.TypeIndexFailed`, `driverunbacked.NoImage` (was `KnownException`), `etwpatches.Path` and `Target` (`ModuleLoadedHere` removed), `kernelregions.Table`, `cpulist.Number` and `PointsBack` (`PrcbBase` removed), `timerlist.Processor` and `Dpc` (`DueTime` is now `uint64`, `Signaled` `bool`), `syscalllist.ArgumentBytes`, `moduleunloaded.Clock`. `devicetree.Kind` values are now `driver`, `device`, `attached`; `DriverOffset` is now the driver's kernel address. `driverirp.Unbacked` and `BelowKernelSpace` are removed (`Unowned` remains). | Owner review |
| O2 | Owner decision: `windows.kernel.read_info` variable names are the PDB and WDK names of their sources; the debugger data block rows are gone (I4). | Owner review |
| O3 | The debugger data block is encoded on every capture and untyped; its decoding is not specified. | A Microsoft source for the encoding |
| O4 | The `_KTIMER.Dpc` transform (T5) rests on measurement only: no Microsoft source documents it. It is consistent on 179 of 179 DPC timers. | A Microsoft source |
| O5 | 4-byte kernels: unloaded records refused, service entries taken as addresses (O8), cpu count as one byte; no 32-bit capture. | A 32-bit capture (Q7) |
| O6 | The wrap rule of 4.8 step 5 is not exercised: no capture has 50 unloads (U2). | A capture with more than 50 unloads |
| O7 | Timer links with low bits set (T7) are skipped. Their meaning is not known; on mem2 and mem7 masking the bits gives DPCs in modules. | A Microsoft source or a capture where the bit's meaning shows |
| O8 | x86 service table entries are taken as routine addresses without measurement. | A 32-bit capture |
| O9 | `windows.syscall.list` lists the native table only; the win32k table (S4) is session space and reads through the kernel space on three captures only. | Owner decision on a session-space listing |
| O10 | Owner decision: `windows.module.list_drivers` stays a placeholder (4.6), as before. | Owner decision |
| O11 | Owner decision: the ETW function set is the `Etw`, `NtTrace` and `ZwTrace` exports of ntdll (E1); advapi32 and kernel-mode providers are not checked. | Owner review |
| O12 | Owner decision: the default match size of find_pattern is `RowPreviewBytes` (128), and 0 is refused. | Owner review |
| O13 | Owner decision: `windows.timer.list` lists timers with a DPC only; the others are counted (T5). | Owner review |
| O14 | A process whose ntdll export table does not read is skipped (4.15 step 2), though its entry points read: 11 processes on mem2 and 29 on mem7 hold a readable planted RET that gives no row. A fallback to the exports of the same ntdll file at the same base in another process needs a measurement that the base is one per boot. Owner decision 2026-11-12: skip now; fallback in v0.2.0 after measuring same base per boot. Deferred to v0.2.0 (owner decision 2026-11-12). Done: 4.15 step 2 states the skip; the real-image ETW coverage test counts these processes per image (mem2 11, mem7 29, mem1 and mem5 0) and leaves them out of the planted-row check. | v0.2.0: a per-boot base measurement, then the fallback |
| O15 | The kernel PE header rows had been left out of 4.10. Owner decision 2026-11-12: add the PE header fields back. Done: 4.10 step 5, W13, I5, sections 6, 7 and 9; `tools/windows/kernelinfo/kernel_read_info.go` (`imageHeader`) and two fixture tests in `kernel_read_info_test.go`. `TimeDateStamp` is shown as W13 defines it; I5 shows it is not a link time on the 19045 and 26100 kernels, and no allowed source says what those builds store there. | A Microsoft source for the field on those builds |
| O16 | Probe of the timer walk between breaks (T9). Owner decision 2026-11-12: probe the walk. Result: not a bug. Every timer the recovering walk does not list lies past a link that does not point back, which S03 4.3 step 2.6 (L4) stops at; the mem2 timers of T9 are reached that way only. The timers 0xffff8b88891771d0 and 0xffff9e03faf31710 of T9 are reached by the backward walk with every link pointing back (S03 4.4), so the recovering walk lists them. Done: `timerwalkfacts`. | None |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept |
| O2 | PDB and WDK names |
| O3 | Leave undecoded |
| O4 | Accept measured rule |
| O5 | Defer to v0.2.0 |
| O6 | Defer to v0.2.0 |
| O7 | Skip them |
| O8 | Defer to v0.2.0 |
| O9 | Native table only |
| O10 | Stay a placeholder |
| O11 | ntdll exports only |
| O12 | 128, refuse 0 |
| O13 | DPC timers only, count rest |
| O14 | Skip now; fallback in v0.2.0 after measuring same base per boot |
| O15 | Add the PE header fields back |
| O16 | Probe the walk |

## 11. Provenance

Author: the project, 2026-11-12. Sources: the WDK 10.0.28000.0 headers `km/wdm.h` and `km/ntddk.h`; Microsoft Learn pages for DEVICE_OBJECT, UNICODE_STRING, FILETIME and Processor Groups, and the PE Format specification; the Intel SDM; the ntoskrnl types and symbols of the five captures through the project's symbol tables; the project's measurements with `drivertoolfacts` and `timerwalkfacts`. The previous implementation was read only for its exported names, callers, tool names and option keys. Every rule rests on the sources and measurements above.
