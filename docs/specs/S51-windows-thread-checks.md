# S51: Windows thread checks

Version 1, 2026-11-12.

## 1. Purpose

An examiner who has the thread list of a Windows capture asks four narrower questions of it. Which threads cannot run because someone suspended them? Which kernel threads start in code that no loaded driver holds, as a thread of an unloaded or hidden driver does? Which user threads start in memory that no image maps, as a thread started on injected code does? Which threads carry hardware breakpoints, as a debugger or an in-process hook leaves them?

This specification defines one tool per question: `windows.thread.list_suspended`, `windows.thread.find_orphaned`, `windows.thread.find_suspicious` and `windows.thread.check_debug_registers`. Each tool reports facts the kernel recorded. None of them proves intent: section 9 explains every row the captures gave.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | The kernel's address space, for thread, process and trap-frame members. |
| Physical memory | Only for `find_orphaned`, whose threads come from the pool scan (S31, S50). |
| Symbol table | The kernel's types (section 3, T1 to T4) and the pointer size. |
| Thread list | `windows.thread.list` (S50): `threadlist.Run` and its `Thread` rows. |
| Thread scan | `windows.thread.scan` (S50): `threadscan.Run` and its `Thread` rows. |
| Process list | `any.process.list` (S25), unfiltered, to find the owner of each thread. |
| Process ranges | `memoryranges.Decoder.Mappings` (S24): each process's VAD ranges with kind, protection and file. |
| Loaded modules | `windows.module.list`, unfiltered, with `modulelist.Placed` and `modulelist.Containing`. |
| Image exports | `pesymbols.Exports`: the export table of an image range (PE/COFF export directory). |
| Options | The common `pid` option, applied to the thread's process ID. The tools add no option. |
| Limits | None of their own; the walkers they call apply theirs. |

The image is untrusted. Every value can be anything.

## 3. Facts from the sources

| # | Fact | Source |
|---|---|---|
| F1 | "Each thread has a suspend count (with a maximum value of MAXIMUM_SUSPEND_COUNT). If the suspend count is greater than zero, the thread is suspended; otherwise, the thread is not suspended and is eligible for execution." Suspending a thread "causes the thread to stop executing user-mode (application) code." | Microsoft Learn, "SuspendThread function (processthreadsapi.h)", page dated 2018-12-05, accessed 2026-11-12. |
| F2 | `PsCreateSystemThread` "creates a system thread that executes in kernel mode". `ProcessHandle` is "an open handle for the process in whose address space the thread is to be run"; "If this parameter is not supplied, the thread will be created in the initial system process." `StartRoutine` is "the entry point for the newly created system thread". "Such a system thread has no TEB or user-mode context and runs only in kernel mode." | Microsoft Learn, "PsCreateSystemThread function (wdm.h)", page dated 2023-01-12, accessed 2026-11-12. |
| F3 | `lpStartAddress` of `CreateRemoteThread` "represents the starting address of the thread in the remote process. The function must exist in the remote process." The call "may succeed even if lpStartAddress points to data, code, or is not accessible." | Microsoft Learn, "CreateRemoteThread function (processthreadsapi.h)", page dated 2018-12-05, accessed 2026-11-12. |
| F4 | Pages of type `MEM_IMAGE` "are mapped into the view of an image section", `MEM_MAPPED` pages "are mapped into the view of a section", and `MEM_PRIVATE` pages "are private (that is, not shared by other processes)". | Microsoft Learn, "MEMORY_BASIC_INFORMATION (winnt.h)", page dated 2018-12-05, accessed 2026-11-12. |
| F5 | The x64 `CONTEXT` carries `Dr0`, `Dr1`, `Dr2`, `Dr3`, `Dr6` and `Dr7` as `DWORD64` members, the per-thread copy of the debug registers that `GetThreadContext` and `SetThreadContext` move. | Microsoft Learn, "CONTEXT structure (x86 64-bit)", page dated 2018-12-05, accessed 2026-11-12. |
| F6 | DR0 to DR3 hold the linear addresses of breakpoints 0 to 3. In DR7, bits 0, 2, 4 and 6 (L0 to L3) and bits 1, 3, 5 and 7 (G0 to G3) enable breakpoints 0 to 3 locally and globally. R/Wn (bits 16+4n and 17+4n) selects the condition: 00 instruction execution, 01 data writes, 10 I/O reads or writes (with CR4.DE set), 11 data reads or writes. LENn (bits 18+4n and 19+4n) selects the length: 00 one byte, 01 two bytes, 10 eight bytes on processors that support it, 11 four bytes. Bits 12, 14 and 15 are reserved and must be 0. In 64-bit mode bits 63:32 are reserved and must be 0; writing 1 to them raises #GP. | Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 3B, chapter 18, "Debug Registers" and "Debug Control Register (DR7)" (order number 253669). |
| F7 | A 64-bit process has user space within 0x000'00000000 through 0x7FFF'FFFFFFFF; for 4-byte pointers user space is below 0x80000000. | S17 F5. |
| F8 | The privilege level of a code segment selector is in its bits 1:0, and the current privilege level is that of the CS register; level 3 is the least privileged, where applications run. An interrupt or exception from level 3 saves the interrupted CS. | Intel SDM Vol. 3A, chapter 5, "Privilege Levels", and chapter 6, "Exception and Interrupt Handling" (order number 253668). |
| F9 | The PE export directory gives each export's RVA; an RVA inside the export directory is a forwarder, not code. | Microsoft Learn, "PE Format", section "The .edata Section", accessed 2026-11-12; `pe.ParseExports`. |

### Types

T1 to T4 come from `threadcheckfacts -types` over the four kernel tables of the captures: 26100 (`0D960CE103763A6097E839406D8B369F` on mem1, `953A8DE880B0818C32DA2DEC1D79C2D9` on mem6 and mem7), 19045 (`F57E740B088E5056E8AF0772F1CC5BEB`), 14393 (`3DFC5F7228304C26859E55E481700385`).

| # | Measured type facts |
|---|---|
| T1 | `_KTHREAD.SuspendCount` is a `char` at 0x284 in all four tables. `_KTHREAD.SystemThread` is bit 10 of `MiscFlags` (an `int` at 0x74) in all four. `_KTHREAD.FreezeCount` is a one-bit field of `ThreadFlags` (0x78): bit 14 on 26100 and 19045, bit 13 on 14393. It is a flag, not a count. `_KTHREAD.Header` is a `_DISPATCHER_HEADER` at 0; `_DISPATCHER_HEADER.DebugActive` is an `unsigned char` at 3. `_KTHREAD.TrapFrame` is a `_KTRAP_FRAME*` at 0x90; `_KTHREAD.Process` a `_KPROCESS*` at 0x220. |
| T2 | `_ETHREAD.Tcb` is the `_KTHREAD` at 0. `StartAddress` and `Win32StartAddress` are `void*`: 0x4e0 and 0x560 (26100), 0x450 and 0x4d0 (19045), 0x608 and 0x688 (14393). `_ETHREAD.Terminated` is bit 0 of `CrossThreadFlags` (0x5a0, 0x510, 0x6c0). |
| T3 | `_KTRAP_FRAME` is 0x190 bytes in all four tables, with `Dr0` 0xd8, `Dr1` 0xe0, `Dr2` 0xe8, `Dr3` 0xf0, `Dr6` 0xf8 and `Dr7` 0x100, each an `unsigned long long`, `SegCs` an `unsigned short` at 0x170, and `Rip` 0x168 and `Rsp` 0x180, each an `unsigned long long`. |
| T4 | `_EPROCESS.VadCount` exists (S43 T1). `_KPROCESS.SecureState` exists on every table as an unnamed union with no recorded width; its first pointer-wide word is read, as S43 does. `_KPROCESS.FreezeCount` is an `unsigned int` and `_KPROCESS.DeepFreeze` bit 3 of `ProcessFlags`. `_KTHREAD_STATE` names 0 to 9, with `Terminated` 4. |

### Measurements

M1 to M9 come from `threadcheckfacts -rows` on 2026-11-12 over mem1_win11, mem2_win10, mem5_server2016, mem6_server2025 and mem7_server2025, in that order, run on the S50 thread list and thread scan. The thread list gave 1,123, 1,974, 1,303, 1,298 and 1,210 threads of 83, 153, 71, 101 and 90 processes; the module list 195, 195, 142, 158 and 165 modules.

| # | Measured |
|---|---|
| M1 | `SuspendCount` reads on every listed thread. It is 0 everywhere except 4 threads on mem2 and 5 on mem6, all of explorer.exe, all with count 1 and state `Waiting`. Every one has `StartAddress` at ntdll.dll's `RtlUserThreadStart` and `Win32StartAddress` at page offset 0x35b0 (mem2) or 0x0c0 (mem6) of WorkFoldersShell.dll; on mem2 one of them (tid 10796) starts at 0x7ff8e0e435b0, which no kept range maps: the same offset in another load of that DLL, in a process whose walk kept 729 ranges while `VadCount` holds 740. No suspended thread is terminated. |
| M2 | The `FreezeCount` flag is set on 0, 20, 51, 37 and 35 threads, all of packaged-application processes: SearchApp.exe (mem2); SearchUI.exe and ShellExperienceHost (mem5); SearchHost.exe and ShellExperienceHost (mem6); SearchHost.exe and StartMenuExperienceHost (mem7). On mem5 to mem7 those processes have `_KPROCESS.DeepFreeze` set. `_KPROCESS.FreezeCount` is 0 on every process. No frozen thread has a nonzero `SuspendCount`. |
| M3 | `SystemThread` is set on 251, 482, 151, 184 and 207 listed threads. Their owners are System (231, 449, 149, 178, 202) and, on some captures, MemCompression, Registry and csrss.exe. Every one has `Win32StartAddress` equal to `StartAddress`, and every `StartAddress` lies in a loaded module: ntoskrnl.exe for 121, 341, 87, 93 and 113, the rest in drivers. |
| M4 | The thread scan finds 2,216, 2,294, 1,326, 1,345 and 1,441 threads, of which 1,087, 317, 23, 45 and 231 are on no process's list. `SystemThread` is set on 1,167, 484, 151, 184 and 208 of them, and `Terminated` on 899, 5, 0, 5 and 1 of those. Every system thread that has not terminated (268, 479, 151, 179, 207) starts in a loaded module. |
| M5 | Of threads without `SystemThread`, `StartAddress` lies in an image range of ntdll.dll for 791, 1,378, 1,034, 1,022 and 908, and is 0 for 80, 113, 98, 89 and 82: the S50 thread list gives 0 when `_ETHREAD.StartAddressInvalid` is set. `Win32StartAddress` lies in an image range for 870, 1,490, 1,132, 1,111 and 990, and is 0 on one thread of mem1. No start address of either kind lies in a private or a mapped-file range. Every image range that holds one has protection `PAGE_EXECUTE_WRITECOPY`. |
| M6 | The other user start addresses lie in no kept range: 1, 1, 20, 3 and 12 for `StartAddress`, 1, 2, 20, 3 and 12 for `Win32StartAddress`. They are: on mem1, LsaIso.exe (start 0x9), whose `SecureState` is nonzero; on mem2, the M1 explorer.exe thread and a terminated thread of an exited svchost.exe with no ranges; on mem5, 20 threads of msedge.exe (pid 5136), whose walk kept 1 range while `VadCount` holds 211 (S43 M2); on mem6, 3 terminated threads of exited MoNotification.exe processes with no ranges; on mem7, 8 such threads, and 4 threads of WmiPrvSE.exe, whose walk kept 1 range while `VadCount` holds 87. On mem7 one more thread, on LogonUI.exe's list, has a `_KTHREAD.Process` that names no listed process. |
| M7 | `_ETHREAD.Terminated` is set exactly on the listed threads in state `Terminated`: 101, 163, 22, 159 and 136. |
| M8 | `DebugActive` is 0 on every listed thread (6,908). Of the user-mode trap frames (SegCs RPL 3: 768, 1,197, 1,132, 832 and 635), five have a nonzero `Dr0` to `Dr3` or a nonzero low byte of `Dr7`: ShellHost.exe on mem1 (terminated, `Dr7` 0xf0f0f000f0f0f0), powershell.exe on mem5 (terminated, UTF-16 text in every slot, `Dr7` 0x2b004a00540049), lsass.exe on mem6 (`Dr0` to `Dr7` 0x6d126 down to 0x6d121), and on mem7 StartMenuExperienceHost (terminated, `Dr7` 0x7e229) and WmiPrvSE.exe (`Dr7` 0xffa3cbe4ffa3cbe4). Each `Dr7` has reserved bits set (F6): bits 63:32 in the first, second and fifth, bits 12, 14 and 15 in the third, bits 14 and 15 in the fourth. |
| M9 | Kernel-mode trap frames (SegCs RPL 0: 23, 23, 8, 27 and 15) hold kernel pointers and small integers in the `Dr` slots in 17, 18, 6, 25 and 15 of them. A kernel entry from kernel mode does not store the debug registers there. |

## 4. Algorithm

### 4.1 Common steps

1. Each tool refuses a profile whose OS is not Windows.
2. **System thread.** A thread is a system thread when `_KTHREAD.SystemThread` is set (F2, M3). When the table lacks the member, a thread is a system thread when its process ID is 4, the initial system process (F2). A flag that does not read is counted and leaves the thread unexamined.
3. **Owner.** A thread's owner is the process at `_KTHREAD.Process` (the thread list's `Process` column), not the list it was found on (M6). The owner must be in the unfiltered process list; otherwise the thread is counted as "owner not listed" and not examined.
4. **User address.** An address is a user address when bit 63 is clear for 8-byte pointers and when it is below 0x80000000 for 4-byte pointers (F7).
5. **Placement.** A user address is placed in the owner's ranges from `Decoder.Mappings`, walked once per owner. The holding range is the one with `Start ≤ address ≤ End`. A walk that fails leaves the owner's threads unexamined, with one diagnostic per owner.
6. **Walk short.** An owner's walk is short when `_EPROCESS.VadCount` reads and exceeds the ranges kept (S43 M2, M6), or when the first pointer-wide word of `_KPROCESS.SecureState` reads nonzero (T4, M6, S43 M2). An address in no range of a short walk is not judged.
7. **Export name.** For an address in a range of kind `image`, the export name is the name of an export whose address (range start plus RVA) equals it, forwarders and unnamed exports excluded (F9); of several such names, the first in byte order. Only an exact match names an address. An export table that does not read leaves the name empty and is counted.

### 4.2 `windows.thread.list_suspended`

1. Run the thread list with the `pid` option.
2. A thread whose `SuspendCount` does not read is counted; in strict mode it is an error.
3. `SuspendCount` is a signed byte (T1). A negative value is no count the kernel keeps (F1); it is counted as out of range and not listed.
4. List every thread whose `SuspendCount` is greater than 0 (F1), whatever its state.
5. Read the `FreezeCount` flag (T1) for each listed thread. It is reported, not used to select (M2, O1).
6. Name the export at each user start address (4.1 steps 3, 5 and 7).

### 4.3 `windows.thread.find_orphaned`

1. Run the module list unfiltered and keep the modules with a known range (`modulelist.Placed`). With none, the tool fails: no address can be judged.
2. Run the thread scan, which finds threads that are on no list (M4). Keep threads whose process ID passes the `pid` option.
3. Read the system-thread flag and `_ETHREAD.Terminated` from the thread's kernel address when the scan gives one, and otherwise from its physical address when the member ends inside the same 4 KB page. Skip threads that are not system threads (4.1 step 2).
4. Skip a terminated thread: its driver may unload after it exits (M7).
5. Skip a thread whose `StartAddress` does not read or is 0; both cases share one count. `StartAddress` is the start routine (F2), and equals `Win32StartAddress` on every system thread (M3).
6. Report the thread when `StartAddress` lies in no placed module.

### 4.4 `windows.thread.find_suspicious`

1. Run the thread list with the `pid` option and skip system threads (4.1 step 2).
2. Find the owner (4.1 step 3). Skip an owner with no ranges at all: an exited process whose address space is gone (M6). Its threads are counted.
3. Examine `StartAddress`, then `Win32StartAddress`. An address that does not read, is 0 (M5) or is not a user address is not examined.
4. For each examined address:
   - in no range, and the walk not short (4.1 step 6): finding `start_unmapped` (F3: the start routine "must exist in the remote process");
   - in a range of kind `private`: finding `start_in_private_memory` (F4);
   - in a range of kind `mapped`: finding `start_in_mapped_file` (F4: a view of a section that is not an image);
   - in a range of kind `image`: no finding (F4, M5);
   - in a range of unknown kind: counted, not judged.

### 4.5 `windows.thread.check_debug_registers`

1. Run the thread list with the `pid` option.
2. Skip a thread without a trap frame and count one whose trap frame pointer did not read. A frame is a user-mode frame when the low two bits of its `SegCs` are 3 and its `Rip` and `Rsp` are user addresses (F8, 4.1 step 4). Skip any other frame (M9).
   - The frame is read and judged by the thread list's shared reader, `threadlist.ReadTrapFrame` (S50). Its `ErrKernelModeTrapFrame` counts as "kernel-mode frame" and any other read failure as "trap frame unread".
3. Read `Dr7` with its table width. It must have no reserved bit set (F6): bits 12, 14 and 15, and bits 63:32 when the member is 8 bytes. A `Dr7` that breaks this is counted as not a saved register and the thread is not reported (M8).
4. When no L or G bit of breakpoints 0 to 3 is set, the thread has no breakpoint.
5. Otherwise read `Dr0` to `Dr3` for every enabled breakpoint, decode its condition and length (F6), and place each user address in the owner's ranges with its export name (4.1 steps 3, 4, 5 and 7; a short walk is not considered).
6. Read `DebugActive` and report it; it does not select (M8, O2).

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| `SuspendCount` reads and is not negative | F1, T1 | counted; strict mode: `ErrSuspendCountUnread` |
| System-thread flag reads | T1 | counted; strict mode: `ErrSystemFlagUnread` |
| Owner is a listed process | M6 | counted as "owner not listed" |
| Owner's range walk succeeds | S24 | one diagnostic per owner; strict mode: the walk's error |
| An address in no range is judged only when the walk is not short | S43 M2, M6 | counted as "walk short" |
| `Dr7` reserved bits are 0 | F6, M8 | counted as "reserved bits set" |
| The trap frame holds user-mode state | F8, M9 | counted as "kernel-mode frame" |
| At least one module has a known range | section 4.3 step 1 | `ErrNoModuleRanges` |

## 6. Failure modes

| Sentinel or diagnostic | Meaning |
|---|---|
| `threadsuspended: suspend count does not read` (`ErrSuspendCountUnread`) | strict mode only; otherwise counted in the summary. |
| `threadorphaned: no loaded module has a readable range` (`ErrNoModuleRanges`) | 4.3 step 1. |
| `threadorphaned: system-thread flag does not read`, `threadsuspicious: system-thread flag does not read` (`ErrSystemFlagUnread`) | strict mode only. |
| `threaddebugregisters: symbol table lacks a _KTRAP_FRAME member the check needs` (`ErrLayout`) | `Dr0` to `Dr3`, `Dr7`, `SegCs`, `Rip` or `Rsp` is missing. |
| `threaddebugregisters: trap frame does not read` (`ErrTrapFrameUnread`) | strict mode only; otherwise counted. |
| `threadaddress: owning process is not in the process list` (`ErrOwnerNotListed`) | 4.1 step 3. |
| `<tool>: process at 0x<eprocess>: range walk failed: <err>` | 4.1 step 5; in strict mode `find_suspicious` returns it as an error. |
| `<tool>: <n> threads...` | one summary per run, with every count of sections 4.2 to 4.5. |
| `windows.thread.find_orphaned: symbol table has no _KTHREAD.SystemThread; threads of process 4 are taken as system threads` | 4.1 step 2. |
| `windows.thread.list_suspended: process ranges not read, start exports not named: <err>`, `windows.thread.check_debug_registers: process ranges not read, breakpoints not placed: <err>` | the process list or range decoder failed; the rows stay, without export names or placement. |

A failure of the thread list, the thread scan or the module list fails the tool, wrapped with the tool name. A failure of the process list or the range decoder fails `find_suspicious` (`<tool>: process ranges: %w`) and is a diagnostic in the other two tools that use it.

## 7. Result schema

`windows.thread.list_suspended` gives `threadsuspended.Thread`, sorted by PID, then TID:

| Field | Type | Meaning |
|---|---|---|
| `PID`, `TID` | uint64 | The thread's client ID. |
| `Process` | string | The listed process's image name. |
| `ETHREAD` | uint64 | Kernel address of the thread. |
| `State` | string | `_KTHREAD_STATE` name. |
| `SuspendCount` | int32 | Greater than 0. |
| `Frozen`, `FrozenUnreadable` | bool | The `FreezeCount` flag (T1); both false when the table lacks it. |
| `StartAddress`, `StartPath`, `StartExport` | uint64, string, string | The start address, its path from the thread list (S50 4.4), its exact export name or empty. |
| `Win32StartAddress`, `Win32StartPath`, `Win32StartExport` | uint64, string, string | The same for `Win32StartAddress`. |

`windows.thread.find_orphaned` gives `threadscan.Thread` rows (S50), sorted by PID, TID, then physical offset.

`windows.thread.find_suspicious` gives `threadsuspicious.Thread`, sorted by PID, TID, then start address kind (`start` before `win32_start`):

| Field | Type | Meaning |
|---|---|---|
| `PID`, `TID`, `Process`, `ETHREAD`, `State` | as above | |
| `AddressKind` | `AddressKind` | `start` (`StartAddress`) or `win32_start` (`Win32StartAddress`). |
| `Address` | uint64 | The examined address. |
| `Finding` | `Finding` | `start_unmapped`, `start_in_private_memory` or `start_in_mapped_file`. |
| `RangeStart`, `RangeEnd`, `RangeType`, `Protection`, `Path` | uint64, uint64, string, string, string | The holding range (S24), all empty for `start_unmapped`. |

`windows.thread.check_debug_registers` gives `threaddebugregisters.Thread`, sorted by PID, then TID:

| Field | Type | Meaning |
|---|---|---|
| `PID`, `TID`, `Process`, `ETHREAD`, `State` | as above | |
| `TrapFrame` | uint64 | Kernel address of the user-mode trap frame. |
| `Dr7` | uint64 | As saved. |
| `DebugActive`, `DebugActiveUnreadable` | uint8, bool | `_DISPATCHER_HEADER.DebugActive` of the thread. |
| `Breakpoints` | []`Breakpoint` | One per enabled breakpoint, in index order. |

`Breakpoint`: `Index` (int, 0 to 3), `Address` (uint64), `Local`, `Global` (bool), `Condition` (`execute`, `write`, `io`, `read_write`), `Length` (bytes: 1, 2, 4 or 8), `AddressUnreadable` (bool), and the placement `RangeType`, `Path`, `Export` (strings, empty when not placed).

## 8. Limits

No `Limits` field of their own. Each tool reads a fixed number of members per thread; the walkers it calls (thread list, thread scan, VAD walk, export parser) apply their own caps. Range walks and export tables are read once per owner and image range.

## 9. Acceptance

1. `threadcheckfacts -tools` runs the four tools on each capture. On 2026-11-12 they gave (mem1, mem2, mem5, mem6, mem7):
   - `list_suspended`: 0, 4, 0, 5, 0 rows: the M1 threads. No suspend count was unread or negative.
   - `find_orphaned`: 0 rows on every capture (M3, M4); 899, 5, 0, 5 and 1 system threads skipped as terminated.
   - `find_suspicious`: 0 rows on every capture. Every address of M6 is excused: 2, 1, 40, 0 and 8 addresses lie in no range of a short walk (4.1 step 6: LsaIso.exe; the explorer.exe thread of M1; msedge.exe; WmiPrvSE.exe), 0, 1, 0, 3 and 8 threads have an owner without ranges (4.4 step 2), and 1 thread on mem7 has an owner that is not listed (4.1 step 3).
   - `check_debug_registers`: 0 rows on every capture. The frames of M8 are counted as reserved bits set (1, 0, 1, 1, 1); the second mem7 frame has a `Rip` or `Rsp` in the kernel half and is counted as a kernel-mode frame (23, 23, 8, 27, 16).
2. Synthetic tests: a suspended, a frozen, a negative-count and an unread-count thread; a system thread in a module, outside every module, terminated, and with a zero start; user threads in an image, a private range, a mapped file, no range with a full and a short walk, an owner that is not listed and an owner without ranges; `Dr7` values for each condition and length, a reserved-bit value and a kernel-mode frame; strict mode for each unread member.
3. Fuzz targets: `FuzzDecodeDebugControl` (any 64-bit `Dr7` and width: never panics, gives breakpoints only for enable bits, never for a reserved-bit value) and `FuzzHolding` (any ranges and address: the range returned holds the address, and none is returned when no range holds it).

## 10. Open points

| # | Point | How to close it |
|---|---|---|
| O1 | Owner decision: frozen threads (the `FreezeCount` flag, M2) are reported in a field but not listed. Process freeze is not documented on Microsoft Learn. | Owner decision on listing frozen threads, perhaps behind an option (Q2). |
| O2 | Owner decision: `DebugActive` does not gate the debug-register check. It is 0 on every measured thread, and no capture has a thread with real hardware breakpoints, so its meaning is not measured. | A capture of a process with a breakpoint set through `SetThreadContext`, to measure `DebugActive` and the trap frame. |
| O3 | Owner decision (Q2): row fields renamed from the 0.1.0 rows: `StartFile` to `StartPath`, `StartSymbol` to `StartExport` (and the `Win32` pair); `Context` to `AddressKind`, `VADPath` to `Path`, `Note` to the typed `Finding`; `State` becomes the state name; `Breakpoints` holds only enabled breakpoints, with `Range` and `Symbol` replaced by `RangeType`, `Path` and `Export`. Export names are exact matches only. | Owner review of the row contracts. |
| O4 | `find_suspicious` no longer compares a start address with the process's own executable. A start in an image of another program is not a fact against any source used here. | Owner decision whether such a rule is wanted, with a measured basis. |
| O5 | `_ETHREAD.StartAddressInvalid` (M5) has no documentation; the thread list's 0 for those threads is skipped, not judged. | Measure what the member's threads have in common. |
| O6 | x86 kernels (4-byte pointers): the rules carry over through the table widths, but no 32-bit capture was measured. | A 32-bit capture (Q7). |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Flag only, do not list |
| O2 | Do not gate on it |
| O3 | Accept renames |
| O4 | Do not flag |
| O5 | Skip them |
| O6 | Defer to v0.2.0 |

## 11. Provenance

Author: the project, 2026-11-12. Sources: as cited in section 3, with access dates. Measurements: `threadcheckfacts` on the five captures named in section 3. Every rule rests on the sources and measurements above.
