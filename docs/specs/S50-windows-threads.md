# S50: Windows threads: the per-process thread lists and the thread pool scan

Version 1, 2026-11-12.

## 1. Purpose

A thread is what runs code. An examiner wants each thread the kernel holds: its process and ID, what it was doing (its scheduler state and why it waits), when it started and ended, where it began to run and in which image file or driver that is, and the user-mode registers it left behind when it last entered the kernel. Threads that have exited, or whose allocation was freed and is not yet reused, can still sit in kernel pool when no list holds them any more.

`windows.thread.list` answers the first question from the lists the kernel links each process's threads into. `windows.thread.scan` answers the second from the pool allocations tagged for threads. Both share the column reader of 4.4 and 4.5. `ReadTrapFrame` decodes a thread's trap frame on demand for the tools that write register state (the process dump). The thread checks (`threadsuspended`, `threadorphaned`, `threadsuspicious`), the timeline, the process comparison (through `ScanOwners`) and the examples build on these rows.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | `_ETHREAD` bodies of listed threads, `_KTRAP_FRAME`s, VADs and file objects (S24), the loaded module list. |
| Physical memory | The thread scan's address space (S31). The scan fails without it. |
| Symbol table | The ntoskrnl types of 3.2, the enumerations `_KTHREAD_STATE` and `_KWAIT_REASON`. |
| Processes | `any.process.list` (S25), unfiltered; the thread list keeps the processes the `pid` option names. |
| Checks and walkers | The S03 `_LIST_ENTRY` walker (`winkernel.ListWalker.WalkRecovering`), the S17 thread check (`processlist.NewThreadCheck`), the S31 executive object scan (`tools.Context.ExecutiveScan`, `scan.FindExecutiveObjectsPlaced`), the S24 VAD walk and file names (`memoryranges.ProcessVADs`, `memoryranges.FileNames`). |
| Options | `pid` (the thread list), `strict`, `diagnostics`. No tool-specific option. |
| Limits | `MaxListEntries` (each thread list, through the walker), `Workers` (the scan's sweep). |

The image is untrusted. Every value can be anything.

## 3. Facts from the sources

### 3.1 Documentation

| # | Fact | Source |
|---|---|---|
| D1 | `System.Diagnostics.ThreadState`: `Initialized` 0 "initialized, but has not yet started", `Ready` 1, `Running` 2 "currently using a processor", `Standby` 3, `Terminated` 4 "has finished executing and has exited", `Wait` 5 "not ready to use the processor because it is waiting for a peripheral operation to complete or a resource to become free", `Transition` 6, `Unknown` 7. | Microsoft Learn, "ThreadState Enum (System.Diagnostics)", dated 2025-07-01, accessed 2026-11-12. |
| D2 | "The priority levels range from zero (lowest priority) to 31 (highest priority). Only the zero-page thread can have a priority of zero." | Microsoft Learn, "Scheduling Priorities", dated 2025-07-14, accessed 2026-11-12. |
| D3 | "Each thread has a suspend count (with a maximum value of MAXIMUM_SUSPEND_COUNT). If the suspend count is greater than zero, the thread is suspended; otherwise, the thread is not suspended and is eligible for execution." | Microsoft Learn, "SuspendThread function (processthreadsapi.h)", dated 2018-12-05, accessed 2026-11-12. |
| D4 | A FILETIME counts 100-nanosecond intervals since January 1, 1601 (UTC), and `FileTimeToSystemTime` requires a value below 0x8000000000000000. | S17 F1, F2. |
| D5 | A 64-bit process has user space within 0x000'00000000 through 0x7FFF'FFFFFFFF; all kernel-mode code shares one system space. | S17 F5 (Microsoft Learn, "Virtual Address Spaces"). |
| D6 | The current privilege level is held in bits 0 and 1 of the CS and SS segment registers; 0 is the most privileged level and 3 the least. | Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 3A (order number 253668-093US), chapter "Protection", section "Privilege Levels". |
| D7 | In 64-bit mode an interrupt or exception pushes SS:RSP unconditionally, then RFLAGS, CS and RIP of the interrupted procedure, onto the handler's stack. | Intel SDM Vol. 3A, chapter "Interrupt and Exception Handling", section "64-Bit Mode Stack Frame". |
| D8 | `PsCreateSystemThread` creates a system thread with no TEB and no user-mode context, in the initial system process when no process is named. | S25 D3 (Microsoft Learn, "PsCreateSystemThread function (wdm.h)"). |

### 3.2 Kernel types

Read through the project's kernel tables with `threadfacts -types` for builds 26100 (mem1, GUID 0D960CE103763A6097E839406D8B369F; mem6 and mem7, 953A8DE880B0818C32DA2DEC1D79C2D9), 19045 (mem2, F57E740B088E5056E8AF0772F1CC5BEB) and 14393 (mem5, 3DFC5F7228304C26859E55E481700385). Offsets are given as 26100 / 19045 / 14393; mem1 and mem6 agree.

| # | Fact |
|---|---|
| T1 | `_ETHREAD` (1944 or 1928 / 2200 / 2016 bytes): `Tcb` (`_KTHREAD`) at 0; `Cid` (`_CLIENT_ID`) 0x508 / 0x478 / 0x630; `CreateTime` and `ExitTime` (`_LARGE_INTEGER`) 0x4c0 and 0x4c8 / 0x430 and 0x438 / 0x5e0 and 0x5e8; `StartAddress` (void *) 0x4e0 / 0x450 / 0x608; `Win32StartAddress` (void *) 0x560 / 0x4d0 / 0x688; `ThreadListEntry` (`_LIST_ENTRY`) 0x578 / 0x4e8 / 0x698. No table has `ThreadsProcess`. `_CLIENT_ID` is `UniqueProcess` and `UniqueThread`, two `void *` at 0 and 8. |
| T2 | Shared storage: `ExitTime` is the first pointer of `KeyedWaitChain` (`_LIST_ENTRY`, same offset), and `StartAddress` is the second pointer of `PostBlockList` (`_LIST_ENTRY` at `StartAddress` − 8). `StartAddressInvalid` is bit 3 of the byte at 0x5a8 / 0x518 / 0x6c8. |
| T3 | `_KTHREAD`, the same in all four tables: `Header` (`_DISPATCHER_HEADER`) 0, `InitialStack` 0x28, `StackLimit` 0x30, `TrapFrame` (`_KTRAP_FRAME *`) 0x90, `Priority` (char) 0xc3, `Teb` (void *) 0xf0, `State` (unsigned char) 0x184, `WaitMode` (char) 0x187, `Process` (`_KPROCESS *`) 0x220, `WaitReason` (unsigned char) 0x283, `SuspendCount` (char) 0x284, `ThreadListEntry` (`_LIST_ENTRY`) 0x2f8. |
| T4 | `_EPROCESS.ThreadListHead` (`_LIST_ENTRY`) 0x370 / 0x5e0 / 0x488 and `_KPROCESS.ThreadListHead` (`_LIST_ENTRY`) 0x30; `_EPROCESS.ActiveThreads` (unsigned int) 0x380 / 0x5f0 / 0x498. |
| T5 | `_KTRAP_FRAME` is 400 bytes in all four, with `MxCsr` (unsigned int) 0x2c, `Rax` 0x30, `Rcx` 0x38, `Rdx` 0x40, `R8` 0x48, `R9` 0x50, `R10` 0x58, `R11` 0x60, `SegDs` 0x130, `SegEs` 0x132, `SegFs` 0x134, `SegGs` 0x136 (unsigned short), `Rbx` 0x140, `Rdi` 0x148, `Rsi` 0x150, `Rbp` 0x158, `Rip` 0x168, `SegCs` (unsigned short) 0x170, `EFlags` (unsigned int) 0x178, `Rsp` 0x180, `SegSs` (unsigned short) 0x188; the 64-bit registers are unsigned long long. No member holds R12 to R15. |
| T6 | `_KTHREAD_STATE`: `Initialized` 0, `Ready` 1, `Running` 2, `Standby` 3, `Terminated` 4, `Waiting` 5, `Transition` 6, `DeferredReady` 7, `GateWaitObsolete` 8, `WaitingForProcessInSwap` 9 in all four. Values 0 to 6 are D1's. `_KWAIT_REASON` runs from `Executive` 0 to `MaximumWaitReason` 40 (`Suspended` 5, `UserRequest` 6, `WrQueue` 15, `WrTerminated` 22 among them). `_MODE`: `KernelMode` 0, `UserMode` 1. |

### 3.3 Measurements

M1 to M10 come from `threadfacts -types -pool` on 2026-11-12 over mem1_win11, mem2_win10, mem5_server2016, mem6_server2025 and mem7_server2025 (mem7 shares mem6's table). Processes are the S25 list (83, 153, 71, 101, 90: 498). Threads are those walked from each process's `_EPROCESS.ThreadListHead` with the S03 recovering walk: 1,123, 1,974, 1,303, 1,298, 1,210 (6,908).

| # | Measured |
|---|---|
| M1 | Two lists: every thread on a `_KPROCESS.ThreadListHead` is also on its `_EPROCESS.ThreadListHead`. 553 threads (93, 156, 21, 151, 132) are on the executive list only, and every one of them is `Terminated`. `ActiveThreads` equals the executive walk's count in 287 processes, is smaller in 192 (by up to 40) and larger in 19. Walks that stop at a broken link and recover from the other side: 15, 12, 3, 10, 8 processes. |
| M2 | `Cid.UniqueProcess` equals the listing process's PID and `_KTHREAD.Process` its `_EPROCESS` for every thread except one on mem7 (both differ). The S17 thread check rejects none of the 6,908. |
| M3 | States: `Waiting` 6,321, `Terminated` 581, `Running` 6. Every `Terminated` thread has wait reason `WrTerminated`. Among `Waiting` threads the commonest reasons are `UserRequest` 2,662, `WrQueue` 2,464 and `Executive` 642, then `WrUserRequest`, `WrLpcReceive`, `WrAlertByThreadId`, `Suspended`, `WrFreePage`, `DelayExecution`, `WrLpcReply`, `WrKernel`, `WrVirtualMemory`, `WrPageOut`. Wait mode: `UserMode` 5,422, `KernelMode` 1,486. |
| M4 | `ExitTime`: for every one of the 6,327 threads not `Terminated` the 8 bytes hold their own address (an empty `KeyedWaitChain`, T2), a value with bit 63 set. For every one of the 581 `Terminated` threads they hold a FILETIME below 2^63. |
| M5 | `StartAddressInvalid` is set on 461 threads (79, 113, 98, 89, 82). For exactly those, `StartAddress` holds a kernel address inside no loaded module and the 8 bytes before it hold a kernel address too (a `PostBlockList` in use, T2); on 109 of them it points into the thread's own `_ETHREAD`. With the bit clear, the 8 bytes before `StartAddress` are 0 on every thread. |
| M6 | Start addresses with `StartAddressInvalid` clear (6,447): 5,134 in user space inside a VAD that maps a file, 1,275 in system space inside a loaded module, 37 in user space inside no VAD, 1 zero. `Win32StartAddress` (6,908): 5,593 in a file-backed VAD, 1,275 in a loaded module, 38 in no VAD, 1 in a VAD without a file, 1 zero. |
| M7 | `Teb` is 0 on 1,847 threads, 1,209 of them in the System process (D8), and in user space on the other 5,061; never in system space. `SuspendCount` is nonzero on 9 threads, at most 1. `Priority` lies in 0..31 on every thread (D2). |
| M8 | `TrapFrame`: 0 on 1,268 threads, 3 of which have a TEB. Of the 5,640 nonzero pointers, the frame does not read on 980 (paged-out kernel stacks of waiting user threads, and exited threads) and reads on 4,660. Every frame of a thread that is not `Terminated` lies between `StackLimit` and `InitialStack`, 5,023 of them exactly one `_KTRAP_FRAME` (400 bytes) below `InitialStack`; the 570 frames off the stack all belong to `Terminated` threads. |
| M9 | `SegCs & 3` on the 4,660 frames that read: 3 on 4,564, 0 on 91, 1 on 2, 2 on 3. Every frame with 3 has `Rip` and `Rsp` in user space except 1 (mem7). 6 frames with 0 have `Rip` in user space. |
| M10 | Pool scan (S31, mismatched TypeIndex kept): 2,263, 2,294, 1,326, 1,357, 1,453 allocations accepted; the S17 thread check rejects 47, 0, 0, 12, 12 of them (all but one for their IDs, one for its creation time). The rest hold 1,123 of 1,123, 1,972 of 1,974, 1,302 of 1,303, 1,298 of 1,298 and 1,208 of 1,210 listed threads, plus 1,093, 322, 24, 47 and 233 threads that no list holds, of which 1,062, 283, 8, 40 and 64 carry an exit time. 3 and 5 accepted rows on mem1 and mem7 have no kernel address. |

## 4. Algorithm

### 4.1 Members

1. **List members, required.** `_EPROCESS.ThreadListHead`, `_ETHREAD.ThreadListEntry`, `_ETHREAD.Cid` with `_CLIENT_ID.UniqueThread`, and the native `_LIST_ENTRY` layout (S03). Without one the thread list fails.
2. **Scan members, required.** The S17 thread check must be usable (`Cid` with both `_CLIENT_ID` members). Without it the thread scan fails: a pool scan with no body check would report any bytes behind a `Thre` tag.
3. **Optional members.** Each column of 4.3 and 4.4 reads its member at the width the table gives (`symbols.ResolveIntField`). A table that names the member but gives no width (a hand-built table) is read at the width T1, T3 or T5 records: pointers at the pointer size, `CreateTime` and `ExitTime` 8 bytes, `State`, `WaitReason`, `SuspendCount`, `Priority` and `StartAddressInvalid` 1 byte, the trap frame registers at their T5 widths. A member the table lacks leaves only its column unreadable. `_ETHREAD.Tcb` is taken as the `_KTHREAD` offset; absent, it is 0 (T1).
4. **Owners.** `ScanOwners` also needs `_KTHREAD.Process`; without it it fails with `ErrNoThreadCheck`.

### 4.2 Thread list

1. Take the S25 process list without the `pid` filter, then keep the processes the `pid` option names. A process list that fails fails the tool.
2. For each kept process, walk the list at `_EPROCESS.ThreadListHead` with the S03 recovering walk, `MaxListEntries` as its cap, strict mode as its mode and the tool's diagnostics as its report. The executive list is the one walked because it is the larger: it holds every thread of the kernel list and also the threads that have terminated (M1). A head that does not read is a diagnostic, or the tool's error in strict mode.
3. Each walked entry less the offset of `_ETHREAD.ThreadListEntry` is a thread (S03 container rule). Its `UniqueThread` must read; otherwise the thread is left out with a diagnostic, or the tool fails in strict mode.
4. The S17 thread check runs on every thread. A rejection is a diagnostic only: the kernel linked the thread, and M2 measured no rejection, so a rejection marks smear rather than a non-thread.
5. Rows keep process order, then walk order.

### 4.3 Thread columns

Read from the thread's body with the reader that holds it (kernel memory for the list, physical memory for the scan).

1. **Identity.** `PID` is `Cid.UniqueProcess`; on the list it is the listing process's PID (M2 measured them equal but one). `TID` is `Cid.UniqueThread`.
2. **Owner.** `Process` is `_KTHREAD.Process` (M2).
3. **Times.** `CreateTime` and `ExitTime` are 8-byte values decoded as FILETIMEs (D4). A value of 0, or with bit 63 set, is no time and gives the zero time, readable. For `ExitTime` this is the rule that separates the exit time from the `KeyedWaitChain` that shares its storage (T2, M4).
4. **Start addresses.** `StartAddress` and `Win32StartAddress` are pointers. When the table has `StartAddressInvalid` and the bit reads 1, `StartAddress` is reported as 0 with `StartAddressInvalid` set: its storage then holds `PostBlockList` (T2, M5). A bit that does not read leaves the address as read.
5. **List-only columns.** `Teb` (pointer), `TrapFrame` (pointer), `SuspendCount` and `Priority` (signed, at their width, D2, D3), `State` and `WaitReason` (unsigned). `StateName` and `WaitReasonName` are the names of the value in `_KTHREAD_STATE` and `_KWAIT_REASON` (T6). A value that is not in the enumeration, or a table without it, gives an empty name; the value stays.

### 4.4 Owning module

For each start address that is nonzero and readable:

1. **User space** (bit 63 clear, D5; below 0x80000000 on a table with 4-byte pointers): the VAD of the owning process (`Process`) that contains the address (`Start` ≤ address ≤ `End`, S24), and the file that VAD maps (`FileNames.Name`). No VAD, or a VAD without a file, gives no path.
2. **System space**: the loaded kernel module whose range contains the address (`modulelist.Containing`), named by its full path, or by its base name when the path is empty or unread. No module gives no path.
3. The owner's VADs are walked once per owner, only when one of its threads has a user-space address. The list passes its processes. Any other owner (a scanned thread's, which may be freed) must first pass the S17 process check, which also gives its PID for messages. An owner that fails the check, or whose VAD walk fails, gives no paths and one diagnostic per owner. The module list is read once, on first need; failing, it gives no paths and one diagnostic.

### 4.5 Trap frame

`ReadTrapFrame(ctx, address)` decodes the `_KTRAP_FRAME` at `address` in kernel memory.

1. An address of 0 is `ErrNoTrapFrame`: the thread has no saved user context (M8).
2. `Rip`, `Rsp` and `SegCs` are required, at their widths from the table; any other register of T5 that the table lacks is left 0. A table without the three (a 32-bit table names them otherwise) is `ErrTrapFrameLayout`.
3. Read once the bytes from the start of the frame to the end of the last member used. A short or failed read is `ErrTrapFrameUnread`.
4. The frame holds user-mode state only when `SegCs & 3` is 3 (D6) and `Rip` and `Rsp` are both in user space (D5, D7). Otherwise it is `ErrKernelModeTrapFrame`: a frame saved on entry from kernel mode holds kernel addresses (M9), which a debugger would read as a user stack.
5. Registers R12 to R15 are not in the frame (T5) and are not returned.

### 4.6 Thread scan

1. Physical memory is required.
2. The body type tag is `_ETHREAD.Tcb`, `_KTHREAD.Header`, `_DISPATCHER_HEADER.Type` = `ThreadObject` (S31 4.5 step 5); a table without it leaves the body to the thread check, with a diagnostic. `ExecutiveScan` resolves the layout and identity with `scan.ThreadFilter`; mismatched TypeIndex values are kept and flagged, because a freed thread loses its header's TypeIndex while its body stays (S31 M2).
3. The decoder runs the S17 thread check on the body in physical memory and refuses a candidate it rejects (M10). An accepted candidate gives its columns (4.3, without the list-only columns).
4. Each row's `Offset` is the body's physical address, `VirtualOffset` its kernel address or 0 (S31 4.8), `OtherCopy` the other mapped copy's body or 0 (S31 4.7), `TypeIndexFailed` the S31 flag.
5. Owning modules (4.4) are added after the scan.
6. Rows keep the scan's order (S31 4.9). A diagnostic gives the row count, the tag hits and the counts of `ObjectScanStats.Describe`, the TypeIndex-flagged count among them.

### 4.7 Thread owners

`ScanOwners` runs 4.6 steps 1 to 3 and returns, for every accepted thread whose `_KTHREAD.Process` reads, its physical address and that pointer. It reads no other column and no path. The process comparison (S26 V5) uses it.

### 4.8 Reporting unread columns

`ColumnReader.Unread` names the first column whose member the table has but which did not read, in the order `StartAddress`, `Win32StartAddress`, `CreateTime`, `ExitTime`, `Process`. `ReportUnread` keeps such a row with a diagnostic, or fails in strict mode. `KeepListed` drops it with a diagnostic, or fails in strict mode. `ReportAbsent` gives one diagnostic per column whose member the table lacks.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| List members present | 4.1 | `ErrNoListMember` |
| A listed thread's `UniqueThread` reads | 4.2 step 3 | thread left out with a diagnostic; strict: error |
| Listed thread passes S17 | M2 | diagnostic only |
| Scan candidate passes S17 | S17, M10 | refused (`BodyRejected`) |
| FILETIME nonzero and below 2^63 | D4, M4 | zero time, readable |
| `StartAddressInvalid` clear | T2, M5 | `StartAddress` 0, `StartAddressInvalid` set |
| Trap frame address nonzero | M8 | `ErrNoTrapFrame` |
| Trap frame `Rip`, `Rsp`, `SegCs` described | T5 | `ErrTrapFrameLayout` |
| Trap frame reads | | `ErrTrapFrameUnread` |
| `SegCs` RPL 3, `Rip` and `Rsp` in user space | D5, D6, D7, M9 | `ErrKernelModeTrapFrame` |

## 6. Failure modes

| Case | Result |
|---|---|
| Profile not Windows | `<tool>: unsupported profile os "<os>"` |
| List members absent | `threadlist: symbol table lacks a member the thread list needs` (`ErrNoListMember`), wrapped with the member |
| S17 check unusable | `threadscan: symbol table lacks the thread id members` (`ErrNoThreadCheck`) |
| No physical memory | `threadscan: no physical memory to scan` (`ErrNoPhysicalMemory`) |
| Pool scan build or layout refused | the `ExecutiveScan` error |
| Pool sweep fails | `windows.thread.scan: pool tag "Thre": %w` |
| Thread list head unreadable, walk broken | the S03 walker's diagnostic; strict: its error |
| Thread ID unread | `windows.thread.list: _ETHREAD at 0x<addr>: thread id does not read: %w` |
| S17 rejection of a listed thread | `windows.thread.list: _ETHREAD at 0x<addr>: thread check: <error>` (diagnostic) |
| Column unread | `<tool>: pid <pid> tid <tid> _ETHREAD at 0x<addr>: <column> does not read, kept` (`, skipped` from `KeepListed`); strict: the same text without the suffix as an error |
| Column absent | `<tool>: symbol table has no <member>: <column> unreadable on every thread` |
| Owner fails the S17 process check, VAD walk failed, module list failed | `<tool>: _EPROCESS at 0x<addr>: owning file of start addresses not found: <error>`; `<tool>: kernel modules not listed, start addresses in system space have no module: <error>` |
| Enumeration absent | `<tool>: symbol table has no <enum>: <column> names empty` |
| VAD file names not resolvable | `<tool>: VAD file names not resolved, start addresses in user space have no file: <error>` |
| Body type tag absent | `windows.thread.scan: symbol table has no _ETHREAD.Tcb.Header.Type: bodies are judged by the thread check alone` |
| Trap frame | `threadlist: trap frame address is 0`, `threadlist: symbol table lacks a trap frame member`, `threadlist: trap frame does not read`, `threadlist: trap frame holds kernel-mode state`; all but the first wrapped as `windows.thread.list: trap frame at 0x<addr>: …: %w` |

## 7. Result schema

`threadscan.Columns` (both tools):

| Field | Type | Meaning |
|---|---|---|
| `StartAddress`, `StartAddressUnreadable`, `StartAddressInvalid` | uint64, bool, bool | 4.3 step 4 |
| `StartPath` | string | 4.4; empty when none |
| `Win32StartAddress`, `Win32StartAddressUnreadable`, `Win32StartPath` | uint64, bool, string | 4.3, 4.4 |
| `CreateTime`, `CreateTimeUnreadable`, `ExitTime`, `ExitTimeUnreadable` | time.Time (UTC), bool | 4.3 step 3; zero time when no time |
| `Process`, `ProcessUnreadable` | uint64, bool | `_KTHREAD.Process` |

`threadlist.Thread`: `PID`, `ProcessName`, `TID`, `ETHREAD` (kernel address), `ListEPROCESS` (the process whose list held it), `Teb` and `TebUnreadable`, `TrapFrame` and `TrapFrameUnreadable`, `SuspendCount` and `Priority` (int32) with their `…Unreadable`, `State` (uint64), `StateName`, `StateUnreadable`, `WaitReason` (uint64), `WaitReasonName`, `WaitReasonUnreadable`, and the columns. Order 4.2 step 5.

`threadscan.Thread`: `Offset` (physical body), `VirtualOffset` (kernel body or 0), `PID`, `TID`, `OtherCopy`, `TypeIndexFailed`, and the columns. Order 4.6 step 6.

`threadscan.Owned`: `Offset`, `Process`.

`threadlist.Registers`: `Rax`, `Rcx`, `Rdx`, `Rbx`, `Rsp`, `Rbp`, `Rsi`, `Rdi`, `R8` to `R11`, `Rip` (uint64); `EFlags`, `MxCsr` (uint32); `SegCs`, `SegSs`, `SegDs`, `SegEs`, `SegFs`, `SegGs` (uint16).

## 8. Limits

- `MaxListEntries` caps each thread list walk (S03); a list that reaches it is a broken walk.
- `Workers` sets the scan's sweep goroutines (S31).
- The VAD walk applies its own cap (S24 8). The trap frame read is one bounded read of at most the frame's size.

## 9. Acceptance

1. Synthetic fixtures (`internal/testsupport/s50_fixture.go`): a listed process with threads of each kind, an exited thread with an exit time, a thread whose `StartAddressInvalid` is set, a thread whose start addresses lie in a file-backed VAD and one in a loaded module, a thread on no list, a pooled thread that the S17 check rejects, a broken thread list, an unreadable column in normal and strict mode, the `pid` option, and trap frames of user and kernel mode, unread and absent.
2. Fuzz targets: `FuzzTrapFrame` (arbitrary frame bytes: no panic; a returned frame has `SegCs & 3` = 3 and `Rip` and `Rsp` with bit 63 clear) and `FuzzThreadColumns` (arbitrary `_ETHREAD` bytes: no panic; an exit time is set only from a value below 2^63, and a set `StartAddressInvalid` gives `StartAddress` 0). On 2026-11-12 each ran 30 s without failure; `FuzzTrapFrame` reported 4.7 million executions, and `FuzzThreadColumns` ran 2 million executions in 14 s when bounded by count.
3. On the captures, `threadfacts -tool` (2026-11-12). The trap frame counts are `ReadTrapFrame` results on every listed thread: user-mode state, `ErrKernelModeTrapFrame`, `ErrTrapFrameUnread`, `ErrNoTrapFrame`. "Named" counts rows whose `Win32StartPath` is not empty (a file-backed VAD or a loaded module).

| Capture | list rows | named | `StartAddressInvalid` | trap frames | scan rows | TypeIndex flagged | no kernel address | named |
|---|---|---|---|---|---|---|---|---|
| mem1_win11 | 1,123 | 1,121 | 79 | 768 / 23 / 83 / 249 | 2,216 | 1,074 | 3 | 2,187 |
| mem2_win10 | 1,974 | 1,972 | 113 | 1,197 / 23 / 272 / 482 | 2,294 | 290 | 0 | 2,236 |
| mem5_server2016 | 1,303 | 1,283 | 98 | 1,132 / 8 / 14 / 149 | 1,326 | 9 | 0 | 1,299 |
| mem6_server2025 | 1,298 | 1,294 | 89 | 832 / 27 / 257 / 182 | 1,345 | 48 | 0 | 1,333 |
| mem7_server2025 | 1,210 | 1,198 | 82 | 634 / 16 / 354 / 206 | 1,441 | 10 | 5 | 1,415 |

   - The list rows are M1's walk exactly; the trap frame counts agree with M8 and M9 (a frame is refused for `SegCs & 3` other than 3, or for an address in system space).
   - The scan rows are M10's accepted allocations less the S17 rejections; one row of mem6 and one of mem7 that M10 counted as TypeIndex-flagged is among the rejected.
   - The scan gives 15, 16, 11, 11 and 14 diagnostics: kernel page tables that do not read, owners that fail the S17 process check (4.4 step 3) and VAD nodes the S24 walk leaves out.
   - Times on this machine: list 0.5 s to 2.0 s, scan 1.8 s to 15 s (mem1, 10.9 GB, is the slowest).

## 10. Open points

| # | Point | How to close it |
|---|---|---|
| O1 | Row field names are kept from 0.1.0 so that the thread checks, the timeline, the process dump and the examples keep compiling during the rewrite: `ETHREAD`, `ListEPROCESS`, `Offset`, `VirtualOffset`, `OtherCopy`, `StartPath`, `Win32StartPath`. Under the §4 contract they would be `Address`, `ListProcess`, `Physical`, `Address`, `OtherCopyAddress`, `StartFile`, `Win32StartFile`. | Owner decision (Q2). |
| O2 | New fields: `WaitReason`, `WaitReasonName`, `WaitReasonUnreadable` (list), `StartAddressInvalid` (columns), `TypeIndexFailed` (scan). Removed: `Registers.PreviousMode` (T5 shows the byte is shared with `InterruptRetpolineState`, and no caller reads it). New sentinels `ErrNoTrapFrame`, `ErrTrapFrameLayout`, `ErrTrapFrameUnread`, `ErrNoListMember`, `ErrNoThreadCheck`, `ErrNoPhysicalMemory`. | Owner review (Q2). |
| O3 | `StartAddress` is reported as 0 when `StartAddressInvalid` is set; the shared bytes are not shown. | Owner decision: keep, or show the raw value with the flag. |
| O4 | A listed thread the S17 check rejects is kept with a diagnostic (4.2 step 4). None was measured. | Owner decision. |
| O5 | Start addresses in system space are now attributed to loaded modules (4.4 step 2); in 0.1.0 a System process thread had no path. | Owner review. |
| O6 | The thread scan ignores the `pid` option, as in 0.1.0; the thread list applies it. | Owner decision. |
| O7 | 32-bit tables: the list and scan are table-driven, but `ReadTrapFrame` refuses a 32-bit frame (its members are named otherwise), and no 32-bit capture was measured. | A 32-bit capture (Q7). |
| O8 | M8 shows every live thread's trap frame on its own kernel stack. A rule refusing a frame off the stack is not adopted, because the frames off the stack are those of exited threads and the user-mode test (4.5 step 4) already refuses the kernel-mode ones. | Measure on more builds before adopting. |
| O9 | The meaning of `StartAddressInvalid` rests on its PDB name, the shared storage (T2) and M5; no public document describes it. | Owner decision on a measured rule. |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep 0.1.0 names |
| O2 | Accept |
| O3 | Report 0 |
| O4 | Keep with diagnostic |
| O5 | Attribute to modules |
| O6 | Keep ignoring pid |
| O7 | Defer to v0.2.0 |
| O8 | Do not adopt the rule |
| O9 | Accept measured rule |

## 11. Provenance

Author: the project, 2026-11-12. Sources: Microsoft Learn pages and the Intel SDM as cited in 3.1, with access dates; the ntoskrnl types of 3.2 read through the project's symbol tables; the measurements of 3.3 with `threadfacts`. Every rule rests on the sources and measurements above.
