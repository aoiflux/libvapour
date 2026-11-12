# S17: Windows process and thread checks

Version 1, 2026-11-12.

## 1. Purpose

Pool scans, the network tools, the process comparison and the thread scan are handed addresses that may hold an `_EPROCESS` or an `_ETHREAD`. Some are live objects. Others are freed, half-overwritten or never were objects. An examiner needs to know which candidates hold values that a real process or thread can hold.

This specification defines two checks: one for a process candidate and one for a thread candidate. A check does not prove that an object is real. It rejects a candidate whose values break a fact from Microsoft's documentation, the kernel's own types, or a measurement on the project's captures. Each check also gives the reason for a rejection, so that a caller can report it.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | The kernel's address space. It is used to read the capture clock (4.1). |
| Candidate memory | The address space that holds the candidate. A pool scan may pass a reader other than kernel memory. |
| Candidate address | The address of the `_EPROCESS` or `_ETHREAD`. |
| Symbol table | The kernel's types, the pointer size, and the global symbols `KeBootTime` and `KeBootTimeBias`. |
| Physical memory | Optional: the image's physical address space. Only its size is used. |

The image is untrusted. Every value can be anything.

## 3. Facts from the sources

| # | Fact | Source |
|---|---|---|
| F1 | A FILETIME "contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC)". | Microsoft Learn, "FILETIME structure (minwinbase.h)", accessed 2026-11-12. |
| F2 | `FileTimeToSystemTime` requires the value to be less than 0x8000000000000000. | Microsoft Learn, "FileTimeToSystemTime function (timezoneapi.h)", accessed 2026-11-12. |
| F3 | `GetProcessId` and `GetThreadId` return a `DWORD`. A return of 0 means that the call failed. | Microsoft Learn, "GetProcessId function" and "GetThreadId function" (processthreadsapi.h), accessed 2026-11-12. |
| F4 | "The low order two bits of a handle are ignored by the system", and `OBJ_HANDLE_TAGBITS` is 3. `_CLIENT_ID.UniqueProcess`, `_CLIENT_ID.UniqueThread` and `_EPROCESS.UniqueProcessId` are typed `void*` (a `HANDLE`). | WDK 10.0.28000.0 `shared/ntdef.h`; measured in the kernel tables (M1). |
| F5 | A 64-bit process has user space within 0x000'00000000 through 0x7FFF'FFFFFFFF. In 32-bit Windows the lower 2 GB is user space, and boot options can raise that to 3 GB. All kernel-mode code shares one system space. | Microsoft Learn, "Virtual Address Spaces" (Windows drivers), accessed 2026-11-12. |
| F6 | On AMD64, `KeQuerySystemTime` reads the 64-bit value at `KI_USER_SHARED_DATA + 0x14`, the `SystemTime` member of `KUSER_SHARED_DATA`. `KSYSTEM_TIME` is `{ ULONG LowPart; LONG High1Time; LONG High2Time; }`. | WDK 10.0.28000.0 `km/wdm.h`, `SharedSystemTime`, `KeQuerySystemTime`, `KSYSTEM_TIME`. |
| F7 | CR3 bits 11:0 hold flags or a PCID, never address bits. Bits M−1:12 hold the physical address of the top paging structure, and M (MAXPHYADDR) is at most 52. | Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 3A, "Paging" chapter (order number 253668-093US, chapter 5), CR3 format tables. |
| F8 | A `LIST_ENTRY` head of an empty list has both links pointing to itself. | S03, L2. |

### Measurements

M1 to M5 come from `processfacts`, run on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 and mem7_server2025. Each run walks `PsActiveProcessHead` with the S03 recovering walk and each process's `ThreadListHead` with the same walker. The 5 captures give 498 processes and 6,908 threads.

| # | Measured |
|---|---|
| M1 | In all four kernel tables (the two Server 2025 captures share one): `UniqueProcessId` is `void*`, `ImageFileName` is `unsigned char[15]`, `CreateTime` and `ExitTime` are `_LARGE_INTEGER`, `Pcb` is the `_KPROCESS` at offset 0, `_KPROCESS.DirectoryTableBase` is an 8-byte unsigned integer, and `ThreadListHead` is a `_LIST_ENTRY`. `_ETHREAD.Cid` is a `_CLIENT_ID` of two `void*`, `_ETHREAD.CreateTime` is a `_LARGE_INTEGER`, and no table has `_ETHREAD.ThreadsProcess`. `_KUSER_SHARED_DATA.SystemTime` is at 0x14 in every table. Every table has `KeBootTime` and `KeBootTimeBias`. |
| M2 | Every PID and TID is a nonzero multiple of 4. The largest PID is 12852 and the largest TID is 13288. Every image name has a nonzero first byte. |
| M3 | Every process creation time is at or after `KeBootTime − KeBootTimeBias`, and on every capture some fall between that value and `KeBootTime`. On mem1 the bias is 288.5 s and the earliest process is 288.4 s before `KeBootTime`. Creation times run up to 6.5 s past the capture's `SystemTime`, and thread creation times up to 7.4 s past it, because acquisition takes time. Every exit time that is set lies between its process's creation time and `SystemTime`. |
| M4 | The threads with TID 12 to 28 of PID 4, the System process, have `CreateTime` 0 on mem1, mem2 and mem5, and values under 0.2 s from 1601 on both Server 2025 captures. Every other thread has a creation time inside the M3 window. The threads of `PsIdleProcess` have CID process 0, TID 0 or a multiple of 4, and `CreateTime` 0. Several threads are created up to 40 µs before their process's `CreateTime`. |
| M5 | Every `DirectoryTableBase` has bits 11:0 clear and a frame address below the size of physical memory. Each process's `ThreadListHead` either points to itself on both links (18 processes) or has both links in system space (480). The links of 14 live processes do not lead back to the head on the first hop, because of smear during acquisition. |

## 4. Algorithm

### 4.1 Capture window

Both checks hold times to one window, read once from kernel memory.

1. **Latest.** Read 8 bytes at `KUSER_SHARED_DATA` (S03, B1) plus the `SystemTime` member offset, as an unsigned little-endian value (F6). If it reads and is nonzero, Latest is that value plus the allowance of 4.4. Otherwise Latest is 0x7FFFFFFFFFFFFFFF (F2). Latest never exceeds that value.
2. **Earliest.** Read 8 bytes at `KeBootTime` as an unsigned value, and 8 bytes at `KeBootTimeBias` as a signed value. If both read and the boot time is larger than the bias's magnitude, Earliest is the boot time minus that magnitude (M3). Otherwise Earliest is 1.
3. A time `t` is in the window when `Earliest ≤ t ≤ Latest`.

### 4.2 Process check

The members come from the symbol table. `ImageFileName` and `UniqueProcessId` are required. Without them the check is unusable, and it rejects every candidate. Any other member that the table lacks drops the rule that needs it.

The rules run in this order, and the first rule that fails gives the rejection:

1. **Image name.** Read `ImageFileName`. It must read, and its first byte must not be 0 (M2).
2. **Process ID.** Read `UniqueProcessId` as a pointer. It must be nonzero, a multiple of 4 and at most 0xFFFFFFFC (F3, F4, M2). 0xFFFFFFFC is the largest multiple of 4 that fits a `DWORD`.
3. **Creation time.** Read `CreateTime` as 8 bytes. It must be in the window (4.1, M3). No process is exempt: the System process passes on every capture.
4. **Exit time.** Read `ExitTime` as 8 bytes. If it is 0, the process has not exited. Otherwise it must be in the window and not before the creation time (M3).
5. **Page-table root.** Read `Pcb.DirectoryTableBase` with its own width from the table, or the pointer size when the table gives none. Clear bits 11:0 (F7). The frame address that remains must be nonzero. When physical memory is known, the frame must lie below its size (M5). Otherwise it must lie below 2^52 (F7).
6. **Thread list.** Read both links of `ThreadListHead`. Each link must either point to the head itself (F8) or lie in system space (F5, M5). For 8-byte pointers, system space means bit 63 is set: user space ends at 0x7FFF'FFFFFFFF, and a canonical address above it has bit 63 set. For 4-byte pointers, the link must be at least 0x80000000. The check does not follow the links: M5 shows that one hop fails on live processes in a smeared capture.

A candidate that passes every rule gives its PID and image name, the name as read up to its first NUL byte.

### 4.3 Thread check

`_ETHREAD.Cid` with `_CLIENT_ID.UniqueThread` and `_CLIENT_ID.UniqueProcess` is required. Without them the check is unusable, and callers say so. `_ETHREAD.CreateTime` is optional.

1. **Thread ID.** Read `Cid.UniqueThread` as a pointer. It must pass the rule of 4.2 step 2.
2. **Owner ID.** Read `Cid.UniqueProcess` the same way. It must pass the same rule. This rejects the idle process's threads (M4): their values, CID process 0 and creation time 0, are the values of a zero-filled body.
3. **Creation time.** Read `CreateTime` as 8 bytes. It must not exceed Latest. Unless the owner ID is 4, it must also be at least Earliest. The System process's first threads are created before the clock is set (M4).

A thread's creation time is not compared with its process's (M4).

### 4.4 Allowance

Latest is the capture's `SystemTime` plus 24 hours, in FILETIME units (864,000,000,000). The measured overshoot is at most 7.4 s (M3), but it grows with the length of the acquisition, which the image does not record. The allowance changes how much garbage the rule rejects very little. A uniformly random 63-bit value lands in a window of a few days with odds near 10^−7, with or without the allowance. The owner accepted the value on 2026-11-12 (O1).

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Image name is not empty | M2 | `ErrNoImageName` |
| ID is nonzero, a multiple of 4, at most 0xFFFFFFFC | F3, F4, M2 | `ErrBadID` |
| Process creation time in the window | F1, F2, M3 | `ErrCreateTime` |
| Exit time 0, or in the window and not before creation | M3 | `ErrExitTime` |
| Page-table frame nonzero and inside physical memory | F7, M5 | `ErrPageTableRoot` |
| Thread-list links point to the head or into system space | F5, F8, M5 | `ErrThreadLinks` |
| Thread creation time in the window, except the lower bound for owner 4 | M3, M4 | `ErrCreateTime` |
| A member that the rule needs reads | Section 2 | `ErrMemberUnread` |

## 6. Failure modes

| Sentinel | Meaning |
|---|---|
| `ErrCheckUnusable` | The table lacks a required member (4.2, 4.3). |
| `ErrMemberUnread` | A member read failed. |
| `ErrNoImageName`, `ErrBadID`, `ErrCreateTime`, `ErrExitTime`, `ErrPageTableRoot`, `ErrThreadLinks` | The rule of section 5 failed. |

The checks return the sentinel itself, with no wrapping, because a pool scan runs them on every candidate. A caller that reports a rejection adds the tool name and the candidate address. Strict mode does not apply: a rejected candidate is a result, not a failed read of a structure the tool relies on.

## 7. Result schema

| Result | Fields |
|---|---|
| Process identity | `PID` (uint64), `Name` (string: bytes up to the first NUL, not decoded) |
| Thread check | an error only |
| Window | `Earliest`, `Latest` (uint64 FILETIME values) and `Holds(t)` |

## 8. Limits

No `Limits` field applies. Each check reads a fixed number of members, and no loop depends on image data.

## 9. Acceptance

1. Every process and thread that M2 to M5 measured passes, and no thread of the idle process does. `processfacts` runs both checks on each capture. On 2026-11-12 they rejected 0 of 498 processes and 0 of 6,908 threads, and accepted none of the idle threads.
2. Synthetic fixtures for each rule: one passing candidate, and one candidate that breaks only that rule and gets its sentinel.
3. Window fixtures: system time and boot time present, each one absent, and a bias larger than the boot time.
4. A fuzz target that feeds arbitrary bytes as a candidate body to both checks. It must not panic, and any accepted candidate must satisfy every rule of section 5 as recomputed by the test.
5. With `-pool`, the same script runs the pool scan with these checks. On 2026-11-12 the scan matched by image name every listed process on mem2 and mem5, and every one except System on mem1, mem6 and mem7. System is also missing when the check accepts every candidate, so the scan finds no pool allocation for it on those builds. That is a pool-scan matter, outside S17.

## 10. Open points

| # | Point | How to close it |
|---|---|---|
| O1 | The 24-hour allowance (4.4) is a choice, not a measurement. | Closed 2026-11-12: the owner accepted 24 hours. |
| O2 | `KeBootTime` and `KeBootTimeBias` have no public documentation. Their use rests on M3 alone, and the tables do not record their types. | The owner accepted their use on M3 on 2026-11-12. Still worth measuring on more builds, and on a capture taken after the clock was moved back. |
| O3 | x86 kernels (4-byte pointers) are covered by F5, but no 32-bit capture was measured. | A 32-bit capture, if the support matrix gains one (Q7). |
| O4 | M2's name rule is measured on live processes only. A rule on the bytes of the name (Learn forbids characters 1 to 31 in file names) is not adopted, because the kernel's narrowing of UTF-16 names to bytes is not documented. | Measure the narrowing on a process with a non-ASCII image name. |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep 24 hours |
| O2 | Use them on M3 evidence |
| O3 | Ship as written, mark untested |
| O4 | Keep the live-process rule |

## 11. Provenance

Author: the project, 2026-11-12. Sources: as cited in section 3, with access dates. Measurements: `processfacts` on the five captures named in section 3. Every rule rests on the sources and measurements above.
