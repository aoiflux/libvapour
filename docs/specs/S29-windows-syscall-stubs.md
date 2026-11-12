# S29: Windows system-call stubs

Version 1, 2026-11-12.

## 1. Purpose

User-mode code enters the Windows kernel through small stubs in `ntdll.dll` and `win32u.dll`: each loads a service number and issues the processor's system-call instruction. Security products and malware both rewrite these stubs to intercept calls. Malware also carries its own copies, outside the system images, so that a rewritten stub in ntdll never sees the call ("direct" system calls), or jumps into the system-call instruction of ntdll from its own code so that the call appears to come from ntdll ("indirect" system calls).

Three tools answer three questions:

| Tool | Question |
|---|---|
| `windows.syscall.compare_stubs` | For each exported stub of ntdll and win32u, do all processes hold the same bytes, and which processes differ? |
| `windows.syscall.find_direct` | Which executable memory outside ntdll and win32u holds a stub that issues `SYSCALL` itself? |
| `windows.syscall.find_indirect` | Which executable memory outside ntdll and win32u holds a stub that jumps to a `SYSCALL` inside ntdll or win32u? |

None of them judges intent. Section 9 shows that every capture has legitimate findings.

## 2. Inputs

| Input | Use |
|---|---|
| Process memory ranges | `any.memory.list` rows (`memoryranges.Mapping`, S24): process, directory table base, range, protection, type, file path. |
| Process address spaces | `tools.Context.ProcessSpace`. |
| Export tables | `pesymbols.Exports`, the project's export parser (S18's PE reader). |
| Kernel symbol table | `_KUSER_SHARED_DATA.SystemCall`. |
| Options | `pid` (through the memory ranges), `strict`, `diagnostics`. No option of their own. |
| Limits | `MaxRegionScanBytes` (bytes scanned per range), and the limits of the export parser. |

The image is untrusted: every byte, address and name can hold any value.

## 3. Facts from the sources

| # | Fact | Source |
|---|---|---|
| F1 | "For SYSCALL, the processor saves RFLAGS into R11 and the RIP of the next instruction into RCX"; it then reads the target instruction pointer from `IA32_LSTAR`. SYSRET "Copies the value in RCX into RIP". So no system-call argument can travel in RCX, and the call returns to the instruction after `SYSCALL`. `SYSCALL` is `0F 05`. | Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 3A (order number 253668-093US), 6.8.8 "Fast System Calls in 64-Bit Mode"; Vol. 2B, SYSCALL. |
| F2 | `INT imm8` is `CD ib`; `RET` is `C3` and `RET imm16` is `C2 iw`; `CALL r/m` is `FF /2`; `JMP rel8` is `EB cb`, `JMP rel32` is `E9 cd`, `JMP r/m64` is `FF /4`; `MOV r32, imm32` is `B8+rd id`; `MOV r64, imm64` is `REX.W B8+rd io`; `MOV r64, r/m64` is `REX.W 8B /r`; `TEST r/m8, imm8` is `F6 /0 ib`; `Jcc rel8` is `7x cb`. With ModRM `25` in 64-bit mode, `FF /4` is `JMP [RIP+disp32]`. | Intel SDM Vol. 2, instruction reference for INT, RET, CALL, JMP, MOV, TEST and Jcc; Vol. 2A, 2.2.1.6 (RIP-relative addressing). |
| F3 | `KUSER_SHARED_DATA.SystemCall`: "On AMD64, this value is initialized to a nonzero value if the system operates with an altered view of the system service call mechanism." `SYSTEM_CALL_SYSCALL` is 0 and `SYSTEM_CALL_INT_2E` is 1; "Assembler logic assumes a zero value for syscall and a nonzero value for int 2e". The member is at 0x308. | Microsoft Learn, "KUSER_SHARED_DATA structure (ntddk.h)", accessed 2026-11-12; WDK 10.0.28000.0 `km/ntddk.h`, lines 9074 to 9077, 9420 to 9425, 9655 to 9721. |
| F4 | All four kernel tables give `_KUSER_SHARED_DATA.SystemCall` at 0x308. | Measured with `stubfacts` on 2026-11-12. |
| F5 | An export's address is the image base plus its RVA; a forwarder RVA lies inside the export directory and holds a name, not code. | PE/COFF specification, "The .edata Section"; S18. |
| F6 | The Defender platform runs from `%ProgramData%\Microsoft\Windows Defender\Platform\<antimalware platform version>`; "If that path doesn't exist, it goes to `%ProgramFiles%\Windows Defender`", which also holds "the version shipped with the operating system". | Microsoft Learn, "Microsoft Defender Antivirus security intelligence and product updates and support", sections "How to install an update" and "How to roll back an update", accessed 2026-11-12. |

### Measurements

M1 to M7 come from `stubfacts` (`-blocks` adds the scans), run on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393) and mem6_server2025 (26100).

| # | Measured |
|---|---|
| M1 | Exported `Nt`/`Zw` names in the 64-bit ntdll and in win32u. Rows (one per stub address) and the stubs of the system-call form of 4.2: ntdll 494 (488), 478 (472), 455 (449), 494 (488); win32u 1494 (1493), 1318 (1318), 1138 (1138), 1478 (1477). The 32-bit SysWOW64 ntdll on mem5 and mem6: 475 (468) and 515 (508) of the 32-bit form; SysWOW64 win32u: 1136 (880, 256 unread) and 1484 (1219, 256 unread). On mem1 and mem2 the SysWOW64 export tables do not read in any process. No two stubs of one module carry the same service number. |
| M2 | Successive 64-bit stubs are 0x20 bytes apart (ntdll 486 of 487 gaps, win32u 1492 of 1492 on mem1; the same on every capture); successive 32-bit stubs are 0x10 apart (506 of 507, 1216 of 1217 on mem6). |
| M3 | Every 64-bit stub of the system-call form has the bytes `4C 8B D1 B8 <n> F6 04 25 08 03 FE 7F 01 75 03 0F 05 C3 CD 2E C3` (on all four builds): `mov r10, rcx; mov eax, n; test byte [0x7FFE0308], 1; jne +3; syscall; ret; int 2e; ret`. 0x7FFE0308 is the user address of `SystemCall` (F3, F4, M4). Every 32-bit stub of that form is `B8 <n> BA <a> FF D2 C2 <iw> 90`: `mov eax, n; mov edx, a; call edx; ret iw`. |
| M4 | In every process whose page reads, the 16 bytes at 0x7FFE0000 + 0x260 equal the kernel's `KUSER_SHARED_DATA` at the same offset: 75 of 79, 144 of 149, 68 of 68, 87 of 93 (the rest unread). |
| M5 | The exports that are not of the system-call form are the same in every process: `NtQuerySystemTime` and `NtGetTickCount` (a jump, or other code), and four `NtdllDefWindowProc_*` and `NtdllDialogWndProc_*` jumps. |
| M6 | Defender's images: mem2 `\ProgramData\Microsoft\Windows Defender\Platform\4.18.26040.7-0\MsMpEng.exe`, `MpDefenderCoreService.exe` and `NisSrv.exe`; mem5 and mem6 `\Program Files\Windows Defender\MsMpEng.exe` (and `NisSrv.exe` on mem6). |
| M7 | Each process maps one 64-bit ntdll; 1 to 3 processes per capture also map the SysWOW64 copies. One image view of a DLL at one base appears in up to 147 processes. |

## 4. Algorithm

### 4.1 System images

A stub module is a memory range of type `image` whose file name, the path after its last `\` or `/`, is `ntdll.dll` or `win32u.dll` ignoring case. Two paths are two modules: the 64-bit and the SysWOW64 copies are compared separately.

### 4.2 Stub forms

A stub's bytes have one of these forms, tried in order:

| Form | Rule | Number |
|---|---|---|
| `syscall` | `4C 8B D1 B8 <n>` (`mov r10, rcx; mov eax, n`, F1, F2) followed by `0F 05 C3`, or by the SystemCall test of M3 with the address 0x7FFE0000 + `_KUSER_SHARED_DATA.SystemCall` from the table (F3, F4, M4) | n |
| `x86_call` | `B8 <n> BA <a> FF D2` (`mov eax, n; mov edx, a; call edx`, M3) | n |
| `jump` | first instruction `EB`, `E9` or `FF 25` (F2) | 0 |
| `other` | anything else | 0 |
| `unread` | no process gave the bytes | 0 |

Without the `SystemCall` member, only the bare `0F 05 C3` tail counts as `syscall`.

### 4.3 `compare_stubs`

1. Take the memory ranges (S24) and keep the stub modules (4.1).
2. For each module path, read the export table of every instance and merge the names: one file has one table, but a page of names may be absent in one process and resident in another. A module whose table reads in no process gives a diagnostic and no rows.
3. Keep the exports whose name starts with `Nt` or `Zw` and that are not forwarders (F5). Exports at one RVA are one stub; its row is named by the first `Nt` name in sort order, and the other names are aliases.
4. A stub's window runs from its RVA to the next stub's RVA in the module, at most 0x20 bytes (M2), so no window holds two stubs.
5. Read the window in each process that maps the module. A window past the image size or one that does not read counts as unread for that process.
6. Group the processes by identical bytes. The agreeing group is the largest; between equal sizes, the group whose first process comes first in the memory-range order. When two groups tie for the largest, the row is a tie and names no differing process: the image does not say which copy is the original.
7. The row's form and number come from the agreeing group's bytes (4.2), and its address from the first process of that group.

### 4.4 `find_direct` and `find_indirect`

1. Take the memory ranges (S24). For each process, in range order: the executable is the image range whose file name starts with the process's image name (the kernel's image name is cut from that file name); the stub modules (4.1) are set aside; every other range whose protection names an `EXECUTE` access is scanned.
2. An image range of one path at one base is scanned in the first process that maps it only. Image views of one file share its pages (M7), so a later process would give the same bytes; the coverage counts the views not rescanned.
3. Scan each range page by page, up to `MaxRegionScanBytes`. A page that does not read is counted as unread and skipped.
4. **Anchor.** Every `4C 8B D1` (`mov r10, rcx`, F1, F2) is a candidate, also across a page end.
5. **Preamble.** The block starts at the anchor when `B8 <n>` follows it, or 5 bytes before it when `B8 <n>` precedes it: the two moves are independent, so either order sets up the same call.
6. **Body.** Decode instructions from the block start inside a window of 0x20 bytes (M2). A `CALL`, `RET`, `INT3`, `LEAVE` or an undecodable byte ends the attempt without a block. A conditional jump is allowed, as in the system's own stubs (M3).
   - **Direct:** the block ends at an instruction that decodes as `SYSCALL`, prefixes included, immediately followed by `C3` (F1: the call returns to the next instruction). `SyscallAt` is that instruction's address. A `JMP` first means no direct block.
   - **Indirect:** the block ends at a `JMP` whose target is computed from the bytes (F2): `EB`, `E9` (relative), `FF 25` (the 8-byte slot at RIP+disp32), or `FF /4` with a register operand after a `mov r64, imm64` to that register in the same block. The target must lie inside a stub module of the same process and hold `0F 05`. A `SYSCALL` first means no indirect block.
7. A block found consumes its window; the next candidate inside it is skipped.
8. A process whose address space cannot be built is skipped with a diagnostic. Each run adds one diagnostic with the coverage (section 7).

### 4.5 Defender

A finding is marked `Defender` when the process's executable path, lowercased with `/` as `\`, contains `\program files\windows defender\` or `\programdata\microsoft\windows defender\platform\` (F6, M6). The owner decided that Defender is identified by path; a process cannot choose the path of its image file, while it can choose its name.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| A stub row's bytes come from a full read of its window | 4.3 step 5 | counted in `Unread`, not compared |
| A block starts with both preamble moves | F1, M3 | no block |
| No call, return, breakpoint or undecodable byte before the end instruction | F2, M3 | no block |
| A direct block's `SYSCALL` is followed by `RET` | F1, M3 | no block |
| An indirect block's target is a `SYSCALL` inside ntdll or win32u of the same process | F1, F2, 4.1 | no block |
| A block fits in 0x20 bytes | M2 | no block |

## 6. Failure modes

| Case | Result |
|---|---|
| Profile not Windows | error |
| Memory ranges fail | error (`<tool>: process memory ranges: %w`) |
| Export table unread in every process | diagnostic `windows.syscall.compare_stubs: <path> at 0x<base>: export table not read in any process: <cause>`; no rows for that module |
| Process space unavailable | diagnostic `<tool>: <process> (<pid>): process space: <cause>`; process skipped and counted |
| Page unread | counted in `Coverage.Unread` |

The scans read best-effort page by page, so strict mode adds nothing beyond the memory-range walk's own strict handling.

## 7. Result schema

`syscallstub.Row` (`compare_stubs`), sorted by module path ignoring case, then `Function`:

| Field | Type | Meaning |
|---|---|---|
| `Module` | string | Image path of the module. |
| `Function`, `Aliases` | string, []string | Row name (4.3 step 3) and the other names at the RVA. |
| `RVA`, `Address` | uint32, uint64 | Stub RVA, and its address in the first agreeing process. |
| `Form`, `Number` | `Form`, uint32 | 4.2. `Number` is 0 unless the form is `syscall` or `x86_call`. |
| `Processes`, `Unread` | int | Processes that read the window, and those that did not. |
| `Variants`, `Agreeing` | int | Distinct byte sequences; size of the agreeing group. |
| `Differing` | []string | `<process> (<pid>)` outside the agreeing group, in memory-range order; empty on a tie. `DifferingText()` joins them with `, `. |
| `Tie` | bool | 4.3 step 6. |

`syscallstub.Finding` (`find_direct`, `find_indirect`), in memory-range order of processes, then address: `Process`, `PID`, `Path` (the range's file, empty for private memory), `Address` (block start), `Number`, `SyscallAt` (the `SYSCALL` in the block, or the jump target), `Instructions` (decoded text joined by `; `), `Defender`.

`syscallstub.Coverage`: `Processes`, `Skipped`, `Mappings` (ranges scanned), `Shared` (image views not rescanned), `Bytes` (read), `Unread`, `Candidates` (anchors), `Blocks`.

`IsStubName(name)` reports the `Nt`/`Zw` prefix rule of 4.3 step 3.

## 8. Limits

`MaxRegionScanBytes` caps each range. The block window is 0x20 bytes and each stub window at most 0x20 bytes (M2). The export parser applies `MaxTableEntries` and `MaxNameBytes`. Each loop is bounded by the number of ranges and exports that the memory walk and the parser have already bounded.

## 9. Acceptance

1. Synthetic fixtures (`s29_fixture_test.go`, `syscalls_test.go`, `blocks_test.go`): agreeing stubs with an alias; a hooked stub naming its process; a tie; an unread window; an export table unread in every process; every form of 4.2, with and without the `SystemCall` member; the stub-module filter; a direct block, one across a page end, both move orders; blocks broken by a call, a missing `RET`, a missing `mov eax` and a jump; ntdll and data ranges not scanned; indirect blocks through a RIP slot and through `mov r11, imm64; jmp r11`, and one whose target is not a `SYSCALL`; a shared image scanned once; Defender marked by path only; unread pages counted.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzClassify` (any bytes; a `syscall` form always has the preamble; no number on `jump` or `other`): 3.22 million executions. `FuzzDecodeBlock` (any bytes in an executable range; every finding points at an instruction that decodes as `SYSCALL`, a direct finding lies inside its window, and the coverage counts every finding): 194,242 executions. Its first run found a `SYSCALL` with a REX prefix (`41 0F 05`), which the processor runs as `SYSCALL`; the corpus keeps it.
3. On the captures, 2026-11-12:

| | mem1_win11 | mem2_win10 | mem5_server2016 | mem6_server2025 |
|---|---|---|---|---|
| `compare_stubs` rows | 1,988 | 1,796 | 3,204 | 3,971 |
| Rows that differ | 0 | 19 ntdll stubs, 2 `msedge.exe` | 19 ntdll stubs, 3 to 6 `msedge.exe` | 0 |
| `find_direct` blocks | 13 (`LsaIso.exe`, `iumdll.dll`) | 12 (`LsaIso.exe`, `iumdll.dll`) | 86 (85 `wow64win.dll` in `MicrosoftEdgeUpdate`, 1 `msedge_elf.dll`) | 61 (`wow64win.dll`) |
| `find_indirect` blocks | 0 | 0 | 0 | 0 |
| Processes, ranges scanned, shared views | 79, 878, 3,369 | 149, 1,642, 6,677 | 68, 802, 2,573 | 93, 933, 3,720 |
| Bytes read, unread | 343 MB, 666 MB | 392 MB, 1,547 MB | 249 MB, 810 MB | 196 MB, 596 MB |
| Anchors | 13,775 | 9,478 | 4,337 | 8,457 |

The differing `msedge.exe` stubs are the browser sandbox's own interceptions in its child processes; the direct blocks are the system's isolated-user-mode and WoW64 thunks and the browser's loader. No finding is marked `Defender` on any capture.

## 10. Open points

| # | Point | How to close it |
|---|---|---|
| O1 | Owner decision (Q2): the row and finding field names (`Agreeing`, `Differing`, `Variants`, `Processes`, `Form`, `Number`, `Aliases`, `RVA`, `Path`, `SyscallAt`, `Instructions`) and the coverage fields replace the 0.1.0 names. `Row.Module` stays exported (section 7); no `StubLength` field or name exists. | Owner review. |
| O2 | Owner decision: `iumdll.dll` and `wow64win.dll` issue `SYSCALL` themselves on every measured capture (M1 to M7, section 9). They are reported, not treated as stub modules. | Owner decision on a wider stub-module list. |
| O3 | A block must start with `mov r10, rcx` and `mov eax, imm32` (F1). Code that sets R10 another way, or loads EAX from memory, is not found. | Owner decision; a capture with such code. |
| O4 | An image view at one base is scanned once (4.4 step 2). A copy-on-write page changed in one process only is missed when an earlier process maps the same view. | Compare page frames of shared views. |
| O5 | The SysWOW64 export tables did not read on mem1 and mem2, so their 32-bit stubs were not compared there. | A capture with those pages resident. |
| O6 | The 0x7FFE0000 user address of `KUSER_SHARED_DATA` rests on M4; Learn gives the kernel address only. | A Learn or WDK statement of the user mapping. |
| O7 | On mem7 `compare_stubs` groups only the processes the S25 list walk returns, and that walk stops at mem7's process-list break (S25 M1). Probe, `stubfacts -unlisted` on 2026-11-12: following Blink pointers from `PsActiveProcessHead` without the back-link check reaches 11 processes off the list. 9 of them map the native ntdll at 0x7ff8514c0000, and all 45 stub windows read and equal the listed majority in each: `powershell.exe` 1684, `conhost.exe` 7552, `cmd.exe` 2408, `sshd.exe` 3532 and 3988, `NisSrv.exe` 2972, `ShellHost.exe` 6900, `MpDefenderCore` 1752, `MsMpEng.exe` 2340. The other 2 map no native ntdll: `dllhost.exe` 4016 has 1 range, and `sshd.exe` 1216 has exited with no range. The thread scan finds 13 running owners off the list, and 12 of them agree on all 45 stubs. Not a bug: `compare_stubs` groups the processes the list walk returns. | Owner decision 2026-11-12 (follow-up MU2): probe. Not a bug, cause S25 O1 (report the break only). Done: no code change. |
| O8 | On mem5 `find_direct` reports one block outside ntdll and win32u: `msedge.exe` pid 1856 at 0x7ff9cafde000 in `msedge_elf.dll`, a full copy of the native 64-bit stub form of M3, with system-call number 0x28. | Owner decision 2026-11-12 (follow-up MU1): keep. A stub copy outside ntdll and win32u is the evidence the tool exists for. Done: no change. |
| O9 | 4.4 step 1 takes a range's executable access from its VAD protection only. The S35 rule for pages made executable later would also scan such pages in ranges without EXECUTE access. | Owner decision 2026-11-12 (follow-up M7): Deferred to v0.2.0 (owner decision 2026-11-12). |
| O10 | A stub or block window whose process page-table entry is a prototype entry is counted unread. It is not read through the section's prototype entries. | Owner decision 2026-11-12 (follow-up M8): Deferred to v0.2.0 (owner decision 2026-11-12). |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Accept the new names |
| O2 | Report them, not as stub modules |
| O3 | Require both instructions |
| O4 | Defer to v0.2.0 |
| O5 | Leave uncompared |
| O6 | Keep the measured address |
| O7 | Probe: not a bug |
| O8 | Keep |
| O9 | Defer to v0.2.0 |
| O10 | Defer to v0.2.0 |

## 11. Provenance

Author: the project, 2026-11-12. Sources: the Intel SDM; Microsoft Learn and the WDK 10.0.28000.0 headers as cited; the PE/COFF specification; the captured ntdll and win32u export tables and bytes, and the kernel types in the project's symbol tables. Measurements: `stubfacts` on the four captures named in section 3. Every rule rests on the sources and measurements above.
