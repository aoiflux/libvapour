# S67: Measured private layouts of tcpip.sys and conhost.exe

Version 1, 2026-11-12.

## 1. Purpose

Two families of tools read structures that Microsoft does not describe: the network tools (S28) read tcpip.sys's connection, listener and UDP endpoint objects and the tables that hold them, and the console tools (S33) read conhost.exe's console state and command histories. The public PDBs of both modules carry function and data names but no types. This specification re-derives every member offset those tools use from the captures alone: each offset is located from values the capture itself confirms, then tied to the instruction of the captured module that reads the member. A build whose offsets could not be derived this way is refused.

The layouts are data, not logic: `tools/windows/network/tcpiplayouts.go` and `tools/windows/consolelist/layout.go` with `layouts.go`. The measuring programs are `tcpiplayoutfacts` and `conhostlayoutfacts`, with the shared reader `imagecode`.

## 2. Inputs

| Input | Meaning |
|---|---|
| Captures | mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100), mem7_server2025 (26100) in E:\dataset\memory. |
| Host tables | mem7_server2025_groundtruth: `tcp_before.csv`, `udp_before.csv` (the host's own endpoint tables saved before the capture), `time_before.txt` (the host's UTC offset). |
| Module images | tcpip.sys from the kernel module list; conhost.exe from the host process's `_EPROCESS.SectionBaseAddress`. Pages that do not read are not decoded. |
| Symbols | tcpip.pdb and conhost.pdb publics through the session's PDB loader (`ctx.LoadPDB`); ntoskrnl types `_POOL_HEADER`, `_RTL_DYNAMIC_HASH_TABLE`, `_RTL_BITMAP`, `_LIST_ENTRY`, `_EPROCESS`. |
| Tools | `processlist` (S17 process check, capture window), `consolelist.FindHosts` and the S33 readers for the console data check. |

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | `TCPSTATE` numbers the states from `TCPSTATE_CLOSED` 0 to `TCPSTATE_TIME_WAIT` 10; `MIB_TCP_STATE` numbers the same states from 1. | Microsoft Learn "TCPSTATE (mstcpip.h)", "MIB_TCPROW2 (tcpmib.h)", accessed 2026-11-12 (S28 D1, D3) |
| D2 | `AF_INET` is 2 and `AF_INET6` 23. Ports are carried in network byte order. | Microsoft Learn "socket function", "MIB_TCPROW2" (S28 D2, D3) |
| D3 | A pool allocation is preceded by `_POOL_HEADER` (16 bytes on x64) whose `PoolTag` and `BlockSize` (in 16-byte units) describe it. | ntoskrnl PDB `_POOL_HEADER`, builds 14393, 19045, 26100 |
| D4 | The library's `list` is doubly linked, `vector` keeps one linear run and a capacity, a string's capacity is never below its size. | Microsoft Learn "list Class", "vector class", "basic_string Class" (S33 F3-F5) |
| D5 | The library's internal member order (the list node's links before the element, a string's inline buffer before its size and capacity, the deque's map) is not documented on Microsoft Learn; every such member here is measured. | Microsoft Learn C++ Standard Library reference, checked 2026-11-12 |

### tcpip.sys: code

Each offset below is the displacement of an instruction in the named routine of the capture's own tcpip.sys, found by `tcpiplayoutfacts` (the routine and its offset print on every run). Listener and UDP members are addressed through the port-chain link (`next`) in the enumeration routines; the object offset is `next` + displacement. PDBs: 14393 A577CBBD…-1 (mem5), 19045 F4CA288A…-1 (mem2), 26100 DAC097D9…-1 (mem1), 26100 11B241AD…-1 (mem6, mem7).

| # | Member | 14393 | 19045 | 26100 (mem1) | 26100 (mem6/7) | Routine, instruction (mem7) |
|---|---|---|---|---|---|---|
| C1 | partition stride | 0x80 | 0xc0 | 0xc0 | 0xc0 | `TcpEnumerateConnections`: `lea r15,[rax+2*rax]`; `shl r15, 0x6` (`shl rsi, 0x7` on 14393) |
| C2 | partition → endpoint hash table | 0x8 | 0x8 | 0x8 | 0x8 | `mov rcx, qword ptr [r15+0x8]` before `RtlWeaklyEnumerateEntryHashTable` |
| C3 | `PartitionCount` width | u16 | u16 | u16 | u16 | `movzx esi, word ptr [PartitionCount]`, `cmp si, word ptr [PartitionCount]` |
| C4 | tcpEndpoint.listEntry | 0x28 | 0x28 | 0x30 | 0x30 | `lea rbx, ptr [rax-0x30]` on the enumerated entry |
| C5 | tcpEndpoint.inetAF; inetAF.family | 0x10; 0x18 | 0x10; 0x18 | 0x18; 0x18 | 0x18; 0x18 | `mov rdx,[rbx+0x18]`; `cmp word ptr [rdx+0x18], 0x17` |
| C6 | tcpEndpoint.addressInfo; .local; localAddress.address; .remote | 0x18; 0; 0x10; 0x10 | same | 0x20; 0; 0x10; 0x10 | same as mem1 | `mov rax,[rbx+0x20]`; `mov rcx,[rax]`; `mov rax,[rcx+0x10]`; `mov r8,[rax+0x10]` |
| C7 | tcpEndpoint.state | 0x6c | 0x6c | 0x70 | 0x70 | `mov edx,[rbx+0x70]`; `inc edx` (stored as `MIB_TCP_STATE`, D1) |
| C8 | tcpEndpoint.localPort, remotePort | 0x70, 0x72 | 0x70, 0x72 | 0x74, 0x76 | 0x74, 0x76 | `movzx r8d, word ptr [rbx+0x74]`, `movzx edx, word ptr [rbx+0x76]` |
| C9 | tcpEndpoint.owner | 0x258 | 0x2d8 | 0x350 | 0x348 | `mov rcx,[rbx+0x348]`; `call PsGetProcessId` |
| C10 | tcpEndpoint creation time | 0x268 | 0x2e8 | 0x360 | 0x358 | `mov rax,[rbx+0x358]` stored after the PID |
| C11 | tcpListener owner, createTime, localAddress, inetAF, localPort (from next) | −0x48, −0x38, −0x18, −0x10, −0x6 | same | same | same | `TcpEnumerateListeners`: `mov rcx,[rsi-0x48]`, `mov rax,[rsi-0x38]`, `mov rax,[rsi-0x18]`, `mov rax,[rsi-0x10]`, `movzx ecx, word ptr [rsi-0x6]` |
| C12 | udpEndpoint owner, createTime, localAddress, inetAF, localPort (from next) | −0x48, −0x18, −0x10, −0x50, +0x8 | −0x48, −0x18, −0x10, −0x50, +0x30 | same as 19045 | same | `UdpEnumerateEndpoints`: `mov rcx,[rsi-0x48]`, `mov rax,[rsi-0x18]`, `mov rax,[rsi-0x10]`, `lea r13,[rsi-0x50]`, `movzx edx, word ptr [rsi+0x30]` |
| C13 | tcpListener.next (object − next) | — | 0x78 | 0x80 | — | `lea rbx, ptr [rsi-0x78]` (19045), `lea rbx, ptr [rsi-0x80]` (mem1) |
| C14 | compartmentSet.compartment; compartment.protocol; protocolCompartment.portPool | 0x148; 0x20; 0 | same | same | same | `TcpGetPortPoolInCurrentCompartment` (or `InetGetCompartmentContext`): `mov rdi,[rbx+0x148]`, `mov rax,[rdi+0x20]`, `mov rax,[rax]`; the publics hold a pointer to the set (`mov rbx,[TcpCompartmentSet]`) |
| C15 | portPool.bitmap; portPool.assignments | 0xd8; 0xe8 | 0xd0; 0xe0 | 0xd0; 0xe0 | 0xd0; 0xe0 | `InetGetPortEnumerationNextPort`: `add rcx, 0xd0` before `RtlFindSetBits`; `InetLookupPortEndpoint`: `mov rsi,[rcx+8*rax+0xe0]` with rax = port >> 8 |
| C16 | portAssignment.list; entry stride; entry object | 0x18; 0x18; 0x8 | 0x18; 0x20; 0x10 | same as 19045 | same | `add rdi,[rsi+0x18]` after `shl rdi, 0x5` (port & 0xff); `cmp qword ptr [rdi+0x10], 0x0`; 14393: `lea rcx,[rdi+2*rdi]`, `lea r14,[rax+8*rcx]`, `cmp qword ptr [r14+0x8], rbx` |
| C17 | chain links: two low bits are flags; flags 2 is a listener in the TCP pool | all | all | all | all | `TcpEnumerateListeners`: `and rbx, -0x4`; `and al, 0x3`; `cmp al, 0x2` |

### tcpip.sys: data

`tcpiplayoutfacts` walks the tables with C1 to C3 and C14 to C17 only, then finds each object's start from the `_POOL_HEADER` in front of its link (D3: the nearest header within 4 KiB whose tag is `TcpE`/`TTcb`, `TcpL` or `UdpA` and whose block reaches past the link). A member is located as the set of offsets at which a predicate holds for every object of its kind: owner = a pointer that the process list holds or that passes the S17 process check; creation time = a FILETIME in the capture window (boot to `KUSER_SHARED_DATA.SystemTime` + 1 h); inetAF = a pointer whose family (C5) is 2 or 23; listener and UDP local port = a big-endian u16 equal to the bitmap bit; connection local port = a big-endian u16 whose bit is set in the TCP pool; addressInfo = a pointer whose chain (C6) reads an address. Run 2026-11-12:

| # | Measured |
|---|---|
| M1 | Objects found: mem1 5 connections (`TTcb`, block 0x4f0), 17 listeners (`TcpL` 0x150), 21 UDP (`UdpA` 0x190); mem2 6 (`TcpE` 0x470), 22 (0x150), 26 (0x180); mem5 7 (`TcpE` 0x300), 20 (0x140), 17 (0x140); mem6 6 (`TTcb` 0x4b0), 21, 17; mem7 13, 23, 25. Partitions 16, 8, 32, 4, 4 with `TableSize` 128. |
| M2 | Every link sits at one offset from its object's start: listEntry 0x28 (14393, 19045), 0x30 (26100); listener next 0x78 (14393, 19045), 0x80 (26100); UDP next 0x70 (14393, 19045), 0x78 (26100). These agree with C4 and C13. |
| M3 | The data admits exactly one offset for: connection owner, inetAF, localPort, addressInfo, listEntry; listener and UDP owner, createTime, localPort, next. Each is the code's (C4-C13). The inetAF of listeners and UDP endpoints is admitted at two offsets (e.g. 0x30 and 0x70 for 26100 listeners); the code reads the second. Connection `state` and the local addresses are admitted at many offsets; the code decides and the data admits it. Code and data agree on 18, 18, 17, 16 and 17 members per capture (mem1, mem2, mem5, mem6, mem7); the rest are code only (table offsets, remotePort). |
| M4 | mem2's partition 6 has an entry whose Blink does not name the entry before it (S28 M3); the walk stops there. |
| M5 | Connection creation time: the data admits 0x358, 0x360 and 0x370 on mem6 and mem7 and 0x360, 0x368, 0x378 on mem1. On mem7 both 0x358 and 0x360 equal the host's `CreationTime` to the second for 13 of 13 connections, 0x370 for 9; the two never hold the same value. mem1's code reads 0x360, mem6/7's 0x358. |
| M6 | Connection owner: 0x350 on mem1, 0x348 on mem6 and mem7, each for every connection; the other offset names no process (S28 M10). |
| M7 | mem7 against the host's tables: 13 of 13 connections match a host row by both addresses and ports, with 13 PIDs and 13 creation seconds equal, and 12 states (the 13th holds `TCPSTATE_CLOSED` where the host's first table says `Established`, S28 M9); 23 of 23 listeners match with 23 PIDs and 23 creation seconds; 19 of 25 UDP endpoints match, 18 with PID and second. |
| M8 | `PartitionCount` is read as a u16 by the code (C3); the u32 the S28 list reads is the same value on every capture (the next two bytes are 0). |
| M9 | 14393 (mem5): the partition, port pool and chain members (C1, C2, C4, C13 with listener next 0x78 and UDP next 0x70, C14-C16) were measured and every walked object passed (7, 20, 17). They are not merged into the 14393 layout (O3). |

### conhost.exe

`conhostlayoutfacts` reads the conhost.exe of each host process and its PDB publics. Code on mem2 (PDB F020B0E2…-1, 19045):

| # | Member | Offset | Routine, instruction |
|---|---|---|---|
| K1 | console object | rva 0xc2e68 | `??0Globals@@QEAA@XZ`+0xe5: `lea rcx,[rip+…]` passed to `??0CONSOLE_INFORMATION@@QEAA@XZ` |
| K2 | historySize, historyMax | console + 0x90, + 0x94 (u32) | `GetConsoleHistoryInfoImpl`+0x1d, +0x26: two dword loads stored to `CONSOLE_HISTORY_INFO.HistoryBufferSize` and `.NumberOfHistoryBuffers` |
| K3 | activeScreen | console + 0x718 | `CONSOLE_INFORMATION::GetActiveOutputBuffer`: `mov rax,[rcx+0x718]` |
| K4 | title; string length, capacity | console + 0x698; + 0x10, + 0x18 | `GetConsoleTitleWImplHelper`+0x4a, +0x51 (`cmp capacity, 0x8`), +0x62 |
| K5 | string inline below capacity 8; length 0x10; capacity 0x18; history application | element + 0x20 | `CommandHistory::IsAppNameMatch`: `add rcx, 0x20`; `cmp qword ptr [rcx+0x18], 0x8`; `mov rax,[rcx+0x10]` |
| K6 | list node next 0, element at 0x10; history process | node + 0x50 | `CommandHistory::s_Find`: `mov rax,[rax]`; `cmp qword ptr [rax+0x50], rcx`; `add rax, 0x10` |
| K7 | history list head, count | console + 0x2368, + 0x2370 | public `CommandHistory::s_historyLists` at rva 0xc51d0; `s_Allocate` reads the size at 0xc51d8 |
| K8 | process list node → record; record pid | node + 0x10; record + 0x1c (u32) | `ConsoleProcessList::FindProcessInList`: `mov rcx,[rax+0x10]`; `cmp dword ptr [rcx+0x1c], edx` |
| K9 | text buffer row count, first row | + 0x20 (u64), + 0x58 (s16) | `TextBuffer::GetRowByOffset`: `mov rcx,[rcx+0x20]`; `movsx r9, word ptr [rdi+0x58]`; row = (firstRow + offset) mod rowCount, then the row deque's `at` |
| K10 | alias map | public `g_aliasData` at rva 0xc5170 = console + 0x2308; its list head one pointer in, + 0x2310 | publics |

Data (mem2, PID 3804), reading the console at K1 with the layout: S33's C1-C5 pass; title "Windows PowerShell", original title the `powershell.exe` path, screen 120 × 3000, history 50 / 4, one attached process (PID 8400, listed), one history ("powershell.exe", buffer 50, recall −1, owner PID 8400, 0 commands), one active screen of 3000 rows (135 cells wide, 9 with text), no aliases.

| # | Measured |
|---|---|
| M10 | The members not named in K1-K10 are data only, from the console of K1: screenWidth/screenHeight + 0x20/+ 0x22 (s16; equal the PowerShell `ScreenBufferSize`, S33 M5); processList + 0x558 with its size + 0x560; screenList + 0x570; originalTitle + 0x6d8; screen textBuffer 0x38, next 0x40; text buffer rows 0x8; row cells 0x8 and width 0x50; vector begin 0, end 8, capacity end 0x10 (S33 M6); history commands element + 0 (node 0x10), capacity node 0x28 (u64, equals 50), lastDisplayed node 0x5c (s16, −1), node end 0x60. |
| M11 | The text buffer's `rows` is the map of a `deque` of rows: the two words after it (4096 and 0, S33 M6) are the map size and the deque's start offset. With a start offset of 0 the map index of row *k* is *k*. |
| M12 | Alias entry name 0x10 with its inner list 0x38, alias source 0x10 and target 0x30 are not confirmed: the only console has no aliases. |
| M13 | 4 bytes before the alias list head (+ 0x2310) read 1.0 as a float: the map's load factor (S33 M4). |
| M14 | mem5 (14393): conhost.exe is 0x11000 bytes with 35 routines; no console object is in it. Not measured. |
| M15 | mem6 (26100): conhost.exe's debug directory does not read ("no CodeView record"), and no history is in the host (S33 M8); mem1 and mem7 have no conhost.exe. 26100 is not measured. |

## 4. Algorithm

### 4.1 tcpip layout (`tcpiplayouts.go`)

1. One record per build range: 14393; 19041 to 19045; 26100. `LayoutForBuild(build)` returns the record's symbol table, other builds an error.
2. Each record lists, per member, the offset and the captures it was measured on (section 3). A member is in a record only when it has at least one capture.
3. The table holds the types `tcpEndpoint`, `tcpListener`, `udpEndpoint`, `inetAF`, `addressInfo`, `localAddress` and, when the record has walk members, `partition`, `compartmentSet`, `compartment`, `protocolCompartment`, `portPool`, `portAssignment`, `portAssignmentList`, `portAssignmentEntry`. A struct's size is the end of its last member; `partition` and `portAssignmentEntry` are the measured strides (C1, C16).
4. 26100 carries both owner offsets, 0x348 first (M6); the table names the first and S28 reads the rest from the record (`layoutNamed`).
5. 26100's creation time is 0x360: the offset mem1's code reads and that holds the creation second on mem6 and mem7 (M5, O1).

### 4.2 conhost layout (`layout.go`, `layouts.go`)

1. One layout, keyed by file-set build 19041 (S33 4.1), from section 3. Offsets in a history are from its list node.
2. 14393 and 26100 have no layout (M14, M15): `LayoutFor` refuses them with `ErrUnsupportedVersion`.

### 4.3 Measuring programs

1. `tcpiplayoutfacts <capture>...`: print the code evidence (section 3) per PDB, walk the tables, locate each member from the data, settle each member (agree, holds for *n* of *m*, or code only) and, with `-truth`, compare the decoded rows with the host's tables. `-gate` prints the row count and SHA-256 of the JSON rows of both network tools, with and without `include_corrupt`.
2. `conhostlayoutfacts <capture>...`: print the code evidence for each host's conhost.exe and read the console at K1 through the layout. `-gate` prints the count and digest of both console tools.
3. Both take `-publics`, `-dis`, `-xref` (with `-b`), `-disp` with `-in`, for reading the module's code.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| An offset is kept only when the capture's code reads the member there and the data admits it | Section 3 method | The member stays out; a build missing a member S28 or S33 needs is refused |
| An object starts after the pool header whose tag and block cover its link | D3 | The link is reported and not used |
| A hash bucket entry's Blink names the entry before it | `_LIST_ENTRY` (S03), M4 | The bucket walk stops |
| A build without a measured module is refused | Section 1 | `LayoutForBuild` error; `ErrUnsupportedVersion` |

## 6. Failure modes

| Case | Result |
|---|---|
| tcpip build outside the measured ranges | `no measured tcpip.sys layout for Windows build <n>` (S28 then reports its `ErrLayout`) |
| conhost build 14393, 26100 or any other unmeasured | `consolelist: no measured conhost layout for this windows build` (`ErrUnsupportedVersion`) |
| Measuring program: routine on an unread page or instruction not found | `code <member> …: MISSING in <routine>: <instruction>` |

## 7. Result schema

No rows of their own. The layouts change no row field. User-visible changes: `windows.console.scan_history` now refuses 26100 (before: searched with an unmeasured history layout and found 0 rows on mem6); `windows.console.list` refuses 26100 with the generic message instead of the layout's own reason.

## 8. Limits

None: the layouts are tables. The measuring programs bound a bucket walk at 4,096 entries, a port chain at 256 links and the pool-header search at 4 KiB.

## 9. Acceptance

1. Tests: `tools/windows/network/s67_layout_test.go` (every offset of section 3 per build; strides; the two 26100 owners and the size covering the second; refusal of unmeasured builds; every build has the members every decode needs). `tools/windows/consolelist/s67_layout_test.go` (every member of section 3; history members inside the node; adjacent aligned settings; list sizes after heads; 14393, 17763, 22000, 22631 and 26100 refused). No parser is added, so no fuzz target is added; the S28 and S33 fuzz targets run on the new layouts.
2. Gate, `-gate` before and after the change, 2026-11-12, rows identical on every capture:

| Capture | `network.list` | `network.scan` | `network.scan` include_corrupt | `console.list` | `console.scan_history` |
|---|---|---|---|---|---|
| mem1_win11 | 43, 2f2c1649… | 68, 9b6a6618… | 81, 780d9545… | 0 (refused) | 0 |
| mem2_win10 | 54, 62e0afd2… | 66, 33a03773… | 130, 19ddc7bf… | 1, 21edd6d3… | 1, d9cbe0ef… |
| mem5_server2016 | 0 (refused, no tables) | 62, e4731e6b… | 106, 5e420327… | 0 (refused) | 0 (refused) |
| mem6_server2025 | 44, 54534475… | 51, e0fa4465… | 55, 6f3116f5… | 0 (refused) | 0 |
| mem7_server2025 | 61, 090cfd4e… | 76, 71ee6d96… | 83, 619b3752… | 0 (refused) | 0 |

   `network.list` with include_corrupt equals the default on every capture. The only difference is the 26100 console error text (section 7).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision: 26100 has two tcpip.sys versions that read the creation time at different offsets (M5). The layout keeps 0x360, which mem1's code reads and which holds the creation second on mem6/7; mem6/7's code reads 0x358. A layout keyed by tcpip.sys version, or a second creation-time offset like the owner's, would make mem6/7 exact. | Owner decision; selection by tcpip.pdb GUID |
| O2 | Owner decision (Q3): the private member names (`tcpEndpoint`, `inetAF`, `addressInfo`, `localAddress`, `partition`, `compartmentSet`, `portPool`, `portAssignmentList`, …; `historySize`, `historyMax`, `lastDisplayed`, `firstRow`, `processNode`, `aliasEntry`, …) are kept: each names what the measurement shows the member holds, and S28, S33 and `netfacts` read them by name. | Owner decision |
| O3 | Owner decision: 14393's walk members are measured (M9) but not merged, so `windows.network.list` still refuses mem5. Merging them would add list rows on mem5. | Owner decision; a 14393 list gate |
| O4 | Owner decision: 26100 console histories are refused (M15). Before this step a history layout for 26100 without a measurement was used. | A 26100 capture with a readable conhost.exe debug record and a `cmd.exe` history |
| O5 | The conhost members of M10 and M12 rest on data or on nothing (aliases): no routine reading them was on a readable page or was looked for. | Disassemble the alias and screen routines on a capture where their pages read |
| O6 | The row deque's start offset (M11) is not read; a buffer whose deque was rotated would read rows from the wrong map slots. | A capture whose screen deque start is not 0 |
| O7 | The MSVC container layouts (D5) have no Microsoft Learn source; they are measured on one conhost.exe. | Owner decision on that source |
| O8 | x86 kernels and builds other than those measured are refused. | A capture per build |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep single offset 0x360 |
| O2 | Keep names |
| O3 | Keep refusing mem5 |
| O4 | Refuse |
| O5 | Defer to v0.2.0 |
| O6 | Defer until a capture |
| O7 | Keep measured layouts |
| O8 | Refuse |

## 11. Provenance

Written from Microsoft Learn's IP Helper, Winsock and C++ Standard Library documentation, the ntoskrnl types and the tcpip.pdb and conhost.pdb publics in the project's symbol tables, the captured tcpip.sys and conhost.exe code, the captures' own data and the mem7 host's endpoint tables. The old layout files and the pre-rewrite measurement scripts were not used as a source: the old layout files were read only for their exported API, and the old scripts were deleted without being read beyond their callers. Every rule rests on the sources and measurements above.
