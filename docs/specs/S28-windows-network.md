# S28: Windows network endpoints (table walk and pool scan)

Version 1, 2026-11-12.

## 1. Purpose

An examiner wants the network endpoints a Windows host held when it was captured: TCP connections with both ends and their state, TCP listeners, and UDP endpoints, each with the process that owns it and the time it was created. tcpip.sys keeps them in its own tables. Endpoints that were closed shortly before the capture can survive in freed pool after the tables forget them.

`windows.network.list` walks tcpip.sys's tables: the connection hash tables of its partitions and the port pools of its TCP and UDP compartments. `windows.network.scan` finds the same objects by the pool tags of their allocations in physical memory, which also finds endpoints the tables no longer hold. Both decode one object in the same way and apply the same checks, so a row means the same thing whichever tool produced it.

tcpip.sys's private types are not in its public PDB (M1). The member offsets come from `tcpiplayouts.go`, a measured layout per build that this specification uses but does not re-derive; a build without a measured layout is refused.

## 2. Inputs

| Input | Meaning |
|---|---|
| Kernel memory | Kernel virtual reads: every pointer an endpoint holds, and the tables the list walks. |
| Physical memory | `windows.network.scan` only: the pool sweep and each candidate body. |
| Symbol table | The kernel table with the measured tcpip layout merged in by the session (option `windows.network.scan.layout` names it): `tcpEndpoint`, `tcpListener`, `udpEndpoint`, `inetAF`, `addressInfo`, `localAddress`, and for the list `partition`, `compartmentSet`, `compartment`, `protocolCompartment`, `portPool`, `portAssignment`, `portAssignmentList`, `portAssignmentEntry`. Kernel types `_LIST_ENTRY`, `_RTL_DYNAMIC_HASH_TABLE`, `_RTL_BITMAP`, `_POOL_HEADER`, and the S17 process members. |
| tcpip.sys publics | `PartitionTable`, `PartitionCount`, `TcpCompartmentSet`, `UdpCompartmentSet`, resolved from tcpip.pdb through `pesymbols.Resolve` (list only). |
| Options | `windows.network.list.include_corrupt`, `windows.network.scan.include_corrupt` (bool), `pid`, strict mode. |
| Limits | `MaxTableEntries` (partitions), `MaxListEntries` (entries per bucket, endpoints per port), `Workers` (pool sweep). |

## 3. Facts from the sources

### Documentation

| # | Fact | Source |
|---|---|---|
| D1 | `TCPSTATE`: `TCPSTATE_CLOSED`, `_LISTEN`, `_SYN_SENT`, `_SYN_RCVD`, `_ESTABLISHED`, `_FIN_WAIT_1`, `_FIN_WAIT_2`, `_CLOSE_WAIT`, `_CLOSING`, `_LAST_ACK`, `_TIME_WAIT`, `_MAX`, numbered from 0 in that order. `LISTEN` is "waiting for a connection request from any remote TCP and port". | Microsoft Learn, "TCPSTATE (mstcpip.h)", dated 2018-12-05, accessed 2026-11-12. |
| D2 | `AF_INET` is 2 (IPv4) and `AF_INET6` is 23 (IPv6). `IPPROTO_TCP` is 6 and `IPPROTO_UDP` 17. | Microsoft Learn, "socket function (winsock2.h)", dated 2018-12-05, accessed 2026-11-12. |
| D3 | `MIB_TCPROW2`: `dwLocalPort` and `dwRemotePort` are "in network byte order"; a `dwLocalAddr` of zero "indicates the listener can accept a connection on any interface"; `dwOwningPid` is "the PID of the process that issued a context bind". `MIB_TCP_STATE` numbers the same states from 1 (`CLOSED`) to 12 (`DELETE_TCB`). | Microsoft Learn, "MIB_TCPROW2 (tcpmib.h)", dated 2018-12-05, accessed 2026-11-12. |
| D4 | An IPv4 address is 4 bytes (`IN_ADDR`), an IPv6 address 16 bytes (`IN6_ADDR`), both in network byte order; the unspecified addresses are 0.0.0.0 and `::`. | Microsoft Learn, "IN_ADDR structure (inaddr.h)" and "IN6_ADDR structure (in6addr.h)", accessed 2026-11-12; RFC 4291 2.5.2. |
| D5 | TCP and UDP ports are 16-bit numbers. | RFC 9293 3.1, RFC 768. |
| D6 | A `FILETIME` counts 100 ns intervals since 1601-01-01 UTC. | S17 F1. |

### Kernel types

Read through the project's kernel tables for builds 26100 (mem1, mem6, mem7), 19045 (mem2) and 14393 (mem5) with `netfacts -raw`.

| # | Fact |
|---|---|
| T1 | `_RTL_DYNAMIC_HASH_TABLE` is 40 bytes in all: `Flags` 0, `Shift` 4, `TableSize` 8, `Pivot` 0xc, `DivisorMask` 0x10, `NumEntries` 0x14, `NonEmptyBuckets` 0x18, `NumEnumerators` 0x1c (all `unsigned int`), `Directory` 0x20 (`void*`). `_RTL_DYNAMIC_HASH_TABLE_ENTRY` is `Linkage` (`_LIST_ENTRY`) 0 and `Signature` 0x10. |
| T2 | `_RTL_BITMAP` is 16 bytes: `SizeOfBitMap` (`unsigned int`) 0, `Buffer` (`unsigned int*`) 8. `_LIST_ENTRY` is 16 bytes: `Flink` 0, `Blink` 8. |

### Measured layout (kept, not re-measured here)

`tcpiplayouts.go` names the measured members and records the captures that confirmed each (`LayoutForBuild`, `LayoutBuilds`). Builds 26100 and 19041 to 19045 have every member below; 14393 has no `listEntry`, no `next` and no table members, so only the scan runs on it.

| Type | Members used |
|---|---|
| `tcpEndpoint` | `inetAF` (pointer), `addressInfo` (pointer), `listEntry` (`_LIST_ENTRY`), `state` (u32), `localPort`, `remotePort` (u16), `owner` (pointer; the layout record keeps a second offset for 26100), `createTime` (u64) |
| `tcpListener`, `udpEndpoint` | `inetAF`, `owner`, `createTime`, `localAddress` (pointer), `localPort`, `next` (pointer) |
| `inetAF` | `family` (u16) |
| `addressInfo` | `local` (pointer to `localAddress`), `remote` (pointer to the address bytes) |
| `localAddress` | `address` (pointer to a pointer to the address bytes) |
| `partition` | size, `endpoints` (pointer to `_RTL_DYNAMIC_HASH_TABLE`) |
| `compartmentSet` → `compartment` → `protocolCompartment` → `portPool` | `compartment`, `protocol`, `portPool` (pointers) |
| `portPool` | `bitmap` (`_RTL_BITMAP`), `assignments` (256 pointers) |
| `portAssignment`, `portAssignmentList`, `portAssignmentEntry` | `list` (pointer), `object` (pointer), entry size |

### Measurements

M1 to M13 come from `netfacts` on 2026-11-12 over mem1_win11 (26100), mem2_win10 (19045), mem5_server2016 (14393), mem6_server2025 (26100) and mem7_server2025 (26100). mem7 was captured with the host's own endpoint tables saved before and after the capture (`tcp_before.csv`, `tcp_after.csv`, `udp_before.csv`, `udp_after.csv`; the host's `Get-NetTCPConnection` and `Get-NetUDPEndpoint` output).

| # | Measured |
|---|---|
| M1 | tcpip.pdb (mem1 DAC097D9…-1, mem2 F4CA288A…-1, mem5 A577CBBD…-1, mem6 and mem7 11B241AD…-1) has 9,313 publics on mem2 and no types: none of `_TCP_ENDPOINT`, `TCB`, `_TCB`, `_INETAF`, `_PARTITION`, `_TCP_LISTENER`, `_UDP_ENDPOINT`, `_INET_PORT_POOL` resolves. `PartitionTable`, `PartitionCount`, `TcpCompartmentSet` and `UdpCompartmentSet` are publics in all five. |
| M2 | `PartitionTable` holds a pointer to an array of `PartitionCount` partitions of the layout's partition size (16, 8, 32, 4, 4 partitions). Each partition's `endpoints` points to an `_RTL_DYNAMIC_HASH_TABLE` with `TableSize` 128; its `Directory` is an array of 128 list heads, and the entries chained on them number `NumEntries` with `NonEmptyBuckets` heads filled, except one mem2 table (M3). Each entry is the `listEntry` member of a `tcpEndpoint`. |
| M3 | On mem2 one bucket breaks: an entry's `Blink` does not name the entry before it, and the two objects past it decode as no endpoint (family 0 and 26400). The S03 walker stops there; that table lists 1 of its `NumEntries` 2. |
| M4 | A second hash table, at partition offset 0x10, chains the same connections through another member (endpoint offset 0x40 on 19045, 0x48 on 26100): 5, 7, 6 and 13 entries, all `tcpEndpoint` allocations already in the first table. The layout does not name it. |
| M5 | `TcpCompartmentSet` and `UdpCompartmentSet` hold a pointer to the compartment set; `compartment`, `protocol` and `portPool` lead to the port pool with every pointer's low 4 bits clear. Each bitmap has `SizeOfBitMap` 65,536. For every set bit *p*, `assignments[p >> 8]` is nonzero, and the entry at `list + object + (p & 0xff) × entry size` is 0 or a pointer whose two low bits are flags. With the flags cleared it points at the `next` member of the first endpoint bound to *p*; each endpoint's `next` points at the next one's, and 0 ends the chain. |
| M6 | Flags: in the TCP pools every entry and link with value 2 leads to a `TcpL` allocation (22, 17, 21, 23 listeners); every entry with value 1 leads to none (9, 5, 6, 12), and on mem7 those 12 are exactly the host's 12 `Bound` rows before the capture (11 after). In the UDP pools every entry is 1 and leads to a `UdpA` allocation (26, 21, 17, 25). Set bits with a null entry: 62 of 84 (mem2 TCP), 61 of 77 (mem2 UDP), 1 on the others. |
| M7 | Each listener's and UDP endpoint's `localPort`, read big-endian, equals the bit it was found under: 22 + 21, 31 + 26, 27 + 17, 35 + 25 objects decoded on mem1, mem2, mem6, mem7, none read little-endian. Connection ports read big-endian match the host's tables on mem7. |
| M8 | `inetAF.family` is 2 or 23 on every listed endpoint. The 25 TCP pool objects of M6 that are not listeners give other values. |
| M9 | Connection `state` values listed: 4 (all captures), 2 (mem2), 0 and 7 (mem7). On mem7 the 11 stable `Established` host rows are value 4 and the `CloseWait` row is value 7: the member holds the `TCPSTATE` numbering of D1, not `MIB_TCP_STATE`. The value-0 connection (to port 80) is `Established` in the host's first table and absent from its second. |
| M10 | 26100 owner offset: on mem1 0x350 names a process for 5 of 5 connections and 0x348 for none; on mem6 and mem7 0x348 for 6 and 13, 0x350 for none. On 19045 0x2d8 names one for every listed connection. Listener and UDP owners name a process for every listed object. |
| M11 | Pool tags read from the header 16 bytes before each listed object: connections `TcpE` on 19045 (block size 72) and `TTcb` on 26100 (80 on mem1, 76 on mem6 and mem7); listeners `TcpL` (22); UDP `UdpA` (25 on 19045, 26 on 26100). Every one has pool type 2 (non-paged). On 14393 the scan finds `TcpE`, `TcpL` and `UdpA` objects that pass every rule (section 9). |
| M12 | Listener `localAddress` is 0 for 16 of 17, 21 of 22, 20 of 21, 21 of 23; on mem7 the two others are the host's two listeners bound to 127.0.0.1 and 172.25.122.105, and the 21 null ones are its 8 `0.0.0.0` and 13 `::` listeners. UDP `localAddress` is set for 11, 11, 3 and 3. |
| M13 | Every listed creation time lies in the S17 capture window. |

## 4. Algorithm

### 4.1 Layout

1. The context must hold memory, symbols and a Windows profile, and the table's pointer size must be 8: every measured layout is for x64 (`ErrNotWindows`, `ErrPointerSize`).
2. Resolve the endpoint members of section 3 from the table. A missing member is `ErrLayout` and ends the run: offsets of another build would decode plausible rows from the wrong places.
3. Owner offsets: the table's `tcpEndpoint.owner`, then any other offset the named layout record holds (M10).
4. The table members (`partition` … `portAssignmentEntry`, `_RTL_DYNAMIC_HASH_TABLE`, `_RTL_BITMAP`, `_LIST_ENTRY`) are resolved only when `listEntry` and both `next` members exist. Without them the list refuses the build (`ErrNoTables`).

### 4.2 Decoding one object

The body is read whole from the given reader (kernel memory for the list, physical memory for the scan), the type's size from the layout. Every pointer in it is followed through kernel memory. A body that does not read is `ErrObjectUnread`.

Connection (`tcpEndpoint`):

1. `state` → `StateValue`; the name is `TCPSTATE` entry *value* (D1, M9), else `UNKNOWN`. Ports are read big-endian (D3, M7).
2. **Family.** `inetAF` must be a system-space pointer (bit 63 set, S17 F5), its `family` must read and be 2 or 23 (D2, M8); else `ErrFamily`.
3. **State.** The value must be below `TCPSTATE_MAX` (11) (D1); else `ErrState`.
4. **Ports.** Local and remote port must be nonzero (D5, M7); else `ErrPort`.
5. **Addresses.** `addressInfo` → `local` → `localAddress.address` → pointer → 4 or 16 bytes; `addressInfo` → `remote` → 4 or 16 bytes (D4). Each pointer must be in system space. A failure sets `IPProblem` and leaves that address invalid; the row stays.
6. **Owner.** For each owner offset in order, a system-space pointer that passes the S17 process check gives `OwningPID`, `OwnerImage` and `OwnerAddress` (M10). If none does, `OwnerProblem` holds the last reason; the row stays.
7. **Creation time.** `createTime` as a FILETIME (D6): 0 sets `TimeProblem` to `ErrTimeAbsent` ("creation time is 0"); a value outside the S17 capture window sets `ErrTimeWindow` ("creation time does not fit this capture") (M13). Otherwise `CreateTime`, UTC.

Listener and UDP endpoint: step 2, then the local port must be nonzero (`ErrPort`). A null `localAddress` is the unspecified address of the family (D3, D4, M12); otherwise step 5 for the local address only. Then steps 6 and 7 with the single owner offset. A listener's `State` is `LISTEN` (value 1), the kind's state by D1; no member is read for it.

### 4.3 Table walk (`windows.network.list`)

1. Resolve the four publics of tcpip.sys (M1). Any missing is `ErrTcpipSymbols`.
2. **Partitions.** Read the pointer at `PartitionTable` and the u32 at `PartitionCount` (M2). The pointer must be in system space. More partitions than `MaxTableEntries` are cut with a diagnostic.
3. For partition *i* at table + *i* × partition size, read `endpoints`; it must be in system space. Read `TableSize`, `NumEntries` and `Directory` (T1). `TableSize` must be 1 to 128: only the flat directory of M2 was measured (O1).
4. For each bucket head at `Directory` + *b* × size of `_LIST_ENTRY`, walk with the S03 walker in recovering mode, `MaxListEntries` per bucket (M3). Each entry's endpoint is entry − `listEntry`. Decode it as a connection (4.2). An endpoint met twice is taken once.
5. A table whose walked count differs from `NumEntries` gets a diagnostic (M3).
6. **Port pools.** For TCP (listeners) and UDP: read the pointer at the compartment-set public, then `compartment`, `protocol`, `portPool`, each a system-space pointer (M5). The bitmap must have 65,536 bits (D5, M5) and a buffer that reads.
7. For each set bit *p*: `assignments[p >> 8]`, its `list`, and the entry at `list + object + (p & 0xff) × entry size` (M5). A null value skips the port. In the TCP pool an entry whose flags are not 2 is a port held by something other than a listener (M6): it is counted, not decoded.
8. **Chain.** Clear the two flag bits; the endpoint is the value − `next`. Decode it (4.2); its local port must equal *p* (M7), else `ErrBoundPort`. The next value is read at the same address. The chain ends at 0, at an endpoint met before, or after `MaxListEntries` (diagnostic).
9. Rows come in kind order (connections, listeners, UDP endpoints), then by object address.

### 4.4 Pool scan (`windows.network.scan`)

1. Filters: `TcpE` and `TTcb` → `tcpEndpoint`, `TcpL` → `tcpListener`, `UdpA` → `udpEndpoint`, each non-paged or free pool (M11). Every tag is swept on every build: a tag that does not belong to the build gives candidates that fail 4.2.
2. The shared pool sweep (`tools.Context.StructureScan`, `scan.FindFilteredStructsPlaced`) checks each header and hands the body's physical address to 4.2 with physical memory as the reader. Byte-identical copies are settled by the scan package; the reported row names the other mapped copy.
3. Rows keep the scan's order (kernel-mapped first by virtual address, then by physical address). `ObjectAddress` is the body's kernel address, or 0 when no kernel mapping of the frame was found; `ObjectPhysical` is the body's physical address; `PoolTag` the tag.

### 4.5 Both tools

1. A row whose decode failed a rule of 4.2 or 4.3 step 8 is dropped and counted, unless the tool's `include_corrupt` option is set; then it stays with `Rejected` set to the rule's message.
2. With a `pid` option, only rows whose `OwningPID` is in the set are returned.
3. One diagnostic sums the failed rules by reason.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| Body reads | 4.2 | `ErrObjectUnread` |
| `inetAF` in system space, family 2 or 23 | D2, S17 F5, M8 | `ErrFamily` |
| Connection state below `TCPSTATE_MAX` | D1, M9 | `ErrState` |
| Ports nonzero (both ends of a connection, the local end otherwise) | D5, M7 | `ErrPort` |
| Port pool endpoint's local port is the bit it was found under | M5, M7 | `ErrBoundPort` |
| Address pointers in system space and readable | D4, S17 F5 | `IPProblem`; row kept |
| An owner pointer passes the S17 process check | S17, M10 | `OwnerProblem`; row kept |
| Creation time nonzero and in the capture window | D6, S17 4.1, M13 | `TimeProblem`; row kept |
| TCP pool entry flags 2 start a listener chain | M6 | Port counted, not decoded |
| Bucket walk links back | S03, M3 | Walk recovered or stopped; diagnostic |
| Walked entries equal `NumEntries` | T1, M2 | Diagnostic |
| `TableSize` 1 to 128 | M2, O1 | Table not walked; diagnostic |
| Bitmap holds 65,536 bits | D5, M5 | Pool not walked; diagnostic |

## 6. Failure modes

| Case | Result |
|---|---|
| Not Windows, or pointer size not 8 | `ErrNotWindows`, `ErrPointerSize` |
| No measured layout merged, or a member missing | `<tool>: <type>.<member>: network: symbol table lacks a member of the measured tcpip layout: …` (`ErrLayout`) |
| Layout without tables (14393) | `windows.network.list: layout "tcpip-14393": …` (`ErrNoTables`); the scan runs |
| tcpip.sys publics missing | `windows.network.list: network: tcpip.sys symbols not resolved: …` (`ErrTcpipSymbols`) |
| Partition table, endpoint table, compartment chain or bitmap unread | Diagnostic `windows.network.list: <object> at 0x<addr>: <what failed>: %w`; that part is skipped. In strict mode the run returns the error. |
| A bucket walk fails | The S03 walker's diagnostic; in strict mode the error |
| Rule failures | Diagnostic `<tool>: <n> objects not listed: <count> <reason>; …` (list) or `windows.network.scan: <hits> pool tag hits, <passed> passed the pool header checks, <rows> rows, <n> failed the endpoint checks: …` (scan) |
| No physical memory (scan) | `ErrObjectUnread` |
| Pool scan refused (build before Windows 8) | The context's `ErrPoolScanUnsupportedBuild` |

## 7. Result schema

`network.Endpoint`, one per object:

| Field | Type | Meaning |
|---|---|---|
| `Kind` | `EndpointKind` | `tcp_connection`, `tcp_listener`, `udp_endpoint`; `Protocol()` gives `tcp` or `udp` |
| `Family` | `Family` | `ipv4`, `ipv6`; empty when the family check failed |
| `LocalIP`, `RemoteIP` | `netip.Addr` | Invalid when unread; `RemoteIP` is invalid for listeners and UDP endpoints |
| `LocalPort`, `RemotePort` | `uint16` | Host order; `RemotePort` 0 for listeners and UDP endpoints |
| `State`, `StateValue` | `TCPState`, `uint32` | `TCPSTATE` name and raw value for connections; `LISTEN`/1 for listeners; empty/0 for UDP |
| `OwningPID`, `OwnerImage`, `OwnerAddress` | `uint64`, `string`, `uint64` | From the S17 check; zero when `OwnerProblem` is set |
| `CreateTime` | `time.Time` | UTC; zero when `TimeProblem` is set |
| `ObjectAddress` | `uint64` | Kernel virtual address of the object (0 for a scanned frame without a kernel mapping) |
| `ObjectPhysical`, `OtherCopyPhysical`, `PoolTag` | `uint64`, `uint64`, `string` | Scan only |
| `IPProblem`, `OwnerProblem`, `TimeProblem` | `string` | Why a value is absent; empty when it was read |
| `Rejected` | `string` | Only with `include_corrupt`: the rule the object failed |

## 8. Limits

- `MaxTableEntries`: partitions read from `PartitionCount`.
- `MaxListEntries`: entries per hash bucket and endpoints per port chain.
- `Workers`: pool sweep workers.
- Fixed by the sources, not limits: 128 buckets per table (M2), 65,536 ports and 256 assignment blocks (D5, M5).

## 9. Acceptance

1. Synthetic fixtures (`s28_fixture_test.go`, on the 26100 measured layout): every rule of section 5 passing and failing alone; IPv4 and IPv6 connections; wildcard and bound listeners; the second owner offset; the capture window; two partitions with a broken bucket and a `NumEntries` mismatch; a `TableSize` above 128; a TCP pool with a flag-1 entry, a two-listener chain and a port mismatch; a UDP pool; `include_corrupt`; the `pid` filter; the scan over a physical buffer with one object per tag and a garbage candidate; refusal without a layout, without tables and without tcpip symbols.
2. Fuzz targets, 30 s each on 2026-11-12: `FuzzDecodeEndpoint` (arbitrary body for each kind, with marked words replaced by real or garbage pointers; no panic, only rule errors, every accepted row satisfies section 5 as recomputed and its problems agree with its empty values): 1,955,610 executions. `FuzzPortPoolChain` (arbitrary entry and chain links with arbitrary flags among real listeners, a listener on another port, 0 and an unmapped address; no panic, no endpoint listed twice, every row's port equals its bit, no chain walked from an entry without flags 2): 418,626 executions.
3. On the captures, `netfacts`, 2026-11-12:

| Capture | List rows: connections / listeners / UDP | Scan rows: connections / listeners / UDP | Scan: tag hits, header passed, failed rules | Listed rows the scan misses | Owner resolved (list, scan) |
|---|---|---|---|---|---|
| mem1_win11 | 5 / 17 / 21 | 29 / 17 / 22 | 622, 158, 26 | 0 | 43 of 43, 68 of 68 |
| mem2_win10 | 6 / 22 / 26 | 15 / 22 / 29 | 303, 158, 77 | 0 | 54 of 54, 66 of 66 |
| mem5_server2016 | refused (no tables) | 19 / 20 / 23 | 441, 230, 102 | n/a | n/a, 62 of 62 |
| mem6_server2025 | 6 / 21 / 17 | 13 / 21 / 17 | 168, 55, 4 | 0 | 44 of 44, 48 of 51 |
| mem7_server2025 | 13 / 23 / 25 | 28 / 23 / 25 | 213, 83, 7 | 0 | 61 of 61, 76 of 76 |

   - Families: list connections are all IPv4 on every capture; listeners IPv4/IPv6 9/8, 11/11, 9/12, 10/13; UDP 12/9, 15/11, 9/8, 13/12. The scan adds 2 IPv6 connections on mem1.
   - Connection states (list): `ESTABLISHED` 5, 5, 6, 11; `SYN_SENT` 1 on mem2; `CLOSED` 1 and `CLOSE_WAIT` 1 on mem7. The scan's extra connections are `CLOSED` (24, 9, 7 and 14 on mem1, mem2, mem6, mem7): connections the tables no longer hold. One more on mem7 is `ESTABLISHED` and in neither host table. mem5's scan has 12 `CLOSED` and 7 `ESTABLISHED` connections. The scan adds 1 UDP endpoint on mem1 and 3 on mem2. The 3 mem6 scan rows without an owner are closed connections whose process image name is empty (an exited process).
   - No row on any capture has an `IPProblem` or a `TimeProblem`.
   - mem7 against the host's tables (rows present both before and after the capture): the list matches 11 of 11 `Established`, 1 of 1 `CloseWait`, 23 of 23 `Listen` and 18 of 18 UDP rows by addresses, ports, state and PID. Its other rows are the `CLOSED` connection of M9, a UDP `0.0.0.0:3702` whose owner changed between the two host tables, and a UDP `:::3702` of the same process that neither host table shows. The host's 19 stable `TimeWait` and 11 `Bound` rows are not listed (O2, O3).
   - Scan rejections by rule: family 12, 69, 90, 1, 2; port 0: 14, 8, 12, 3, 5 (on mem7 all five are UDP endpoints with port 0 and no owner or time, O4).

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Only `TableSize` 128 with a flat directory was measured; a larger table's directory form has no public source, so such a table is not walked. | A capture with more connections than 128 buckets hold, or a source for the directory |
| O2 | `TIME_WAIT` connections (19 stable on mem7) are in neither the measured partition table nor the measured allocations. | Measure the second partition table (M4) and the time-wait allocations; a layout change (owner, Q3) |
| O3 | TCP port pool entries with flags 1 (`Bound` on the host, M6) are counted, not decoded: their object type is not in the measured layout. | Measure those objects; owner decision on reporting bound-only ports |
| O4 | UDP endpoints with local port 0 are rejected (`ErrPort`); they may be sockets not yet bound. | Owner decision: report them flagged |
| O5 | The pool tags (M11), the flag values (M6), the hash table and port pool shapes (M2, M5) and the 26100 second owner offset (M10) rest on measurements only. | Owner decision on measured constants |
| O6 | Owner decision (Q3): the private-structure member names in `tcpiplayouts.go` (`tcpEndpoint`, `inetAF`, `addressInfo`, `portPool`, `portAssignmentList`, …) are the project's labels for measured offsets and are kept as they are. |  Owner decision |
| O7 | Owner decision (Q2): row fields are renamed from the 0.1.0 schema (`Proto`, `LocalAddr`, `RemoteAddr`, `StateName`, `StateKnown`, `Listener`, `PID`, `Owner`, `Created`, `Offset`, `VirtualOffset`, `OtherCopy`, `LocalAddrUnreadable`, `RemoteAddrUnreadable`) to section 7's names; tool names and option keys are kept. | Owner decision |
| O8 | Owner decision (Q8): delete `tools/windows/network/testdata/golden_endpoints.json`; no test reads it after S28. | Owner decision |
| O9 | The list does not walk the second partition table (M4), which holds the same connections; it could cross-check a smeared first table. | Measurement on a smeared capture |
| O10 | x86 kernels and builds other than 14393, 19041 to 19045 and 26100 have no measured layout and are refused. | A capture per build (Q7) and a re-measurement step |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Do not walk larger tables |
| O2 | Defer to v0.2.0 |
| O3 | Defer to v0.2.0 |
| O4 | Reject with ErrPort |
| O5 | Accept the measured constants |
| O6 | Accept project labels |
| O7 | Accept section 7 names |
| O8 | Delete it |
| O9 | Defer to v0.2.0 |
| O10 | Refuse them |

## 11. Provenance

Written from Microsoft Learn's Winsock and IP Helper documentation, RFC 768, RFC 4291 and RFC 9293, the ntoskrnl types and tcpip.sys publics in the project's symbol tables, the measured layout in `tcpiplayouts.go`, and the project's measurements, including the mem7 host's own endpoint tables. Every rule rests on the sources and measurements above.
