# S13: Linux socket enumeration per address family

Version 1, 2026-11-12.

## 1. Purpose

Network activity on a Linux host is carried by sockets, and a socket is reached from user space only through a file descriptor. An examiner needs, for each socket a process holds open: the process, the descriptor, the address family, type and protocol, the local and remote addresses, the state, the network namespace and any filter program attached to it. This specification defines how the open files of every task are followed to their `struct sock`, how each address family's fields are read and rendered, and which families are decoded. It is the source for the `linux.socket.list` tool and for the sock decoder that `linux.socket.scan` reuses.

The task walk is S01. Module lookup is not used.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxobj.Kernel` | Kernel-space memory, the symbol table, the address form and the effective Limits. |
| Tasks | S01 task walk with threads | Every task, leader before its threads. |
| Symbols | symbol table | `socket_file_ops`, `init_net`; the types in section 3. |
| Options | tool options | `linux.socket.list.netns` (uint); the session PID set. |
| Limits | effective `limits.Limits` | Section 8. |

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17 unless a row names fewer. The supported captures run 6.14 (Fedora 40) and 6.17 (Ubuntu 24). Paths are under the kernel tree.

### File to sock

| # | Fact | Source |
|---|---|---|
| F1 | A file is a socket when `file->f_op == &socket_file_ops`; its `private_data` is then the `struct socket`. | `net/socket.c` `sock_from_file`, every tag. |
| F2 | `sock_alloc_file` sets `sock->file = file` and `file->private_data = sock`. `__sock_release` sets `sock->file = NULL` while the socket is released. | `net/socket.c`, every tag. |
| F3 | `struct socket` holds `socket_state state`, `short type`, `unsigned long flags`, `struct file *file`, `struct sock *sk` and `const struct proto_ops *ops`. `sock_graft` sets `parent->sk = sk` and, through `sk_set_socket`, `sk->sk_socket = parent`. | `include/linux/net.h`; `include/net/sock.h` `sock_graft`, `sk_set_socket`; v4.19, v6.17. |
| F4 | Each family's sock type begins with `struct sock sk`: `inet_sock`, `unix_sock`, `netlink_sock` (commented "struct sock has to be the first member"), `packet_sock`, `xdp_sock`, `vsock_sock` and `bt_sock`. | `include/net/inet_sock.h`, `include/net/af_unix.h`, `net/netlink/af_netlink.h`, `net/packet/internal.h`, `include/net/xdp_sock.h`, `include/net/af_vsock.h`, `include/net/bluetooth/bluetooth.h`. |
| F5 | `struct socket_alloc { struct socket socket; struct inode vfs_inode; }`, and `SOCK_INODE(sock)` is that `vfs_inode`. `sock_alloc` sets `i_ino = get_next_ino()`, and `get_next_ino` steps past 0, so a socket inode number is never 0. v6.17 also caches it in `sock.sk_ino`. | `include/net/sock.h`; `net/socket.c` `sock_alloc`; `fs/inode.c` `get_next_ino`; v4.19, v6.17 (`sk_ino` only at v6.17). |
| F6 | `sock_net(sk)` is `read_pnet(&sk->sk_net)`, with `sk_net` the `skc_net` of `sock_common`. `possible_net_t` holds `struct net *net` only with `CONFIG_NET_NS`; without it `read_pnet` returns `&init_net`. A namespace's number is `net.ns.inum`, an `unsigned int` in `struct ns_common`. | `include/net/sock.h`; `include/net/net_namespace.h`; `include/linux/ns_common.h`; v4.19, v6.17. |
| F7 | `struct sock_common` has `__be32 skc_daddr`, `__be32 skc_rcv_saddr`, `__be16 skc_dport`, `__u16 skc_num`, `unsigned short skc_family`, `volatile unsigned char skc_state`, `possible_net_t skc_net`, and with IPv6 `struct in6_addr skc_v6_daddr` and `skc_v6_rcv_saddr`. `struct sock` begins with `__sk_common` and has `sk_filter`, `sk_socket`, `sk_type` and `sk_protocol`. `sk_type` and `sk_protocol` are bit-fields of 16 and 8 bits at v4.19 and `u16` members from v6.1. | `include/net/sock.h`, every tag. |
| F8 | `sock_init_data` sets `sk_state = TCP_CLOSE` for every new sock. | `net/core/sock.c`, v4.19, v6.17. |
| F9 | `socket(2)` strips the flag bits (`type &= SOCK_TYPE_MASK`, mask 0xf) before the sock is made, so `sk_type` holds a bare `SOCK_*` value. | `net/socket.c`; `include/linux/net.h`; v4.19, v6.1, v6.17. |

### Tasks and descriptors

| # | Fact | Source |
|---|---|---|
| T1 | `task_struct.files` points at a `files_struct` whose `fdt` points at a `struct fdtable { unsigned int max_fds; struct file **fd; ... }`. | `include/linux/fdtable.h`, v4.19, v6.17. |
| T2 | `copy_files` with `CLONE_FILES` takes a reference on the parent's `files_struct` instead of copying it, so the threads of a process normally share one table; a fork copies it (`dup_fd`). | `kernel/fork.c`, v4.19, v6.17. |

### Internet families

| # | Fact | Source |
|---|---|---|
| I1 | `inet_daddr`, `inet_rcv_saddr`, `inet_dport` and `inet_num` are `#define`s for the `sock_common` members. `inet_sock` has its own `__be16 inet_sport`. | `include/net/inet_sock.h`, every tag. |
| I2 | `/proc/net/tcp` prints the local end as `inet_rcv_saddr` and `ntohs(inet_sport)`, and the remote end as `inet_daddr` and `ntohs(inet_dport)`. `/proc/net/tcp6` uses `sk_v6_rcv_saddr` and `sk_v6_daddr` with the same ports. | `net/ipv4/tcp_ipv4.c` `get_tcp4_sock`, `net/ipv6/tcp_ipv6.c` `get_tcp6_sock`, v4.19, v6.17. |
| I3 | `inet_timewait_sock` and request socks carry only a `sock_common` and have no `struct socket`, so no descriptor leads to them. | `include/net/inet_timewait_sock.h`, `include/net/inet_connection_sock.h`, v4.19, v6.17. |
| I4 | `inet_sock.pinet6` points at a `struct ipv6_pinfo` whose first member, `saddr`, is the source address the socket sends from; the bound address the kernel reports is `sk_v6_rcv_saddr` (I2), so `ipv6_pinfo` is not read. An IPv4 peer of an IPv6 socket is held as a v4-mapped address (`ipv6_addr_v4mapped`), which RFC 5952 section 5 writes as `::ffff:a.b.c.d`. | `include/linux/ipv6.h`, `include/net/ipv6.h`, v4.19, v6.17; RFC 5952. |

### AF_UNIX

| # | Fact | Source |
|---|---|---|
| U1 | `unix_sock` has `struct unix_address *addr`, `struct path path` and `struct sock *peer`. | `include/net/af_unix.h`, every tag. |
| U2 | `struct unix_address { refcount_t refcnt; int len; struct sockaddr_un name[]; }`; v4.19 also has `unsigned int hash` before `name`. `sockaddr_un` is `sun_family` then `char sun_path[108]`. | `include/net/af_unix.h`; `include/uapi/linux/un.h`; every tag. |
| U3 | `unix_seq_show` prints a bound address as follows: `len` less the offset of `sun_path` bytes; if `sun_path[0]` is not 0 the last byte (the NUL) is dropped; otherwise an `@` is printed for the first byte; every NUL byte that remains is printed as `@`. | `net/unix/af_unix.c` (`len - sizeof(short)` at v4.19, `len - offsetof(struct sockaddr_un, sun_path)` at v6.17). |
| U4 | A path name is stored with `len = strlen(sun_path) + offset + 1`, so with a 108-byte path `len` is 111. An abstract name has `offset < len ≤ sizeof(struct sockaddr_un)`. Auto-bind gives an abstract name of 5 hex digits. | `net/unix/af_unix.c` `unix_mkname` v4.19, `unix_mkname_bsd`, `unix_validate_addr`, `unix_autobind` v6.17. |
| U5 | AF_UNIX uses TCP state numbers in `sk_state`: `TCP_LISTEN` in `listen`, `TCP_ESTABLISHED` on both ends in `connect`, `TCP_CLOSE` otherwise. | `net/unix/af_unix.c`, v4.19, v6.17. |

### AF_NETLINK

| # | Fact | Source |
|---|---|---|
| L1 | `netlink_sock` has `u32 portid`, `u32 dst_portid`, `u32 dst_group`, `u32 ngroups` and `unsigned long *groups`. | `net/netlink/af_netlink.h`, every tag. |
| L2 | `netlink_getname` gives the local address as `nl_pid = portid` and `nl_groups = groups ? groups[0] : 0`, and the peer address as `nl_pid = dst_portid` and `nl_groups = netlink_group_mask(dst_group)`. `nl_groups` is `__u32`. | `net/netlink/af_netlink.c`; `include/uapi/linux/netlink.h`; v4.19, v6.17. |
| L3 | `netlink_group_mask(g)` is 0 for `g` 0 or above 32, else `1 << (g - 1)`. | `net/netlink/af_netlink.c`, v6.17. |
| L4 | `netlink_connect` writes `NETLINK_UNCONNECTED` (0) or `NETLINK_CONNECTED` (1) to `sk_state`. A socket that never called `connect` keeps F8's `TCP_CLOSE`. | `include/uapi/linux/netlink.h`; `net/netlink/af_netlink.c`; v4.19, v6.1, v6.17. |

### AF_PACKET, AF_XDP, AF_VSOCK, AF_BLUETOOTH

| # | Fact | Source |
|---|---|---|
| P1 | `packet_sock` has `int ifindex` (the bound device) and `__be16 num` (the protocol). `packet_getname` reports them as `sll_ifindex` and `sll_protocol`; `/proc/net/packet` prints `ntohs(num)`. | `net/packet/internal.h`; `net/packet/af_packet.c`; v4.19, v6.17. |
| P2 | `packet_getname` finds the device with `dev_get_by_index_rcu(sock_net(sk), ifindex)`. Every device of a namespace is on `net.dev_base_head` through `net_device.dev_list` (`for_each_netdev`), and has `char name[IFNAMSIZ]`, `IFNAMSIZ` 16, and `int ifindex`. | `net/packet/af_packet.c` v6.17; `include/linux/netdevice.h`, `include/uapi/linux/if.h`, v4.19, v6.14, v6.17. |
| X1 | `xdp_sock` has `struct net_device *dev` and `u16 queue_id`. From v6.1 it also has `enum { XSK_READY = 0, XSK_BOUND, XSK_UNBOUND } state`; v4.19 has no state. | `include/net/xdp_sock.h`. |
| V1 | `vsock_sock` has `struct sockaddr_vm local_addr` and `remote_addr`; `sockaddr_vm` has `unsigned int svm_port` and `unsigned int svm_cid`. | `include/net/af_vsock.h`; `include/uapi/linux/vm_sockets.h`; v4.19, v6.17. |
| V2 | `VMADDR_CID_ANY` and `VMADDR_PORT_ANY` are `-1U`. | `include/uapi/linux/vm_sockets.h`, v6.17. |
| V3 | AF_VSOCK uses the TCP state numbers in `sk_state` (`TCP_CLOSE`, `TCP_SYN_SENT`, `TCP_ESTABLISHED`, `TCP_CLOSING`, `TCP_LISTEN`). | `net/vmw_vsock/af_vsock.c` header comment, v4.19, v6.17. |
| H1 | Bluetooth protocol numbers are `BTPROTO_L2CAP` 0 to `BTPROTO_AVDTP` 7, and `BTPROTO_ISO` 8 from v6.1. Bluetooth states are `BT_CONNECTED` 1 ("equal to TCP_ESTABLISHED") to `BT_CLOSED` 9, in the order of N9. | `include/net/bluetooth/bluetooth.h`. |

### Socket filters

| # | Fact | Source |
|---|---|---|
| B1 | `struct sk_filter { refcount_t refcnt; struct rcu_head rcu; struct bpf_prog *prog; }`. | `include/linux/filter.h`, every tag. |
| B2 | `struct bpf_prog` has `enum bpf_prog_type type`, `u32 len`, `struct bpf_prog_aux *aux` and `struct sock_fprog_kern *orig_prog`; `sock_fprog_kern` is `{ u16 len; struct sock_filter *filter; }`. | `include/linux/filter.h` v4.19, v6.17 (`bpf_prog` is in `include/linux/bpf.h` at v6.17). |
| B3 | A classic filter (`SO_ATTACH_FILTER`) is built by `__get_filter`, which keeps a copy of the user's program in `orig_prog` with its instruction count in `orig_prog->len`. | `net/core/filter.c` `__get_filter`, `bpf_prog_store_orig_filter`, v4.19, v6.17. |
| B4 | An eBPF filter (`SO_ATTACH_BPF`) is a loaded program of type `BPF_PROG_TYPE_SOCKET_FILTER`, taken by descriptor. Only `bpf_prog_load` gives a program an id, from `idr_alloc_cyclic(..., 1, INT_MAX, ...)`, so ids start at 1 and a classic filter has none. `bpf_prog_aux` has `u32 id` and `char name[BPF_OBJ_NAME_LEN]`, `BPF_OBJ_NAME_LEN` 16. | `net/core/filter.c` `__get_bpf`; `kernel/bpf/syscall.c` `bpf_prog_alloc_id`; `include/linux/bpf.h`, `include/uapi/linux/bpf.h`; v4.19, v6.17. |

### Name tables

| # | Table | Source |
|---|---|---|
| N1 | `AF_*` by value: 0 `AF_UNSPEC` to 44 `AF_XDP`, with 12 `AF_DECnet`; 45 `AF_MCTP` at v6.1 onwards. `AF_MAX` is 45 at v4.19 and 46 from v6.1. | `include/linux/socket.h`; the v6.1, v6.4, v6.14 and v6.17 tables are identical. |
| N2 | `enum sock_type`: `SOCK_STREAM` 1, `SOCK_DGRAM` 2, `SOCK_RAW` 3, `SOCK_RDM` 4, `SOCK_SEQPACKET` 5, `SOCK_DCCP` 6, `SOCK_PACKET` 10. | `include/linux/net.h`, every tag. |
| N3 | TCP states: `TCP_ESTABLISHED` 1 to `TCP_NEW_SYN_RECV` 12; `TCP_BOUND_INACTIVE` 13 at v6.14 and v6.17, not at v4.19 to v6.4. | `include/net/tcp_states.h`. |
| N4 | `IPPROTO_*` from the `enum` in `include/uapi/linux/in.h` (v6.17 adds `IPPROTO_L2TP` 115, `ETHERNET` 143, `AGGFRAG` 144, `SMC` 256, `MPTCP` 262 over v4.19), and `IPPROTO_ICMPV6` 58 from `include/uapi/linux/in6.h`. | v4.19, v6.17. |
| N5 | `NETLINK_*` protocol numbers 0 to 22, 17 unused. | `include/uapi/linux/netlink.h`, v4.19, v6.17. |
| N6 | Netlink states: L4. | |
| N7 | `ETH_P_*`: `802_3` 0x0001, `ALL` 0x0003, `LOOP` 0x0060, `IP` 0x0800, `ARP` 0x0806, `RARP` 0x8035, `8021Q` 0x8100, `IPV6` 0x86DD, `MPLS_UC` 0x8847, `PPP_DISC` 0x8863, `PPP_SES` 0x8864, `PAE` 0x888E, `8021AD` 0x88A8, `LLDP` 0x88CC (v6.17). The rest of the header is not named (O3). | `include/uapi/linux/if_ether.h`, v4.19, v6.17. |
| N8 | `BTPROTO_*`: H1. | |
| N9 | `BT_*` states: `CONNECTED` 1, `OPEN` 2, `BOUND` 3, `LISTEN` 4, `CONNECT` 5, `CONNECT2` 6, `CONFIG` 7, `DISCONN` 8, `CLOSED` 9. | `include/net/bluetooth/bluetooth.h`, v4.19, v6.17. |
| N10 | `XSK_*` states: X1. | |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | Both symbol tables type `socket` (with `file` and `sk`), `socket_alloc`, `sock`, `sock_common` (all F7 members, `sk_type` and `sk_protocol` as `u16`), `possible_net_t` with `net`, `ns_common` with `inum`, `inet_sock`, `unix_sock`, `unix_address` without `hash`, `sockaddr_un`, `netlink_sock`, `packet_sock`, `xdp_sock` (its `state` an anonymous enum), `sk_filter`, `bpf_prog` with `orig_prog`, `bpf_prog_aux` with `id` and `name`, and `net_device`. Neither has `vsock_sock`, `sockaddr_vm` or `bt_sock`: those families are modules whose types the tables do not hold. | `socketfacts -types`, 2026-11-12. |
| M2 | On mem3, 2 socket files lead to a `struct socket` whose `file` is 0 (F2: the socket is being released while the capture runs). No other back link fails on either capture. | `socketfacts`, diagnostics. |
| M3 | Counts per family, state, protocol, filter and namespace. | Section 9. |

## 4. Algorithm

1. **Shape.** `task_struct.files` and `sock.__sk_common` must be in the table, and `socket_file_ops` must resolve; otherwise the tool fails (section 6).
2. **Tasks.** Walk every task with threads (S01), skipping by the session PID set. Report the walk's losses (S01).
3. **Tables.** For each task read `files`. A null pointer is skipped. A `files_struct` already listed is skipped (T2): the row's process is the first task that holds the table, the leader. Read the table and its open files with the shared `linuxobj` descriptor helpers (T1), which drop null slots; a slot that does not read ends the table there, and the cut is counted.
4. **Socket files.** For each open file:
   1. Read `f_op`; a file whose `f_op` is not `socket_file_ops` is not a socket (F1) and is passed over silently.
   2. `socket = private_data`; it must not be null (F1).
   3. `socket.file` must equal the file (F2).
   4. `sk = socket.sk`; it must not be null, and `sk.sk_socket` must equal `socket` (F3).
   5. Decode `sk` (4.1). The inode number is `i_ino` of the `vfs_inode` in the `socket_alloc` holding `socket` (F5).
5. **Namespace option.** With `linux.socket.list.netns` set, keep only rows whose namespace is known and equal to it.
6. Rows are in task walk order, then descriptor order.

### 4.1 Decoding one sock

The sock's own members, including those of its family type, are read from the reader the caller names (kernel space for the list, physical memory for a scan). Everything a pointer leads to is read from kernel space.

1. **Common fields.** Read `skc_family`, `sk_type` and `sk_protocol`. A failure here is an error for this sock (section 6). The family and type are named by N1 and N2.
2. **Namespace.** `net` is `skc_net.net`, or the `init_net` symbol when `possible_net_t` has no members (F6). The namespace is `net.ns.inum`.
3. **Filter.** Read `sk_filter` (B1). Null gives an empty filter. Otherwise read `prog`; when `prog.orig_prog` is not null the filter is `classic len=<orig_prog.len>` (B3); otherwise it is `ebpf id=<aux.id>`, followed by ` name=<aux.name>` when the name is not empty (B4).
4. **State.** Read `skc_state`.
5. **Family.** The family type is found from `sk` by the offset of its member `sk` (F4). When the table has no such type, only steps 1 to 4 and the family's protocol and state apply, and the coverage is **no family type**. `AF_BLUETOOTH` is the exception: its branch reads only the common fields and never checks the table for `bt_sock`, so its coverage stays `full` (O9).

| Family | Protocol | Local address, port | Remote address, port | State |
|---|---|---|---|---|
| `AF_INET` | N4 of `sk_protocol` | `skc_rcv_saddr` as dotted IPv4, big-endian `inet_sport` (I1, I2) | `skc_daddr`, big-endian `skc_dport` | N3 |
| `AF_INET6` | as `AF_INET` | `skc_v6_rcv_saddr` in RFC 5952 form (I4), `inet_sport` | `skc_v6_daddr`, `skc_dport` | N3 |
| `AF_UNIX` | `sk_protocol` in decimal | the name at `addr` rendered as U3, empty when `addr` is null; no port | the name of `peer`'s `addr`, empty when `peer` is null (U1); no port | N3 (U5) |
| `AF_NETLINK` | N5 | `groups[0]` as `0x` and 8 hex digits (0 when `groups` is null), `portid` (L2) | L3 mask of `dst_group` as `0x` and 8 hex digits, `dst_portid` | N6 (L4) |
| `AF_PACKET` | N7 of big-endian `num`, else `0x` and 4 hex digits | name of the device with `ifindex` on the sock's namespace (P2), empty for `ifindex` 0; port `ifindex` | none | none |
| `AF_XDP` | none | name of `dev`, empty when null; port `queue_id` | none | N10 when `state` exists (X1) |
| `AF_VSOCK` | none | `local_addr.svm_cid`, `svm_port`, each `VMADDR_CID_ANY` or `VMADDR_PORT_ANY` for `-1U` (V1, V2) | `remote_addr` likewise | N3 (V3) |
| `AF_BLUETOOTH` | N8 | none | none | N9 |
| any other | `sk_protocol` in decimal | none | none | `skc_state` in decimal |

6. **Unnamed values.** A protocol or state with no entry in its table is given in decimal and counted.
7. **Unix name bytes.** Read `len`; the byte count is `n = len − offset(sun_path)`. It must be 1 to 109 (U4). Read `n` bytes at `name.sun_path` and render them by U3.
8. **Device names.** The device list of a namespace is walked once with the S01 list walk and kept.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| `f_op == socket_file_ops` | F1 | Not a socket; no row, not counted |
| `private_data` not null and `socket.file` is the file | F1, F2; M2 | No row; counted |
| `socket.sk` not null and `sk.sk_socket` is the socket | F3 | No row; counted |
| A unix name has 1 to 109 bytes | U4 | Local or remote address absent; counted |
| A namespace or device lookup reads | F6, P2 | Field absent; counted |

Rows are not required to have a decoded family: every sock that passes the links gives a row (I3: nothing else reaches a descriptor).

## 6. Failure modes

| Case | Result |
|---|---|
| `task_struct` has no `files` | `linuxobj.ErrUnsupported`, the tool fails |
| `socket_file_ops` missing | `ErrNoSocketFileOps` |
| `sock.__sk_common` missing | `ErrNoSockCommon` |
| Option of the wrong type | `tools.ErrOptionType` |
| Task walk losses | S01 diagnostics |
| A files pointer, descriptor table, slot, `f_op` or `comm` does not read, or the table is over the cap | Counted per kind, one diagnostic with the first case |
| `TaskFDs` returns an error, or a task that holds a socket has a `tgid` or `pid` that does not read | The whole tool stops: `linux.socket.list: <error>`, no rows (O10) |
| A back link fails (section 5) | Counted per kind, one diagnostic with the first case: `<object> at 0x<addr>: <member>: socketlist: link does not lead back: it holds 0x<value>` |
| The sock's family, type or protocol does not read | Counted ("socks that do not read") |
| A family member does not read | The field is absent; coverage **partial**; one diagnostic per member with its count |
| The family type is missing | Coverage **no family type**; one diagnostic per family |
| A value with no name | Decimal; one diagnostic per table with its count |
| A device list walk ends other than Closed | Diagnostic with the end and the place (S01) |
| Strict mode | Any task walk loss, any counted loss above, or any partial row is an error. Missing family types and unnamed values stay diagnostics. |

## 7. Result schema

`linux.socket.list` row:

| Field | Type | Meaning |
|---|---|---|
| `PID` | int | `tgid` of the task holding the table |
| `TID` | int | `pid` of that task |
| `Process` | string | its `comm` |
| `FD` | uint | descriptor number |
| `Inode` | uint | socket inode number (F5); 0 when it did not read |
| `Sock` | uint | `struct sock` address, masked |
| `Family` | string | N1 name, or `AF <n>` |
| `Type` | string | N2 name, or `SOCK <n>` |
| `Protocol` | text | 4.1 table |
| `LocalAddress`, `LocalPort`, `RemoteAddress`, `RemotePort` | text | 4.1 table |
| `State` | text | 4.1 table |
| `Filter` | text | 4.1 step 3: empty for no filter |
| `NetNS` | uint | namespace inode number |
| `NetNSKnown` | bool | `NetNS` was read |
| `Coverage` | string | `full`, `partial`, `no family type` or `family not decoded` |

A text field is a value with an "available" flag. Absent (not available) means the family has no such field or it did not read; available and empty means the kernel holds nothing there (an unbound unix socket, no filter). Ports are decimal. The fields from `Family` to `Coverage` are the decoder's result, which `linux.socket.scan` also uses.

## 8. Limits

- `MaxListEntries`: the task walk and each device list (S01).
- `MaxTableEntries`: descriptor slots per table, in the shared descriptor helper.

A unix name is at most 109 bytes and a device name 16 (U4, P2), so no cap applies to them.

## 9. Acceptance

- Synthetic fixtures: one process holding a socket of every decoded family and one undecoded family (AF_CAN); a missing `vsock_sock` type; `possible_net_t` with no members; a table shared by a thread and a forked copy; a file whose socket does not point back and a sock whose `sk_socket` does not; an unreadable unix address; classic and eBPF filters; an unconnected netlink sock; the namespace option, including a wrong type; unnamed values; a missing `socket_file_ops`.
- Fuzz targets: `FuzzUnixPath` (U3 rendering against arbitrary lengths and bytes), `FuzzAddresses` (IPv4, IPv6 and port rendering round trip), `FuzzDecode` (a mapped sock with arbitrary family, family bytes and unix address always decodes).
- On both captures, measured with `socketfacts`, 2026-11-12. Counts are of distinct socks; a sock several processes hold has a row per holder.

| | mem3_ubuntu24 (6.17) | mem4_fedora40 (6.14) |
|---|---|---|
| Rows | 1011 | 1082 |
| Distinct socks | 755 | 824 |
| Socks held by more than one process | 133 | 129 |
| (PID, FD) pairs listed twice | 0 | 0 |
| Rows with inode 0 | 0 | 0 |
| Back links that fail | 2 (`socket.file` 0, M2) | 0 |
| AF_UNIX | 689: `TCP_ESTABLISHED` 623, `TCP_LISTEN` 51, `TCP_CLOSE` 15 | 750: 655, 79, 16 |
| AF_INET | 9: TCP 4 (`TCP_LISTEN` 4), UDP 5 (`TCP_ESTABLISHED` 1, `TCP_CLOSE` 4) | 13: TCP 7, UDP 6; `TCP_LISTEN` 6, `TCP_ESTABLISHED` 1, `TCP_CLOSE` 6 |
| AF_INET6 | 6: TCP 4 (`TCP_LISTEN` 4), UDP 2 (`TCP_CLOSE`) | 8: TCP 3 (`TCP_LISTEN`), UDP 4, ICMPV6 1; `TCP_CLOSE` 5 |
| AF_NETLINK | 49, all `TCP_CLOSE`: `KOBJECT_UEVENT` 32, `ROUTE` 9, `AUDIT` 3, `GENERIC` 2, `NETFILTER` 2, `XFRM` 1 | 51, all `TCP_CLOSE`: 30, 11, 6, 2, 2, 0 |
| AF_PACKET | 1, `ETH_P_ARP` | 1, `ETH_P_ARP` |
| Not decoded | 1 `AF_QIPCRTR` | 1 `AF_QIPCRTR` |
| Coverage | all `full` except the `AF_QIPCRTR` sock | same |
| Namespaces | 3 (750, 3, 2 socks) | 6 (809, 5, 3, 3, 2, 2) |
| Filters | 29 classic (28 netlink, 1 AF_INET), lengths 8 to 23; no eBPF | 26 classic, all netlink; no eBPF |
| Listening TCP endpoints | 8, each one sock; ports 22 (IPv4 and IPv6, each held by 2 processes), 53 (127.0.0.53, 127.0.0.54), 631 (127.0.0.1, ::1), 3350 (::1), 3389 (::) | 9, each one sock held by one process; ports 22 (IPv4, IPv6), 27500, 5355 (IPv4, IPv6), 631 (127.0.0.1, ::1), 53 (127.0.0.53, 127.0.0.54) |
| Unix names | 331 path, 11 abstract, 347 unbound; 65 distinct names, longest 53 bytes; 312 socks name a peer | 369, 17, 364; 96 distinct, longest 53; 333 |

Each listening TCP port therefore appears once per sock: no sock is listed twice for the same process and descriptor, and no listening endpoint has more than one sock. The most common unix names are `/run/systemd/journal/stdout` (96 and 94 socks), `/run/user/1000/bus` (76, 77) and `/run/dbus/system_bus_socket` (59, 76). Abstract names include `@/tmp/.X11-unix/X0` and the systemd bus names of the form `@<16 hex digits>/bus/<unit>/<name>`, which shows U3's `@` prefix. No name holds a byte outside printable ASCII. Neither capture has AF_XDP, AF_VSOCK or AF_BLUETOOTH sockets, so those decoders and the eBPF filter path are checked by fixtures only.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision: enumeration values keep the kernel's prefixes (`AF_`, `SOCK_`, `IPPROTO_`, `TCP_`, `NETLINK_`, `ETH_P_`, `BT_`, `XSK_`). An AF_UNIX listener reads `TCP_LISTEN`, which is the kernel's own value (U5) but may surprise. | Owner choice at the final stage |
| O2 | Owner decision: a socket whose `socket.file` is 0 (M2) is left out and counted. Listing it with a flag would show sockets closed during acquisition. | Owner choice |
| O3 | Only N7's `ETH_P_*` subset is named; other packet protocols print in hexadecimal. | Extend the table if a capture needs it |
| O4 | Bluetooth addresses (in `l2cap_chan`, `rfcomm_pinfo`, `sco_pinfo`) are not decoded, and no capture holds a Bluetooth, vsock or XDP socket, or the types for the first two. | A capture with the modules' types |
| O5 | Families other than those in 4.1 (for example `AF_QIPCRTR`, `AF_ALG`, `AF_CAN`, `AF_KEY`, `AF_TIPC`) give the common fields only. | A spec revision per family, if needed |
| O6 | `sk_type` and `sk_protocol` as v4.19 bit-fields are read through the table's bit offsets; no capture has them. | A v4.19 capture (Q7) |
| O7 | Section 4 reaches socks only through `socket.sk` of an open file, so a sock no open file holds is not listed. The Filter field is `sk_filter` alone (4.1 step 3, B1 to B4), so a reuseport program is not named. Owner decision 2026-11-12 (follow-up PQ3): keep the spec. Done: recorded; no change. | Owner decision |
| O8 | A unix sock's namespace is read from its own `skc_net` (4.1 step 2, F6), as for every other family, so it can differ from the namespace of the task that holds the file. Owner decision 2026-11-12 (follow-up PQ4): accept. Done: recorded; no change. | Owner decision |
| O9 | The `AF_BLUETOOTH` branch of the decoder (`tools/linux/socketlist/decode.go`) never checks the table for `bt_sock`, so a Bluetooth row keeps coverage `full` where the other decoded families give **no family type**. Owner decision 2026-11-12: kept for v0.1.0; check for `bt_sock` and set the coverage in v0.2.0. | v0.2.0 |
| O10 | In `linux.socket.list` (`tools/linux/socketlist/socket_list.go`) a `TaskFDs` error, or one task holding a socket whose `tgid` or `pid` does not read, stops the whole tool with no rows. Owner decision 2026-11-12: kept for v0.1.0; count such a task as a loss, report it and go on in v0.2.0. | v0.2.0 |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Keep AF_, SOCK_, TCP_ prefixes |
| O2 | Leave out and count |
| O3 | Defer to v0.2.0 |
| O4 | Leave undecoded |
| O5 | Defer to v0.2.0 |
| O6 | Ship as written, mark untested |

## 11. Provenance

Written from the kernel sources at the tags in section 3 and the project's measurements. The sources were fetched from `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=<tag>` on 2026-11-12. Every rule rests on the sources and measurements above.
