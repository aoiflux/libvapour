# S40: Linux network namespaces, devices and interface addresses

Version 1, 2026-11-12.

## 1. Purpose

A Linux host's network state is split into network namespaces, each with its own devices, addresses, sockets and Netfilter hooks. An examiner needs to know which namespaces existed, which tasks were in them, which devices each held with the flags, state and hardware address the kernel would report, and which IPv4 and IPv6 addresses were configured on each device. This specification defines the shared `linuxobj` readers for those objects: the namespace list and a task's namespace, the device list of a namespace, one device's record, and the address lists of a device. The tools `linux.network.list_interfaces`, `linux.network.list_addresses` and `linux.network.list_hooks` use them.

Sockets are S13. The descriptor table and socket links of S13 (T1, F1 to F5) are not re-derived here, and no second socket decoder is defined: `tools/linux/socketlist` holds the only one, which `linux.socket.scan` also uses. The list walk is S01.

## 2. Inputs

| Field | Type | Meaning |
|---|---|---|
| Kernel | `linuxobj.Kernel` | Kernel-space memory, the symbol table, the address form and the effective Limits. |
| Symbols | symbol table | `net_namespace_list`, `init_net`; the types in section 3. |
| Limits | effective `limits.Limits` | Section 8. |

The readers take no tool options.

## 3. Facts from the sources

Tags checked: v4.19, v6.1, v6.4, v6.14 and v6.17 unless a row names fewer, fetched from `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=<tag>` on 2026-11-12. Paths are under the kernel tree. The supported captures run 6.17 (Ubuntu 24) and 6.14 (Fedora 40).

### Namespaces

| # | Fact | Source |
|---|---|---|
| N1 | `net_namespace_list` is a `struct list_head`; `for_each_net` walks it with `list_for_each_entry(VAR, &net_namespace_list, list)`, so every `struct net` is linked through its member `list`. | `include/net/net_namespace.h`, every tag. |
| N2 | `setup_net` adds a namespace with `list_add_tail_rcu(&net->list, &net_namespace_list)`; `cleanup_net` removes it with `list_del_rcu(&net->list)`. A namespace is therefore on the list from setup until its cleanup work runs, whether or not a task still holds it. | `net/core/net_namespace.c`, every tag. |
| N3 | `struct net` has `struct ns_common ns`, and `struct ns_common` has `unsigned int inum`, the namespace's inode number. | `include/net/net_namespace.h`; `include/linux/ns_common.h`; every tag. |
| N4 | `struct nsproxy` has `struct net *net_ns`; a task's network namespace is `task->nsproxy->net_ns`. `exit_task_namespaces` calls `switch_task_namespaces(p, NULL)`, so an exiting task has a null `nsproxy`. | `include/linux/nsproxy.h`; `kernel/nsproxy.c`; every tag. |
| N5 | `possible_net_t` and `init_net`: S13 F6. A device's namespace is `dev_net(dev)`, which is `read_pnet(&dev->nd_net)`. | `include/linux/netdevice.h`, every tag. |
| N6 | `net_ns_net_init` gives a namespace its number with `ns_alloc_inum`, which returns `PROC_DYNAMIC_FIRST` (0xF0000000) plus an IDA index, so the first namespace set up, `init_net`, gets 0xF0000000. At v6.17 `init_net` instead takes the fixed `PROC_NET_INIT_INO`, `NET_NS_INIT_INO` 0xEFFFFFF9, and only later namespaces are allocated. No namespace number is 0. | `net/core/net_namespace.c`, `include/linux/proc_ns.h`, `fs/proc/generic.c`, every tag; `include/uapi/linux/nsfs.h`, v6.17. |

### Devices

| # | Fact | Source |
|---|---|---|
| D1 | `struct net` has `struct list_head dev_base_head`; `for_each_netdev(net, d)` is `list_for_each_entry(d, &(net)->dev_base_head, dev_list)`, and `list_netdevice` links a device with `list_add_tail_rcu(&dev->dev_list, &net->dev_base_head)`. | `include/net/net_namespace.h`, `include/linux/netdevice.h`, `net/core/dev.c`, every tag. |
| D2 | `struct net_device` has `char name[IFNAMSIZ]`, `int ifindex`, `unsigned int flags`, `unsigned short gflags`, `unsigned long state`, `unsigned int mtu`, `unsigned char perm_addr[MAX_ADDR_LEN]`, `unsigned char addr_len`, `unsigned char *dev_addr` (`const` from v6.1), `struct in_device *ip_ptr`, `struct inet6_dev *ip6_ptr`, `struct Qdisc *qdisc`, `unsigned int tx_queue_len` and `possible_net_t nd_net`. `operstate` is `unsigned char` at v4.19, v6.1 and v6.4 and `unsigned int` at v6.14 and v6.17. `IFNAMSIZ` is 16 and `MAX_ADDR_LEN` is 32. | `include/linux/netdevice.h`; `include/uapi/linux/if.h`; `include/uapi/linux/netdevice.h`; every tag. |
| D3 | `rtnl_fill_ifinfo` reports `ifi_flags = dev_get_flags(dev)` (`netif_get_flags` at v6.17), `IFLA_IFNAME` from `name`, `IFLA_MTU` from `mtu`, `IFLA_TXQLEN` from `tx_queue_len`, `IFLA_QDISC` from `qdisc->ops->id` only when `qdisc` is not null, and `IFLA_ADDRESS` as `addr_len` bytes at `dev_addr` only when `addr_len` is not 0. From v6.1 it also reports `IFLA_PERM_ADDRESS` as `addr_len` bytes of `perm_addr`. | `net/core/rtnetlink.c`, every tag (`IFLA_PERM_ADDRESS` from v6.1, absent at v4.19). |
| D4 | `dev_get_flags` returns `(flags & ~(IFF_PROMISC | IFF_ALLMULTI | IFF_RUNNING | IFF_LOWER_UP | IFF_DORMANT)) | (gflags & (IFF_PROMISC | IFF_ALLMULTI))`, then, only if `netif_running`, adds `IFF_RUNNING` when `netif_oper_up`, `IFF_LOWER_UP` when `netif_carrier_ok` and `IFF_DORMANT` when `netif_dormant`. | `net/core/dev.c` `dev_get_flags` (v4.19 to v6.14), `netif_get_flags` (v6.17). |
| D5 | `netif_running` tests bit `__LINK_STATE_START` of `state`, `netif_carrier_ok` is the bit `__LINK_STATE_NOCARRIER` clear, `netif_dormant` tests `__LINK_STATE_DORMANT`, and `netif_oper_up` is `operstate` `IF_OPER_UP` or `IF_OPER_UNKNOWN`. | `include/linux/netdevice.h`, every tag. |
| D6 | `enum netdev_state_t` is `__LINK_STATE_START` 0, `PRESENT` 1, `NOCARRIER` 2, `LINKWATCH_PENDING` 3, `DORMANT` 4, and `TESTING` 5 from v6.1. | `include/linux/netdevice.h`, every tag. |
| D7 | `enum net_device_flags` is `IFF_UP` `1<<0` to `IFF_DYNAMIC` `1<<15` in the order of T1, then `IFF_LOWER_UP` `1<<16`, `IFF_DORMANT` `1<<17` and `IFF_ECHO` `1<<18`. The table is the same at every tag. | `include/uapi/linux/if.h`, every tag. |
| D8 | The operational states are `IF_OPER_UNKNOWN` 0, `NOTPRESENT` 1, `DOWN` 2, `LOWERLAYERDOWN` 3, `TESTING` 4, `DORMANT` 5 and `UP` 6 (RFC 2863). `rtnl_fill_ifinfo` reports `IF_OPER_DOWN` for a device that is not running. | `include/uapi/linux/if.h`; `net/core/rtnetlink.c`; every tag. |
| D9 | `alloc_netdev_mqs` calls `dev_addr_init`, which sets `dev->dev_addr = ha->addr`, so a device that has been allocated has a non-null `dev_addr`. | `net/core/dev.c`, `net/core/dev_addr_lists.c`, every tag. |
| D10 | The sysfs `address` file prints `dev_addr` with `sysfs_format_mac`, which is `"%*phC"` of `addr_len` bytes: each byte as two lower-case hexadecimal digits (`hex_asc` is `"0123456789abcdef"`), separated by `:`. | `net/core/net-sysfs.c`, every tag; `net/ethernet/eth.c`, `lib/vsprintf.c` `hex_string`, `lib/hexdump.c`, v4.19, v6.17. |
| D11 | `struct Qdisc` has `const struct Qdisc_ops *ops`, and `struct Qdisc_ops` has `char id[IFNAMSIZ]`. | `include/net/sch_generic.h`, every tag. |

### Interface addresses

| # | Fact | Source |
|---|---|---|
| A1 | `struct in_device` has `struct in_ifaddr *ifa_list`; `struct in_ifaddr` has `struct in_ifaddr *ifa_next`, `__be32 ifa_local`, `__be32 ifa_address`, `unsigned char ifa_scope` and `unsigned char ifa_prefixlen`. The chain ends at a null `ifa_next` (`for_ifa` at v4.19, `in_dev_for_each_ifa_rcu` from v6.1). | `include/linux/inetdevice.h`, every tag. |
| A2 | `inet_fill_ifaddr` reports `IFA_LOCAL` from `ifa_local` and `IFA_ADDRESS` from `ifa_address`, the peer address on a point-to-point link; an address given without a peer is stored in both (`ifa->ifa_address = ifa->ifa_local` in the ioctl path, `tb[IFA_ADDRESS] = tb[IFA_LOCAL]` in the netlink path). The device's own address is therefore `ifa_local`. `ifa_scope` is reported as the message scope. | `net/ipv4/devinet.c`, every tag. |
| A3 | `struct inet6_dev` has `struct list_head addr_list`; `struct inet6_ifaddr` has `struct in6_addr addr`, `__u32 prefix_len`, `__u16 scope` and `struct list_head if_list`. `ipv6_link_dev_addr` adds an address with `list_add_tail_rcu(&ifp->if_list, p)` and the kernel walks them with `list_for_each_entry(ifa, &idev->addr_list, if_list)`. | `include/net/if_inet6.h`, `net/ipv6/addrconf.c`, every tag. |
| A4 | `IFA_HOST`, `IFA_LINK` and `IFA_SITE` are `IPV6_ADDR_LOOPBACK` 0x10, `IPV6_ADDR_LINKLOCAL` 0x20 and `IPV6_ADDR_SITELOCAL` 0x40. `inet6_fill_ifaddr` reports the scope as `rt_scope(ifa->scope)`, which is `RT_SCOPE_HOST` when the `IFA_HOST` bit is set, else `RT_SCOPE_LINK` for `IFA_LINK`, else `RT_SCOPE_SITE` for `IFA_SITE`, else `RT_SCOPE_UNIVERSE`. | `include/net/if_inet6.h`, `net/ipv6/addrconf.c`, every tag; `include/net/ipv6.h`, v4.19, v6.17. |
| A5 | `enum rt_scope_t` is `RT_SCOPE_UNIVERSE` 0, `SITE` 200, `LINK` 253, `HOST` 254, `NOWHERE` 255. The kernel's own text for them, in `/proc/net/fib_trie`, is `universe`, `site`, `link`, `host`, `nowhere`, and `scope=%d` for any other value. | `include/uapi/linux/rtnetlink.h`; `net/ipv4/fib_trie.c` `rtn_scope`; every tag. |
| A6 | An IPv4 address is a 32-bit value written as four decimal octets in network order (RFC 791 section 3.2); `__be32` holds it in that order. An IPv6 address is 128 bits (RFC 8200, RFC 4291) and its text form is RFC 5952, with a v4-mapped address as `::ffff:a.b.c.d` (section 5). | RFC 791, RFC 8200, RFC 4291, RFC 5952. |

### Name tables

| # | Table | Source |
|---|---|---|
| T1 | `IFF_*` by bit: 0 `UP`, 1 `BROADCAST`, 2 `DEBUG`, 3 `LOOPBACK`, 4 `POINTOPOINT`, 5 `NOTRAILERS`, 6 `RUNNING`, 7 `NOARP`, 8 `PROMISC`, 9 `ALLMULTI`, 10 `MASTER`, 11 `SLAVE`, 12 `MULTICAST`, 13 `PORTSEL`, 14 `AUTOMEDIA`, 15 `DYNAMIC`, 16 `LOWER_UP`, 17 `DORMANT`, 18 `ECHO`. | D7 |
| T2 | `IF_OPER_*`: D8. | |
| T3 | Route scopes: A5. | |

### Measurements

| # | Measurement | Data |
|---|---|---|
| M1 | Both symbol tables type `net` (`list`, `ns`, `dev_base_head`), `ns_common.inum`, `nsproxy.net_ns`, `possible_net_t.net`, `net_device` with every D2 member (`operstate` as `unsigned int`, `gflags` as `short unsigned int`), `Qdisc.ops`, `Qdisc_ops.id`, `in_device.ifa_list`, `in_ifaddr` (A1 members), `inet6_dev.addr_list`, `inet6_ifaddr` (A3 members, `scope` as `short unsigned int`) and `in6_addr` (16 bytes). Both hold `enum netdev_state_t`, `enum net_device_flags` and `enum rt_scope_t` with exactly the values of D6, D7 and A5, and the symbols `net_namespace_list` and `init_net`. | `netnsfacts -types`, 2026-11-12. |
| M2 | Namespaces, devices, addresses and descriptors. | Section 9. |

## 4. Algorithm

### 4.1 Namespaces

1. Resolve `net_namespace_list` and walk it with the S01 list walk over `net.list`, forwards (N1). The entries are `struct net` addresses in list order.
2. A namespace's number is `net.ns.inum` (N3).
3. A task's namespace is `task.nsproxy.net_ns`. A null `nsproxy` means the task holds none (N4); this is not an error.

### 4.2 Devices

1. The devices of a namespace are the S01 list walk from `net.dev_base_head` over `net_device.dev_list`, forwards (D1).
2. A device record is read in this order: identity (`name`, `ifindex`), namespace, the state words (`flags`, `gflags`, `operstate`, `state`), the sizes (`mtu`, `tx_queue_len`), the hardware addresses, the queueing discipline, then the protocol pointers `ip_ptr` and `ip6_ptr`. A failed read of the identity, a state word, a size or a protocol pointer is an error for the device.
3. **Namespace.** `nd_net.net`, or the `init_net` symbol when `possible_net_t` has no `net` member (N5, S13 F6). The record's namespace number is that `net`'s `ns.inum` (N3); it is "known" only when both read and the number is not 0.
4. **Hardware addresses.** Read `addr_len`; a value above `MAX_ADDR_LEN` (32) makes both addresses absent (D2). The current address is `addr_len` bytes at `dev_addr`, absent when `dev_addr` is null or does not read (D3, D9). The permanent address is the first `addr_len` bytes of `perm_addr` (D3). Both are written as D10. With `addr_len` 0 both are present and empty.
5. **Queueing discipline.** Null `qdisc` gives a present, empty value (D3); otherwise `qdisc.ops.id`, absent when `ops` is null or a read fails (D11).
6. **Reported flags.** Computed from the record as D4 and D5, with the `__LINK_STATE_*` bit numbers of D6. Names come from T1, in bit order; a set bit with no name is written as its value in hexadecimal.
7. **Running** is bit `__LINK_STATE_START` of `state`. **Promiscuous** is `IFF_PROMISC` in the stored `flags`, which the kernel sets whenever its promiscuity count is above 0; `gflags` only records a user's request (D4).
8. **Operational state.** `operstate` is named by T2; a value above 6 has no name.

### 4.3 Addresses

1. **IPv4.** With `in_device` null there are no addresses. Otherwise follow `ifa_list` and then each `ifa_next` until a null pointer (A1). Each entry gives `ifa_local` as four octets in memory order (A2, A6), `ifa_prefixlen`, and `ifa_scope` named by T3.
2. **IPv6.** With `inet6_dev` null there are no addresses. Otherwise walk `addr_list` over `inet6_ifaddr.if_list` with the S01 list walk (A3). Each entry gives `addr` as 16 bytes in RFC 5952 form (A6), `prefix_len`, and `scope` mapped by `rt_scope` (A4) and named by T3.
3. Both walks return the addresses read so far and how the walk ended, in the S01 end vocabulary: closed (null pointer or back at the head), head unreadable, link unreadable, entry unreadable, revisited, or capped.

## 5. Validity rules

| Rule | Justification | On failure |
|---|---|---|
| `addr_len` ≤ 32 | D2 | Both hardware addresses absent |
| An IPv4 chain entry is new | A1: the kernel's chain ends at null | Walk ends "revisited" at that entry |
| An address entry's members read | A1, A3 | Walk ends "entry unreadable" at that entry; earlier addresses are kept |
| A namespace number is not 0 | N6 | Namespace not known |

No validity rule is placed on device names, indices or flags: any value the kernel stores is reported as read.

## 6. Failure modes

| Case | Result |
|---|---|
| `net_namespace_list` missing | The symbol error from `Kernel.Symbol` |
| A type or member the reader needs is missing | An error for which `linuxobj.TableGap` is true (`symbols` unknown type or field, `linuxobj.ErrNotInTable`, `linuxobj.ErrUnsupported`). `in_ifaddr` and `inet6_ifaddr` missing give `linuxobj.NotInTable` |
| A list walk ends other than closed | The S01 `List` with its end and place; callers report it |
| A device member read fails (4.2 step 2) | Error naming the member and address: `linuxobj: net_device.<member> at 0x<addr>: <cause>` |
| An address walk ends early | `AddressWalk.End` and `At`; callers count it |
| Limits reached | Walk ends "capped" (section 8) |
| Strict mode | Decided by each tool. `linux.network.list_addresses` and `list_interfaces` fail on any device that does not read and on any namespace, device or address walk that ends early. A table without one address family's type is a diagnostic, not a failure; the other family is still listed |

## 7. Result schema

Readers on `linuxobj.Kernel`: `NetNamespaceList` and `NetNamespaceInode` (4.1 steps 1 and 2), `NsproxyNetNS` (4.1 step 3), `NamespaceDevices` and `ReadNetDevice` (4.2), `IPv4Addresses` and `IPv6Addresses` (4.3). The names follow the kernel's own (`net_namespace_list`, `nsproxy->net_ns`).

`linuxobj.NetDevice`:

| Field | Type | Meaning |
|---|---|---|
| `Addr` | uint | `struct net_device` address |
| `Name` | string | `name` |
| `Index` | int | `ifindex` |
| `Net` | uint | `struct net` address of the device's namespace (4.2 step 3) |
| `NetNS`, `NetNSKnown` | uint, bool | namespace number and whether it was read |
| `Flags`, `GFlags`, `OperState`, `LinkState` | uint | `flags`, `gflags`, `operstate`, `state` as stored |
| `MTU`, `TxQueueLen` | uint | `mtu`, `tx_queue_len` |
| `HardwareAddress`, `PermanentAddress` | text | 4.2 step 4 |
| `Qdisc` | text | 4.2 step 5 |
| `IPv4`, `IPv6` | uint | `ip_ptr`, `ip6_ptr` |

Methods: `ReportedFlags()` (4.2 step 6), `Running()` and `Promiscuous()` (4.2 step 7). Functions: `InterfaceFlagNames`, `OperStateName`, `RouteScopeName`, `IPv6RouteScope`, `FormatHardwareAddress`.

`linuxobj.AddressWalk` holds `Addresses` (each an `InterfaceAddress` of `Entry`, `Address`, `PrefixLen`, `Scope`), `End` and `At`. A text value is `linuxobj.NetText`, shared with S13: absent means not read or not held, present and empty means the kernel holds nothing there.

Tool rows that change (section 10, O1 to O3):

- `linux.network.list_addresses`: `Scope` uses the A5 words (`universe` where it was `global`, `scope=<n>` where it was `unknown`); `Address` is `ifa_local`; an IPv4 walk that ends early no longer stops the IPv6 walk of the same device.
- `linux.network.list_interfaces` and `list_addresses`: `HardwareAddress` is the current address (`dev_addr`), not `perm_addr`; a device whose `dev_addr` does not read is counted as unreadable.

## 8. Limits

- `MaxListEntries`: the namespace list, each device list and each address walk (S01). An IPv4 chain has no head to come back to, so the cap and the revisit check are what end a corrupt one.

A device name is 16 bytes and a hardware address at most 32 (D2), so no cap applies to them.

## 9. Acceptance

- Synthetic fixtures (`tools/linuxobj/net_test.go`): two namespaces in list order with their numbers; a task's namespace and a task with a null `nsproxy`; a full device record, and a device with no hardware address and no queueing discipline; `addr_len` 33; a device in `init_net` when `possible_net_t` is empty; reported flags for a device that is down, running with and without carrier, dormant and user-promiscuous; every name table; an IPv4 chain in order, at the cap, with a cycle and with an unreadable entry; an IPv6 list with link, host, v4-mapped and global addresses; a table without the address types; `TableGap` on each error kind.
- Fuzz targets: `FuzzHardwareAddressText` (D10 text round trip for any byte string), `FuzzReportedFlags` (D4 never changes the stored bits outside the derived and user bits, and a device that is not running reports none of the derived bits), `FuzzIPv4AddressChain` (an arbitrary chain of records always ends and never yields more addresses than records).
- On both captures, measured with `netnsfacts`, 2026-11-12:

| | mem3_ubuntu24 (6.17) | mem4_fedora40 (6.14) |
|---|---|---|
| Namespaces on the list | 4, list closed | 6, list closed |
| Namespace numbers | 4026531833 (init), 4026532139, 4026532253, 4026532321 | 4026531840 (init), 4026532157, 4026532225, 4026532292, 4026532363, 4026532613 |
| Tasks walked | 557: 556 hold a namespace, 1 has a null `nsproxy`, 0 do not read | 573: 572, 1, 0 |
| Distinct `nsproxy->net_ns` | 3, all on the list (549, 4 and 3 tasks) | 6, all on the list (553, 4, 4, 4, 4, 3 tasks) |
| Listed namespaces no task holds | 1 (4026532139, which has only `lo`) | 0 |
| Devices | init: `lo`, `eth0`, `docker0`; each other namespace: `lo` only; 6 in all, every list closed | init: `lo`, `eth0`; each other: `lo`; 7 in all |
| Device namespace | every device's `nd_net` is the namespace it is listed under | same |
| Stored flags | `lo` `UP,LOOPBACK`; `eth0` and `docker0` `UP,BROADCAST,MULTICAST` | same for `lo` and `eth0` |
| Reported flags | `lo` adds `RUNNING,LOWER_UP`; `eth0` adds `RUNNING,LOWER_UP`; `docker0` adds nothing (state 0x7: running, no carrier) | `lo`, `eth0` add `RUNNING,LOWER_UP` |
| Operational states | `lo` `IF_OPER_UNKNOWN` (4), `eth0` `IF_OPER_UP`, `docker0` `IF_OPER_DOWN` | `lo` `IF_OPER_UNKNOWN` (6), `eth0` `IF_OPER_UP` |
| Promiscuous, `gflags` | none, all 0 | none, all 0 |
| Hardware addresses | `lo` all zero; `eth0` current and permanent equal (`00:15:5d:…`); `docker0` current set, permanent all zero | `lo` zero; `eth0` equal |
| Queueing disciplines | `lo` `noqueue`, `eth0` `mq`, `docker0` `noqueue` | `lo` `noqueue`, `eth0` `mq` |
| IPv4 addresses | 6: `127.0.0.1/8 host` on each `lo`, `eth0` one `/20 universe`, `docker0` `172.17.0.1/16 universe` | 7: `127.0.0.1/8 host` × 6, `eth0` one `/20 universe` |
| IPv6 addresses | 5: `::1/128 host` on each `lo`, `eth0` one `fe80::/64 link`; `docker0` none | 7: `::1/128 host` × 6, `eth0` one `fe80::/64 link` |
| Address walks that end early | 0 | 0 |
| Descriptor tables (distinct `files_struct`) | 116 | 124 |
| Socket descriptors (`f_op` is `socket_file_ops`, S13 F1) | 1013 in 113 tables, at most 131 in one | 1082 in 120 tables, at most 168 |
| Distinct socket inodes behind them | 757 | 824 |
| `linux.socket.list` rows, distinct inodes | 1011, 755: the 2 missing descriptors are the released sockets of S13 M2 | 1082, 824 |
| Socks decoded per family (S13) | `AF_UNIX` 689, `AF_NETLINK` 49, `AF_INET` 9, `AF_INET6` 6, `AF_PACKET` 1, all `full`; `AF_QIPCRTR` 1 not decoded | 750, 51, 13, 8, 1, all `full`; `AF_QIPCRTR` 1 |
| Tool rows | `list_interfaces` 6, `list_addresses` 11, `list_hooks` 24; no diagnostics | 7, 14, 66; no diagnostics |

The init namespace's number differs between the captures as N6 predicts: 4026531833 is `NET_NS_INIT_INO` (0xEFFFFFF9) at 6.17 and 4026531840 is the first dynamic number (0xF0000000) at 6.14. No reader assumes a fixed value for it. No device on either capture has a hardware address length other than 6, a set flag bit without a name, or an unnamed operational state, so those paths are checked by fixtures only.

## 10. Open points

| # | Point | Closes with |
|---|---|---|
| O1 | Owner decision: address scopes use the kernel's own words (A5: `universe`, `site`, `link`, `host`, `nowhere`, `scope=<n>`) for both families. This changes `list_addresses` `Scope` from `global` to `universe` and from `unknown` to `scope=<n>`. | Owner choice at the final stage |
| O2 | Owner decision: `HardwareAddress` is the current address `dev_addr` (D3, D9, D10). The permanent address is in the record but not in a row. | Owner choice |
| O3 | Owner decision: `list_interfaces` `OperState` is the stored `operstate`; the kernel reports `IF_OPER_DOWN` for a device that is not running (D8). The flags column already follows D4. | Owner choice |
| O4 | Owner decision: enumeration names keep the kernel prefixes in the readers (`IFF_`, `IF_OPER_`); the two tools strip them, as before. | Owner choice |
| O5 | `possible_net_t` without a `net` member and `operstate` as `unsigned char` (v4.19 to v6.4) are covered by fixtures only; no capture has them. | A v4.19 or v6.1 capture (Q7) |
| O6 | A namespace on the list that no task holds (M2, mem3) is kept alive by something other than a task, for example a bind mount of its nsfs file or an open descriptor. Finding the holder is not specified. | A spec revision if an examiner needs it |
| O7 | The `linux.network.list_interfaces` description refers to a user-space command by name; rule 6 may cover it. Owner decision 2026-11-12: remove the command name. Done: the registered description in `tools/linux/networkinterface/interfaces.go` is "List every Linux network device in every network namespace, with the flags, operational state, hardware address and queueing discipline the kernel reports", which names no command, and this specification names none; checked 2026-11-12, no change was needed. | Owner choice |

### Owner decisions, 2026-11-12

The owner answered every point above. Where a point and this table differ, this table holds.

| Point | Decision |
|---|---|
| O1 | Use the kernel's words |
| O2 | Current address dev_addr |
| O3 | Stored operstate |
| O4 | Readers keep, tools strip |
| O5 | Defer; fixtures only |
| O6 | Leave out of scope |
| O7 | Remove the command name |

## 11. Provenance

Written from the kernel sources at the tags in section 3, RFC 791, RFC 4291, RFC 5952 and RFC 8200, and the project's measurements. The kernel sources were fetched from `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=<tag>` on 2026-11-12. Every rule rests on the sources and measurements above.
