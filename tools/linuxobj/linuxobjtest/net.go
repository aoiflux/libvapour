package linuxobjtest

import (
	"github.com/aoiflux/libvapour/symbols"
)

// Network layouts (S80 3.3): fixed where the header sets the offset on
// x86-64 (CONFIG_IPV6, CONFIG_NET_NS, CONFIG_SMP, no lock debugging),
// placed in v6.17 declaration order elsewhere.
const (
	// struct net, include/linux/net_namespace.h v6.17, placed; ns_common
	// fixed (include/linux/ns_common.h v4.19 to v6.17).
	NetSize        = 0xc8
	NetList        = 0x00
	NetNs          = 0x10
	NsCommonInum   = 0x10
	NetDevBaseHead = 0x28
	NetNF          = 0x38

	// netns_nf, include/net/netns/netfilter.h v6.17, placed:
	// NF_INET_NUMHOOKS 5 and NF_ARP_NUMHOOKS 3 entries.
	NetnsNFSize   = 0x90
	NFHooksIPv4   = 0x00
	NFHooksIPv6   = 0x28
	NFHooksARP    = 0x50
	NFHooksBridge = 0x68

	// net_device, include/linux/netdevice.h v6.17, placed.
	DevSize        = 0xb8
	DevName        = 0x40
	DevList        = 0x50
	DevIfindex     = 0x30
	DevFlags       = 0x18
	DevGFlags      = 0x60
	DevOperstate   = 0x64
	DevAddrLen     = 0x88
	DevMTU         = 0x00
	DevState       = 0x10
	DevPermAddr    = 0x68
	DevDevAddr     = 0x98
	DevIPPtr       = 0x90
	DevIP6Ptr      = 0x20
	DevNdNet       = 0x38
	DevQdisc       = 0xa8
	DevTxQueueLen  = 0xb0
	DevXDPProg     = 0x28
	DevHooksIngr   = 0xa0
	DevHooksEgress = 0x08

	// Qdisc and Qdisc_ops, include/net/sch_generic.h v6.17, fixed.
	QdiscOps   = 0x18
	QdiscOpsID = 0x10

	// in_device placed after dev; in_ifaddr fixed (include/linux/
	// inetdevice.h v4.19 and v6.17); inet6_dev placed after dev;
	// inet6_ifaddr fixed to scope, if_list placed (include/net/if_inet6.h
	// v6.17).
	InDevIfaList   = 0x08
	IfaNext        = 0x10
	IfaAddress     = 0x34
	IfaLocal       = 0x30
	IfaPrefixLen   = 0x45
	IfaScope       = 0x44
	In6DevAddrList = 0x08
	If6Addr        = 0x00
	If6PrefixLen   = 0x10
	If6Scope       = 0x32
	If6List        = 0x50

	// file, dentry, inode, files_struct and fdtable are the AddFS layouts;
	// socket (include/linux/net.h v6.17) is fixed, its socket_wq on a cache
	// line; socket_alloc is the socket then the inode (include/net/sock.h).
	NetFileSize         = FSFileSize
	NetFilePath         = FSFilePath
	NetPathDentry       = 0x08
	NetFileOp           = fileOp
	NetDentrySize       = FSDentSize
	NetDentryInode      = FSDentInode
	NetInodeSize        = FSInodeSize
	NetInodeIno         = FSInodeIno
	NetSocketSize       = 0x80
	NetSocketState      = 0x00
	NetSocketSk         = 0x18
	NetSocketAllocSize  = NetSocketSize + FSInodeSize
	NetSocketAllocInode = NetSocketSize
	NetFilesFdt         = FSFilesFdt
	NetFdtMaxFDs        = FSFdtMaxFDs
	NetFdtFD            = FSFdtFD
	NetTaskFiles        = FSTaskFiles
	NetNsproxyNetNS     = 0x28
	NetFileOpsSize      = 0x18

	// sock_common, include/net/sock.h v6.17, fixed; struct sock placed
	// after it.
	SkcDaddr      = 0x00
	SkcRcvSaddr   = 0x04
	SkcPortpair   = 0x0c
	SkcFamily     = 0x10
	SkcState      = 0x12
	SkcV6Daddr    = 0x38
	SockSize      = 0xb0
	SkProtocol    = 0x9a
	SkType        = 0x98
	SkFilter      = 0x88
	SkReuseportCB = 0xa8
	SkSocket      = 0x90
	SkDestruct    = 0xa0

	// Family socks begin with struct sock: inet_sock, unix_sock and
	// netlink_sock members are fixed from there (v6.17 inet_sock.h,
	// af_unix.h, net/netlink/af_netlink.h); packet_sock and xdp_sock are
	// placed (net/packet/internal.h, include/net/xdp_sock.h).
	ChildSockSize    = 0x110
	InetPinet6       = 0xb0
	InetSport        = 0xc6
	UnixAddr         = 0xb0
	UnixPeer         = 0x108
	UnixAddressLen   = 0x04
	UnixAddressName  = 0x08
	SunPath          = 0x02
	NetlinkPortID    = 0xb8
	NetlinkDstPortID = 0xbc
	NetlinkDstGroup  = 0xc0
	NetlinkGroups    = 0xd0
	NetlinkModule    = 0x108
	PacketIfindex    = 0xb0
	PacketNum        = 0xb4
	XDPDev           = 0xb0
	XDPState         = 0xb8

	// sk_filter (include/linux/filter.h v6.17) and bpf_prog
	// (include/linux/bpf.h v6.17) fixed; bpf_prog_aux fixed to id, name
	// placed.
	SkFilterProg = 0x18
	BPFProgType  = 0x04
	BPFProgAux   = 0x38
	BPFAuxID     = 0x20
	BPFAuxName   = 0x24

	// nf_hook_entries, nf_hook_entry and nf_hook_ops, include/linux/
	// netfilter.h v6.17, fixed.
	NFHookEntriesHook = 0x08
	NFHookEntrySize   = 0x10
	NFHookOpsSize     = 0x48
	NFHookOpsList     = 0x00
	NFHookOpsHook     = 0x20
	NFHookOpsPriority = 0x40
)

const (
	ifNameSize     = 16
	maxAddrLen     = 32
	bpfObjNameLen  = 16
	unixPathMax    = 108
	qdiscSize      = 0x20
	qdiscOpsSize   = 0x20
	inDeviceSize   = 0x10
	inIfaddrSize   = 0x78
	inet6DevSize   = 0x18
	inet6IfaSize   = 0x60
	ipv6PinfoSize  = 0x10
	skFilterSize   = 0x20
	bpfProgSize    = 0x48
	bpfAuxSize     = 0x38
	sockCommonSize = 0x88
)

type Net struct {
	k             *Kernel
	List          uint64
	nets          []uint64
	SocketFileOps uint64
	OtherFileOps  uint64
}

// AddNetTypes declares the S40 and S13 network types and lays out an empty
// net_namespace_list, socket_file_ops, sockfs_dentry_operations and one
// other file_operations for files that are not sockets.
func AddNetTypes(k *Kernel) *Net {
	t := k.Table
	f := field
	u8, u16, u32, u64 := scalar("unsigned char"), scalar("short unsigned int"), scalar("unsigned int"),
		scalar("long long unsigned int")
	if _, err := t.Struct("file"); err != nil {
		declareFileTypes(k)
	}
	k.addFields("task_struct", TaskSize, f("files", NetTaskFiles, ptr("files_struct")))
	k.addFields("nsproxy", nsproxySize, f("net_ns", NetNsproxyNetNS, ptr("net")))

	t.AddStruct(symbols.StructType{Name: "net", Size: NetSize, Fields: []symbols.Field{
		f("list", NetList, scalar("list_head")), f("ns", NetNs, scalar("ns_common")),
		f("dev_base_head", NetDevBaseHead, scalar("list_head")), f("nf", NetNF, scalar("netns_nf")),
	}})
	hooks := func(n uint64) symbols.TypeRef {
		p := ptr("nf_hook_entries")
		return symbols.TypeRef{Name: "nf_hook_entries", IsArray: true, ArrayLength: n, Element: &p}
	}
	t.AddStruct(symbols.StructType{Name: "netns_nf", Size: NetnsNFSize, Fields: []symbols.Field{
		f("hooks_ipv4", NFHooksIPv4, hooks(5)), f("hooks_ipv6", NFHooksIPv6, hooks(5)),
		f("hooks_arp", NFHooksARP, hooks(3)), f("hooks_bridge", NFHooksBridge, hooks(5)),
	}})
	t.AddStruct(symbols.StructType{Name: "possible_net_t", Size: 8, Fields: []symbols.Field{f("net", 0, ptr("net"))}})
	t.AddStruct(symbols.StructType{Name: "net_device", Size: DevSize, Fields: []symbols.Field{
		f("mtu", DevMTU, u32), f("nf_hooks_egress", DevHooksEgress, ptr("nf_hook_entries")),
		f("state", DevState, u64), f("flags", DevFlags, u32), f("ip6_ptr", DevIP6Ptr, ptr("inet6_dev")),
		f("xdp_prog", DevXDPProg, ptr("bpf_prog")), f("ifindex", DevIfindex, scalar("int")),
		f("nd_net", DevNdNet, scalar("possible_net_t")), f("name", DevName, array("char", ifNameSize)),
		f("dev_list", DevList, scalar("list_head")), f("gflags", DevGFlags, u16),
		f("operstate", DevOperstate, u32), f("perm_addr", DevPermAddr, array("unsigned char", maxAddrLen)),
		f("addr_len", DevAddrLen, u8), f("ip_ptr", DevIPPtr, ptr("in_device")),
		f("dev_addr", DevDevAddr, ptr("unsigned char")),
		f("nf_hooks_ingress", DevHooksIngr, ptr("nf_hook_entries")),
		f("qdisc", DevQdisc, ptr("Qdisc")), f("tx_queue_len", DevTxQueueLen, u32),
	}})
	t.AddStruct(symbols.StructType{Name: "Qdisc", Size: qdiscSize, Fields: []symbols.Field{f("ops", QdiscOps, ptr("Qdisc_ops"))}})
	t.AddStruct(symbols.StructType{Name: "Qdisc_ops", Size: qdiscOpsSize, Fields: []symbols.Field{f("id", QdiscOpsID, array("char", ifNameSize))}})
	t.AddStruct(symbols.StructType{Name: "in_device", Size: inDeviceSize, Fields: []symbols.Field{f("ifa_list", InDevIfaList, ptr("in_ifaddr"))}})
	t.AddStruct(symbols.StructType{Name: "in_ifaddr", Size: inIfaddrSize, Fields: []symbols.Field{
		f("ifa_next", IfaNext, ptr("in_ifaddr")), f("ifa_local", IfaLocal, u32), f("ifa_address", IfaAddress, u32),
		f("ifa_scope", IfaScope, u8), f("ifa_prefixlen", IfaPrefixLen, u8),
	}})
	t.AddStruct(symbols.StructType{Name: "in6_addr_union", Size: 16, Fields: []symbols.Field{
		f("u6_addr8", 0, array("unsigned char", 16)), f("u6_addr32", 0, array("unsigned int", 4)),
	}})
	t.AddStruct(symbols.StructType{Name: "in6_addr", Size: 16, Fields: []symbols.Field{f("in6_u", 0, scalar("in6_addr_union"))}})
	t.AddStruct(symbols.StructType{Name: "inet6_dev", Size: inet6DevSize, Fields: []symbols.Field{
		f("addr_list", In6DevAddrList, scalar("list_head")),
	}})
	t.AddStruct(symbols.StructType{Name: "inet6_ifaddr", Size: inet6IfaSize, Fields: []symbols.Field{
		f("addr", If6Addr, scalar("in6_addr")), f("prefix_len", If6PrefixLen, u32),
		f("scope", If6Scope, u16), f("if_list", If6List, scalar("list_head")),
	}})
	declareNetEnums(t)

	t.AddStruct(symbols.StructType{Name: "file_operations", Size: NetFileOpsSize, Fields: []symbols.Field{
		f("owner", 0, ptr("module")), f("llseek", 8, voidPtr()), f("read", 0x10, voidPtr()),
	}})
	t.AddStruct(symbols.StructType{Name: "socket", Size: NetSocketSize, Fields: []symbols.Field{
		f("state", NetSocketState, u32), f("sk", NetSocketSk, ptr("sock")),
	}})
	t.AddStruct(symbols.StructType{Name: "socket_alloc", Size: NetSocketAllocSize, Fields: []symbols.Field{
		f("socket", 0, scalar("socket")), f("vfs_inode", NetSocketAllocInode, scalar("inode")),
	}})
	t.AddStruct(symbols.StructType{Name: "sock_common", Size: sockCommonSize, Fields: []symbols.Field{
		f("skc_daddr", SkcDaddr, u32), f("skc_rcv_saddr", SkcRcvSaddr, u32),
		f("skc_portpair", SkcPortpair, u32), f("skc_dport", SkcPortpair, u16), f("skc_num", SkcPortpair+2, u16),
		f("skc_family", SkcFamily, u16), f("skc_state", SkcState, u8),
		f("skc_v6_daddr", SkcV6Daddr, scalar("in6_addr")),
	}})
	t.AddStruct(symbols.StructType{Name: "sock", Size: SockSize, Fields: []symbols.Field{
		f("__sk_common", 0, scalar("sock_common")), f("sk_filter", SkFilter, ptr("sk_filter")),
		f("sk_socket", SkSocket, ptr("socket")), f("sk_type", SkType, u16), f("sk_protocol", SkProtocol, u16),
		f("sk_destruct", SkDestruct, voidPtr()), f("sk_reuseport_cb", SkReuseportCB, ptr("sock_reuseport")),
	}})
	family := func(name string, fields ...symbols.Field) {
		t.AddStruct(symbols.StructType{Name: name, Size: ChildSockSize,
			Fields: append([]symbols.Field{f("sk", 0, scalar("sock"))}, fields...)})
	}
	family("inet_sock", f("pinet6", InetPinet6, ptr("ipv6_pinfo")), f("inet_sport", InetSport, u16))
	t.AddStruct(symbols.StructType{Name: "ipv6_pinfo", Size: ipv6PinfoSize, Fields: []symbols.Field{f("saddr", 0, scalar("in6_addr"))}})
	family("unix_sock", f("addr", UnixAddr, ptr("unix_address")), f("peer", UnixPeer, ptr("sock")))
	t.AddStruct(symbols.StructType{Name: "unix_address", Size: UnixAddressName, Fields: []symbols.Field{
		f("len", UnixAddressLen, scalar("int")),
		f("name", UnixAddressName, symbols.TypeRef{Name: "sockaddr_un", IsArray: true, Element: &symbols.TypeRef{Name: "sockaddr_un"}}),
	}})
	t.AddStruct(symbols.StructType{Name: "sockaddr_un", Size: SunPath + unixPathMax, Fields: []symbols.Field{
		f("sun_family", 0, u16), f("sun_path", SunPath, array("char", unixPathMax)),
	}})
	family("netlink_sock", f("portid", NetlinkPortID, u32), f("dst_portid", NetlinkDstPortID, u32),
		f("dst_group", NetlinkDstGroup, u32), f("groups", NetlinkGroups, ptr("long unsigned int")),
		f("module", NetlinkModule, ptr("module")))
	family("packet_sock", f("ifindex", PacketIfindex, scalar("int")), f("num", PacketNum, u16))
	family("xdp_sock", f("dev", XDPDev, ptr("net_device")), f("state", XDPState, scalar("xsk_state")))
	t.AddStruct(symbols.StructType{Name: "sk_filter", Size: skFilterSize, Fields: []symbols.Field{f("prog", SkFilterProg, ptr("bpf_prog"))}})
	t.AddStruct(symbols.StructType{Name: "bpf_prog", Size: bpfProgSize, Fields: []symbols.Field{
		f("type", BPFProgType, scalar("bpf_prog_type")), f("aux", BPFProgAux, ptr("bpf_prog_aux")),
	}})
	t.AddStruct(symbols.StructType{Name: "bpf_prog_aux", Size: bpfAuxSize, Fields: []symbols.Field{
		f("id", BPFAuxID, u32), f("name", BPFAuxName, array("char", bpfObjNameLen)),
	}})
	t.AddStruct(symbols.StructType{Name: "nf_hook_entry", Size: NFHookEntrySize, Fields: []symbols.Field{
		f("hook", 0, voidPtr()), f("priv", 8, voidPtr()),
	}})
	t.AddStruct(symbols.StructType{Name: "nf_hook_entries", Size: NFHookEntriesHook, Fields: []symbols.Field{
		f("num_hook_entries", 0, u16),
		f("hooks", NFHookEntriesHook, symbols.TypeRef{Name: "nf_hook_entry", IsArray: true, Element: &symbols.TypeRef{Name: "nf_hook_entry"}}),
	}})
	t.AddStruct(symbols.StructType{Name: "nf_hook_ops", Size: NFHookOpsSize, Fields: []symbols.Field{
		f("list", NFHookOpsList, scalar("list_head")), f("hook", NFHookOpsHook, voidPtr()),
		f("priority", NFHookOpsPriority, scalar("int")),
	}})

	n := &Net{k: k}
	n.List = k.Alloc(16)
	k.Circle(n.List)
	t.AddSymbol(symbols.Symbol{Name: "net_namespace_list", Address: n.List, Type: "list_head"})
	n.SocketFileOps = k.Alloc(NetFileOpsSize)
	t.AddSymbol(symbols.Symbol{Name: "socket_file_ops", Address: n.SocketFileOps, Type: "file_operations"})
	t.AddSymbol(symbols.Symbol{Name: "sockfs_dentry_operations", Address: k.Alloc(dentOpsSize), Type: "dentry_operations"})
	n.OtherFileOps = k.Alloc(NetFileOpsSize)
	return n
}

// The enumerations S40 names values from: rt_scope_t (include/uapi/linux/
// rtnetlink.h), netdev_state_t (include/linux/netdevice.h), the IFF_ flags
// (include/uapi/linux/if.h), bpf_prog_type (include/uapi/linux/bpf.h) and
// the xdp_sock state (include/net/xdp_sock.h), all v6.17.
func declareNetEnums(t *symbols.Table) {
	enum := func(name string, values ...symbols.EnumValue) {
		t.AddEnum(symbols.EnumType{Name: name, Size: 4, Values: values})
	}
	ev := func(name string, v int64) symbols.EnumValue { return symbols.EnumValue{Name: name, Value: v} }
	enum("rt_scope_t", ev("RT_SCOPE_UNIVERSE", 0), ev("RT_SCOPE_SITE", 200), ev("RT_SCOPE_LINK", 253),
		ev("RT_SCOPE_HOST", 254), ev("RT_SCOPE_NOWHERE", 255))
	var states []symbols.EnumValue
	for n, name := range []string{"__LINK_STATE_START", "__LINK_STATE_PRESENT", "__LINK_STATE_NOCARRIER",
		"__LINK_STATE_LINKWATCH_PENDING", "__LINK_STATE_DORMANT", "__LINK_STATE_TESTING"} {
		states = append(states, ev(name, int64(n)))
	}
	enum("netdev_state_t", states...)
	var flags []symbols.EnumValue
	for bit, name := range []string{"IFF_UP", "IFF_BROADCAST", "IFF_DEBUG", "IFF_LOOPBACK", "IFF_POINTOPOINT",
		"IFF_NOTRAILERS", "IFF_RUNNING", "IFF_NOARP", "IFF_PROMISC", "IFF_ALLMULTI", "IFF_MASTER", "IFF_SLAVE",
		"IFF_MULTICAST", "IFF_PORTSEL", "IFF_AUTOMEDIA", "IFF_DYNAMIC", "IFF_LOWER_UP", "IFF_DORMANT", "IFF_ECHO"} {
		flags = append(flags, ev(name, 1<<bit))
	}
	enum("net_device_flags", flags...)
	enum("bpf_prog_type", ev("BPF_PROG_TYPE_UNSPEC", 0), ev("BPF_PROG_TYPE_SOCKET_FILTER", 1),
		ev("BPF_PROG_TYPE_KPROBE", 2))
	enum("xsk_state", ev("XSK_READY", 0), ev("XSK_BOUND", 1), ev("XSK_UNBOUND", 2))
}

// AddNamespace lays out a network namespace with no devices and puts it at
// the tail of net_namespace_list.
func (n *Net) AddNamespace(inum uint32) uint64 {
	k := n.k
	net := k.Alloc(NetSize)
	k.Mem.U32(net+NetNs+NsCommonInum, inum)
	k.Circle(net + NetDevBaseHead)
	n.nets = append(n.nets, net)
	heads := []uint64{n.List}
	for _, m := range n.nets {
		heads = append(heads, m+NetList)
	}
	k.Circle(heads...)
	return net
}

type Device struct {
	Name              string
	Ifindex           int32
	Flags             uint32
	GFlags            uint16
	Operstate         uint8
	MTU               uint32
	TxQueueLen        uint32
	State             uint64
	PermAddr, DevAddr []byte
	Qdisc             string
}

// AddDevices puts the devices on net's dev_base_head in order; addr_len is
// the longer of the two addresses, and a nil DevAddr leaves dev_addr null.
func (n *Net) AddDevices(net uint64, devs ...Device) []uint64 {
	k := n.k
	heads := []uint64{net + NetDevBaseHead}
	var out []uint64
	for _, d := range devs {
		a := k.Alloc(DevSize)
		name := make([]byte, ifNameSize)
		copy(name, d.Name)
		k.Mem.Write(a+DevName, name)
		k.Mem.U32(a+DevIfindex, uint32(d.Ifindex))
		k.Mem.U32(a+DevFlags, d.Flags)
		k.Mem.u16(a+DevGFlags, d.GFlags)
		k.Mem.U32(a+DevOperstate, uint32(d.Operstate))
		k.Mem.Write(a+DevAddrLen, []byte{byte(max(len(d.PermAddr), len(d.DevAddr)))})
		k.Mem.U32(a+DevMTU, d.MTU)
		k.Mem.U64(a+DevState, d.State)
		k.Mem.Write(a+DevPermAddr, d.PermAddr)
		if d.DevAddr != nil {
			b := k.Alloc(uint64(len(d.DevAddr)))
			k.Mem.Write(b, d.DevAddr)
			k.Mem.U64(a+DevDevAddr, b)
		}
		k.Mem.U64(a+DevNdNet, net)
		k.Mem.U32(a+DevTxQueueLen, d.TxQueueLen)
		if d.Qdisc != "" {
			q, ops := k.Alloc(qdiscSize), k.Alloc(qdiscOpsSize)
			id := make([]byte, ifNameSize)
			copy(id, d.Qdisc)
			k.Mem.Write(ops+QdiscOpsID, id)
			k.Mem.U64(q+QdiscOps, ops)
			k.Mem.U64(a+DevQdisc, q)
		}
		heads = append(heads, a+DevList)
		out = append(out, a)
	}
	k.Circle(heads...)
	return out
}

type InAddr struct {
	Address          [4]byte
	PrefixLen, Scope uint8
}

// SetInAddrs gives the device an in_device whose ifa_list chains the
// addresses in order, each its own local address.
func (n *Net) SetInAddrs(dev uint64, addrs ...InAddr) uint64 {
	k := n.k
	in := k.Alloc(inDeviceSize)
	k.Mem.U64(dev+DevIPPtr, in)
	link := in + InDevIfaList
	for _, a := range addrs {
		ifa := k.Alloc(inIfaddrSize)
		k.Mem.Write(ifa+IfaAddress, a.Address[:])
		k.Mem.Write(ifa+IfaLocal, a.Address[:])
		k.Mem.Write(ifa+IfaPrefixLen, []byte{a.PrefixLen})
		k.Mem.Write(ifa+IfaScope, []byte{a.Scope})
		k.Mem.U64(link, ifa)
		link = ifa + IfaNext
	}
	return in
}

type Inet6Addr struct {
	Address   [16]byte
	PrefixLen uint32
	Scope     int32
}

// SetInet6Addrs gives the device an inet6_dev whose addr_list holds the
// addresses in order.
func (n *Net) SetInet6Addrs(dev uint64, addrs ...Inet6Addr) uint64 {
	k := n.k
	in := k.Alloc(inet6DevSize)
	k.Mem.U64(dev+DevIP6Ptr, in)
	heads := []uint64{in + In6DevAddrList}
	for _, a := range addrs {
		ifa := k.Alloc(inet6IfaSize)
		k.Mem.Write(ifa+If6Addr, a.Address[:])
		k.Mem.U32(ifa+If6PrefixLen, a.PrefixLen)
		k.Mem.u16(ifa+If6Scope, uint16(a.Scope))
		heads = append(heads, ifa+If6List)
	}
	k.Circle(heads...)
	return in
}

func (n *Net) SetTaskNetNS(task, net uint64) {
	n.k.Mem.U64(n.read64(task+TaskNsproxy)+NetNsproxyNetNS, net)
}

func (n *Net) read64(addr uint64) uint64 { return n.k.Mem.read64(addr) }

// SetFiles gives the task a descriptor table of slots entries holding files
// from descriptor 0, and returns its files_struct.
func (n *Net) SetFiles(task uint64, slots uint32, files ...uint64) uint64 {
	k := n.k
	fs, fdt := k.Alloc(FSFilesSize), k.Alloc(FSFdtSize)
	fd := k.Alloc(uint64(slots) * fdtableSlotWidth)
	for i, f := range files {
		k.Mem.U64(fd+uint64(i)*fdtableSlotWidth, f)
	}
	k.Mem.U32(fdt+NetFdtMaxFDs, slots)
	k.Mem.U64(fdt+NetFdtFD, fd)
	k.Mem.U64(fs+NetFilesFdt, fdt)
	k.Mem.U64(task+NetTaskFiles, fs)
	return fs
}

// ShareFiles points the task at another task's files_struct, as CLONE_FILES
// does.
func (n *Net) ShareFiles(task, fs uint64) { n.k.Mem.U64(task+NetTaskFiles, fs) }

func (n *Net) PlainFile() uint64 {
	f := n.k.Alloc(NetFileSize)
	n.k.Mem.U64(f+NetFileOp, n.OtherFileOps)
	return f
}

type Sock struct {
	Size        uint64
	Family      uint16
	Type        uint16
	Protocol    uint16
	State       uint8
	SocketState uint32
	Ino         uint64
}

// AddSock lays out a sock of s.Size bytes (SockSize when 0), its
// socket_alloc, and a socket file whose dentry names the socket inode; the
// file is not on any descriptor table.
func (n *Net) AddSock(s Sock) (sock, file uint64) {
	k := n.k
	size := s.Size
	if size == 0 {
		size = SockSize
	}
	sock = k.Alloc(size)
	alloc := k.Alloc(NetSocketAllocSize)
	k.Mem.U32(alloc+NetSocketState, s.SocketState)
	k.Mem.U64(alloc+NetSocketSk, sock)
	k.Mem.U64(alloc+NetSocketAllocInode+NetInodeIno, s.Ino)
	k.Mem.u16(sock+SkcFamily, s.Family)
	k.Mem.Write(sock+SkcState, []byte{s.State})
	k.Mem.u16(sock+SkProtocol, s.Protocol)
	k.Mem.u16(sock+SkType, s.Type)
	k.Mem.U64(sock+SkSocket, alloc)
	dentry := k.Alloc(NetDentrySize)
	k.Mem.U64(dentry+NetDentryInode, alloc+NetSocketAllocInode)
	file = k.Alloc(NetFileSize)
	k.Mem.U64(file+NetFilePath+NetPathDentry, dentry)
	k.Mem.U64(file+NetFileOp, n.SocketFileOps)
	return sock, file
}
