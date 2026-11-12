package socketlist

import (
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

type Coverage string

const (
	CoverageFull       Coverage = "full"
	CoveragePartial    Coverage = "partial"
	CoverageNoType     Coverage = "no family type"
	CoverageNotDecoded Coverage = "family not decoded"
)

type Text = linuxobj.NetText

func text(s string) Text { return linuxobj.NetTextOf(s) }

type Decoded struct {
	Family        string
	Type          string
	Protocol      Text
	LocalAddress  Text
	LocalPort     Text
	RemoteAddress Text
	RemotePort    Text
	State         Text
	Filter        Text
	NetNS         uint64
	NetNSKnown    bool
	Coverage      Coverage
}

var ErrNoSockCommon = errors.New("socketlist: symbol table has no sock.__sk_common")

// Decoder reads struct sock objects. The sock's own members are read from the
// reader each call names, so a scan can pass physical memory; everything a
// pointer leads to is read from kernel space.
type Decoder struct {
	k       *linuxobj.Kernel
	mem     memory.MemoryReader
	common  uint64
	nets    map[uint64]netInfo
	initNet uint64

	Misses   map[string]int
	NoType   map[string]int
	Unnamed  map[string]int
	DevLists []string
}

type netInfo struct {
	inum    uint64
	known   bool
	devices map[int64]string
	listed  bool
}

func NewDecoder(k *linuxobj.Kernel) (*Decoder, error) {
	f, err := k.Member("sock", "__sk_common")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSockCommon, err)
	}
	d := &Decoder{k: k, mem: k.Memory(), common: f.Offset, nets: map[uint64]netInfo{},
		Misses: map[string]int{}, NoType: map[string]int{}, Unnamed: map[string]int{}}
	if s, err := k.Symbol("init_net"); err == nil {
		d.initNet = s.Address
	}
	return d, nil
}

type read struct {
	d    *Decoder
	in   memory.MemoryReader
	sk   uint64
	net  uint64
	lost bool
}

func (r *read) miss(what string) {
	r.d.Misses[what]++
	r.lost = true
}

func (r *read) uint(mem memory.MemoryReader, base uint64, typ, member string) (uint64, bool) {
	v, err := r.d.k.Uint(mem, base, typ, member)
	if err != nil {
		r.miss(typ + "." + member)
		return 0, false
	}
	return v, true
}

func (r *read) pointer(mem memory.MemoryReader, base uint64, typ, member string) (uint64, bool) {
	v, err := r.d.k.Pointer(mem, base, typ, member)
	if err != nil {
		r.miss(typ + "." + member)
		return 0, false
	}
	return v, true
}

func (r *read) bytes(mem memory.MemoryReader, base uint64, typ, member string, n uint64) ([]byte, bool) {
	f, err := r.d.k.Member(typ, member)
	if err != nil {
		r.miss(typ + "." + member)
		return nil, false
	}
	b, err := mem.ReadAt(base+f.Offset, n)
	if err != nil || uint64(len(b)) != n {
		r.miss(typ + "." + member)
		return nil, false
	}
	return b, true
}

func (r *read) common(member string) (uint64, bool) {
	return r.uint(r.in, r.sk+r.d.common, "sock_common", member)
}

func (r *read) commonBytes(member string, n uint64) ([]byte, bool) {
	return r.bytes(r.in, r.sk+r.d.common, "sock_common", member, n)
}

// container gives the start of a family's sock type, which holds struct sock
// as its member sk (S13 F4), or false when the table has no such type.
func (r *read) container(typ string) (uint64, bool) {
	f, err := r.d.k.Member(typ, "sk")
	if err != nil || r.sk < f.Offset {
		return 0, false
	}
	return r.sk - f.Offset, true
}

// Decode reads the sock at sk. Only the family, type and protocol are needed
// for a row; any other member that does not read leaves its field absent and
// the coverage partial.
func (d *Decoder) Decode(in memory.MemoryReader, sk uint64) (Decoded, error) {
	k := d.k
	family, err := k.Uint(in, sk+d.common, "sock_common", "skc_family")
	if err != nil {
		return Decoded{}, err
	}
	typ, err := k.Uint(in, sk, "sock", "sk_type")
	if err != nil {
		return Decoded{}, err
	}
	proto, err := k.Uint(in, sk, "sock", "sk_protocol")
	if err != nil {
		return Decoded{}, err
	}
	r := &read{d: d, in: in, sk: sk}
	out := Decoded{Family: FamilyName(family), Type: TypeName(typ), Coverage: CoverageFull}
	if net, ok := r.sockNet(); ok {
		r.net = net
		out.NetNS, out.NetNSKnown = r.d.netns(net)
		if !out.NetNSKnown {
			r.miss("net.ns.inum")
		}
	}
	out.Filter = r.filter()
	state, stateOK := r.common("skc_state")
	switch family {
	case afInet, afInet6:
		r.inet(&out, family, proto, state, stateOK)
	case afUnix:
		out.Protocol = text(strconv.FormatUint(proto, 10))
		r.unix(&out, state, stateOK)
	case afNetlink:
		r.netlink(&out, proto, state, stateOK)
	case afPacket:
		r.packet(&out)
	case afXDP:
		r.xdp(&out)
	case afVsock:
		r.vsock(&out, state, stateOK)
	case afBluetooth:
		out.Protocol = r.named(indexedName(btProtocolNames[:]), proto, "bluetooth protocol")
		if stateOK {
			out.State = r.named(indexedName(btStateNames[:]), state, "bluetooth state")
		}
	default:
		out.Coverage = CoverageNotDecoded
		out.Protocol = text(strconv.FormatUint(proto, 10))
		if stateOK {
			out.State = text(strconv.FormatUint(state, 10))
		}
	}
	if r.lost && out.Coverage == CoverageFull {
		out.Coverage = CoveragePartial
	}
	return out, nil
}

func indexedName(table []string) func(uint64) (string, bool) {
	return func(v uint64) (string, bool) { return indexed(table, v) }
}

func (r *read) named(lookup func(uint64) (string, bool), v uint64, what string) Text {
	s, ok := lookup(v)
	if !ok {
		r.d.Unnamed[what]++
	}
	return text(orNumber(s, ok, v))
}

func (r *read) tcpState(state uint64, ok bool) Text {
	if !ok {
		return Text{}
	}
	return r.named(indexedName(tcpStateNames[:]), state, "tcp state")
}

func (r *read) noType(out *Decoded, typ string) {
	r.d.NoType[out.Family+" ("+typ+")"]++
	out.Coverage = CoverageNoType
}

func (d *Decoder) netns(net uint64) (uint64, bool) {
	info := d.net(net)
	return info.inum, info.known
}

func (d *Decoder) net(net uint64) netInfo {
	if info, ok := d.nets[net]; ok {
		return info
	}
	var info netInfo
	if ns, err := d.k.Member("net", "ns"); err == nil {
		if v, err := d.k.Uint(d.mem, net+ns.Offset, "ns_common", "inum"); err == nil {
			info.inum, info.known = v, true
		}
	}
	d.nets[net] = info
	return info
}

// device names the net_device with an ifindex on a namespace's dev_base_head
// list (S13 P2); the list is walked once per namespace.
func (d *Decoder) device(net, ifindex uint64) (string, bool) {
	info := d.nets[net]
	if !info.listed {
		info.listed = true
		info.devices = map[int64]string{}
		d.listDevices(net, info.devices)
		d.nets[net] = info
	}
	name, ok := info.devices[int64(int32(ifindex))]
	return name, ok
}

func (d *Decoder) listDevices(net uint64, into map[int64]string) {
	k := d.k
	head, err := k.Member("net", "dev_base_head")
	if err != nil {
		d.DevLists = append(d.DevLists, fmt.Sprintf("net at %#x: %v", k.Masked(net), err))
		return
	}
	l, err := k.Walker().List(net+head.Offset, "net_device", "dev_list", linuxwalk.Forward)
	if err != nil {
		d.DevLists = append(d.DevLists, fmt.Sprintf("net at %#x: %v", k.Masked(net), err))
		return
	}
	if l.Broken() {
		d.DevLists = append(d.DevLists, fmt.Sprintf("net at %#x: the device list ends after %d devices at %#x: %s",
			k.Masked(net), len(l.Entries), l.At, l.End))
	}
	for _, dev := range l.Entries {
		idx, err := k.Int(d.mem, dev, "net_device", "ifindex")
		if err != nil {
			continue
		}
		name, err := k.CharArray(d.mem, dev, "net_device", "name")
		if err != nil {
			continue
		}
		into[idx] = name
	}
}

// filter describes the program on sk_filter (S13 B1-B4): a classic filter
// keeps its original program, an eBPF one has an id and a name.
func (r *read) filter() Text {
	d := r.d
	if !d.k.Has("sock", "sk_filter") {
		return Text{}
	}
	f, ok := r.pointer(r.in, r.sk, "sock", "sk_filter")
	if !ok {
		return Text{}
	}
	if f == 0 {
		return text("")
	}
	prog, ok := r.pointer(d.mem, f, "sk_filter", "prog")
	if !ok || prog == 0 {
		r.miss("sk_filter.prog")
		return Text{}
	}
	if orig, ok := r.pointer(d.mem, prog, "bpf_prog", "orig_prog"); ok && orig != 0 {
		n, ok := r.uint(d.mem, orig, "sock_fprog_kern", "len")
		if !ok {
			return Text{}
		}
		return text("classic len=" + strconv.FormatUint(n, 10))
	} else if !ok {
		return Text{}
	}
	aux, ok := r.pointer(d.mem, prog, "bpf_prog", "aux")
	if !ok || aux == 0 {
		r.miss("bpf_prog.aux")
		return Text{}
	}
	id, ok := r.uint(d.mem, aux, "bpf_prog_aux", "id")
	if !ok {
		return Text{}
	}
	s := "ebpf id=" + strconv.FormatUint(id, 10)
	if d.k.Has("bpf_prog_aux", "name") {
		name, err := d.k.CharArray(d.mem, aux, "bpf_prog_aux", "name")
		if err != nil {
			r.miss("bpf_prog_aux.name")
			return Text{}
		}
		if name != "" {
			s += " name=" + name
		}
	}
	return text(s)
}

func (r *read) inet(out *Decoded, family, proto, state uint64, stateOK bool) {
	out.Protocol = r.named(func(v uint64) (string, bool) { return keyed(ipProtocolNames, v) }, proto, "ip protocol")
	out.State = r.tcpState(state, stateOK)
	in, ok := r.container("inet_sock")
	if !ok {
		r.noType(out, "inet_sock")
		return
	}
	if b, ok := r.bytes(r.in, in, "inet_sock", "inet_sport", 2); ok {
		p, _ := Port(b)
		out.LocalPort = text(strconv.FormatUint(uint64(p), 10))
	}
	if b, ok := r.commonBytes("skc_dport", 2); ok {
		p, _ := Port(b)
		out.RemotePort = text(strconv.FormatUint(uint64(p), 10))
	}
	local, remote, size, render := "skc_rcv_saddr", "skc_daddr", uint64(4), IPv4
	if family == afInet6 {
		local, remote, size, render = "skc_v6_rcv_saddr", "skc_v6_daddr", 16, IPv6
	}
	if b, ok := r.commonBytes(local, size); ok {
		s, _ := render(b)
		out.LocalAddress = text(s)
	}
	if b, ok := r.commonBytes(remote, size); ok {
		s, _ := render(b)
		out.RemoteAddress = text(s)
	}
}

func (r *read) unix(out *Decoded, state uint64, stateOK bool) {
	out.State = r.tcpState(state, stateOK)
	u, ok := r.container("unix_sock")
	if !ok {
		r.noType(out, "unix_sock")
		return
	}
	if addr, ok := r.pointer(r.in, u, "unix_sock", "addr"); ok {
		out.LocalAddress = r.unixAddress(addr)
	}
	peer, ok := r.pointer(r.in, u, "unix_sock", "peer")
	if !ok {
		return
	}
	if peer == 0 {
		out.RemoteAddress = text("")
		return
	}
	pu := peer
	if f, err := r.d.k.Member("unix_sock", "sk"); err == nil && peer >= f.Offset {
		pu = peer - f.Offset
	}
	if addr, ok := r.pointer(r.d.mem, pu, "unix_sock", "addr"); ok {
		out.RemoteAddress = r.unixAddress(addr)
	}
}

func (r *read) unixAddress(addr uint64) Text {
	if addr == 0 {
		return text("")
	}
	d := r.d
	length, err := d.k.Int(d.mem, addr, "unix_address", "len")
	if err != nil {
		r.miss("unix_address.len")
		return Text{}
	}
	name, err := d.k.Member("unix_address", "name")
	if err != nil {
		r.miss("unix_address.name")
		return Text{}
	}
	path, err := d.k.Member("sockaddr_un", "sun_path")
	if err != nil {
		r.miss("sockaddr_un.sun_path")
		return Text{}
	}
	n := length - int64(path.Offset)
	if n < 1 || n > sunPathMax+1 {
		r.miss("unix_address.len")
		return Text{}
	}
	b, err := d.mem.ReadAt(addr+name.Offset+path.Offset, uint64(n))
	if err != nil {
		r.miss("sockaddr_un.sun_path")
		return Text{}
	}
	s, err := UnixPath(n, b)
	if err != nil {
		r.miss("unix_address.len")
		return Text{}
	}
	return text(s)
}

func (r *read) netlink(out *Decoded, proto, state uint64, stateOK bool) {
	out.Protocol = r.named(func(v uint64) (string, bool) { return keyed(netlinkProtocolNames, v) }, proto,
		"netlink protocol")
	if stateOK {
		out.State = r.named(indexedName(netlinkStateNames[:]), state, "netlink state")
	}
	n, ok := r.container("netlink_sock")
	if !ok {
		r.noType(out, "netlink_sock")
		return
	}
	if v, ok := r.uint(r.in, n, "netlink_sock", "portid"); ok {
		out.LocalPort = text(strconv.FormatUint(v, 10))
	}
	if v, ok := r.uint(r.in, n, "netlink_sock", "dst_portid"); ok {
		out.RemotePort = text(strconv.FormatUint(v, 10))
	}
	if v, ok := r.uint(r.in, n, "netlink_sock", "dst_group"); ok {
		out.RemoteAddress = text(Hex32(NetlinkGroupMask(v)))
	}
	groups, ok := r.pointer(r.in, n, "netlink_sock", "groups")
	if !ok {
		return
	}
	if groups == 0 {
		out.LocalAddress = text(Hex32(0))
		return
	}
	word, err := r.d.k.PointerAt(r.d.mem, groups)
	if err != nil {
		r.miss("netlink_sock.groups")
		return
	}
	out.LocalAddress = text(Hex32(uint32(word)))
}

func (r *read) packet(out *Decoded) {
	p, ok := r.container("packet_sock")
	if !ok {
		r.noType(out, "packet_sock")
		return
	}
	if b, ok := r.bytes(r.in, p, "packet_sock", "num", 2); ok {
		v, _ := Port(b)
		out.Protocol = text(ethProtocol(v))
	}
	idx, err := r.d.k.Int(r.in, p, "packet_sock", "ifindex")
	if err != nil {
		r.miss("packet_sock.ifindex")
		return
	}
	out.LocalPort = text(strconv.FormatInt(idx, 10))
	if idx == 0 {
		out.LocalAddress = text("")
		return
	}
	if r.net == 0 {
		return
	}
	if name, ok := r.d.device(r.net, uint64(idx)); ok {
		out.LocalAddress = text(name)
	} else {
		r.miss("packet_sock.ifindex device")
	}
}

// sockNet is sock_net(): skc_net.net, or init_net when possible_net_t is
// empty because the kernel has no CONFIG_NET_NS (S13 F6).
func (r *read) sockNet() (uint64, bool) {
	d := r.d
	pnet, err := d.k.Member("sock_common", "skc_net")
	if err != nil {
		r.miss("sock_common.skc_net")
		return 0, false
	}
	if !d.k.Has(pnet.Type.Name, "net") {
		return d.initNet, d.initNet != 0
	}
	net, ok := r.pointer(r.in, r.sk+d.common+pnet.Offset, pnet.Type.Name, "net")
	if ok && net == 0 {
		r.miss("possible_net_t.net")
	}
	return net, ok && net != 0
}

func (r *read) xdp(out *Decoded) {
	x, ok := r.container("xdp_sock")
	if !ok {
		r.noType(out, "xdp_sock")
		return
	}
	if dev, ok := r.pointer(r.in, x, "xdp_sock", "dev"); ok {
		if dev == 0 {
			out.LocalAddress = text("")
		} else if name, err := r.d.k.CharArray(r.d.mem, dev, "net_device", "name"); err == nil {
			out.LocalAddress = text(name)
		} else {
			r.miss("net_device.name")
		}
	}
	if v, ok := r.uint(r.in, x, "xdp_sock", "queue_id"); ok {
		out.LocalPort = text(strconv.FormatUint(v, 10))
	}
	if r.d.k.Has("xdp_sock", "state") {
		if v, ok := r.uint(r.in, x, "xdp_sock", "state"); ok {
			out.State = r.named(indexedName(xskStateNames[:]), v, "xdp state")
		}
	}
}

func (r *read) vsock(out *Decoded, state uint64, stateOK bool) {
	out.State = r.tcpState(state, stateOK)
	v, ok := r.container("vsock_sock")
	if !ok {
		r.noType(out, "vsock_sock")
		return
	}
	end := func(member string) (Text, Text) {
		f, err := r.d.k.Member("vsock_sock", member)
		if err != nil {
			r.miss("vsock_sock." + member)
			return Text{}, Text{}
		}
		cid, ok1 := r.uint(r.in, v+f.Offset, "sockaddr_vm", "svm_cid")
		port, ok2 := r.uint(r.in, v+f.Offset, "sockaddr_vm", "svm_port")
		var a, p Text
		if ok1 {
			a = text(VsockWord(cid, "VMADDR_CID_ANY"))
		}
		if ok2 {
			p = text(VsockWord(port, "VMADDR_PORT_ANY"))
		}
		return a, p
	}
	out.LocalAddress, out.LocalPort = end("local_addr")
	out.RemoteAddress, out.RemotePort = end("remote_addr")
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// Report gives one diagnostic per kind of loss, with its count.
func (d *Decoder) Report(diag func(format string, args ...any), tool string) {
	for _, what := range sortedKeys(d.Misses) {
		diag("%s: %d sockets: %s does not read", tool, d.Misses[what], what)
	}
	for _, what := range sortedKeys(d.NoType) {
		diag("%s: %d sockets of %s: the symbol table has no such type, so only the common fields are given",
			tool, d.NoType[what], what)
	}
	for _, what := range sortedKeys(d.Unnamed) {
		diag("%s: %d sockets have a %s with no name in the sources; it is given as a number", tool, d.Unnamed[what], what)
	}
	for _, l := range d.DevLists {
		diag("%s: %s", tool, l)
	}
}

func (d *Decoder) Lossy() bool { return len(d.Misses) > 0 || len(d.DevLists) > 0 }
