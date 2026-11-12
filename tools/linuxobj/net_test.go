package linuxobj_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const (
	iffUp        = 1 << 0
	iffBroadcast = 1 << 1
	iffLoopback  = 1 << 3
	iffRunning   = 1 << 6
	iffPromisc   = 1 << 8
	iffAllMulti  = 1 << 9
	iffMulticast = 1 << 12
	iffLowerUp   = 1 << 16
	iffDormant   = 1 << 17

	linkStart     = 1 << 0
	linkNoCarrier = 1 << 2
	linkDormant   = 1 << 4

	operDown = 2
	operUp   = 6
)

func netKernel(t *testing.T) (*lt.Kernel, *lt.Net) {
	t.Helper()
	k := lt.NewKernel(1700000000, 0)
	return k, lt.AddNetTypes(k)
}

func netReader(t *testing.T, k *lt.Kernel, l limits.Limits) *linuxobj.Kernel {
	t.Helper()
	ctx, _ := k.Context(nil)
	ctx.Limits = l
	return linuxobj.New(ctx)
}

func TestNamespacesAreListedInListOrderWithTheirInodes(t *testing.T) {
	k, n := netKernel(t)
	first, second := n.AddNamespace(4026531840), n.AddNamespace(4026532300)
	kern := netReader(t, k, limits.Limits{})
	l, err := kern.NetNamespaceList()
	if err != nil || l.Broken() || !slices.Equal(l.Entries, []uint64{first, second}) {
		t.Fatalf("namespaces %+v err %v, want %#x %#x", l, err, first, second)
	}
	for net, want := range map[uint64]uint64{first: 4026531840, second: 4026532300} {
		if got, err := kern.NetNamespaceInode(net); err != nil || got != want {
			t.Errorf("inode of %#x = %d, %v; want %d", net, got, err, want)
		}
	}
}

func TestTaskNamespaceIsItsNsproxyNetNS(t *testing.T) {
	k, n := netKernel(t)
	net := n.AddNamespace(4026531840)
	task := k.AddTask(lt.Task{PID: 7, TGID: 7, Comm: "sshd"})
	n.SetTaskNetNS(task, net)
	gone := k.AddTask(lt.Task{PID: 8, TGID: 8, Comm: "exiting"})
	k.Mem.U64(gone+lt.TaskNsproxy, 0)
	kern := netReader(t, k, limits.Limits{})
	if got, held, err := kern.NsproxyNetNS(linuxobj.Task{Addr: task}); err != nil || !held || got != net {
		t.Errorf("task namespace = %#x held %v err %v, want %#x", got, held, err, net)
	}
	if got, held, err := kern.NsproxyNetNS(linuxobj.Task{Addr: gone}); err != nil || held || got != 0 {
		t.Errorf("task without nsproxy = %#x held %v err %v, want none", got, held, err)
	}
}

func TestDeviceRecordHoldsTheReportedFields(t *testing.T) {
	k, n := netKernel(t)
	net := n.AddNamespace(4026531840)
	mac := []byte{0x52, 0x54, 0x00, 0xab, 0xcd, 0xef}
	devs := n.AddDevices(net,
		lt.Device{Name: "eth0", Ifindex: 2, Flags: iffUp | iffBroadcast | iffMulticast, Operstate: operUp,
			MTU: 1500, TxQueueLen: 1000, State: linkStart, PermAddr: []byte{2, 0, 0, 0, 0, 1}, DevAddr: mac,
			Qdisc: "fq_codel"},
		lt.Device{Name: "sit0", Ifindex: 3},
	)
	kern := netReader(t, k, limits.Limits{})
	l, err := kern.NamespaceDevices(net)
	if err != nil || l.Broken() || !slices.Equal(l.Entries, devs) {
		t.Fatalf("devices %+v err %v", l, err)
	}
	d, err := kern.ReadNetDevice(devs[0])
	if err != nil {
		t.Fatal(err)
	}
	want := linuxobj.NetDevice{Addr: devs[0], Name: "eth0", Index: 2, Net: net, NetNS: 4026531840, NetNSKnown: true,
		Flags: iffUp | iffBroadcast | iffMulticast, OperState: operUp, LinkState: linkStart, MTU: 1500,
		TxQueueLen: 1000, HardwareAddress: linuxobj.NetTextOf("52:54:00:ab:cd:ef"),
		PermanentAddress: linuxobj.NetTextOf("02:00:00:00:00:01"), Qdisc: linuxobj.NetTextOf("fq_codel")}
	if d != want {
		t.Errorf("eth0 =\n%+v\nwant\n%+v", d, want)
	}
	d, err = kern.ReadNetDevice(devs[1])
	if err != nil {
		t.Fatal(err)
	}
	if d.HardwareAddress != (linuxobj.NetText{}) || d.PermanentAddress != linuxobj.NetTextOf("") ||
		d.Qdisc != linuxobj.NetTextOf("") {
		t.Errorf("sit0: hardware %+v permanent %+v qdisc %+v; want absent, empty, empty",
			d.HardwareAddress, d.PermanentAddress, d.Qdisc)
	}
}

func TestDeviceAddressLengthOverTheKernelMaximumIsAbsent(t *testing.T) {
	k, n := netKernel(t)
	dev := n.AddDevices(n.AddNamespace(1), lt.Device{Name: "x", DevAddr: make([]byte, 6)})[0]
	k.Mem.Write(dev+lt.DevAddrLen, []byte{33})
	d, err := netReader(t, k, limits.Limits{}).ReadNetDevice(dev)
	if err != nil {
		t.Fatal(err)
	}
	if d.HardwareAddress.Available || d.PermanentAddress.Available {
		t.Errorf("addr_len 33: %+v %+v, want both absent", d.HardwareAddress, d.PermanentAddress)
	}
}

func TestDeviceWithoutNetNamespacesIsInInitNet(t *testing.T) {
	k, n := netKernel(t)
	net := n.AddNamespace(4026531840)
	dev := n.AddDevices(net, lt.Device{Name: "lo"})[0]
	k.Mem.U64(dev+lt.DevNdNet, 0)
	k.Table.AddStruct(symbols.StructType{Name: "possible_net_t", Size: 0})
	k.Table.AddSymbol(symbols.Symbol{Name: "init_net", Address: net, Type: "net"})
	d, err := netReader(t, k, limits.Limits{}).ReadNetDevice(dev)
	if err != nil || d.Net != net || !d.NetNSKnown || d.NetNS != 4026531840 {
		t.Errorf("device %+v err %v, want init_net %#x", d, err, net)
	}
}

func TestReportedFlagsFollowTheLinkState(t *testing.T) {
	for _, c := range []struct {
		name               string
		flags, gflags      uint64
		oper, state, wants uint64
	}{
		{"down device drops volatile bits", iffUp | iffRunning | iffLowerUp | iffPromisc, 0, operUp, 0, iffUp},
		{"running with carrier", iffUp | iffLoopback, 0, 0, linkStart, iffUp | iffLoopback | iffRunning | iffLowerUp},
		{"running without carrier", iffUp, 0, operDown, linkStart | linkNoCarrier, iffUp},
		{"dormant", iffUp, 0, operUp, linkStart | linkDormant, iffUp | iffRunning | iffLowerUp | iffDormant},
		{"user promiscuous", iffUp | iffPromisc, iffPromisc | iffAllMulti, operUp, 0,
			iffUp | iffPromisc | iffAllMulti},
	} {
		d := linuxobj.NetDevice{Flags: c.flags, GFlags: c.gflags, OperState: c.oper, LinkState: c.state}
		if got := d.ReportedFlags(); got != c.wants {
			t.Errorf("%s: %#x, want %#x", c.name, got, c.wants)
		}
	}
	if !(linuxobj.NetDevice{Flags: iffPromisc}).Promiscuous() || (linuxobj.NetDevice{GFlags: iffPromisc}).Promiscuous() {
		t.Error("Promiscuous does not follow the stored flag")
	}
}

func TestNameTables(t *testing.T) {
	if got := linuxobj.InterfaceFlagNames(iffUp | iffLoopback | iffLowerUp | 1<<20); !slices.Equal(got,
		[]string{"IFF_UP", "IFF_LOOPBACK", "IFF_LOWER_UP", "0x100000"}) {
		t.Errorf("flag names %q", got)
	}
	for v, want := range []string{"IF_OPER_UNKNOWN", "IF_OPER_NOTPRESENT", "IF_OPER_DOWN", "IF_OPER_LOWERLAYERDOWN",
		"IF_OPER_TESTING", "IF_OPER_DORMANT", "IF_OPER_UP"} {
		if got, ok := linuxobj.OperStateName(uint64(v)); !ok || got != want {
			t.Errorf("oper state %d = %q %v", v, got, ok)
		}
	}
	if _, ok := linuxobj.OperStateName(7); ok {
		t.Error("oper state 7 named")
	}
	for v, want := range map[uint64]string{0: "universe", 200: "site", 253: "link", 254: "host", 255: "nowhere",
		7: "scope=7"} {
		if got := linuxobj.RouteScopeName(v); got != want {
			t.Errorf("scope %d = %q, want %q", v, got, want)
		}
	}
	for v, want := range map[uint64]uint64{0: 0, linuxobj.IFAHost: 254, linuxobj.IFALink: 253,
		linuxobj.IFASite: 200, linuxobj.IFAHost | linuxobj.IFALink: 254, 0x0e: 0} {
		if got := linuxobj.IPv6RouteScope(v); got != want {
			t.Errorf("IPv6 scope %#x = %d, want %d", v, got, want)
		}
	}
}

func addressesOf(w linuxobj.AddressWalk) []string {
	var out []string
	for _, a := range w.Addresses {
		out = append(out, fmt.Sprintf("%s/%d %s", a.Address, a.PrefixLen, a.Scope))
	}
	return out
}

func TestIPv4AddressChain(t *testing.T) {
	k, n := netKernel(t)
	dev := n.AddDevices(n.AddNamespace(1), lt.Device{Name: "eth0"})[0]
	in := n.SetInAddrs(dev, lt.InAddr{Address: [4]byte{10, 0, 0, 5}, PrefixLen: 24},
		lt.InAddr{Address: [4]byte{127, 0, 0, 1}, PrefixLen: 8, Scope: 254},
		lt.InAddr{Address: [4]byte{192, 0, 2, 9}, PrefixLen: 32, Scope: 7})
	kern := netReader(t, k, limits.Limits{})
	w, err := kern.IPv4Addresses(in)
	if err != nil || w.Broken() || !slices.Equal(addressesOf(w),
		[]string{"10.0.0.5/24 universe", "127.0.0.1/8 host", "192.0.2.9/32 scope=7"}) {
		t.Fatalf("walk %+v err %v", w, err)
	}
	if w, err := kern.IPv4Addresses(0); err != nil || w.Broken() || len(w.Addresses) != 0 {
		t.Errorf("no in_device: %+v %v", w, err)
	}

	capped, err := netReader(t, k, limits.Limits{MaxListEntries: 2}).IPv4Addresses(in)
	if err != nil || capped.End != linuxwalk.Capped || len(capped.Addresses) != 2 {
		t.Errorf("at cap 2: %+v err %v", capped, err)
	}

	second := w.Addresses[1].Entry
	k.Mem.U64(second+lt.IfaNext, w.Addresses[0].Entry)
	loop, err := kern.IPv4Addresses(in)
	if err != nil || loop.End != linuxwalk.Revisited || len(loop.Addresses) != 2 {
		t.Errorf("cycle: %+v err %v", loop, err)
	}

	page := k.Alloc(0x2000)
	k.Mem.Unmap(page + 0x1000)
	k.Mem.U64(second+lt.IfaNext, page+0xff0)
	cut, err := kern.IPv4Addresses(in)
	if err != nil || cut.End != linuxwalk.EntryUnreadable || cut.At != page+0xff0 || len(cut.Addresses) != 2 {
		t.Errorf("unreadable entry: %+v err %v", cut, err)
	}
}

func TestIPv6AddressList(t *testing.T) {
	k, n := netKernel(t)
	dev := n.AddDevices(n.AddNamespace(1), lt.Device{Name: "eth0"})[0]
	in6 := n.SetInet6Addrs(dev,
		lt.Inet6Addr{Address: [16]byte{0: 0xfe, 1: 0x80, 15: 1}, PrefixLen: 64, Scope: linuxobj.IFALink},
		lt.Inet6Addr{Address: [16]byte{15: 1}, PrefixLen: 128, Scope: linuxobj.IFAHost},
		lt.Inet6Addr{Address: [16]byte{10: 0xff, 11: 0xff, 12: 192, 13: 0, 14: 2, 15: 1}, PrefixLen: 96},
		lt.Inet6Addr{Address: [16]byte{0: 0x20, 1: 0x01, 2: 0x0d, 3: 0xb8, 15: 1}, PrefixLen: 64})
	w, err := netReader(t, k, limits.Limits{}).IPv6Addresses(in6)
	if err != nil || w.Broken() || !slices.Equal(addressesOf(w), []string{"fe80::1/64 link", "::1/128 host",
		"::ffff:192.0.2.1/96 universe", "2001:db8::1/64 universe"}) {
		t.Errorf("walk %q end %v err %v", addressesOf(w), w.End, err)
	}
}

func TestAddressWalksReportATableWithoutTheirTypes(t *testing.T) {
	kern := netReader(t, lt.NewKernel(1700000000, 0), limits.Limits{})
	_, err4 := kern.IPv4Addresses(0x1000)
	_, err6 := kern.IPv6Addresses(0x1000)
	for _, err := range []error{err4, err6} {
		if !errors.Is(err, linuxobj.ErrNotInTable) || !linuxobj.TableGap(err) {
			t.Errorf("err %v, want a table gap", err)
		}
	}
}

func TestTableGap(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("linuxobj: pointer at 0x10: unmapped"), false},
		{fmt.Errorf("x: %w", symbols.UnknownTypeError{TypeName: "in_device"}), true},
		{fmt.Errorf("x: %w", symbols.UnknownFieldError{TypeName: "net", FieldName: "ns"}), true},
		{symbols.UnusableTypeError{TypeName: "net"}, true},
		{linuxobj.NotInTable("inet6_dev"), true},
		{fmt.Errorf("x: %w", linuxobj.ErrUnsupported), true},
	} {
		if got := linuxobj.TableGap(c.err); got != c.want {
			t.Errorf("TableGap(%v) = %v", c.err, got)
		}
	}
}

func TestHardwareAddressText(t *testing.T) {
	for in, want := range map[string]string{"": "", "\x00\x1a\x2B\xff": "00:1a:2b:ff",
		"\x52\x54\x00\x12\x34\x56": "52:54:00:12:34:56"} {
		if got := linuxobj.FormatHardwareAddress([]byte(in)); got != want {
			t.Errorf("% x = %q, want %q", in, got, want)
		}
	}
}
