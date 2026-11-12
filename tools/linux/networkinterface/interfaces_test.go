package networkinterface

import (
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	hostNS        = 4026531840
	otherNS       = 4026532000
	iffUp         = 0x1
	iffBroadcast  = 0x2
	iffLoopback   = 0x8
	iffPromisc    = 0x100
	iffMulticast  = 0x1000
	linkStart     = 1 << 0
	linkNoCarrier = 1 << 2
)

func text(s string) linuxobj.NetText { return linuxobj.NetTextOf(s) }

type fixture struct {
	k    *lt.Kernel
	n    *lt.Net
	devs []uint64
}

func newFixture() *fixture {
	k := lt.NewKernel(1700000000, 0)
	n := lt.AddNetTypes(k)
	host := n.AddNamespace(hostNS)
	devs := n.AddDevices(host,
		lt.Device{Name: "lo", Ifindex: 1, Flags: iffUp | iffLoopback, Operstate: 0, MTU: 65536,
			TxQueueLen: 1000, State: linkStart, DevAddr: make([]byte, 6), Qdisc: "noqueue"},
		lt.Device{Name: "eth0", Ifindex: 2, Flags: iffUp | iffBroadcast | iffMulticast | iffPromisc,
			Operstate: 6, MTU: 1500, TxQueueLen: 1000, State: linkStart,
			PermAddr: []byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}, DevAddr: []byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x57},
			Qdisc: "fq_codel"},
		lt.Device{Name: "br0", Ifindex: 3, Flags: iffUp | iffBroadcast, Operstate: 2, MTU: 1500,
			State: linkStart | linkNoCarrier, DevAddr: []byte{2, 0, 0, 0, 0, 1}})
	n.SetInAddrs(devs[0], lt.InAddr{Address: [4]byte{127, 0, 0, 1}, PrefixLen: 8, Scope: 254})
	n.SetInet6Addrs(devs[0], lt.Inet6Addr{Address: [16]byte{15: 1}, PrefixLen: 128, Scope: linuxobj.IFAHost})
	n.SetInAddrs(devs[1], lt.InAddr{Address: [4]byte{10, 0, 0, 5}, PrefixLen: 24},
		lt.InAddr{Address: [4]byte{10, 0, 0, 6}, PrefixLen: 24, Scope: 7})
	n.SetInet6Addrs(devs[1], lt.Inet6Addr{Address: [16]byte{0: 0xfe, 1: 0x80, 15: 1}, PrefixLen: 64,
		Scope: linuxobj.IFALink})
	other := n.AddNamespace(otherNS)
	devs = append(devs, n.AddDevices(other, lt.Device{Name: "veth0", Ifindex: 4, Flags: iffUp, Operstate: 9,
		MTU: 1500, DevAddr: make([]byte, 6)})...)
	return &fixture{k: k, n: n, devs: devs}
}

func TestRunLinkReportsTheKernelsViewOfEachDevice(t *testing.T) {
	f := newFixture()
	ctx, diags := f.k.Context(nil)
	rows, err := RunLink(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []Link{
		{NetNS: hostNS, NetNSKnown: true, Index: 1, Interface: "lo", HardwareAddress: "00:00:00:00:00:00",
			OperState: text("UNKNOWN"), MTU: 65536, Qdisc: text("noqueue"), TxQueueLength: 1000,
			Flags: "UP,LOOPBACK,RUNNING,LOWER_UP"},
		{NetNS: hostNS, NetNSKnown: true, Index: 2, Interface: "eth0", HardwareAddress: "52:54:00:12:34:57",
			OperState: text("UP"), MTU: 1500, Qdisc: text("fq_codel"), TxQueueLength: 1000,
			Flags: "UP,BROADCAST,RUNNING,MULTICAST,LOWER_UP"},
		{NetNS: hostNS, NetNSKnown: true, Index: 3, Interface: "br0", HardwareAddress: "02:00:00:00:00:01",
			OperState: text("DOWN"), MTU: 1500, Qdisc: text(""), Flags: "UP,BROADCAST"},
		{NetNS: otherNS, NetNSKnown: true, Index: 4, Interface: "veth0", HardwareAddress: "00:00:00:00:00:00",
			MTU: 1500, Qdisc: text(""), Flags: "UP"},
	}
	if !slices.Equal(rows, want) {
		t.Errorf("got\n%+v\nwant\n%+v", rows, want)
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "1 devices hold an operational state with no IF_OPER_ name") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestRunAddrListsBothFamiliesOfEachDevice(t *testing.T) {
	f := newFixture()
	ctx, _ := f.k.Context(nil)
	rows, err := RunAddr(ctx)
	if err != nil {
		t.Fatal(err)
	}
	type got struct {
		dev, addr, scope string
		fam              Family
		prefix           uint64
		promisc          bool
	}
	var have []got
	for _, r := range rows {
		have = append(have, got{r.Interface, r.Address, r.Scope, r.Family, r.PrefixLength, r.Promiscuous})
	}
	want := []got{
		{"lo", "127.0.0.1", "host", FamilyIPv4, 8, false},
		{"lo", "::1", "host", FamilyIPv6, 128, false},
		{"eth0", "10.0.0.5", "universe", FamilyIPv4, 24, true},
		{"eth0", "10.0.0.6", "scope=7", FamilyIPv4, 24, true},
		{"eth0", "fe80::1", "link", FamilyIPv6, 64, true},
	}
	if !slices.Equal(have, want) {
		t.Errorf("got\n%+v\nwant\n%+v", have, want)
	}
}

func TestADeviceWhoseAddressDoesNotReadIsCountedAndStrictFails(t *testing.T) {
	f := newFixture()
	f.k.Mem.U64(f.devs[1]+lt.DevDevAddr, 0xffff888077000000)
	ctx, diags := f.k.Context(nil)
	rows, err := RunLink(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Errorf("rows %+v", rows)
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "does not read") {
		t.Errorf("diagnostics %q", *diags)
	}
	ctx, _ = f.k.Context(map[string]any{"strict": true})
	if _, err := RunAddr(ctx); err == nil || !strings.Contains(err.Error(), "strict mode") {
		t.Errorf("strict: %v", err)
	}
}

func TestAnIPv4WalkThatEndsEarlyKeepsTheIPv6Walk(t *testing.T) {
	f := newFixture()
	in, err := f.k.Mem.ReadAt(f.devs[1]+lt.DevIPPtr, 8)
	if err != nil {
		t.Fatal(err)
	}
	inDev := uint64(0)
	for i := 7; i >= 0; i-- {
		inDev = inDev<<8 | uint64(in[i])
	}
	f.k.Mem.U64(inDev+lt.InDevIfaList, 0xffff888077000000)
	ctx, diags := f.k.Context(nil)
	rows, err := RunAddr(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var eth []string
	for _, r := range rows {
		if r.Interface == "eth0" {
			eth = append(eth, r.Address)
		}
	}
	if !slices.Equal(eth, []string{"fe80::1"}) {
		t.Errorf("eth0 addresses %v, diagnostics %q", eth, *diags)
	}
}

func TestAKernelWithoutIPv6StillListsIPv4(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	n := lt.AddNetTypes(k)
	host := n.AddNamespace(hostNS)
	devs := n.AddDevices(host, lt.Device{Name: "lo", Ifindex: 1, DevAddr: make([]byte, 6)})
	n.SetInAddrs(devs[0], lt.InAddr{Address: [4]byte{127, 0, 0, 1}, PrefixLen: 8, Scope: 254})
	k.Mem.U64(devs[0]+lt.DevIP6Ptr, k.Alloc(0x40))
	ctx, diags := k.Context(nil)
	ctx.Symbols = withoutType{k.Table, "inet6_ifaddr"}
	rows, err := RunAddr(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Family != FamilyIPv4 {
		t.Errorf("rows %+v", rows)
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "IPv6 addresses are not listed") {
		t.Errorf("diagnostics %q", *diags)
	}
}

type withoutType struct {
	*symbols.Table
	hidden string
}

func (w withoutType) Struct(name string) (symbols.StructType, error) {
	if name == w.hidden {
		return symbols.StructType{}, symbols.UnknownTypeError{TypeName: name}
	}
	return w.Table.Struct(name)
}

func (w withoutType) Field(typ, member string) (symbols.Field, error) {
	if typ == w.hidden {
		return symbols.Field{}, symbols.UnknownTypeError{TypeName: typ}
	}
	return w.Table.Field(typ, member)
}
