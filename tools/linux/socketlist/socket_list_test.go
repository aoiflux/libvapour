package socketlist

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools"
)

func absent() Text { return Text{} }

type world struct {
	f                                              *fixture
	tcp, tcp6, path, abstract, client, nl, pkt, xs made
	vs, bt, can                                    made
}

// One process holding a socket of every decoded family, plus one the tool
// does not decode, on the namespace given to each.
func newWorld(t *testing.T, l layout) world {
	t.Helper()
	f := newFixture(l)
	m := f.k.Mem
	w := world{f: f}

	w.tcp = f.sock(spec{family: afInet, typ: 1, proto: 6, state: 10})
	m.Write(w.tcp.sk+skcRcvSaddr, []byte{0, 0, 0, 0})
	f.be16(w.tcp.sk+inetSport, 22)

	w.tcp6 = f.sock(spec{family: afInet6, typ: 1, proto: 6, state: 1})
	m.Write(w.tcp6.sk+skcV6Saddr, []byte{0xfe, 0x80, 15: 1})
	m.Write(w.tcp6.sk+skcV6Daddr, []byte{0x20, 0x01, 0x0d, 0xb8, 15: 2})
	f.be16(w.tcp6.sk+inetSport, 40000)
	f.be16(w.tcp6.sk+skcDport, 443)

	w.path = f.sock(spec{family: afUnix, typ: 1, state: 10})
	f.unixName(w.path.sk, []byte("/run/a.sock\x00"))
	w.abstract = f.sock(spec{family: afUnix, typ: 2, state: 7})
	f.unixName(w.abstract.sk, []byte("\x00x\x00y"))
	w.client = f.sock(spec{family: afUnix, typ: 1, state: 1})
	m.U64(w.client.sk+unixPeer, w.path.sk)

	w.nl = f.sock(spec{family: afNetlink, typ: 3, proto: 15, state: 1})
	m.U32(w.nl.sk+nlPortid, 812)
	m.U32(w.nl.sk+nlDstGroup, 3)
	groups := f.k.Alloc(8)
	m.U64(groups, 0x5)
	m.U64(w.nl.sk+nlGroups, groups)

	devs := f.devices(f.initNet, "lo", "eth0")
	w.pkt = f.sock(spec{family: afPacket, typ: 3})
	m.U32(w.pkt.sk+pktIfindex, 2)
	f.be16(w.pkt.sk+pktNum, 0x0003)

	w.xs = f.sock(spec{family: afXDP, typ: 3, net: f.netB})
	m.U64(w.xs.sk+xdpDev, devs[1])
	f.u16(w.xs.sk+xdpQueue, 4)
	m.U32(w.xs.sk+xdpState, 1)

	w.vs = f.sock(spec{family: afVsock, typ: 1, state: 10})
	m.U32(w.vs.sk+vsLocal+svmCid, 0xffffffff)
	m.U32(w.vs.sk+vsLocal+svmPort, 1024)

	w.bt = f.sock(spec{family: afBluetooth, typ: 5, proto: 3, state: 4})
	w.can = f.sock(spec{family: 29, typ: 3, proto: 1, state: 7})

	files := f.files(16, w.tcp.file, f.plainFile(), w.tcp6.file, w.path.file, w.abstract.file, w.client.file,
		w.nl.file, w.pkt.file, w.xs.file, w.vs.file, w.bt.file, w.can.file)
	f.tasks = append(f.tasks, f.task(100, 100, "sshd", files))
	f.link()
	return w
}

func run(t *testing.T, f *fixture, opts map[string]any) ([]Socket, []string) {
	t.Helper()
	ctx, diags := f.k.Context(opts)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return rows, *diags
}

const mask = 1<<48 - 1

func bySock(rows []Socket) map[uint64]Socket {
	out := map[uint64]Socket{}
	for _, r := range rows {
		out[r.Sock|^uint64(mask)] = r
	}
	return out
}

func TestEachFamilyDecodesItsAddresses(t *testing.T) {
	w := newWorld(t, layout{})
	rows, diags := run(t, w.f, nil)
	if len(rows) != 11 {
		t.Fatalf("%d rows, want 11: %+v\n%q", len(rows), rows, diags)
	}
	got := bySock(rows)
	want := map[uint64]Decoded{
		w.tcp.sk: {Family: "AF_INET", Type: "SOCK_STREAM", Protocol: text("IPPROTO_TCP"),
			LocalAddress: text("0.0.0.0"), LocalPort: text("22"), RemoteAddress: text("0.0.0.0"), RemotePort: text("0"),
			State: text("TCP_LISTEN")},
		w.tcp6.sk: {Family: "AF_INET6", Type: "SOCK_STREAM", Protocol: text("IPPROTO_TCP"),
			LocalAddress: text("fe80::1"), LocalPort: text("40000"), RemoteAddress: text("2001:db8::2"),
			RemotePort: text("443"), State: text("TCP_ESTABLISHED")},
		w.path.sk: {Family: "AF_UNIX", Type: "SOCK_STREAM", Protocol: text("0"), LocalAddress: text("/run/a.sock"),
			RemoteAddress: text(""), State: text("TCP_LISTEN")},
		w.abstract.sk: {Family: "AF_UNIX", Type: "SOCK_DGRAM", Protocol: text("0"), LocalAddress: text("@x@y"),
			RemoteAddress: text(""), State: text("TCP_CLOSE")},
		w.client.sk: {Family: "AF_UNIX", Type: "SOCK_STREAM", Protocol: text("0"), LocalAddress: text(""),
			RemoteAddress: text("/run/a.sock"), State: text("TCP_ESTABLISHED")},
		w.nl.sk: {Family: "AF_NETLINK", Type: "SOCK_RAW", Protocol: text("NETLINK_KOBJECT_UEVENT"),
			LocalAddress: text("0x00000005"), LocalPort: text("812"), RemoteAddress: text("0x00000004"),
			RemotePort: text("0"), State: text("NETLINK_CONNECTED")},
		w.pkt.sk: {Family: "AF_PACKET", Type: "SOCK_RAW", Protocol: text("ETH_P_ALL"), LocalAddress: text("eth0"),
			LocalPort: text("2")},
		w.xs.sk: {Family: "AF_XDP", Type: "SOCK_RAW", LocalAddress: text("eth0"), LocalPort: text("4"),
			State: text("XSK_BOUND")},
		w.vs.sk: {Family: "AF_VSOCK", Type: "SOCK_STREAM", LocalAddress: text("VMADDR_CID_ANY"),
			LocalPort: text("1024"), RemoteAddress: text("0"), RemotePort: text("0"), State: text("TCP_LISTEN")},
		w.bt.sk: {Family: "AF_BLUETOOTH", Type: "SOCK_SEQPACKET", Protocol: text("BTPROTO_RFCOMM"),
			State: text("BT_LISTEN")},
		w.can.sk: {Family: "AF_CAN", Type: "SOCK_RAW", Protocol: text("1"), State: text("7"),
			Coverage: CoverageNotDecoded},
	}
	for sk, d := range want {
		r, ok := got[sk]
		if !ok {
			t.Errorf("no row for the %s sock", d.Family)
			continue
		}
		if d.Coverage == "" {
			d.Coverage = CoverageFull
		}
		d.Filter = text("")
		d.NetNS, d.NetNSKnown = initInum, true
		if sk == w.xs.sk {
			d.NetNS = otherInum
		}
		if r.Decoded != d {
			t.Errorf("%s:\n got %+v\nwant %+v", d.Family, r.Decoded, d)
		}
		if r.PID != 100 || r.TID != 100 || r.Process != "sshd" || r.Inode == 0 {
			t.Errorf("%s: owner %d/%d %q inode %d", d.Family, r.PID, r.TID, r.Process, r.Inode)
		}
	}
	if fd := got[w.tcp6.sk].FD; fd != 2 {
		t.Errorf("the IPv6 socket is fd %d, want 2 (fd 1 is not a socket)", fd)
	}
	if len(diags) != 0 {
		t.Errorf("diags %q", diags)
	}
}

func TestAMissingFamilyTypeKeepsTheCommonFields(t *testing.T) {
	w := newWorld(t, layout{noVsock: true})
	rows, diags := run(t, w.f, nil)
	r := bySock(rows)[w.vs.sk]
	want := Decoded{Family: "AF_VSOCK", Type: "SOCK_STREAM", State: text("TCP_LISTEN"), Filter: text(""),
		NetNS: initInum, NetNSKnown: true, Coverage: CoverageNoType}
	if r.Decoded != want {
		t.Errorf("got %+v\nwant %+v", r.Decoded, want)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "AF_VSOCK (vsock_sock)") {
		t.Errorf("diags %q", diags)
	}
}

func TestWithoutNetNamespacesEverySockIsInInitNet(t *testing.T) {
	w := newWorld(t, layout{noNetNSType: true})
	rows, _ := run(t, w.f, nil)
	for _, r := range rows {
		if !r.NetNSKnown || r.NetNS != initInum {
			t.Errorf("%s: netns %d known %v", r.Family, r.NetNS, r.NetNSKnown)
		}
	}
}

func TestSharedTablesAreListedOncePerProcess(t *testing.T) {
	f := newFixture(layout{})
	s := f.sock(spec{family: afInet, typ: 1, proto: 6, state: 10})
	f.be16(s.sk+inetSport, 22)
	parent := f.files(4, s.file)
	child := f.files(4, nil...)
	f.k.Mem.U64(child, 0)
	childFD := f.k.Alloc(32)
	f.k.Mem.U64(childFD+24, s.file)
	fdt := f.k.Alloc(0x20)
	f.k.Mem.U32(fdt+fdtMax, 4)
	f.k.Mem.U64(fdt+fdtFD, childFD)
	f.k.Mem.U64(child+filesFdt, fdt)
	leader := f.task(200, 200, "sshd", parent)
	thread := f.task(201, 200, "sshd", parent)
	f.k.LinkThreads(leader, thread)
	forked := f.task(300, 300, "sshd", child)
	f.tasks = []uint64{leader, forked}
	f.link()
	rows, _ := run(t, f, nil)
	if len(rows) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	if rows[0].PID != 200 || rows[0].TID != 200 || rows[0].FD != 0 || rows[1].PID != 300 || rows[1].FD != 3 {
		t.Errorf("rows %+v", rows)
	}
	if rows[0].Sock != rows[1].Sock {
		t.Error("the forked descriptor is not the same sock")
	}
}

func TestALinkThatDoesNotLeadBackLeavesTheSocketOut(t *testing.T) {
	f := newFixture(layout{})
	good := f.sock(spec{family: afUnix, typ: 1, state: 7})
	stale := f.sock(spec{family: afUnix, typ: 1, state: 7})
	f.k.Mem.U64(stale.socket+socketFile, 0)
	orphan := f.sock(spec{family: afUnix, typ: 1, state: 7})
	f.k.Mem.U64(orphan.sk+skSocket, 0)
	f.tasks = []uint64{f.task(10, 10, "a", f.files(4, good.file, stale.file, orphan.file))}
	f.link()
	rows, diags := run(t, f, nil)
	if len(rows) != 1 || rows[0].Sock != good.sk&mask {
		t.Fatalf("rows %+v", rows)
	}
	all := strings.Join(diags, "\n")
	for _, want := range []string{"1 sockets whose file does not lead back", "1 socks whose sk_socket does not lead back"} {
		if !strings.Contains(all, want) {
			t.Errorf("no %q in %q", want, diags)
		}
	}
	ctx, _ := f.k.Context(map[string]any{"strict": true})
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "strict mode") {
		t.Errorf("strict mode: %v", err)
	}
}

func TestAnUnreadableMemberMakesThePartialCoverage(t *testing.T) {
	f := newFixture(layout{})
	s := f.sock(spec{family: afUnix, typ: 1, state: 10})
	f.k.Mem.U64(s.sk+unixAddr, 0xffff888077770000)
	f.tasks = []uint64{f.task(10, 10, "a", f.files(2, s.file))}
	f.link()
	rows, diags := run(t, f, nil)
	if len(rows) != 1 || rows[0].Coverage != CoveragePartial || rows[0].LocalAddress != absent() {
		t.Fatalf("rows %+v", rows)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "unix_address.len does not read") {
		t.Errorf("diags %q", diags)
	}
}

func TestFiltersNameTheirProgram(t *testing.T) {
	f := newFixture(layout{})
	m := f.k.Mem
	classic := f.sock(spec{family: afNetlink, typ: 3, state: 7})
	ebpf := f.sock(spec{family: afInet, typ: 2, proto: 17, state: 7})
	for i, s := range []made{classic, ebpf} {
		sf, prog := f.k.Alloc(0x20), f.k.Alloc(0x48)
		m.U64(s.sk+skFilter, sf)
		m.U64(sf+sfProg, prog)
		if i == 0 {
			orig := f.k.Alloc(0x10)
			f.u16(orig+fprogLen, 11)
			m.U64(prog+progOrig, orig)
			continue
		}
		aux := f.k.Alloc(0x40)
		m.U32(aux+auxID, 42)
		m.Write(aux+auxName, []byte("drop_all\x00"))
		m.U64(prog+progAux, aux)
	}
	f.tasks = []uint64{f.task(10, 10, "a", f.files(2, classic.file, ebpf.file))}
	f.link()
	rows, _ := run(t, f, nil)
	got := bySock(rows)
	if v := got[classic.sk].Filter; v != text("classic len=11") {
		t.Errorf("classic filter %+v", v)
	}
	if v := got[ebpf.sk].Filter; v != text("ebpf id=42 name=drop_all") {
		t.Errorf("ebpf filter %+v", v)
	}
	if got[classic.sk].State != text("TCP_CLOSE") {
		t.Errorf("an unconnected netlink sock's state is %+v", got[classic.sk].State)
	}
}

func TestTheNamespaceOptionKeepsOneNamespace(t *testing.T) {
	w := newWorld(t, layout{})
	rows, _ := run(t, w.f, map[string]any{OptionNetNS: uint64(otherInum)})
	if len(rows) != 1 || rows[0].Sock != w.xs.sk&mask {
		t.Errorf("rows %+v", rows)
	}
	ctx, _ := w.f.k.Context(map[string]any{OptionNetNS: "many"})
	if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("err %v, want ErrOptionType", err)
	}
}

func TestAValueWithNoNameStaysANumber(t *testing.T) {
	f := newFixture(layout{})
	s := f.sock(spec{family: afInet, typ: 9, proto: 200, state: 40})
	f.tasks = []uint64{f.task(10, 10, "a", f.files(1, s.file))}
	f.link()
	rows, diags := run(t, f, nil)
	if len(rows) != 1 || rows[0].Type != "SOCK 9" || rows[0].Protocol != text("200") || rows[0].State != text("40") {
		t.Fatalf("rows %+v", rows)
	}
	if rows[0].Coverage != CoverageFull {
		t.Errorf("coverage %q", rows[0].Coverage)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "tcp state with no name") {
		t.Errorf("diags %q", diags)
	}
}

func TestWithoutSocketFileOpsTheToolFails(t *testing.T) {
	f := newFixture(layout{noFileOps: true})
	ctx, _ := f.k.Context(nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoSocketFileOps) {
		t.Errorf("err %v", err)
	}
}

func TestFamilyAndTypeNamesFollowTheSources(t *testing.T) {
	for v, want := range map[uint64]string{0: "AF_UNSPEC", 12: "AF_DECnet", 44: "AF_XDP", 45: "AF_MCTP", 46: "AF 46"} {
		if got := FamilyName(v); got != want {
			t.Errorf("family %d: %q, want %q", v, got, want)
		}
	}
	for v, want := range map[uint64]string{1: "SOCK_STREAM", 10: "SOCK_PACKET", 7: "SOCK 7"} {
		if got := TypeName(v); got != want {
			t.Errorf("type %d: %q, want %q", v, got, want)
		}
	}
}
