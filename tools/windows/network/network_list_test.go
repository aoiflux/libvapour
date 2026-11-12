package network

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

type listed struct {
	w       *world
	g       tcpipGlobals
	conns   []uint64
	tcp     []uint64
	udp     []uint64
	held    uint64
	process uint64
}

// Two partitions, a TCP pool with a two-listener chain, a single listener and
// a port held by a connection, and a UDP pool with a chain of two.
func buildListed(t *testing.T) *listed {
	w := newWorld(t)
	f := &listed{w: w, process: w.process(8, "svchost.exe")}
	for i := range 3 {
		c := w.defaultConn()
		c.lport, c.owner = uint16(49700+i), f.process
		f.conns = append(f.conns, w.connection(c))
	}
	table, count := w.partitions([]map[int][]uint64{{3: {f.conns[0], f.conns[1]}}, {127: {f.conns[2]}}})
	listener := func(fam uint16, port uint16) uint64 {
		return w.bound(boundSpec{kind: KindListener, family: fam, port: port, owner: f.process, created: fxCreated})
	}
	f.tcp = []uint64{listener(addressFamilyInet, 135), listener(addressFamilyInet6, 135), listener(addressFamilyInet, 445)}
	f.held = w.connection(w.defaultConn())
	tcp := w.portPool(KindListener, map[uint16]portChain{
		135:   {flags: tcpListenerFlags, objects: f.tcp[:2]},
		445:   {flags: tcpListenerFlags, objects: f.tcp[2:]},
		49700: {flags: 1, objects: []uint64{f.held}},
	})
	datagram := func(fam uint16, port uint16) uint64 {
		return w.bound(boundSpec{kind: KindDatagram, family: fam, port: port, owner: f.process, created: fxCreated})
	}
	f.udp = []uint64{datagram(addressFamilyInet, 5353), datagram(addressFamilyInet6, 5353)}
	udp := w.portPool(KindDatagram, map[uint16]portChain{5353: {flags: 1, objects: f.udp}})
	f.g = tcpipGlobals{partitionTable: table, partitionCount: count,
		compartments: map[EndpointKind]uint64{KindListener: tcp, KindDatagram: udp}}
	return f
}

func (f *listed) run(t *testing.T, ctx tools.Context, include bool) []Endpoint {
	t.Helper()
	l, err := resolveLayout(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := listTables(ctx, l, f.g, include)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func addresses(rows []Endpoint) []uint64 {
	out := make([]uint64, len(rows))
	for i, e := range rows {
		out[i] = e.ObjectAddress
	}
	return out
}

func sameAddresses(got, want []uint64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestTheListWalksPartitionsAndPortPools(t *testing.T) {
	f := buildListed(t)
	rows := f.run(t, f.w.ctx(nil), false)
	want := append(append(append([]uint64{}, f.conns...), f.tcp...), f.udp...)
	if !sameAddresses(addresses(rows), want) {
		t.Fatalf("rows at %x, want %x", addresses(rows), want)
	}
	kinds := map[EndpointKind]int{}
	for _, e := range rows {
		kinds[e.Kind]++
		if e.OwningPID != 8 || e.Rejected != "" {
			t.Errorf("row %+v", e)
		}
	}
	if kinds[KindConnection] != 3 || kinds[KindListener] != 3 || kinds[KindDatagram] != 2 {
		t.Errorf("kinds %v", kinds)
	}
	if rows[3].LocalPort != 135 || rows[4].Family != FamilyIPv6 || rows[5].LocalPort != 445 {
		t.Errorf("listeners %+v %+v %+v", rows[3], rows[4], rows[5])
	}
	held := false
	for _, d := range f.w.diags {
		held = held || strings.Contains(d, "1 ports held by entries that are not listeners")
	}
	if !held {
		t.Errorf("the flag-1 entry was not counted: %q", f.w.diags)
	}
}

func TestABrokenBucketIsRecoveredAndReported(t *testing.T) {
	f := buildListed(t)
	link := f.w.off(typeTCPEndpoint, memberListEntry)
	f.w.k.u64(f.conns[1]+link+8, fxKernel+0x123450)
	rows := f.run(t, f.w.ctx(nil), false)
	got := map[uint64]bool{}
	for _, e := range rows {
		got[e.ObjectAddress] = true
	}
	for _, c := range f.conns {
		if !got[c] {
			t.Errorf("connection 0x%x lost; the recovering walk should reach it from the other side", c)
		}
	}
	text := strings.Join(f.w.diags, "\n")
	if !strings.Contains(text, "does not link back") {
		t.Errorf("no back-link diagnostic: %s", text)
	}
}

func TestAWalkShortOfNumEntriesIsReported(t *testing.T) {
	f := buildListed(t)
	table, _ := readPointer(f.w.k, f.g.partitionTable)
	hash, _ := readPointer(f.w.k, table+f.w.off(typePartition, memberEndpoints))
	f.w.k.u32(hash+0x14, 5)
	f.run(t, f.w.ctx(nil), false)
	if !strings.Contains(strings.Join(f.w.diags, "\n"), "walked 2 entries, NumEntries is 5") {
		t.Errorf("diagnostics %q", f.w.diags)
	}
}

func TestATableLargerThanMeasuredIsNotWalked(t *testing.T) {
	f := buildListed(t)
	table, _ := readPointer(f.w.k, f.g.partitionTable)
	hash, _ := readPointer(f.w.k, table+f.w.off(typePartition, memberEndpoints))
	f.w.k.u32(hash+8, 256)
	rows := f.run(t, f.w.ctx(nil), false)
	for _, e := range rows {
		if e.ObjectAddress == f.conns[0] {
			t.Errorf("a 256-bucket table was walked")
		}
	}
	if !strings.Contains(strings.Join(f.w.diags, "\n"), "TableSize 256 has no measured directory form") {
		t.Errorf("diagnostics %q", f.w.diags)
	}
	ctx := f.w.ctx(map[string]any{"strict": true})
	l, _ := resolveLayout(ctx)
	if _, err := listTables(ctx, l, f.g, false); !errors.Is(err, ErrNoTables) {
		t.Errorf("strict mode: got %v", err)
	}
}

func TestPartitionsPastMaxTableEntriesAreCut(t *testing.T) {
	f := buildListed(t)
	ctx := f.w.ctx(nil)
	ctx.Limits = limits.Limits{MaxTableEntries: 1}
	rows := f.run(t, ctx, false)
	for _, e := range rows {
		if e.ObjectAddress == f.conns[2] {
			t.Errorf("the second partition was read")
		}
	}
	if !strings.Contains(strings.Join(f.w.diags, "\n"), "more than MaxTableEntries 1") {
		t.Errorf("diagnostics %q", f.w.diags)
	}
}

func TestAPoolEndpointOnAnotherPortIsRejected(t *testing.T) {
	f := buildListed(t)
	port := f.w.off(typeTCPListener, memberLocalPort)
	f.w.k.write(f.tcp[2]+port, be16(446))
	rows := f.run(t, f.w.ctx(nil), false)
	for _, e := range rows {
		if e.ObjectAddress == f.tcp[2] {
			t.Errorf("listener on 446 listed under 445")
		}
	}
	if !strings.Contains(strings.Join(f.w.diags, "\n"), "1 local port is not the port the pool entry is for") {
		t.Errorf("diagnostics %q", f.w.diags)
	}
	rows = f.run(t, f.w.ctx(nil), true)
	found := false
	for _, e := range rows {
		if e.ObjectAddress == f.tcp[2] {
			found = e.Rejected == ErrBoundPort.Error()
		}
	}
	if !found {
		t.Errorf("include_corrupt did not keep the rejected listener")
	}
}

func TestAChainLoopEndsAtAnEndpointMetBefore(t *testing.T) {
	f := buildListed(t)
	next := f.w.off(typeUDPEndpoint, memberNext)
	f.w.k.u64(f.udp[1]+next, (f.udp[0]+next)|1)
	rows := f.run(t, f.w.ctx(nil), false)
	n := 0
	for _, e := range rows {
		if e.Kind == KindDatagram {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d UDP rows", n)
	}
}

func TestThePIDOptionFiltersRows(t *testing.T) {
	f := buildListed(t)
	rows := f.run(t, f.w.ctx(map[string]any{"pid": uint64(1236)}), false)
	if len(rows) != 0 {
		t.Errorf("pid 1236 kept %d rows of pid 8", len(rows))
	}
	if rows := f.run(t, f.w.ctx(map[string]any{"pid": uint64(8)}), false); len(rows) != 8 {
		t.Errorf("pid 8 kept %d rows", len(rows))
	}
}

func TestAnUnreadPortPoolIsADiagnostic(t *testing.T) {
	f := buildListed(t)
	f.g.compartments[KindDatagram] = fxKernel + 0x7000000
	rows := f.run(t, f.w.ctx(nil), false)
	for _, e := range rows {
		if e.Kind == KindDatagram {
			t.Errorf("UDP row from an unread pool")
		}
	}
	if !strings.Contains(strings.Join(f.w.diags, "\n"), "udp port pool") {
		t.Errorf("diagnostics %q", f.w.diags)
	}
}

func TestTheListRefusesWhatItCannotRead(t *testing.T) {
	w := newWorld(t)
	ctx := w.ctx(nil)
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := RunNetworkList(ctx); !errors.Is(err, ErrNotWindows) {
		t.Errorf("linux profile: %v", err)
	}
	ctx = w.ctx(nil)
	ctx.Symbols = symbols.NewTable("kernel", 8)
	if _, err := RunNetworkList(ctx); !errors.Is(err, ErrLayout) {
		t.Errorf("no layout: %v", err)
	}
	if _, err := Run(ctx); !errors.Is(err, ErrLayout) {
		t.Errorf("scan without layout: %v", err)
	}
	old, err := LayoutForBuild(14393)
	if err != nil {
		t.Fatal(err)
	}
	ctx = w.ctx(map[string]any{tools.OptionNetworkScanLayout: "tcpip-14393"})
	ctx.Symbols = old
	if _, err := RunNetworkList(ctx); !errors.Is(err, ErrNoTables) {
		t.Errorf("14393: %v", err)
	}
	if _, err := RunNetworkList(w.ctx(nil)); !errors.Is(err, ErrTcpipSymbols) {
		t.Errorf("no tcpip.sys: %v", err)
	}
	ctx = w.ctx(map[string]any{OptionNetworkListIncludeCorrupt: []int{1}})
	if _, err := RunNetworkList(ctx); err == nil {
		t.Errorf("a list option of the wrong type was accepted")
	}
}

func TestEndpointIPsAreValidOnEveryListedRow(t *testing.T) {
	f := buildListed(t)
	for _, e := range f.run(t, f.w.ctx(nil), false) {
		if !e.LocalIP.IsValid() || e.Kind == KindConnection && !e.RemoteIP.IsValid() || e.Kind != KindConnection && e.RemoteIP != (netip.Addr{}) {
			t.Errorf("addresses of %+v", e)
		}
	}
}
