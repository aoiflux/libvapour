package network

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/tools"
)

type scanned struct {
	w    *world
	phys *testsupport.PagedMemory
	at   map[string]uint64
}

// One allocation per tag, each in its own page, and a TcpE allocation whose
// body is not a connection.
func buildScanned(t *testing.T) *scanned {
	w := newWorld(t)
	s := &scanned{w: w, phys: testsupport.NewPagedMemory(0x10000), at: map[string]uint64{}}
	owner := w.process(8, "svchost.exe")
	conn := w.defaultConn()
	conn.owner = owner
	bodies := []struct {
		name, tag string
		body      []byte
	}{
		{"TTcb", "TTcb", w.connectionBody(conn)},
		{"TcpL", "TcpL", w.boundBody(boundSpec{kind: KindListener, family: addressFamilyInet, port: 135, owner: owner, created: fxCreated})},
		{"UdpA", "UdpA", w.boundBody(boundSpec{kind: KindDatagram, family: addressFamilyInet6, port: 5353, owner: owner, created: fxCreated})},
		{"garbage", "TcpE", make([]byte, w.size(typeTCPEndpoint))},
	}
	for i, b := range bodies {
		header := uint64(i+1) * fxPage
		buf := make([]byte, testsupport.PoolHeaderSize+len(b.body))
		testsupport.WritePoolHeader(buf, 0, b.tag, testsupport.BlocksFor(uint64(len(buf))), testsupport.NonPagedPoolType)
		copy(buf[testsupport.PoolHeaderSize:], b.body)
		s.phys.WriteAt(header, buf)
		s.at[b.name] = header + testsupport.PoolHeaderSize
	}
	return s
}

func (s *scanned) ctx(options map[string]any) tools.Context {
	opts := map[string]any{tools.OptionPhysicalMemory: s.phys}
	for k, v := range options {
		opts[k] = v
	}
	return s.w.ctx(opts)
}

func TestTheScanFindsOneObjectPerTag(t *testing.T) {
	s := buildScanned(t)
	rows, err := Run(s.ctx(nil))
	if err != nil {
		t.Fatal(err)
	}
	byTag := map[string]Endpoint{}
	for _, e := range rows {
		byTag[e.PoolTag] = e
	}
	if len(rows) != 3 {
		t.Fatalf("%d rows: %+v", len(rows), rows)
	}
	for tag, kind := range map[string]EndpointKind{"TTcb": KindConnection, "TcpL": KindListener, "UdpA": KindDatagram} {
		e, ok := byTag[tag]
		if !ok || e.Kind != kind || e.ObjectPhysical != s.at[tag] || e.OwningPID != 8 || e.ObjectAddress != 0 {
			t.Errorf("%s: %+v", tag, e)
		}
	}
	if byTag["UdpA"].Family != FamilyIPv6 || byTag["TcpL"].LocalPort != 135 || byTag["TTcb"].RemotePort != 443 {
		t.Errorf("decoded %+v", byTag)
	}
	text := strings.Join(s.w.diags, "\n")
	if !strings.Contains(text, "4 pool tag hits, 4 passed the pool header checks, 3 rows, 1 failed the endpoint checks: 1 address family") {
		t.Errorf("diagnostics %s", text)
	}
}

func TestIncludeCorruptKeepsTheRejectedCandidate(t *testing.T) {
	s := buildScanned(t)
	rows, err := Run(s.ctx(map[string]any{OptionIncludeCorrupt: true}))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range rows {
		if e.ObjectPhysical == s.at["garbage"] {
			found = e.Rejected == ErrFamily.Error() && e.PoolTag == "TcpE"
		}
	}
	if len(rows) != 4 || !found {
		t.Errorf("rows %+v", rows)
	}
}

func TestTheScanNeedsPhysicalMemoryAndAnOptionOfTheRightType(t *testing.T) {
	s := buildScanned(t)
	if _, err := Run(s.w.ctx(nil)); !errors.Is(err, ErrObjectUnread) {
		t.Errorf("no physical memory: %v", err)
	}
	if _, err := Run(s.ctx(map[string]any{OptionIncludeCorrupt: 3.5})); err == nil {
		t.Errorf("a float option was accepted")
	}
}

func TestTheScanKeepsOnlyTheGivenPIDs(t *testing.T) {
	s := buildScanned(t)
	if rows, err := Run(s.ctx(map[string]any{"pid": uint64(12)})); err != nil || len(rows) != 0 {
		t.Errorf("pid 12: %d rows, %v", len(rows), err)
	}
}
