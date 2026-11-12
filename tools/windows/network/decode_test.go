package network

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/util"
)

func TestAConnectionDecodesEveryMember(t *testing.T) {
	w := newWorld(t)
	c := w.defaultConn()
	at := w.connection(c)
	d := w.decoder(w.ctx(nil))
	e, err := d.connection(w.k, at)
	if err != nil {
		t.Fatal(err)
	}
	created, _ := util.FiletimeToTime(fxCreated)
	if e.Kind != KindConnection || e.Family != FamilyIPv4 || e.LocalIP != c.local || e.RemoteIP != c.remote ||
		e.LocalPort != 49700 || e.RemotePort != 443 || e.State != TCPStateEstablished || e.StateValue != 4 ||
		e.OwningPID != 1236 || e.OwnerImage != "chrome.exe" || e.OwnerAddress != c.owner || !e.CreateTime.Equal(created) {
		t.Errorf("decoded %+v", e)
	}
	if e.IPProblem != "" || e.OwnerProblem != "" || e.TimeProblem != "" {
		t.Errorf("problems on a clean connection: %+v", e)
	}
	if e.CreateTime.Location() != time.UTC {
		t.Errorf("creation time not in UTC: %v", e.CreateTime)
	}
}

func TestAnIPv6ConnectionReadsSixteenBytes(t *testing.T) {
	w := newWorld(t)
	c := w.defaultConn()
	c.local, c.remote = netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:db8::7")
	e, err := w.decoder(w.ctx(nil)).connection(w.k, w.connection(c))
	if err != nil || e.Family != FamilyIPv6 || e.LocalIP != c.local || e.RemoteIP != c.remote {
		t.Errorf("got %+v, %v", e, err)
	}
}

func TestTheStateIsTheTCPSTATEOrdinal(t *testing.T) {
	w := newWorld(t)
	for v, want := range tcpStates {
		c := w.defaultConn()
		c.state = uint32(v)
		e, err := w.decoder(w.ctx(nil)).connection(w.k, w.connection(c))
		if err != nil || e.State != want {
			t.Errorf("value %d: got %q, %v; want %q", v, e.State, err, want)
		}
	}
}

func TestTheSecondMeasuredOwnerOffsetIsTried(t *testing.T) {
	w := newWorld(t)
	c := w.defaultConn()
	c.ownerSlot = 1
	e, err := w.decoder(w.ctx(nil)).connection(w.k, w.connection(c))
	if err != nil || e.OwningPID != 1236 || e.OwnerProblem != "" {
		t.Errorf("got %+v, %v", e, err)
	}
}

func TestEachConnectionRuleRejects(t *testing.T) {
	w := newWorld(t)
	for _, tc := range []struct {
		name string
		edit func(*connSpec)
		want error
	}{
		{"family pointer in user space", func(c *connSpec) { c.family = 0x7ff000000000 }, ErrFamily},
		{"family pointer unmapped", func(c *connSpec) { c.family = fxKernel + 0x7000000 }, ErrFamily},
		{"family neither AF_INET nor AF_INET6", func(c *connSpec) { c.family = w.family(7) }, ErrFamily},
		{"state TCPSTATE_MAX", func(c *connSpec) { c.state = 11 }, ErrState},
		{"local port 0", func(c *connSpec) { c.lport = 0 }, ErrPort},
		{"remote port 0", func(c *connSpec) { c.rport = 0 }, ErrPort},
	} {
		c := w.defaultConn()
		tc.edit(&c)
		_, err := w.decoder(w.ctx(nil)).connection(w.k, w.connection(c))
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
	if _, err := w.decoder(w.ctx(nil)).connection(w.k, fxKernel+0x7000000); !errors.Is(err, ErrObjectUnread) {
		t.Errorf("unmapped object: got %v", err)
	}
}

func TestProblemsKeepTheRow(t *testing.T) {
	w := newWorld(t)
	for _, tc := range []struct {
		name  string
		edit  func(*connSpec)
		check func(Endpoint) bool
	}{
		{"address info in user space", func(c *connSpec) { c.info = 0x1000 },
			func(e Endpoint) bool { return e.IPProblem != "" && !e.LocalIP.IsValid() && !e.RemoteIP.IsValid() }},
		{"owner not a process", func(c *connSpec) { c.owner = w.alloc(fxProcessSize) },
			func(e Endpoint) bool { return e.OwnerProblem != "" && e.OwningPID == 0 && e.OwnerImage == "" }},
		{"owner in user space", func(c *connSpec) { c.owner = 0x400000 },
			func(e Endpoint) bool { return e.OwnerProblem != "" }},
		{"creation time 0", func(c *connSpec) { c.created = 0 },
			func(e Endpoint) bool { return e.TimeProblem == ErrTimeAbsent.Error() && e.CreateTime.IsZero() }},
		{"creation time before boot", func(c *connSpec) { c.created = fxBoot - 1 },
			func(e Endpoint) bool { return e.TimeProblem == ErrTimeWindow.Error() && e.CreateTime.IsZero() }},
		{"creation time past the capture", func(c *connSpec) { c.created = fxNow + 2*864_000_000_000 },
			func(e Endpoint) bool { return e.TimeProblem == ErrTimeWindow.Error() }},
	} {
		c := w.defaultConn()
		tc.edit(&c)
		e, err := w.decoder(w.ctx(nil)).connection(w.k, w.connection(c))
		if err != nil || !tc.check(e) {
			t.Errorf("%s: got %+v, %v", tc.name, e, err)
		}
	}
}

func TestABoundEndpointWithoutALocalAddressIsTheWildcard(t *testing.T) {
	w := newWorld(t)
	owner := w.process(4, "System")
	for _, tc := range []struct {
		spec boundSpec
		want netip.Addr
	}{
		{boundSpec{kind: KindListener, family: addressFamilyInet, port: 445, owner: owner, created: fxCreated}, netip.IPv4Unspecified()},
		{boundSpec{kind: KindListener, family: addressFamilyInet6, port: 445, owner: owner, created: fxCreated}, netip.IPv6Unspecified()},
		{boundSpec{kind: KindDatagram, family: addressFamilyInet, local: netip.MustParseAddr("172.25.0.9"), port: 137,
			owner: owner, created: fxCreated}, netip.MustParseAddr("172.25.0.9")},
	} {
		e, err := w.decoder(w.ctx(nil)).bound(w.k, tc.spec.kind, w.bound(tc.spec))
		if err != nil || e.LocalIP != tc.want || e.LocalPort != tc.spec.port || e.OwningPID != 4 || e.RemoteIP.IsValid() {
			t.Errorf("%+v: got %+v, %v", tc.spec, e, err)
		}
		wantState := TCPState("")
		if tc.spec.kind == KindListener {
			wantState = TCPStateListen
		}
		if e.State != wantState {
			t.Errorf("%s state %q", tc.spec.kind, e.State)
		}
	}
}

func TestBoundEndpointRules(t *testing.T) {
	w := newWorld(t)
	for _, tc := range []struct {
		spec boundSpec
		want error
	}{
		{boundSpec{kind: KindDatagram, family: 17, port: 53}, ErrFamily},
		{boundSpec{kind: KindDatagram, family: addressFamilyInet}, ErrPort},
		{boundSpec{kind: KindListener, family: addressFamilyInet6}, ErrPort},
	} {
		if _, err := w.decoder(w.ctx(nil)).bound(w.k, tc.spec.kind, w.bound(tc.spec)); !errors.Is(err, tc.want) {
			t.Errorf("%+v: got %v, want %v", tc.spec, err, tc.want)
		}
	}
}

func TestKindProtocols(t *testing.T) {
	for k, want := range map[EndpointKind]string{KindConnection: "tcp", KindListener: "tcp", KindDatagram: "udp", "x": ""} {
		if got := k.Protocol(); got != want {
			t.Errorf("%s: %q", k, got)
		}
	}
}
