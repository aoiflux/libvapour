package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/examples/internal/cli"
	"github.com/aoiflux/libvapour/tools/linux/socketlist"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	"github.com/aoiflux/libvapour/tools/windows/network"
)

func TestAnEndpointPrintsOnlyWhatWasRead(t *testing.T) {
	var out strings.Builder
	printEndpoints(&out, []network.Endpoint{
		{Kind: network.KindListener, Family: network.FamilyIPv6, LocalIP: netip.MustParseAddr("::"), LocalPort: 445,
			State: network.TCPStateListen, OwningPID: 4, OwnerImage: "System"},
		{Kind: network.KindConnection, Family: network.FamilyIPv4, LocalPort: 49700,
			RemoteIP: netip.MustParseAddr("192.0.2.7"), RemotePort: 443, State: network.TCPStateEstablished,
			OwnerProblem: "owner unreadable"},
		{Kind: network.KindDatagram, Family: network.FamilyIPv4, LocalIP: netip.MustParseAddr("0.0.0.0"), LocalPort: 53,
			OwningPID: 1200, OwnerImage: "dns.exe"},
	})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if lines[0] != "3 endpoints" {
		t.Errorf("count line %q", lines[0])
	}
	for i, want := range [][]string{
		{"tcp", "ipv6", "[::]:445", "-", "LISTEN", "4", "System", "-"},
		{"tcp", "ipv4", cli.Unreadable + ":49700", "192.0.2.7:443", "ESTABLISHED", "-", "-", "-"},
		{"udp", "ipv4", "0.0.0.0:53", "-", "-", "1200", "dns.exe", "-"},
	} {
		if got := strings.Fields(lines[2+i]); strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("endpoint %d printed %q, want %q", i, got, want)
		}
	}
}

func TestOnlyIPSocketsAreListedWithoutAll(t *testing.T) {
	sockets := []socketlist.Socket{
		{PID: 1, Process: "systemd", Decoded: socketlist.Decoded{Family: "AF_UNIX",
			LocalAddress: linuxobj.NetTextOf("/run/systemd/notify")}},
		{PID: 812, Process: "sshd", Decoded: socketlist.Decoded{Family: "AF_INET6", Type: "SOCK_STREAM",
			Protocol: linuxobj.NetTextOf("IPPROTO_TCP"), LocalAddress: linuxobj.NetTextOf("::"),
			LocalPort: linuxobj.NetTextOf("22"), State: linuxobj.NetTextOf("TCP_LISTEN")}},
	}
	var out strings.Builder
	printSockets(&out, sockets, false)
	if strings.Contains(out.String(), "systemd") || !strings.Contains(out.String(), "[::]:22") {
		t.Errorf("without -all:\n%s", out.String())
	}
	out.Reset()
	printSockets(&out, sockets, true)
	if !strings.Contains(out.String(), "/run/systemd/notify") {
		t.Errorf("-all left out the AF_UNIX socket:\n%s", out.String())
	}
}
