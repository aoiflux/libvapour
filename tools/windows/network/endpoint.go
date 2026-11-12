// TCP connections, TCP listeners and UDP endpoints that tcpip.sys keeps,
// found by walking its tables (windows.network.list) or by pool tag
// (windows.network.scan). Both decode one object the same way (S28).
package network

import (
	"errors"
	"net/netip"
	"time"
)

type EndpointKind string

const (
	KindConnection EndpointKind = "tcp_connection"
	KindListener   EndpointKind = "tcp_listener"
	KindDatagram   EndpointKind = "udp_endpoint"
)

func (k EndpointKind) Protocol() string {
	switch k {
	case KindConnection, KindListener:
		return "tcp"
	case KindDatagram:
		return "udp"
	}
	return ""
}

type Family string

const (
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

// Microsoft Learn, socket function: AF_INET 2, AF_INET6 23 (S28 D2).
const (
	addressFamilyInet  = 2
	addressFamilyInet6 = 23
)

func familyOf(v uint16) (Family, bool) {
	switch v {
	case addressFamilyInet:
		return FamilyIPv4, true
	case addressFamilyInet6:
		return FamilyIPv6, true
	}
	return "", false
}

func (f Family) addressBytes() uint64 {
	if f == FamilyIPv6 {
		return 16
	}
	return 4
}

func (f Family) unspecified() netip.Addr {
	if f == FamilyIPv6 {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

type TCPState string

// The TCPSTATE enumeration of mstcpip.h, in its order (S28 D1, M9).
var tcpStates = []TCPState{
	"CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT_1",
	"FIN_WAIT_2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT",
}

const (
	TCPStateClosed      TCPState = "CLOSED"
	TCPStateListen      TCPState = "LISTEN"
	TCPStateEstablished TCPState = "ESTABLISHED"
	TCPStateUnknown     TCPState = "UNKNOWN"
)

const stateListen = 1

func stateOf(v uint32) (TCPState, bool) {
	if uint64(v) < uint64(len(tcpStates)) {
		return tcpStates[v], true
	}
	return TCPStateUnknown, false
}

type Endpoint struct {
	Kind       EndpointKind
	Family     Family
	LocalIP    netip.Addr
	LocalPort  uint16
	RemoteIP   netip.Addr
	RemotePort uint16
	State      TCPState
	StateValue uint32

	OwningPID    uint64
	OwnerImage   string
	OwnerAddress uint64
	CreateTime   time.Time

	ObjectAddress     uint64
	ObjectPhysical    uint64
	OtherCopyPhysical uint64
	PoolTag           string

	IPProblem    string
	OwnerProblem string
	TimeProblem  string
	Rejected     string
}

var (
	ErrNotWindows   = errors.New("network: profile is not windows")
	ErrPointerSize  = errors.New("network: measured layouts are for 64-bit kernels only")
	ErrLayout       = errors.New("network: symbol table lacks a member of the measured tcpip layout")
	ErrNoTables     = errors.New("network: measured tcpip layout has no endpoint tables for this build")
	ErrTcpipSymbols = errors.New("network: tcpip.sys symbols not resolved")
	ErrObjectUnread = errors.New("network: object does not read")
	ErrFamily       = errors.New("network: address family is not AF_INET or AF_INET6")
	ErrState        = errors.New("network: tcp state is past the TCPSTATE range")
	ErrPort         = errors.New("network: port is 0")
	ErrBoundPort    = errors.New("network: local port is not the port the pool entry is for")
	ErrPointer      = errors.New("network: pointer is outside system space")
	ErrIPUnread     = errors.New("network: ip address does not read")
	ErrOwner        = errors.New("network: no owner pointer names a process")
	ErrTimeAbsent   = errors.New("network: creation time is 0")
	ErrTimeWindow   = errors.New("network: creation time does not fit this capture")
)
