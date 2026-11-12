package linuxobj

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

type InterfaceAddress struct {
	Entry     uint64
	Address   string
	PrefixLen uint64
	Scope     string
}

type AddressWalk struct {
	Addresses []InterfaceAddress
	End       linuxwalk.End
	At        uint64
}

func (w AddressWalk) Broken() bool { return w.End != linuxwalk.Closed }

func (k *Kernel) IPv4Addresses(inDev uint64) (AddressWalk, error) {
	var w AddressWalk
	if k.Masked(inDev) == 0 {
		return w, nil
	}
	if !k.HasType("in_ifaddr") {
		return w, NotInTable("in_ifaddr")
	}
	local, err := k.Member("in_ifaddr", "ifa_local")
	if err != nil {
		return w, fmt.Errorf("linuxobj: in_ifaddr.ifa_local: %w", err)
	}
	ifa, err := k.Pointer(k.mem, inDev, "in_device", "ifa_list")
	if err != nil {
		if TableGap(err) {
			return w, err
		}
		w.End, w.At = linuxwalk.HeadUnreadable, inDev
		return w, nil
	}
	most := k.ctx.Bounds().MaxListEntries
	seen := map[uint64]struct{}{}
	for k.Masked(ifa) != 0 {
		if _, again := seen[ifa]; again {
			w.End, w.At = linuxwalk.Revisited, ifa
			return w, nil
		}
		if len(w.Addresses) >= most {
			w.End, w.At = linuxwalk.Capped, ifa
			return w, nil
		}
		seen[ifa] = struct{}{}
		a, next, err := k.ipv4Address(ifa, local.Offset)
		if err != nil {
			w.End, w.At = linuxwalk.EntryUnreadable, ifa
			return w, nil
		}
		w.Addresses = append(w.Addresses, a)
		ifa = next
	}
	return w, nil
}

func (k *Kernel) ipv4Address(ifa, localAt uint64) (InterfaceAddress, uint64, error) {
	a := InterfaceAddress{Entry: ifa}
	b, err := k.readNetBytes(ifa+localAt, 4)
	if err != nil {
		return a, 0, err
	}
	a.Address = netip.AddrFrom4([4]byte(b)).String()
	if a.PrefixLen, err = k.Uint(k.mem, ifa, "in_ifaddr", "ifa_prefixlen"); err != nil {
		return a, 0, err
	}
	scope, err := k.Uint(k.mem, ifa, "in_ifaddr", "ifa_scope")
	if err != nil {
		return a, 0, err
	}
	a.Scope = RouteScopeName(scope)
	next, err := k.Pointer(k.mem, ifa, "in_ifaddr", "ifa_next")
	return a, next, err
}

func (k *Kernel) IPv6Addresses(in6Dev uint64) (AddressWalk, error) {
	var w AddressWalk
	if k.Masked(in6Dev) == 0 {
		return w, nil
	}
	if !k.HasType("inet6_ifaddr") {
		return w, NotInTable("inet6_ifaddr")
	}
	head, err := k.Member("inet6_dev", "addr_list")
	if err != nil {
		return w, fmt.Errorf("linuxobj: inet6_dev.addr_list: %w", err)
	}
	addr, err := k.Member("inet6_ifaddr", "addr")
	if err != nil {
		return w, fmt.Errorf("linuxobj: inet6_ifaddr.addr: %w", err)
	}
	l, err := k.Walker().List(in6Dev+head.Offset, "inet6_ifaddr", "if_list", linuxwalk.Forward)
	if err != nil {
		return w, err
	}
	w.End, w.At = l.End, l.At
	for _, e := range l.Entries {
		a, err := k.ipv6Address(e, addr.Offset)
		if err != nil {
			w.End, w.At = linuxwalk.EntryUnreadable, e
			return w, nil
		}
		w.Addresses = append(w.Addresses, a)
	}
	return w, nil
}

func (k *Kernel) ipv6Address(ifa, addrAt uint64) (InterfaceAddress, error) {
	a := InterfaceAddress{Entry: ifa}
	b, err := k.readNetBytes(ifa+addrAt, 16)
	if err != nil {
		return a, err
	}
	a.Address = netip.AddrFrom16([16]byte(b)).String()
	if a.PrefixLen, err = k.Uint(k.mem, ifa, "inet6_ifaddr", "prefix_len"); err != nil {
		return a, err
	}
	scope, err := k.Uint(k.mem, ifa, "inet6_ifaddr", "scope")
	if err != nil {
		return a, err
	}
	a.Scope = RouteScopeName(IPv6RouteScope(scope))
	return a, nil
}

func (k *Kernel) readNetBytes(at, n uint64) ([]byte, error) {
	b, err := k.mem.ReadAt(at, n)
	if err != nil {
		return nil, fmt.Errorf("linuxobj: %d bytes at %#x: %w", n, at, err)
	}
	if uint64(len(b)) != n {
		return nil, fmt.Errorf("linuxobj: %d bytes at %#x: %w", n, at, errNetShortRead)
	}
	return b, nil
}

var errNetShortRead = errors.New("linuxobj: short read")

func FormatHardwareAddress(b []byte) string {
	const digits = "0123456789abcdef"
	var s strings.Builder
	for i, c := range b {
		if i > 0 {
			s.WriteByte(':')
		}
		s.WriteByte(digits[c>>4])
		s.WriteByte(digits[c&0xf])
	}
	return s.String()
}
