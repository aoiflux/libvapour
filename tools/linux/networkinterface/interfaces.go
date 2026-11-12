package networkinterface

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const (
	AddrName = "linux.network.list_addresses"
	LinkName = "linux.network.list_interfaces"
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        AddrName,
			Description: "List the IPv4 and IPv6 addresses configured on every Linux network device, in every network namespace",
		},
		RunAddrAny,
	)
	tools.MustRegister(
		tools.Spec{
			Name:        LinkName,
			Description: "List every Linux network device in every network namespace, with the flags, operational state, hardware address and queueing discipline the kernel reports",
		},
		RunLinkAny,
	)
}

type Link struct {
	NetNS           uint64
	NetNSKnown      bool
	Index           int64
	Interface       string
	HardwareAddress string
	OperState       linuxobj.NetText
	MTU             uint64
	Qdisc           linuxobj.NetText
	TxQueueLength   uint64
	Flags           string
}

type Family string

const (
	FamilyIPv4 Family = "IPv4"
	FamilyIPv6 Family = "IPv6"
)

type Addr struct {
	NetNS           uint64
	NetNSKnown      bool
	Index           int64
	Interface       string
	HardwareAddress string
	Promiscuous     bool
	OperState       linuxobj.NetText
	Family          Family
	Address         string
	PrefixLength    uint64
	Scope           string
}

var ErrNoHardwareAddress = errors.New("networkinterface: dev_addr does not read")

func RunAddrAny(ctx tools.Context) (any, error) { return RunAddr(ctx) }

func RunLinkAny(ctx tools.Context) (any, error) { return RunLink(ctx) }

func RunLink(ctx tools.Context) ([]Link, error) {
	s, err := survey(ctx, LinkName)
	if err != nil {
		return nil, err
	}
	var out []Link
	s.each(func(d device) {
		out = append(out, Link{
			NetNS: d.NetNS, NetNSKnown: d.NetNSKnown, Index: d.Index, Interface: d.Name,
			HardwareAddress: d.HardwareAddress.Value, OperState: d.oper, MTU: d.MTU, Qdisc: d.Qdisc,
			TxQueueLength: d.TxQueueLen, Flags: flagText(d.ReportedFlags()),
		})
	})
	return out, s.finish()
}

func RunAddr(ctx tools.Context) ([]Addr, error) {
	s, err := survey(ctx, AddrName)
	if err != nil {
		return nil, err
	}
	var out []Addr
	s.each(func(d device) {
		base := Addr{
			NetNS: d.NetNS, NetNSKnown: d.NetNSKnown, Index: d.Index, Interface: d.Name,
			HardwareAddress: d.HardwareAddress.Value, Promiscuous: d.Promiscuous(), OperState: d.oper,
		}
		for _, fam := range []struct {
			family Family
			at     uint64
			read   func(uint64) (linuxobj.AddressWalk, error)
		}{{FamilyIPv4, d.IPv4, s.k.IPv4Addresses}, {FamilyIPv6, d.IPv6, s.k.IPv6Addresses}} {
			w, err := fam.read(fam.at)
			if err != nil {
				s.familyFailed(d, fam.family, err)
				continue
			}
			for _, a := range w.Addresses {
				r := base
				r.Family, r.Address, r.PrefixLength, r.Scope = fam.family, a.Address, a.PrefixLen, a.Scope
				out = append(out, r)
			}
			if w.Broken() {
				s.lost("net_device at %#x: %s address walk ended %s at %#x after %d addresses",
					s.k.Masked(d.Addr), fam.family, w.End, s.k.Masked(w.At), len(w.Addresses))
			}
		}
	})
	return out, s.finish()
}

// S62 NI3: the operational state and the reported flags are the kernel's
// names without their prefixes.
func flagText(flags uint64) string {
	names := linuxobj.InterfaceFlagNames(flags)
	for i, n := range names {
		names[i] = strings.TrimPrefix(n, "IFF_")
	}
	return strings.Join(names, ",")
}

type device struct {
	linuxobj.NetDevice
	oper linuxobj.NetText
}

type deviceSurvey struct {
	ctx     tools.Context
	k       *linuxobj.Kernel
	tool    string
	devices []device
	losses  int
	first   string
	gaps    map[Family]bool
}

func survey(ctx tools.Context, tool string) (*deviceSurvey, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", tool, ctx.Profile.OS())
	}
	s := &deviceSurvey{ctx: ctx, k: linuxobj.New(ctx), tool: tool, gaps: map[Family]bool{}}
	nets, err := s.k.NetNamespaceList()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	if nets.Broken() {
		s.lost("net_namespace_list at %#x: walk ended %s after %d namespaces", s.k.Masked(nets.At),
			nets.End, len(nets.Entries))
	}
	unnamed := 0
	for _, net := range nets.Entries {
		devs, err := s.k.NamespaceDevices(net)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tool, err)
		}
		if devs.Broken() {
			s.lost("net at %#x: device list ended %s at %#x after %d devices", s.k.Masked(net), devs.End,
				s.k.Masked(devs.At), len(devs.Entries))
		}
		for _, at := range devs.Entries {
			d, err := s.k.ReadNetDevice(at)
			if err == nil && !d.HardwareAddress.Available {
				err = ErrNoHardwareAddress
			}
			if err != nil {
				if linuxobj.TableGap(err) {
					return nil, fmt.Errorf("%s: %w", tool, err)
				}
				s.lost("net_device at %#x: does not read: %v", s.k.Masked(at), err)
				continue
			}
			dev := device{NetDevice: d}
			if name, ok := linuxobj.OperStateName(d.OperState); ok {
				dev.oper = linuxobj.NetTextOf(strings.TrimPrefix(name, "IF_OPER_"))
			} else {
				unnamed++
			}
			s.devices = append(s.devices, dev)
		}
	}
	if unnamed > 0 {
		ctx.AddDiagnostic("%s: %d devices hold an operational state with no IF_OPER_ name; the state is left absent", tool, unnamed)
	}
	return s, nil
}

func (s *deviceSurvey) each(f func(device)) {
	for _, d := range s.devices {
		f(d)
	}
}

func (s *deviceSurvey) lost(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if s.losses == 0 {
		s.first = msg
	}
	s.losses++
	s.ctx.AddDiagnostic("%s: %s", s.tool, msg)
}

// S62 NI4: a kernel built without one address family has no type for it; the
// other family is still listed.
func (s *deviceSurvey) familyFailed(d device, fam Family, err error) {
	if linuxobj.TableGap(err) {
		if !s.gaps[fam] {
			s.gaps[fam] = true
			s.ctx.AddDiagnostic("%s: %s addresses are not listed: %v", s.tool, fam, err)
		}
		return
	}
	s.lost("net_device at %#x: %s addresses: %v", s.k.Masked(d.Addr), fam, err)
}

func (s *deviceSurvey) finish() error {
	if s.losses > 0 && s.ctx.StrictMode() {
		return fmt.Errorf("%s: strict mode: %d walks or devices did not read; first: %s", s.tool, s.losses, s.first)
	}
	return nil
}
