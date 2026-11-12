package linuxobj

import (
	"fmt"

	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

func (k *Kernel) NetNamespaceList() (linuxwalk.List, error) {
	head, err := k.Symbol("net_namespace_list")
	if err != nil {
		return linuxwalk.List{}, err
	}
	return k.Walker().List(head.Address, "net", "list", linuxwalk.Forward)
}

func (k *Kernel) NetNamespaceInode(net uint64) (uint64, error) {
	ns, err := k.Member("net", "ns")
	if err != nil {
		return 0, fmt.Errorf("linuxobj: net.ns: %w", err)
	}
	typ := ns.Type.Name
	if typ == "" {
		typ = "ns_common"
	}
	return k.Uint(k.mem, net+ns.Offset, typ, "inum")
}

// An exiting task has dropped its nsproxy, so it has no namespace to report.
func (k *Kernel) NsproxyNetNS(t Task) (net uint64, held bool, err error) {
	proxy, err := k.Pointer(k.in(t), t.Addr, "task_struct", "nsproxy")
	if err != nil {
		return 0, false, err
	}
	if k.Masked(proxy) == 0 {
		return 0, false, nil
	}
	net, err = k.Pointer(k.mem, proxy, "nsproxy", "net_ns")
	if err != nil {
		return 0, false, err
	}
	return net, k.Masked(net) != 0, nil
}

func (k *Kernel) NamespaceDevices(net uint64) (linuxwalk.List, error) {
	head, err := k.Member("net", "dev_base_head")
	if err != nil {
		return linuxwalk.List{}, fmt.Errorf("linuxobj: net.dev_base_head: %w", err)
	}
	return k.Walker().List(net+head.Offset, "net_device", "dev_list", linuxwalk.Forward)
}

type NetDevice struct {
	Addr             uint64
	Name             string
	Index            int64
	Net              uint64
	NetNS            uint64
	NetNSKnown       bool
	Flags            uint64
	GFlags           uint64
	OperState        uint64
	LinkState        uint64
	MTU              uint64
	TxQueueLen       uint64
	HardwareAddress  NetText
	PermanentAddress NetText
	Qdisc            NetText
	IPv4             uint64
	IPv6             uint64
}

func (k *Kernel) ReadNetDevice(dev uint64) (NetDevice, error) {
	d := NetDevice{Addr: dev}
	var err error
	if d.Name, err = k.CharArray(k.mem, dev, "net_device", "name"); err != nil {
		return d, err
	}
	if d.Index, err = k.Int(k.mem, dev, "net_device", "ifindex"); err != nil {
		return d, err
	}
	if net, ok := k.deviceNet(dev); ok {
		d.Net = net
		d.NetNS, err = k.NetNamespaceInode(net)
		d.NetNSKnown = err == nil && d.NetNS != 0
	}
	for _, m := range []struct {
		name string
		to   *uint64
	}{
		{"flags", &d.Flags}, {"gflags", &d.GFlags}, {"operstate", &d.OperState}, {"state", &d.LinkState},
		{"mtu", &d.MTU}, {"tx_queue_len", &d.TxQueueLen},
	} {
		if *m.to, err = k.Uint(k.mem, dev, "net_device", m.name); err != nil {
			return d, err
		}
	}
	d.HardwareAddress, d.PermanentAddress = k.deviceHardwareAddresses(dev)
	d.Qdisc = k.deviceQdisc(dev)
	if d.IPv4, err = k.Pointer(k.mem, dev, "net_device", "ip_ptr"); err != nil {
		return d, err
	}
	if d.IPv6, err = k.Pointer(k.mem, dev, "net_device", "ip6_ptr"); err != nil {
		return d, err
	}
	return d, nil
}

// Without CONFIG_NET_NS possible_net_t is empty and every device is in init_net.
func (k *Kernel) deviceNet(dev uint64) (uint64, bool) {
	nd, err := k.Member("net_device", "nd_net")
	if err != nil {
		return 0, false
	}
	typ := nd.Type.Name
	if typ == "" {
		typ = "possible_net_t"
	}
	if !k.Has(typ, "net") {
		s, err := k.Symbol("init_net")
		return s.Address, err == nil
	}
	net, err := k.Pointer(k.mem, dev+nd.Offset, typ, "net")
	return net, err == nil && k.Masked(net) != 0
}

func (k *Kernel) deviceHardwareAddresses(dev uint64) (current, permanent NetText) {
	n, err := k.Uint(k.mem, dev, "net_device", "addr_len")
	if err != nil || n > maxHardwareAddress {
		return
	}
	if p, err := k.Pointer(k.mem, dev, "net_device", "dev_addr"); err == nil && k.Masked(p) != 0 {
		if b, err := k.readNetBytes(p, n); err == nil {
			current = NetTextOf(FormatHardwareAddress(b))
		}
	}
	if f, err := k.Member("net_device", "perm_addr"); err == nil {
		if b, err := k.readNetBytes(dev+f.Offset, n); err == nil {
			permanent = NetTextOf(FormatHardwareAddress(b))
		}
	}
	return
}

func (k *Kernel) deviceQdisc(dev uint64) NetText {
	q, err := k.Pointer(k.mem, dev, "net_device", "qdisc")
	if err != nil {
		return NetText{}
	}
	if k.Masked(q) == 0 {
		return NetTextOf("")
	}
	ops, err := k.Pointer(k.mem, q, "Qdisc", "ops")
	if err != nil || k.Masked(ops) == 0 {
		return NetText{}
	}
	id, err := k.CharArray(k.mem, ops, "Qdisc_ops", "id")
	if err != nil {
		return NetText{}
	}
	return NetTextOf(id)
}

func (d NetDevice) Running() bool { return d.LinkState&(1<<linkStateStart) != 0 }

func (d NetDevice) Promiscuous() bool { return d.Flags&iffPromisc != 0 }

// The stored running, carrier and dormant bits are stale: the kernel recomputes
// them from the link state when it reports a device, and reports the
// promiscuous and all-multicast bits a user set rather than the counted ones.
func (d NetDevice) ReportedFlags() uint64 {
	f := d.Flags&^(iffPromisc|iffAllMulti|iffRunning|iffLowerUp|iffDormant) | d.GFlags&(iffPromisc|iffAllMulti)
	if d.Running() {
		if d.OperState == operUp || d.OperState == operUnknown {
			f |= iffRunning
		}
		if d.LinkState&(1<<linkStateNoCarrier) == 0 {
			f |= iffLowerUp
		}
		if d.LinkState&(1<<linkStateDormant) != 0 {
			f |= iffDormant
		}
	}
	return f
}
