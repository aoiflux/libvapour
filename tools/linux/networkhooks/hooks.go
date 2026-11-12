package networkhooks

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.network.list_hooks"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the Netfilter hook functions of every Linux network namespace and device, with their priority, owner and registration",
		},
		RunAny,
	)
}

type Check string

const (
	CheckConsistent      Check = "consistent"
	CheckRemoved         Check = "removed"
	CheckOpsUnread       Check = "registration does not read"
	CheckFunctionDiffers Check = "function differs from its registration"
	CheckOtherChain      Check = "registered for another chain"
	CheckNoOwner         Check = "function outside the kernel and modules"
)

type Hook struct {
	NetNS           uint64
	NetNSKnown      bool
	Protocol        string
	Hook            string
	Device          string
	Index           int
	Priority        int64
	FunctionAddress uint64
	Module          linuxobj.NetText
	Symbol          linuxobj.NetText
	OpsAddress      uint64
	Registered      string
	Check           Check
}

var ErrNoHookTypes = errors.New("networkhooks: symbol table has no nf_hook_entries layout")

// S62 NH4: the kernel never builds a chain longer than MAX_HOOK_COUNT.
const maxChainEntries = 1024

const (
	protoINET   = 1
	protoNetdev = 5
	hookIngress = 0
	hookEgress  = 1
	inetIngress = 5
)

type family struct {
	member string
	proto  uint64
	name   string
	hooks  []string
}

var inetHooks = []string{"NF_INET_PRE_ROUTING", "NF_INET_LOCAL_IN", "NF_INET_FORWARD", "NF_INET_LOCAL_OUT",
	"NF_INET_POST_ROUTING"}

// S62 NH1, NH6: the per-namespace arrays and the hook names of each.
var families = []family{
	{"hooks_ipv4", 2, "NFPROTO_IPV4", inetHooks},
	{"hooks_ipv6", 10, "NFPROTO_IPV6", inetHooks},
	{"hooks_arp", 3, "NFPROTO_ARP", []string{"NF_ARP_IN", "NF_ARP_OUT", "NF_ARP_FORWARD"}},
	{"hooks_bridge", 7, "NFPROTO_BRIDGE", []string{"NF_BR_PRE_ROUTING", "NF_BR_LOCAL_IN", "NF_BR_FORWARD",
		"NF_BR_LOCAL_OUT", "NF_BR_POST_ROUTING"}},
	{"hooks_decnet", 12, "NFPROTO_DECNET", []string{"NF_DN_PRE_ROUTING", "NF_DN_LOCAL_IN", "NF_DN_FORWARD",
		"NF_DN_LOCAL_OUT", "NF_DN_POST_ROUTING", "NF_DN_HELLO", "NF_DN_ROUTE"}},
}

var deviceChains = []struct {
	member string
	hook   uint64
	name   string
}{{"nf_hooks_ingress", hookIngress, "NF_NETDEV_INGRESS"}, {"nf_hooks_egress", hookEgress, "NF_NETDEV_EGRESS"}}

var protoNames = map[uint64]string{0: "NFPROTO_UNSPEC", 1: "NFPROTO_INET", 2: "NFPROTO_IPV4", 3: "NFPROTO_ARP",
	5: "NFPROTO_NETDEV", 7: "NFPROTO_BRIDGE", 10: "NFPROTO_IPV6", 12: "NFPROTO_DECNET"}

func protoName(v uint64) string {
	if n, ok := protoNames[v]; ok {
		return n
	}
	return fmt.Sprintf("NFPROTO %d", v)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Hook, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	k := linuxobj.New(ctx)
	l, err := newLayout(k)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	w := &walk{ctx: ctx, k: k, l: l}
	if err := w.owners(); err != nil {
		return nil, err
	}
	nets, err := k.NetNamespaceList()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if nets.Broken() {
		w.lost("net_namespace_list at %#x: walk ended %s after %d namespaces", k.Masked(nets.At), nets.End,
			len(nets.Entries))
	}
	for _, net := range nets.Entries {
		w.namespace(net)
	}
	if w.disordered > 0 {
		ctx.AddDiagnostic("%s: %d chains are not in ascending priority order", Name, w.disordered)
	}
	if w.overlapping > 0 {
		ctx.AddDiagnostic("%s: %d hook functions lie in more than one module; the first is named", Name, w.overlapping)
	}
	if ctx.StrictMode() && (w.losses > 0 || w.lossy) {
		return nil, fmt.Errorf("%s: strict mode: %d chains or lists did not read or the module views were read in part; first: %s",
			Name, w.losses, w.first)
	}
	return w.out, nil
}

type layout struct {
	nf        uint64
	arrays    []array
	devices   []deviceChain
	hooks     uint64
	entrySize uint64
	acceptAll uint64
	hasAccept bool
}

type array struct {
	family
	offset uint64
	length uint64
}

type deviceChain struct {
	offset uint64
	hook   uint64
	name   string
}

// S62 NH1 to NH3: the chains are found from the table's own types, so a
// family the kernel was built without has no member and gives no rows.
func newLayout(k *linuxobj.Kernel) (*layout, error) {
	nf, err := k.Member("net", "nf")
	if err != nil {
		return nil, fmt.Errorf("%w: net.nf: %w", ErrNoHookTypes, err)
	}
	hooks, err := k.Member("nf_hook_entries", "hooks")
	if err != nil {
		return nil, fmt.Errorf("%w: nf_hook_entries.hooks: %w", ErrNoHookTypes, err)
	}
	size, err := k.SizeOf("nf_hook_entry")
	if err != nil || size == 0 {
		return nil, fmt.Errorf("%w: nf_hook_entry size: %v", ErrNoHookTypes, err)
	}
	for _, m := range []struct{ typ, member string }{{"nf_hook_entries", "num_hook_entries"}, {"nf_hook_entry", "hook"},
		{"nf_hook_ops", "hook"}, {"nf_hook_ops", "pf"}, {"nf_hook_ops", "hooknum"}, {"nf_hook_ops", "priority"}} {
		if !k.Has(m.typ, m.member) {
			return nil, fmt.Errorf("%w: %s.%s", ErrNoHookTypes, m.typ, m.member)
		}
	}
	l := &layout{nf: nf.Offset, hooks: hooks.Offset, entrySize: size}
	for _, f := range families {
		if !k.Has(nf.Type.Name, f.member) {
			continue
		}
		m, err := k.Member(nf.Type.Name, f.member)
		if err != nil {
			return nil, err
		}
		if !pointerArray(m.Type) {
			return nil, fmt.Errorf("%w: %s.%s is not an array of pointers", ErrNoHookTypes, nf.Type.Name, f.member)
		}
		l.arrays = append(l.arrays, array{family: f, offset: m.Offset, length: m.Type.ArrayLength})
	}
	for _, d := range deviceChains {
		if m, err := k.Member("net_device", d.member); err == nil && m.Type.IsPointer {
			l.devices = append(l.devices, deviceChain{offset: m.Offset, hook: d.hook, name: d.name})
		}
	}
	if s, err := k.Symbol("accept_all"); err == nil {
		l.acceptAll, l.hasAccept = k.Masked(s.Address), true
	}
	return l, nil
}

func pointerArray(t symbols.TypeRef) bool {
	return t.ArrayLength > 0 && t.Element != nil && t.Element.IsPointer
}

type walk struct {
	ctx         tools.Context
	k           *linuxobj.Kernel
	l           *layout
	model       *linuxmodule.Model
	known       []linuxmodule.Module
	lossy       bool
	out         []Hook
	losses      int
	first       string
	disordered  int
	overlapping int
}

func (w *walk) owners() error {
	model, err := w.k.Modules()
	if err != nil {
		return fmt.Errorf("%s: module model: %w", Name, err)
	}
	vs, err := model.Views()
	if err != nil {
		return fmt.Errorf("%s: module views: %w", Name, err)
	}
	vs.Report(w.ctx.AddDiagnostic, Name)
	w.model, w.known, w.lossy = model, vs.Known(), vs.Lossy()
	return nil
}

func (w *walk) lost(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if w.losses == 0 {
		w.first = msg
	}
	w.losses++
	w.ctx.AddDiagnostic("%s: %s", Name, msg)
}

type chain struct {
	netns     uint64
	netnsOK   bool
	proto     uint64
	protoName string
	hook      uint64
	hookName  string
	device    string
	head      uint64
}

func (w *walk) namespace(net uint64) {
	k := w.k
	inum, err := k.NetNamespaceInode(net)
	known := err == nil && inum != 0
	if err != nil {
		w.lost("net at %#x: namespace number does not read: %v", k.Masked(net), err)
	}
	for _, a := range w.l.arrays {
		for i := uint64(0); i < a.length; i++ {
			name := fmt.Sprintf("hook %d", i)
			if i < uint64(len(a.hooks)) {
				name = a.hooks[i]
			}
			w.chain(chain{netns: inum, netnsOK: known, proto: a.proto, protoName: a.name, hook: i, hookName: name,
				head: net + w.l.nf + a.offset + i*k.PointerSize()})
		}
	}
	if len(w.l.devices) == 0 {
		return
	}
	devs, err := k.NamespaceDevices(net)
	if err != nil {
		w.lost("net at %#x: device list: %v", k.Masked(net), err)
		return
	}
	if devs.Broken() {
		w.lost("net at %#x: device list ended %s at %#x after %d devices", k.Masked(net), devs.End,
			k.Masked(devs.At), len(devs.Entries))
	}
	for _, dev := range devs.Entries {
		name, err := k.CharArray(k.Memory(), dev, "net_device", "name")
		if err != nil {
			w.lost("net_device at %#x: name does not read: %v", k.Masked(dev), err)
		}
		for _, d := range w.l.devices {
			w.chain(chain{netns: inum, netnsOK: known, proto: protoNetdev, protoName: protoName(protoNetdev),
				hook: d.hook, hookName: d.name, device: name, head: dev + d.offset})
		}
	}
}

type entry struct {
	fn, ops uint64
}

// S62 NH4, NH5: the head points at one nf_hook_entries block: a count, the
// entries, then one registration pointer per entry.
func (w *walk) chain(c chain) {
	k := w.k
	mem := k.Memory()
	block, err := k.PointerAt(mem, c.head)
	if err != nil {
		w.lost("%s %s chain head at %#x: does not read: %v", c.protoName, c.hookName, k.Masked(c.head), err)
		return
	}
	if k.Masked(block) == 0 {
		return
	}
	n, err := k.Uint(mem, block, "nf_hook_entries", "num_hook_entries")
	if err != nil {
		w.lost("nf_hook_entries at %#x: count does not read: %v", k.Masked(block), err)
		return
	}
	if n == 0 || n > maxChainEntries {
		w.lost("nf_hook_entries at %#x: count %d is outside 1 to %d", k.Masked(block), n, maxChainEntries)
		return
	}
	first := block + w.l.hooks
	opsAt := first + n*w.l.entrySize
	var entries []entry
	for i := uint64(0); i < n; i++ {
		fn, err := k.Pointer(mem, first+i*w.l.entrySize, "nf_hook_entry", "hook")
		if err == nil {
			var ops uint64
			if ops, err = k.PointerAt(mem, opsAt+i*k.PointerSize()); err == nil {
				entries = append(entries, entry{fn: fn, ops: ops})
				continue
			}
		}
		w.lost("nf_hook_entries at %#x: entry %d of %d does not read: %v", k.Masked(block), i, n, err)
		break
	}
	last, seen, ordered := int64(0), false, true
	for i, e := range entries {
		h := w.row(c, i, e)
		if h.Check != CheckRemoved && h.Check != CheckOpsUnread {
			if seen && h.Priority < last {
				ordered = false
			}
			last, seen = h.Priority, true
		}
		w.out = append(w.out, h)
	}
	if !ordered {
		w.disordered++
	}
}

type registration struct {
	fn, proto, hooknum uint64
	priority           int64
}

func (w *walk) registration(ops uint64) (registration, error) {
	k := w.k
	mem := k.Memory()
	var r registration
	var err error
	if r.fn, err = k.Pointer(mem, ops, "nf_hook_ops", "hook"); err != nil {
		return r, err
	}
	if r.proto, err = k.Uint(mem, ops, "nf_hook_ops", "pf"); err != nil {
		return r, err
	}
	if r.hooknum, err = k.Uint(mem, ops, "nf_hook_ops", "hooknum"); err != nil {
		return r, err
	}
	r.priority, err = k.Int(mem, ops, "nf_hook_ops", "priority")
	return r, err
}

func (w *walk) row(c chain, i int, e entry) Hook {
	k := w.k
	h := Hook{NetNS: c.netns, NetNSKnown: c.netnsOK, Protocol: c.protoName, Hook: c.hookName, Device: c.device,
		Index: i, FunctionAddress: k.Masked(e.fn), OpsAddress: k.Masked(e.ops)}
	w.name(&h, e.fn)
	r, err := w.registration(e.ops)
	if err != nil || k.Masked(e.ops) == 0 {
		if err == nil {
			err = errors.New("null pointer")
		}
		w.lost("nf_hook_ops at %#x: does not read: %v", k.Masked(e.ops), err)
		h.Check = CheckOpsUnread
		return h
	}
	h.Priority, h.Registered = r.priority, protoName(r.proto)
	switch {
	case k.Masked(r.fn) != k.Masked(e.fn):
		h.Check = CheckFunctionDiffers
	case w.l.hasAccept && k.Masked(e.fn) == w.l.acceptAll:
		h.Check = CheckRemoved
	case !sameChain(c, r):
		h.Check = CheckOtherChain
	case !h.Module.Available:
		h.Check = CheckNoOwner
	default:
		h.Check = CheckConsistent
	}
	return h
}

// S62 NH3: nf_hook_entry_head is the only place a registration is put into a
// chain, so its family and hook number name the chain it sits in; an INET
// registration is placed in both the IPv4 and IPv6 chains, or, for its
// ingress hook, in the device's ingress chain.
func sameChain(c chain, r registration) bool {
	if c.proto == protoNetdev {
		if r.proto == protoNetdev {
			return r.hooknum == c.hook
		}
		return r.proto == protoINET && r.hooknum == inetIngress && c.hook == hookIngress
	}
	if r.proto == protoINET && (c.proto == 2 || c.proto == 10) {
		return r.hooknum == c.hook
	}
	return r.proto == c.proto && r.hooknum == c.hook
}

func (w *walk) name(h *Hook, fn uint64) {
	own := w.model.Lookup(w.known, fn, w.k.SymbolsAt)
	if !own.Found {
		return
	}
	if own.Owners > 1 {
		w.overlapping++
	}
	module := linuxmodule.KernelOwner
	if !own.Kernel {
		module = own.Module.Name
	}
	h.Module = linuxobj.NetTextOf(module)
	switch {
	case own.Symbol == "":
	case own.Offset == 0:
		h.Symbol = linuxobj.NetTextOf(own.Symbol)
	default:
		h.Symbol = linuxobj.NetTextOf(fmt.Sprintf("%s+%#x", own.Symbol, own.Offset))
	}
}
