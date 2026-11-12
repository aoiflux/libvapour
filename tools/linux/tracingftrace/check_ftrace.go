package tracingftrace

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const Name = "linux.tracing.check_ftrace"

const OptionShowFlags = "linux.tracing.check_ftrace.show_ftrace_flags"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "List the handlers registered with ftrace, their owners and the functions they hook"},
		RunAny,
	)
}

var (
	ErrNoOpsList   = errors.New("tracingftrace: ftrace_ops_list or ftrace_list_end not in the symbol table, or the list head does not read")
	ErrUnsupported = linuxwalk.ErrUnsupported
)

// S15b F11: ftrace allocates a trampoline in module space, but it belongs to
// no module.
const TrampolineAllocated = "allocated code outside modules"

type Scope string

const (
	ScopeFunction Scope = "function"
	ScopeAll      Scope = "all"
	ScopeNone     Scope = "none"
	ScopeUnread   Scope = "unread"
)

type Hook struct {
	OpsAddress        uint64
	CallbackAddress   uint64
	Callback          string
	Module            string
	ModuleAddress     uint64
	ModuleFound       bool
	TrampolineAddress uint64
	TrampolineOwner   string
	Scope             Scope
	HookedAddress     uint64
	HookedModule      string
	HookedSymbol      string
	Excluded          int
	FlagBits          uint64
	Flags             string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Hook, error) {
	showFlags, err := ctx.BoolOption(OptionShowFlags)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	k, err := linuxkern.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	s, err := newShape(k)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	c := &check{shape: s, diag: ctx.AddDiagnostic}
	c.owners(k)
	if showFlags {
		c.release, err = runningRelease(k)
		if err != nil {
			c.diag("%s: linux_banner: release not read, flag bits named differently across kernels are given by number: %v", Name, err)
		}
	}
	list, err := s.opsList()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if list.stop != "" {
		c.lossy = true
		c.diag("%s: ftrace_ops at %#x: %s", Name, list.at, list.stop)
	}
	var out []Hook
	for _, o := range list.ops {
		out = append(out, c.rows(o, showFlags)...)
	}
	if c.unnamed > 0 {
		c.diag("%s: %d looked-up addresses are in modules whose symbols do not read, first module at %#x", Name, c.unnamed, c.firstUnnamed)
	}
	if c.lossy && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: ops, hashes or module views were read in part", Name)
	}
	return out, nil
}

type check struct {
	*shape
	diag         func(string, ...any)
	release      string
	model        *linuxmodule.Model
	known        []linuxmodule.Module
	namer        linuxmodule.KernelNamer
	lossy        bool
	unnamed      int
	firstUnnamed uint64
}

func (c *check) owners(k *linuxkern.Kernel) {
	c.namer = kernelNamer(k)
	model, err := k.Modules()
	if err != nil {
		c.lossy = true
		c.diag("%s: module model: %v", Name, err)
		return
	}
	c.model = model
	vs, err := model.Views()
	if err != nil {
		c.lossy = true
		c.diag("%s: module views: %v", Name, err)
		return
	}
	vs.Report(c.diag, Name)
	if vs.Lossy() {
		c.lossy = true
	}
	c.known = vs.Known()
}

type owner struct {
	module, symbol string
	address        uint64
	found          bool
}

func (c *check) owner(addr uint64) owner {
	if c.model == nil {
		return owner{}
	}
	o := c.model.Lookup(c.known, addr, c.namer)
	if o.Unnamed {
		if c.unnamed == 0 {
			c.firstUnnamed = o.Module.Address
		}
		c.unnamed++
	}
	if !o.Found {
		return owner{}
	}
	var out owner
	out.module, out.symbol = o.Names()
	out.found = true
	if !o.Kernel {
		out.address = o.Module.Address
	}
	return out
}

func runningRelease(k *linuxkern.Kernel) (string, error) {
	at, err := k.Symbol("linux_banner")
	if err != nil {
		return "", err
	}
	_, release, err := autoload.ReadLinuxBanner(k.Mem, at, k.Context().Bounds())
	return release, err
}

func (c *check) trampolineOwner(addr uint64) string {
	if addr == 0 || c.model == nil {
		return ""
	}
	if o := c.owner(addr); o.found {
		return o.module
	}
	return TrampolineAllocated
}

func (c *check) rows(o ops, showFlags bool) []Hook {
	cb := c.owner(o.fn)
	base := Hook{OpsAddress: o.at, CallbackAddress: o.fn, Callback: cb.symbol, Module: cb.module,
		ModuleAddress: cb.address, ModuleFound: cb.found, TrampolineAddress: o.trampoline,
		TrampolineOwner: c.trampolineOwner(o.trampoline), FlagBits: o.flags, Excluded: -1}
	if showFlags {
		base.Flags = FlagNames(o.flags, c.release)
	}
	if !c.filters {
		base.Scope, base.Excluded = ScopeAll, 0
		return []Hook{base}
	}
	f := c.filterOf(o.at)
	if f.notrace.err == nil {
		base.Excluded = len(f.notrace.ips)
	} else {
		c.hashFailed(o.at, "notrace_hash", f.notraceAt, f.notrace.err)
	}
	if f.notrace.unread > 0 || f.filter.unread > 0 {
		c.lossy = true
		c.diag("%s: ftrace_ops at %#x: %d hash entries do not read", Name, o.at, f.notrace.unread+f.filter.unread)
	}
	for _, h := range []struct {
		name string
		at   uint64
		r    hash
	}{{"notrace_hash", f.notraceAt, f.notrace}, {"filter_hash", f.filterAt, f.filter}} {
		if h.r.capped {
			c.lossy = true
			c.diag("%s: ftrace_ops at %#x: %s at %#x: entries stop at Limits.MaxListEntries", Name, o.at, h.name, h.at)
		}
		for _, b := range h.r.broken {
			c.lossy = true
			c.diag("%s: ftrace_ops at %#x: %s at %#x: bucket %d chain ends after %d entries at %#x: %s",
				Name, o.at, h.name, h.at, b.bucket, b.walk.Entries, b.walk.At, b.walk.End)
		}
		if h.r.err == nil && !h.r.empty && uint64(len(h.r.ips)) != h.r.count {
			c.diag("%s: ftrace_ops at %#x: %s at %#x: %d entries found, count says %d", Name, o.at, h.name, h.at,
				len(h.r.ips), h.r.count)
		}
	}
	switch {
	case f.filter.err != nil:
		c.hashFailed(o.at, "filter_hash", f.filterAt, f.filter.err)
		base.Scope = ScopeUnread
		return []Hook{base}
	case f.filter.empty:
		base.Scope = ScopeAll
		return []Hook{base}
	case len(f.filter.ips) == 0:
		base.Scope = ScopeNone
		return []Hook{base}
	}
	out := make([]Hook, 0, len(f.filter.ips))
	for _, ip := range f.filter.ips {
		h := base
		h.Scope, h.HookedAddress = ScopeFunction, ip
		hooked := c.owner(ip)
		h.HookedModule, h.HookedSymbol = hooked.module, hooked.symbol
		out = append(out, h)
	}
	return out
}

func (c *check) hashFailed(ops uint64, name string, at uint64, err error) {
	c.lossy = true
	c.diag("%s: ftrace_ops at %#x: %s at %#x: %v", Name, ops, name, at, err)
}
