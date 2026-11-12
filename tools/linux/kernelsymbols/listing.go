package kernelsymbols

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	ksyms "github.com/aoiflux/libvapour/symbols/kallsyms"
	"github.com/aoiflux/libvapour/symbols/linuxkernel"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.kernel.list_symbols"

const (
	OptionCore    = "linux.kernel.list_symbols.core"
	OptionModules = "linux.kernel.list_symbols.modules"
	OptionFtrace  = "linux.kernel.list_symbols.ftrace"
	OptionBPF     = "linux.kernel.list_symbols.bpf"
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name: Name,
			Description: "List the Linux kernel's symbols in /proc/kallsyms order: the core image's from its own kallsyms " +
				"tables, found without a symbol table, then the modules', ftrace's and BPF's",
		},
		RunAny,
	)
}

type Row struct {
	Address         uint64
	Name            string
	NameUnknown     bool
	Type            string
	Description     string
	Size            int64
	Subsystem       string
	Module          string
	ModuleUnknown   bool
	Exported        bool
	ExportedUnknown bool
}

var ErrNoPhysical = errors.New("kernelsymbols: the session has no physical memory")

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type selection struct{ core, modules, ftrace, bpf bool }

func selected(ctx tools.Context) (selection, error) {
	var s selection
	for _, o := range []struct {
		key string
		to  *bool
	}{{OptionCore, &s.core}, {OptionModules, &s.modules}, {OptionFtrace, &s.ftrace}, {OptionBPF, &s.bpf}} {
		v, err := ctx.BoolOption(o.key)
		if err != nil {
			return selection{}, err
		}
		*o.to = v
	}
	if s == (selection{}) {
		s = selection{true, true, true, true}
	}
	return s, nil
}

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	sel, err := selected(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	var rows []Row
	if sel.core {
		core, err := coreRows(ctx)
		if err != nil {
			return nil, err
		}
		rows = core
	}
	if sel.modules || sel.ftrace || sel.bpf {
		more, err := listedRows(ctx, sel)
		if err != nil {
			return nil, err
		}
		rows = append(rows, more...)
	}
	return rows, nil
}

func coreRows(ctx tools.Context) ([]Row, error) {
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return nil, ErrNoPhysical
	}
	table, kernel, err := decodeCore(physical, ctx.Bounds())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if err := kernel.DamageError(); err != nil && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: %w", Name, err)
	}
	for _, d := range kernel.Diagnostics {
		ctx.AddDiagnostic("%s: %s", Name, d)
	}
	rows := CoreRows(table)
	if hidden := len(table.Symbols) - len(rows); hidden > 0 {
		ctx.AddDiagnostic("%s: %d core symbols have no name and are not listed", Name, hidden)
	}
	return rows, nil
}

func decodeCore(physical memory.MemoryReader, l limits.Limits) (ksyms.Table, linuxkernel.Kernel, error) {
	k, err := linuxkernel.FindKernel(physical, l)
	if err != nil {
		return ksyms.Table{}, k, err
	}
	table, err := ksyms.Decode(k.Space, k.Seeds, k.Limits)
	return table, k, err
}

// CoreRows leaves out unnamed symbols because /proc/kallsyms does (s_show).
func CoreRows(table ksyms.Table) []Row {
	rows := make([]Row, 0, len(table.Symbols))
	for _, s := range table.Symbols {
		if s.Name == "" {
			continue
		}
		r := Row{Address: s.Address, Name: s.Name, Size: s.Size, Subsystem: "core", Module: linuxmodule.KernelOwner,
			ExportedUnknown: true}
		if s.Type != 0 {
			r.Type = string(s.Type)
			r.Description = Describe(s.Type)
		}
		rows = append(rows, r)
	}
	return rows
}

func listedRows(ctx tools.Context, sel selection) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, fmt.Errorf("%s: module, ftrace and BPF symbols need the kernel's symbol table (%s alone does not): %w",
			Name, OptionCore, err)
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: profile os %q is not linux", Name, ctx.Profile.OS())
	}
	k := linuxobj.New(ctx)
	l := k.NewKallsymsLister()
	var rows []Row
	add := func(what string, syms []linuxobj.KernelSymbol) {
		ctx.AddDiagnostic("%s: %d %s symbols", Name, len(syms), what)
		for _, s := range syms {
			rows = append(rows, listedRow(k, s))
		}
	}
	if sel.modules {
		syms, err := l.ModuleSymbols()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		add("module", syms)
	}
	if sel.ftrace {
		add("ftrace", l.FtraceSymbols())
	}
	if sel.bpf {
		add("BPF", l.BPFSymbols())
	}
	failures := l.Report()
	reasons := make([]string, 0, len(failures))
	for why := range failures {
		reasons = append(reasons, why)
	}
	sort.Strings(reasons)
	for _, why := range reasons {
		ctx.AddDiagnostic("%s: %s (%d times)", Name, failures[why].First, failures[why].Count)
	}
	if len(failures) > 0 && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: %d kinds of symbol reads failed", Name, len(failures))
	}
	return rows, nil
}

func listedRow(k *linuxobj.Kernel, s linuxobj.KernelSymbol) Row {
	r := Row{Address: k.Canonical(s.Address), Name: s.Name, NameUnknown: s.NameUnknown, Size: s.Size,
		Subsystem: s.Subsystem, Module: s.Module, ModuleUnknown: !s.ModuleKnown, Exported: s.Exported,
		ExportedUnknown: s.ExportedUnknown || !s.TypeKnown}
	if s.TypeKnown {
		r.Type = s.Type
		if len(s.Type) == 1 {
			r.Description = Describe(s.Type[0])
		}
	}
	return r
}
