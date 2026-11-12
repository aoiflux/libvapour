package linuxobj

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools/linuxmodule"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

type KernelSymbol struct {
	Name            string
	Type            string
	TypeKnown       bool
	Address         uint64
	Offset          uint64
	Size            int64
	Module          string
	ModuleKnown     bool
	Subsystem       string
	Exported        bool
	ExportedUnknown bool
	NameUnknown     bool
}

const (
	subsystemCore   = "core"
	subsystemModule = "module"
	subsystemBPF    = "bpf"
	subsystemFtrace = "ftrace"

	bpfModuleName        = "bpf"
	trampolineModuleName = "__builtin__ftrace"
	trampolineName       = "ftrace_trampoline"

	kernelNameBytes = 512
	bpfTagBytes     = 8
	x86PageSize     = 4096
)

type SymbolFailure struct {
	Count int
	First string
}

type SymbolFailures map[string]SymbolFailure

func (f SymbolFailures) note(reason string, err error) { f.add(reason, err, 1) }

func (f SymbolFailures) add(reason string, err error, n int) {
	e := f[reason]
	if e.Count == 0 {
		e.First = err.Error()
	}
	e.Count += n
	f[reason] = e
}

type exportTable struct {
	values map[string]uint64
	err    error
}

type ftraceFunction struct {
	name, module string
	moduleKnown  bool
	ip, size     uint64
}

type trampoline struct{ start, size uint64 }

type bpfProgram struct {
	name       string
	start, end uint64
}

type bpfForm uint8

const (
	bpfNone bpfForm = iota
	bpfKsym
	bpfProgAux
)

type symbolSources struct {
	k        *Kernel
	failures SymbolFailures
	exports  map[uint64]exportTable
	modNames map[uint64]string
	relative bool
}

func newSymbolSources(k *Kernel) *symbolSources {
	return &symbolSources{k: k, failures: SymbolFailures{}, exports: map[uint64]exportTable{}, modNames: map[uint64]string{},
		relative: k.Has("kernel_symbol", "value_offset")}
}

func letterCase(letter byte, upper bool) string {
	if upper {
		return strings.ToUpper(string(letter))
	}
	return strings.ToLower(string(letter))
}

func (s *symbolSources) list(head, container, member string) []uint64 {
	at, err := s.k.Symbol(head)
	if err != nil {
		return nil
	}
	return s.walk(at.Address, head, container, member)
}

func (s *symbolSources) walk(at uint64, what, container, member string) []uint64 {
	l, err := s.k.Walker().List(at, container, member, linuxwalk.Forward)
	if err != nil {
		s.failures.note(what+" list", fmt.Errorf("%s at %#x: %w", what, at, err))
		return nil
	}
	if l.Broken() {
		s.failures.note(what+" list", fmt.Errorf("%s at %#x: list ends after %d entries at %#x: %s", what, at,
			len(l.Entries), l.At, l.End))
	}
	return l.Entries
}

func (s *symbolSources) exportsOf(mod uint64) exportTable {
	if t, ok := s.exports[mod]; ok {
		return t
	}
	t := s.readExports(mod)
	if t.err != nil && s.k.Has("module", "syms") {
		s.failures.note("module exports", fmt.Errorf("module at %#x: export table: %w", mod, t.err))
	}
	s.exports[mod] = t
	return t
}

func (s *symbolSources) readExports(mod uint64) exportTable {
	k := s.k
	syms, err := k.Pointer(k.mem, mod, "module", "syms")
	if err != nil {
		return exportTable{err: err}
	}
	n, err := k.Uint(k.mem, mod, "module", "num_syms")
	if err != nil {
		return exportTable{err: err}
	}
	t := exportTable{values: map[string]uint64{}}
	if syms == 0 || n == 0 {
		return t
	}
	if n > uint64(k.ctx.Bounds().MaxTableEntries) {
		return exportTable{err: fmt.Errorf("%d entries over Limits.MaxTableEntries", n)}
	}
	entry, err := k.SizeOf("kernel_symbol")
	if err != nil {
		return exportTable{err: err}
	}
	for i := range n {
		at := syms + i*entry
		value, namePtr, err := s.exportEntry(at)
		if err != nil {
			return exportTable{err: err}
		}
		name, err := k.StringAt(namePtr, kernelNameBytes)
		if err != nil {
			return exportTable{err: fmt.Errorf("kernel_symbol at %#x: name: %w", at, err)}
		}
		t.values[name] = value
	}
	return t
}

func (s *symbolSources) exportEntry(at uint64) (value, name uint64, err error) {
	k := s.k
	if !s.relative {
		if value, err = k.Uint(k.mem, at, "kernel_symbol", "value"); err != nil {
			return 0, 0, err
		}
		name, err = k.Pointer(k.mem, at, "kernel_symbol", "name")
		return k.Canonical(value), name, err
	}
	place := func(member string) (uint64, error) {
		f, err := k.Member("kernel_symbol", member)
		if err != nil {
			return 0, err
		}
		off, err := k.Int(k.mem, at, "kernel_symbol", member)
		if err != nil {
			return 0, err
		}
		return k.Canonical(at + f.Offset + uint64(off)), nil
	}
	if value, err = place("value_offset"); err != nil {
		return 0, 0, err
	}
	name, err = place("name_offset")
	return value, name, err
}

func (s *symbolSources) moduleEntry(mod linuxmodule.Module, sym linuxmodule.Symbol) KernelSymbol {
	out := KernelSymbol{Name: sym.Name, Address: s.k.Masked(sym.Address), Size: int64(sym.Size), Module: mod.Name,
		ModuleKnown: true, Subsystem: subsystemModule, TypeKnown: sym.Type != 0}
	exports := s.exportsOf(mod.Address)
	switch {
	case exports.err != nil:
		out.ExportedUnknown = true
		if out.TypeKnown {
			out.Type = string(sym.Type)
		}
	default:
		v, ok := exports.values[sym.Name]
		out.Exported = ok && v == sym.Address
		if out.TypeKnown {
			out.Type = letterCase(sym.Type, out.Exported)
		}
	}
	return out
}

func (s *symbolSources) moduleName(mod uint64) (string, bool) {
	if name, ok := s.modNames[mod]; ok {
		return name, name != ""
	}
	name, err := s.k.moduleName(mod)
	if err != nil {
		s.failures.note("module read", err)
	}
	s.modNames[mod] = name
	return name, err == nil
}

func (s *symbolSources) ftraceFunctions() []ftraceFunction {
	k := s.k
	funcs, err := k.Member("ftrace_mod_map", "funcs")
	if err != nil {
		return nil
	}
	var out []ftraceFunction
	for _, m := range s.list("ftrace_mod_maps", "ftrace_mod_map", "list") {
		mod, err := k.Pointer(k.mem, m, "ftrace_mod_map", "mod")
		if err != nil {
			s.failures.note("ftrace read", fmt.Errorf("ftrace_mod_map at %#x: %w", m, err))
			continue
		}
		name, known := s.moduleName(mod)
		for _, f := range s.walk(m+funcs.Offset, "ftrace_mod_map funcs", "ftrace_mod_func", "list") {
			fn, err := s.ftraceFunction(f)
			if err != nil {
				s.failures.note("ftrace read", fmt.Errorf("ftrace_mod_func at %#x: %w", f, err))
				continue
			}
			fn.module, fn.moduleKnown = name, known
			out = append(out, fn)
		}
	}
	return out
}

func (s *symbolSources) ftraceFunction(at uint64) (ftraceFunction, error) {
	k := s.k
	namePtr, err := k.Pointer(k.mem, at, "ftrace_mod_func", "name")
	if err != nil {
		return ftraceFunction{}, err
	}
	name, err := k.StringAt(namePtr, kernelNameBytes)
	if err != nil {
		return ftraceFunction{}, err
	}
	ip, err := k.Uint(k.mem, at, "ftrace_mod_func", "ip")
	if err != nil {
		return ftraceFunction{}, err
	}
	size, err := k.Uint(k.mem, at, "ftrace_mod_func", "size")
	if err != nil {
		return ftraceFunction{}, err
	}
	return ftraceFunction{name: name, ip: k.Canonical(ip), size: size}, nil
}

func (s *symbolSources) trampolines() []trampoline {
	k := s.k
	var out []trampoline
	for _, op := range s.list("ftrace_ops_trampoline_list", "ftrace_ops", "list") {
		start, err := k.Uint(k.mem, op, "ftrace_ops", "trampoline")
		if err != nil {
			s.failures.note("ftrace read", fmt.Errorf("ftrace_ops at %#x: %w", op, err))
			continue
		}
		if start == 0 {
			continue
		}
		size, err := k.Uint(k.mem, op, "ftrace_ops", "trampoline_size")
		if err != nil {
			s.failures.note("ftrace read", fmt.Errorf("ftrace_ops at %#x: %w", op, err))
			continue
		}
		out = append(out, trampoline{start: k.Canonical(start), size: size})
	}
	return out
}

func (s *symbolSources) bpfForm() bpfForm {
	switch {
	case s.k.Has("bpf_ksym", "lnode"):
		return bpfKsym
	case s.k.Has("bpf_prog_aux", "ksym_lnode"):
		return bpfProgAux
	}
	return bpfNone
}

func (s *symbolSources) bpfPrograms() []bpfProgram {
	var entries []uint64
	form := s.bpfForm()
	switch form {
	case bpfKsym:
		entries = s.list("bpf_kallsyms", "bpf_ksym", "lnode")
	case bpfProgAux:
		entries = s.list("bpf_kallsyms", "bpf_prog_aux", "ksym_lnode")
	}
	var out []bpfProgram
	for _, e := range entries {
		p, err := s.bpfProgram(form, e)
		if err != nil {
			s.failures.note("bpf read", err)
			continue
		}
		out = append(out, p)
	}
	return out
}

func (s *symbolSources) bpfProgram(form bpfForm, at uint64) (bpfProgram, error) {
	if form == bpfKsym {
		return s.readKsym(at)
	}
	return s.readProgAux(at)
}

func (s *symbolSources) readKsym(at uint64) (bpfProgram, error) {
	k := s.k
	start, err := k.Uint(k.mem, at, "bpf_ksym", "start")
	if err != nil {
		return bpfProgram{}, fmt.Errorf("bpf_ksym at %#x: %w", at, err)
	}
	end, err := k.Uint(k.mem, at, "bpf_ksym", "end")
	if err != nil {
		return bpfProgram{}, fmt.Errorf("bpf_ksym at %#x: %w", at, err)
	}
	name, err := k.CharArray(k.mem, at, "bpf_ksym", "name")
	if err != nil {
		return bpfProgram{}, fmt.Errorf("bpf_ksym at %#x: %w", at, err)
	}
	return bpfProgram{name: name, start: k.Canonical(start), end: k.Canonical(end)}, nil
}

func (s *symbolSources) readProgAux(aux uint64) (bpfProgram, error) {
	k := s.k
	fail := func(err error) (bpfProgram, error) {
		return bpfProgram{}, fmt.Errorf("bpf_prog_aux at %#x: %w", aux, err)
	}
	prog, err := k.Pointer(k.mem, aux, "bpf_prog_aux", "prog")
	if err != nil {
		return fail(err)
	}
	fn, err := k.Pointer(k.mem, prog, "bpf_prog", "bpf_func")
	if err != nil {
		return fail(err)
	}
	hdr := fn &^ (x86PageSize - 1)
	pages, err := k.mem.ReadAt(hdr, 4)
	if err != nil || len(pages) < 4 {
		return fail(errors.Join(errors.New("bpf_binary_header unreadable"), err))
	}
	n := uint64(pages[0]) | uint64(pages[1])<<8 | uint64(pages[2])<<16 | uint64(pages[3])<<24
	tagField, err := k.Member("bpf_prog", "tag")
	if err != nil {
		return fail(err)
	}
	tag, err := k.mem.ReadAt(prog+tagField.Offset, bpfTagBytes)
	if err != nil || len(tag) < bpfTagBytes {
		return fail(errors.Join(errors.New("bpf_prog tag unreadable"), err))
	}
	name := "bpf_prog_" + hex.EncodeToString(tag[:bpfTagBytes])
	aux2, err := k.CharArray(k.mem, aux, "bpf_prog_aux", "name")
	if err != nil {
		return fail(err)
	}
	if aux2 != "" {
		name += "_" + aux2
	}
	return bpfProgram{name: name, start: hdr, end: hdr + n*x86PageSize}, nil
}

type KallsymsLister struct {
	src *symbolSources
}

func (k *Kernel) NewKallsymsLister() *KallsymsLister {
	return &KallsymsLister{src: newSymbolSources(k)}
}

func (l *KallsymsLister) Report() SymbolFailures { return l.src.failures }

func (l *KallsymsLister) RelativeExports() bool { return l.src.relative }

func (l *KallsymsLister) ModuleSymbols() ([]KernelSymbol, error) {
	s := l.src
	model, err := s.k.Modules()
	if err != nil {
		return nil, err
	}
	view, err := model.List()
	if err != nil {
		return nil, err
	}
	if view.Walk != nil && view.Walk.Broken() {
		s.failures.note("modules list", fmt.Errorf("modules list ends after %d entries at %#x: %s",
			len(view.Walk.Entries), view.Walk.At, view.Walk.End))
	}
	reasons := make([]error, 0, len(view.Failed))
	for reason := range view.Failed {
		reasons = append(reasons, reason)
	}
	sort.Slice(reasons, func(i, j int) bool { return reasons[i].Error() < reasons[j].Error() })
	for _, reason := range reasons {
		s.failures.add("module read", reason, view.Failed[reason])
	}
	var out []KernelSymbol
	for _, mod := range view.Modules {
		if mod.State == linuxmodule.Unformed {
			continue
		}
		syms, err := model.Symbols(mod)
		if err != nil {
			s.failures.note("module symbols", fmt.Errorf("module %s at %#x: %w", mod.Name, mod.Address, err))
			continue
		}
		if syms.Unread > 0 || syms.Capped {
			s.failures.note("module symbols", fmt.Errorf("module %s at %#x: %d symbols unread, capped %t", mod.Name,
				mod.Address, syms.Unread, syms.Capped))
		}
		for _, sym := range syms.List {
			if sym.Name == "" {
				continue
			}
			out = append(out, s.moduleEntry(mod, sym))
		}
	}
	return out, nil
}

func (l *KallsymsLister) FtraceSymbols() []KernelSymbol {
	s := l.src
	var out []KernelSymbol
	for _, f := range s.ftraceFunctions() {
		out = append(out, KernelSymbol{Name: f.name, Type: "T", TypeKnown: true, Address: s.k.Masked(f.ip),
			Size: int64(f.size), Module: f.module, ModuleKnown: f.moduleKnown, Subsystem: subsystemFtrace, Exported: true})
	}
	for _, t := range s.trampolines() {
		out = append(out, KernelSymbol{Name: trampolineName, Type: "t", TypeKnown: true, Address: s.k.Masked(t.start),
			Size: int64(t.size), Module: trampolineModuleName, ModuleKnown: true, Subsystem: subsystemFtrace})
	}
	return out
}

func (l *KallsymsLister) BPFSymbols() []KernelSymbol {
	s := l.src
	var out []KernelSymbol
	for _, p := range s.bpfPrograms() {
		out = append(out, bpfEntry(s.k, p))
	}
	return out
}

func bpfEntry(k *Kernel, p bpfProgram) KernelSymbol {
	return KernelSymbol{Name: p.name, Type: "t", TypeKnown: true, Address: k.Masked(p.start), Size: int64(p.end - p.start),
		Module: bpfModuleName, ModuleKnown: true, Subsystem: subsystemBPF}
}
