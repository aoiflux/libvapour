package linuxobj

import (
	"fmt"
	"sort"
	"strings"

	ksyms "github.com/aoiflux/libvapour/symbols/kallsyms"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

type coreRange struct{ start, end uint64 }

type answer struct {
	sym KernelSymbol
	ok  bool
}

type Kallsyms struct {
	src *symbolSources

	core    []ksyms.Symbol
	address []uint64
	ranges  []coreRange

	tree        moduleTree
	hasTree     bool
	treeChecked bool

	bpf       bpfForm
	bpfTree   uint64
	ftrace    []ftraceFunction
	tramps    []trampoline
	ftraceRan bool

	answers map[uint64]answer
}

var tableSeeds = []struct {
	name string
	into func(*ksyms.Seeds) *uint64
}{
	{"kallsyms_num_syms", func(s *ksyms.Seeds) *uint64 { return &s.NumSyms }},
	{"kallsyms_names", func(s *ksyms.Seeds) *uint64 { return &s.Names }},
	{"kallsyms_token_table", func(s *ksyms.Seeds) *uint64 { return &s.TokenTable }},
	{"kallsyms_token_index", func(s *ksyms.Seeds) *uint64 { return &s.TokenIndex }},
	{"kallsyms_offsets", func(s *ksyms.Seeds) *uint64 { return &s.Offsets }},
	{"kallsyms_relative_base", func(s *ksyms.Seeds) *uint64 { return &s.RelativeBase }},
	{"_stext", func(s *ksyms.Seeds) *uint64 { return &s.Stext }},
}

func (k *Kernel) NewKallsyms() (*Kallsyms, error) {
	var seeds ksyms.Seeds
	for _, t := range tableSeeds {
		s, err := k.Symbol(t.name)
		if err != nil {
			return nil, err
		}
		*t.into(&seeds) = s.Address
	}
	etext, err := k.Symbol("_etext")
	if err != nil {
		return nil, err
	}
	table, err := ksyms.Decode(k.mem, seeds, k.ctx.Bounds())
	if err != nil {
		return nil, fmt.Errorf("linuxobj: kallsyms table: %w", err)
	}
	s := &Kallsyms{src: newSymbolSources(k), core: table.Symbols, answers: map[uint64]answer{}}
	s.address = make([]uint64, len(table.Symbols))
	for i, sym := range table.Symbols {
		s.address[i] = k.Canonical(sym.Address)
	}
	bound := func(name string) (uint64, bool) {
		v, err := k.Symbol(name)
		return v.Address, err == nil
	}
	text := coreRange{seeds.Stext, etext.Address}
	init := coreRange{}
	if a, ok := bound("_sinittext"); ok {
		if b, ok := bound("_einittext"); ok {
			init = coreRange{a, b}
		}
	}
	s.ranges = []coreRange{text, init}
	if s.allSymbols(text, init) {
		s.ranges = nil
		if end, ok := bound("_end"); ok {
			s.ranges = append(s.ranges, coreRange{seeds.Stext, end})
		}
		if a, ok := bound("__init_begin"); ok {
			if b, ok := bound("__init_end"); ok {
				s.ranges = append(s.ranges, coreRange{a, b})
			}
		}
	}
	s.bpf = s.src.bpfForm()
	if t, err := k.Symbol("bpf_tree"); err == nil {
		s.bpfTree = t.Address
	}
	return s, nil
}

// allSymbols tells a table built with --all-symbols by a symbol outside the
// two text ranges, which the build keeps only with that flag.
func (s *Kallsyms) allSymbols(text, init coreRange) bool {
	for i, sym := range s.core {
		if strings.HasPrefix(sym.Name, "__start_") || strings.HasPrefix(sym.Name, "__stop_") {
			continue
		}
		a := s.address[i]
		inText := a >= text.start && a <= text.end
		inInit := init.end != 0 && a >= init.start && a <= init.end
		if !inText && !inInit {
			return true
		}
	}
	return false
}

func (s *Kallsyms) Report() SymbolFailures { return s.src.failures }

func (s *Kallsyms) SymbolAt(address uint64) (KernelSymbol, bool) {
	a := s.src.k.Canonical(address)
	if r, ok := s.answers[a]; ok {
		return r.sym, r.ok
	}
	sym, ok := s.resolve(a)
	s.answers[a] = answer{sym, ok}
	return sym, ok
}

func (s *Kallsyms) resolve(a uint64) (KernelSymbol, bool) {
	if s.inCore(a) {
		return s.coreAnswer(a)
	}
	for _, step := range []func(uint64) (KernelSymbol, bool){s.moduleAnswer, s.bpfAnswer, s.ftraceAnswer, s.trampolineAnswer} {
		if sym, ok := step(a); ok {
			return sym, true
		}
	}
	return KernelSymbol{}, false
}

func (s *Kallsyms) inCore(a uint64) bool {
	for _, r := range s.ranges {
		if r.end != 0 && a >= r.start && a < r.end {
			return true
		}
	}
	return false
}

func (s *Kallsyms) coreAnswer(a uint64) (KernelSymbol, bool) {
	i := sort.Search(len(s.address), func(i int) bool { return s.address[i] > a }) - 1
	if i < 0 {
		return KernelSymbol{}, false
	}
	for i > 0 && s.address[i-1] == s.address[i] {
		i--
	}
	sym := s.core[i]
	if sym.Name == "" {
		return KernelSymbol{}, false
	}
	out := KernelSymbol{Name: sym.Name, TypeKnown: sym.Type != 0, Address: s.src.k.Masked(s.address[i]),
		Offset: a - s.address[i], Size: sym.Size, Module: linuxmodule.KernelOwner, ModuleKnown: true,
		Subsystem: subsystemCore, ExportedUnknown: true}
	if out.TypeKnown {
		out.Type = string(sym.Type)
	}
	return out, true
}

func (s *Kallsyms) owner(model *linuxmodule.Model, a uint64) (uint64, bool) {
	k := s.src.k
	if !s.treeChecked {
		t, ok, err := k.moduleTree()
		if err != nil {
			s.src.failures.note("module tree", err)
		}
		s.tree, s.hasTree, s.treeChecked = t, ok, true
	}
	if s.hasTree {
		mod, err := k.treeOwner(s.tree, a)
		if err != nil {
			s.src.failures.note("module tree", fmt.Errorf("mod_tree at %#x: %w", s.tree.root, err))
			return 0, false
		}
		return mod, mod != 0
	}
	view, err := model.List()
	if err != nil {
		s.src.failures.note("module list", err)
		return 0, false
	}
	for _, mod := range view.Modules {
		if mod.Holds(a) {
			return mod.Address, true
		}
	}
	return 0, false
}

func (s *Kallsyms) moduleAnswer(a uint64) (KernelSymbol, bool) {
	k := s.src.k
	if !k.HasSymbol("modules") && !k.HasSymbol("mod_tree") {
		return KernelSymbol{}, false
	}
	model, err := k.Modules()
	if err != nil {
		s.src.failures.note("module model", err)
		return KernelSymbol{}, false
	}
	at, ok := s.owner(model, a)
	if !ok {
		return KernelSymbol{}, false
	}
	mod, err := model.Read(at)
	if err != nil {
		s.src.failures.note("module read", fmt.Errorf("module at %#x: %w", at, err))
		return KernelSymbol{}, false
	}
	if mod.State == linuxmodule.Unformed {
		return KernelSymbol{}, false
	}
	if !mod.Holds(a) {
		s.src.failures.note("module tree", fmt.Errorf("module %s at %#x: address %#x: %w", mod.Name, at, a, ErrTreeModule))
		return KernelSymbol{}, false
	}
	syms, err := model.Symbols(mod)
	if err != nil {
		s.src.failures.note("module symbols", fmt.Errorf("module %s at %#x: %w", mod.Name, at, err))
		return KernelSymbol{}, false
	}
	best, end, ok := nearestModuleSymbol(mod, syms.List, a)
	if !ok {
		return KernelSymbol{}, false
	}
	out := s.src.moduleEntry(mod, best)
	out.Offset = a - best.Address
	out.Size = int64(end - best.Address)
	return out, true
}

// mappingName is the S06 F13 test at its widest tag.
func mappingName(name string) bool {
	return strings.HasPrefix(name, "$") || strings.HasPrefix(name, ".L") || strings.HasPrefix(name, "L0")
}

// The returned end is where the best symbol's size stops (S38 M6).
func nearestModuleSymbol(mod linuxmodule.Module, list []linuxmodule.Symbol, a uint64) (linuxmodule.Symbol, uint64, bool) {
	textKind := linuxmodule.Text
	if r, ok := mod.RegionOf(a); ok && r.Kind.Init() {
		textKind = linuxmodule.InitText
	}
	var end uint64
	for _, r := range mod.Regions {
		if r.Kind == textKind {
			end = r.End()
		}
	}
	var best linuxmodule.Symbol
	found := false
	for _, sym := range list {
		if sym.Section == 0 || sym.Name == "" || mappingName(sym.Name) || sym.Address == 0 {
			continue
		}
		if sym.Address <= a && (!found || sym.Address > best.Address) {
			best, found = sym, true
		}
		if sym.Address > a && sym.Address < end {
			end = sym.Address
		}
	}
	if !found || end < best.Address {
		return best, best.Address, found
	}
	return best, end, true
}

func (s *Kallsyms) bpfAnswer(a uint64) (KernelSymbol, bool) {
	k := s.src.k
	if s.bpf == bpfNone || s.bpfTree == 0 {
		return KernelSymbol{}, false
	}
	var node uint64
	switch s.bpf {
	case bpfKsym:
		f, err := k.Member("bpf_ksym", "tnode")
		if err != nil {
			return KernelSymbol{}, false
		}
		node = f.Offset
	default:
		f, err := k.Member("bpf_prog_aux", "ksym_tnode")
		if err != nil {
			return KernelSymbol{}, false
		}
		node = f.Offset
	}
	var hit bpfProgram
	ltn, found, err := k.LatchTreeFind(s.bpfTree, func(n uint64) (int, error) {
		p, err := s.src.bpfProgram(s.bpf, n-node)
		if err != nil {
			return 0, err
		}
		hit = p
		switch {
		case a < p.start:
			return -1, nil
		case s.bpf == bpfKsym && a > p.end, s.bpf == bpfProgAux && a >= p.end:
			return 1, nil
		}
		return 0, nil
	})
	if err != nil {
		s.src.failures.note("bpf tree", fmt.Errorf("bpf_tree at %#x: %w", s.bpfTree, err))
		return KernelSymbol{}, false
	}
	if !found || ltn == 0 {
		return KernelSymbol{}, false
	}
	out := bpfEntry(k, hit)
	out.Offset = a - hit.start
	return out, true
}

func (s *Kallsyms) ftraceLists() {
	if !s.ftraceRan {
		s.ftrace, s.tramps, s.ftraceRan = s.src.ftraceFunctions(), s.src.trampolines(), true
	}
}

func (s *Kallsyms) ftraceAnswer(a uint64) (KernelSymbol, bool) {
	s.ftraceLists()
	for _, f := range s.ftrace {
		if a >= f.ip && a-f.ip < f.size {
			return KernelSymbol{Name: f.name, Type: "T", TypeKnown: true, Address: s.src.k.Masked(f.ip), Offset: a - f.ip,
				Size: int64(f.size), Module: f.module, ModuleKnown: f.moduleKnown, Subsystem: subsystemFtrace,
				Exported: true}, true
		}
	}
	return KernelSymbol{}, false
}

func (s *Kallsyms) trampolineAnswer(a uint64) (KernelSymbol, bool) {
	s.ftraceLists()
	for _, t := range s.tramps {
		if a >= t.start && a-t.start < t.size {
			return KernelSymbol{Name: trampolineName, Type: "t", TypeKnown: true, Address: s.src.k.Masked(t.start),
				Offset: a - t.start, Size: int64(t.size), Module: trampolineModuleName, ModuleKnown: true,
				Subsystem: subsystemFtrace}, true
		}
	}
	return KernelSymbol{}, false
}
