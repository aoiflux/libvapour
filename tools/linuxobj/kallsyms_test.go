package linuxobj_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	textBase  uint64 = 0xffffffff81000000
	moduleA   uint64 = 0xffffffffc0000000
	moduleB   uint64 = 0xffffffffc0010000
	moduleC   uint64 = 0xffffffffc0020000
	initBText uint64 = 0xffffffffc0030000
)

func coreSymbols(all bool) []lt.KSym {
	syms := []lt.KSym{
		{Type: 'T', Name: "_stext", Address: textBase},
		{Type: 'T', Name: "startup_64", Address: textBase},
		{Type: 't', Name: "alpha", Address: textBase + 0x100},
		{Type: 0, Name: "", Address: textBase + 0x300},
		{Type: 'T', Name: "omega", Address: textBase + 0x400},
		{Type: 'T', Name: "_etext", Address: textBase + 0x1000},
		{Type: 'T', Name: "_sinittext", Address: textBase + 0x2000},
		{Type: 't', Name: "early_setup", Address: textBase + 0x2010},
		{Type: 'T', Name: "_einittext", Address: textBase + 0x2100},
	}
	if all {
		syms = append(syms, lt.KSym{Type: 'd', Name: "jiffies_data", Address: textBase + 0x5000},
			lt.KSym{Type: 'B', Name: "_end", Address: textBase + 0x6000})
	}
	return syms
}

func kallsymsKernel(t *testing.T, k *lt.Kernel) *linuxobj.Kallsyms {
	t.Helper()
	ctx, _ := k.Context(nil)
	ks, err := linuxobj.New(ctx).NewKallsyms()
	if err != nil {
		t.Fatalf("NewKallsyms: %v", err)
	}
	return ks
}

func name(ks *linuxobj.Kallsyms, a uint64) string {
	s, ok := ks.SymbolAt(a)
	if !ok {
		return "-"
	}
	return s.Name
}

func TestCoreAnswersFollowTheTableOrderAndSizes(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	k.AddKallsyms(textBase, coreSymbols(false))
	ks := kallsymsKernel(t, k)

	s, ok := ks.SymbolAt(textBase + 0x150)
	if !ok || s.Name != "alpha" || s.Type != "t" || s.Offset != 0x50 || s.Size != 0x200 || s.Module != "kernel" ||
		s.Subsystem != "core" || s.Address != (textBase+0x100)&(1<<48-1) || !s.ExportedUnknown {
		t.Errorf("alpha: %+v %v", s, ok)
	}
	if got := name(ks, textBase+0x10); got != "_stext" {
		t.Errorf("alias: %q, want the first of the equal addresses", got)
	}
	if got := name(ks, textBase+0x310); got != "-" {
		t.Errorf("empty name: %q, want no answer", got)
	}
	if s, ok := ks.SymbolAt(textBase + 0x2050); !ok || s.Name != "early_setup" || s.Size != 0xf0 {
		t.Errorf("init text: %+v %v", s, ok)
	}
	for _, a := range []uint64{textBase - 1, textBase + 0x1000, textBase + 0x1500, textBase + 0x2100, textBase + 0x5010} {
		if got := name(ks, a); got != "-" {
			t.Errorf("%#x outside the text ranges: %q", a, got)
		}
	}
}

func TestATableWithDataSymbolsWidensTheCoreRange(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	k.AddKallsyms(textBase, coreSymbols(true))
	k.Table.AddSymbol(symbols.Symbol{Name: "__init_begin", Address: textBase + 0x2000})
	k.Table.AddSymbol(symbols.Symbol{Name: "__init_end", Address: textBase + 0x3000})
	ks := kallsymsKernel(t, k)
	if s, ok := ks.SymbolAt(textBase + 0x5010); !ok || s.Name != "jiffies_data" || s.Type != "d" {
		t.Errorf("data symbol: %+v %v", s, ok)
	}
	if got := name(ks, textBase+0x1500); got != "_etext" {
		t.Errorf("between _etext and _sinittext: %q, want the symbol below it", got)
	}
	if got := name(ks, textBase+0x2800); got != "_einittext" {
		t.Errorf("init data: %q", got)
	}
	if got := name(ks, textBase+0x6000); got != "-" {
		t.Errorf("_end itself: %q", got)
	}
}

func TestNewKallsymsNeedsTheTableSymbols(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	ctx, _ := k.Context(nil)
	if _, err := linuxobj.New(ctx).NewKallsyms(); err == nil || !strings.Contains(err.Error(), "kallsyms_num_syms") {
		t.Errorf("no table: %v", err)
	}
}

type treeKernel struct {
	k    *lt.Kernel
	mods *lt.Modules
	tree *lt.ModuleTree
}

func newTreeKernel() *treeKernel {
	k := lt.NewKernel(1700000000, 0)
	k.AddKallsyms(textBase, coreSymbols(false))
	mods := lt.AddModuleTypes(k)
	tree := lt.AddModuleTree(k, mods)
	mods.Add("alpha", moduleA, 0x1000, []lt.ModuleSymbol{{Name: "alpha_open", Value: moduleA + 0x100},
		{Name: "alpha_read", Value: moduleA + 0x200}, {Name: "$x", Value: moduleA + 0x180}}, 1)
	mods.Add("beta", moduleB, 0x1000, []lt.ModuleSymbol{{Name: "beta_main", Value: moduleB + 0x10},
		{Name: "beta_init", Value: initBText + 0x20}}, 1)
	mods.Region(moduleB, 4, initBText, 0x800)
	mods.Add("gamma", moduleC, 0x1000, []lt.ModuleSymbol{{Name: "gamma_hidden", Value: moduleC + 0x40}}, 1)
	mods.List(moduleA, moduleB)
	tree.Bounds(moduleA, initBText+0x800)
	tree.Build(0, lt.RegionRef{Module: moduleA}, lt.RegionRef{Module: moduleB}, lt.RegionRef{Module: moduleC},
		lt.RegionRef{Module: moduleB, Kind: 4})
	return &treeKernel{k: k, mods: mods, tree: tree}
}

func TestTheModuleTreeNamesModuleAddresses(t *testing.T) {
	tk := newTreeKernel()
	ks := kallsymsKernel(t, tk.k)
	for _, c := range []struct {
		addr          uint64
		name, module  string
		offset, size  uint64
		noAnswerCause string
	}{
		{addr: moduleA + 0x150, name: "alpha_open", module: "alpha", offset: 0x50, size: 0x100},
		{addr: moduleA + 0x1f0, name: "alpha_open", module: "alpha", offset: 0xf0, size: 0x100},
		{addr: moduleA + 0x250, name: "alpha_read", module: "alpha", offset: 0x50, size: 0xe00},
		{addr: initBText + 0x30, name: "beta_init", module: "beta", offset: 0x10, size: 0x7e0},
		{addr: moduleC + 0x44, name: "gamma_hidden", module: "gamma", offset: 4, size: 0xfc0},
	} {
		s, ok := ks.SymbolAt(c.addr)
		if !ok || s.Name != c.name || s.Module != c.module || s.Offset != c.offset || uint64(s.Size) != c.size ||
			s.Subsystem != "module" || s.Type != "t" || !s.ExportedUnknown {
			t.Errorf("%#x: %+v %v, want %s in %s +%#x size %#x", c.addr, s, ok, c.name, c.module, c.offset, c.size)
		}
	}
	if got := name(ks, moduleA+0x50); got != "-" {
		t.Errorf("below every symbol: %q", got)
	}
	if got := name(ks, moduleA-0x10); got != "-" {
		t.Errorf("below addr_min: %q", got)
	}
	if len(ks.Report()) != 0 {
		t.Errorf("failures: %v", ks.Report())
	}
}

func TestTheSequenceChoosesTheTreeCopy(t *testing.T) {
	tk := newTreeKernel()
	tk.tree.Build(1, lt.RegionRef{Module: moduleA}, lt.RegionRef{Module: moduleB})
	tk.k.Mem.U64(tk.tree.Root+lt.LatchRootTree, 0x1234)
	ks := kallsymsKernel(t, tk.k)
	if got := name(ks, moduleB+0x20); got != "beta_main" {
		t.Errorf("odd sequence: %q, want the second copy's answer", got)
	}
	tk.k.Mem.U32(tk.tree.Root, 2)
	ks = kallsymsKernel(t, tk.k)
	if got := name(ks, moduleB+0x20); got != "-" || ks.Report()["module tree"].Count != 1 {
		t.Errorf("even sequence over a broken first copy: %q, failures %v", got, ks.Report())
	}
}

func TestBrokenTreesAreCountedFailures(t *testing.T) {
	tk := newTreeKernel()
	root := lt.RegionNode(lt.RegionRef{Module: moduleC})
	tk.k.Mem.U64(root+lt.RBNodeLeft, root)
	ks := kallsymsKernel(t, tk.k)
	if got := name(ks, moduleA+0x150); got != "-" {
		t.Errorf("cycle: %q", got)
	}
	f := ks.Report()["module tree"]
	if f.Count != 1 || !strings.Contains(f.First, "reached twice") {
		t.Errorf("cycle failure: %+v", f)
	}

	tk = newTreeKernel()
	tk.k.Mem.U64(lt.RegionNode(lt.RegionRef{Module: moduleC})-lt.ModTreeNodeNode, moduleA)
	ks = kallsymsKernel(t, tk.k)
	if got := name(ks, moduleC+0x44); got != "-" || !strings.Contains(ks.Report()["module tree"].First, "does not hold") {
		t.Errorf("node of another module: %q %v", got, ks.Report())
	}
}

func TestDepthIsBounded(t *testing.T) {
	tk := newTreeKernel()
	ctx, _ := tk.k.Context(nil)
	ctx.Limits.MaxRecursionDepth = 1
	ks, err := linuxobj.New(ctx).NewKallsyms()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ks.SymbolAt(moduleA + 0x150); ok {
		t.Errorf("a leaf two steps down answered with depth 1")
	}
	if f := ks.Report()["module tree"]; !strings.Contains(f.First, "MaxRecursionDepth") {
		t.Errorf("failure %+v", f)
	}
}

func TestWithoutATreeTheModulesListAnswers(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	k.AddKallsyms(textBase, coreSymbols(false))
	mods := lt.AddModuleTypes(k)
	mods.Add("alpha", moduleA, 0x1000, []lt.ModuleSymbol{{Name: "alpha_open", Value: moduleA + 0x100}}, 1)
	mods.Add("gamma", moduleC, 0x1000, []lt.ModuleSymbol{{Name: "gamma_hidden", Value: moduleC + 0x40}}, 1)
	mods.List(moduleA)
	ks := kallsymsKernel(t, k)
	if got := name(ks, moduleA+0x110); got != "alpha_open" {
		t.Errorf("listed module: %q", got)
	}
	if got := name(ks, moduleC+0x44); got != "-" {
		t.Errorf("unlisted module without a tree: %q", got)
	}
}

func TestAnUnformedModuleGivesNoAnswer(t *testing.T) {
	tk := newTreeKernel()
	tk.k.Mem.U32(moduleA+lt.ModuleState, 3)
	ks := kallsymsKernel(t, tk.k)
	if got := name(ks, moduleA+0x150); got != "-" {
		t.Errorf("unformed: %q", got)
	}
}

func listsKernel() (*lt.Kernel, *lt.KallsymsLists) {
	k := lt.NewKernel(1700000000, 0)
	k.AddKallsyms(textBase, coreSymbols(false))
	l := lt.AddKallsymsLists(k, lt.AddModuleTypes(k), false)
	return k, l
}

func TestBPFProgramsAnswerThroughTheirTree(t *testing.T) {
	k, l := listsKernel()
	a := l.BPF("bpf_prog_0123456789abcdef_first", 0xffffffffa0001000, 0xffffffffa0001080)
	b := l.BPF("bpf_prog_fedcba9876543210_second", 0xffffffffa0002000, 0xffffffffa0002100)
	l.BPFTree(0, a, b)
	ks := kallsymsKernel(t, k)
	s, ok := ks.SymbolAt(0xffffffffa0002010)
	if !ok || s.Name != "bpf_prog_fedcba9876543210_second" || s.Offset != 0x10 || s.Size != 0x100 || s.Type != "t" ||
		s.Module != "bpf" || s.Subsystem != "bpf" || s.Exported {
		t.Errorf("second: %+v %v", s, ok)
	}
	if got := name(ks, 0xffffffffa0001080); got != "bpf_prog_0123456789abcdef_first" {
		t.Errorf("end address: %q, want the program it ends", got)
	}
	if got := name(ks, 0xffffffffa0001081); got != "-" {
		t.Errorf("past the end: %q", got)
	}
}

func TestOldBPFProgramsAreNamedFromTagAndName(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	k.AddKallsyms(textBase, coreSymbols(false))
	p := lt.AddProgAux(k)
	p.Add(lt.BPFProgram{Name: "", Tag: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, Func: 0xffffffffa0000040, Pages: 1})
	p.Add(lt.BPFProgram{Name: "sd_fw", Tag: [8]byte{0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 0xff}, Func: 0xffffffffa0004020, Pages: 2})
	ks := kallsymsKernel(t, k)
	s, ok := ks.SymbolAt(0xffffffffa0005ff0)
	if !ok || s.Name != "bpf_prog_deadbeef000102ff_sd_fw" || s.Offset != 0x1ff0 || s.Size != 0x2000 {
		t.Errorf("v4.19 form: %+v %v", s, ok)
	}
	if got := name(ks, 0xffffffffa0000ffc); got != "bpf_prog_0102030405060708" {
		t.Errorf("unnamed program: %q", got)
	}
	if got := name(ks, 0xffffffffa0006000); got != "-" {
		t.Errorf("past the pages: %q", got)
	}
	ctx, _ := k.Context(nil)
	syms := linuxobj.New(ctx).NewKallsymsLister().BPFSymbols()
	if len(syms) != 2 || syms[1].Name != "bpf_prog_deadbeef000102ff_sd_fw" || syms[1].Address != 0xffffa0004000 {
		t.Errorf("listed: %+v", syms)
	}
}

func TestFtraceFunctionsAndTrampolinesAnswerLast(t *testing.T) {
	k, l := listsKernel()
	m := l.Module("alpha", moduleA, nil, nil)
	l.Mods.List(m)
	l.FtraceMap(m, []lt.FtraceFunc{{Name: "alpha_init", IP: 0xffffffffd0000000, Size: 0x20}})
	l.Trampoline(0xffffffffc0400000, 0x100)
	ks := kallsymsKernel(t, k)
	s, ok := ks.SymbolAt(0xffffffffd0000010)
	if !ok || s.Name != "alpha_init" || s.Module != "alpha" || s.Type != "T" || !s.Exported || s.Subsystem != "ftrace" ||
		s.Offset != 0x10 {
		t.Errorf("freed init function: %+v %v", s, ok)
	}
	s, ok = ks.SymbolAt(0xffffffffc04000ff)
	if !ok || s.Name != "ftrace_trampoline" || s.Module != "__builtin__ftrace" || s.Exported || s.Size != 0x100 {
		t.Errorf("trampoline: %+v %v", s, ok)
	}
	if got := name(ks, 0xffffffffc0400100); got != "-" {
		t.Errorf("past the trampoline: %q", got)
	}
}

func TestLatchTreeFindReportsReadsThatFail(t *testing.T) {
	tk := newTreeKernel()
	ctx, _ := tk.k.Context(nil)
	kk := linuxobj.New(ctx)
	_, _, err := kk.LatchTreeFind(0xffff800000000000, func(uint64) (int, error) { return 0, nil })
	if !errors.Is(err, linuxobj.ErrLatchTreeRead) {
		t.Errorf("unmapped root: %v", err)
	}
	stop := errors.New("stop")
	if _, _, err := kk.LatchTreeFind(tk.tree.Root, func(uint64) (int, error) { return 0, stop }); !errors.Is(err, stop) {
		t.Errorf("compare error: %v", err)
	}
	node, found, err := kk.LatchTreeFind(tk.tree.Root, func(n uint64) (int, error) {
		if n == lt.RegionNode(lt.RegionRef{Module: moduleA}) {
			return 0, nil
		}
		return -1, nil
	})
	if err != nil || !found || node != lt.RegionNode(lt.RegionRef{Module: moduleA}) {
		t.Errorf("leftmost: %#x %v %v", node, found, err)
	}
}
