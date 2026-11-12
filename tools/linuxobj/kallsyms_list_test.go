package linuxobj_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func rendered(syms []linuxobj.KernelSymbol) string {
	var out []string
	for _, s := range syms {
		exp := fmt.Sprint(s.Exported)
		if s.ExportedUnknown {
			exp = "unknown"
		}
		out = append(out, fmt.Sprintf("%#x %s %d %s %s %s %s", s.Address, s.Type, s.Size, exp, s.Subsystem, s.Module, s.Name))
	}
	return strings.Join(out, "\n")
}

func listedModules(absolute bool) (*lt.Kernel, *lt.KallsymsLists, uint64) {
	k := lt.NewKernel(1700000000, 0)
	l := lt.AddKallsymsLists(k, lt.AddModuleTypes(k), absolute)
	text := moduleA + 0x100
	a := l.Module("alpha", moduleA, []lt.ElfSym{
		{},
		{Name: "alpha_main", Value: text, Size: 0x40, Type: 't'},
		{Name: "alpha_table", Value: text + 0x40, Size: 8, Type: 'r'},
		{Name: "alpha_twin", Value: text + 0x80, Type: 't'},
		{Name: "", Value: text + 0x90, Type: 't'},
	}, []lt.Export{{Name: "alpha_main", Value: text}, {Name: "alpha_twin", Value: text + 0x88}})
	b := l.Module("beta", moduleB, []lt.ElfSym{{}, {Name: "beta_go", Value: moduleB + 0x10, Type: 'T'}}, nil)
	l.Mods.List(a, b)
	return k, l, a
}

func lister(k *lt.Kernel) *linuxobj.KallsymsLister {
	ctx, _ := k.Context(nil)
	return linuxobj.New(ctx).NewKallsymsLister()
}

func TestModuleSymbolsTakeTheirCaseFromTheExportTable(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		k, _, _ := listedModules(absolute)
		l := lister(k)
		syms, err := l.ModuleSymbols()
		if err != nil {
			t.Fatal(err)
		}
		want := strings.Join([]string{
			"0xffffc0000100 T 64 true module alpha alpha_main",
			"0xffffc0000140 r 8 false module alpha alpha_table",
			"0xffffc0000180 t 0 false module alpha alpha_twin",
			"0xffffc0010010 t 0 false module beta beta_go",
		}, "\n")
		if got := rendered(syms); got != want {
			t.Errorf("absolute %v:\n%s\nwant\n%s", absolute, got, want)
		}
		if l.RelativeExports() == absolute {
			t.Errorf("absolute %v: RelativeExports %v", absolute, l.RelativeExports())
		}
		if len(l.Report()) != 0 {
			t.Errorf("absolute %v: failures %v", absolute, l.Report())
		}
	}
}

func TestAnUnreadableExportTableLeavesTheCaseAsStored(t *testing.T) {
	k, _, a := listedModules(false)
	k.Mem.U64(a+lt.ModuleSyms, 0xffff800000000000)
	l := lister(k)
	syms, err := l.ModuleSymbols()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rendered(syms), "0xffffc0000100 t 64 unknown module alpha alpha_main") {
		t.Errorf("rows:\n%s", rendered(syms))
	}
	if f := l.Report()["module exports"]; f.Count != 1 || !strings.Contains(f.First, "export table") {
		t.Errorf("failure %+v", f)
	}
}

func TestUnformedModulesAreNotListed(t *testing.T) {
	k, _, a := listedModules(false)
	k.Mem.U32(a+lt.ModuleState, 3)
	syms, err := lister(k).ModuleSymbols()
	if err != nil || rendered(syms) != "0xffffc0010010 t 0 false module beta beta_go" {
		t.Errorf("rows %q, %v", rendered(syms), err)
	}
}

func TestModuleSymbolsNeedTheModulesList(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	if _, err := lister(k).ModuleSymbols(); err == nil {
		t.Errorf("no module types: no error")
	}
}

func TestFtraceAndBPFListsKeepListOrder(t *testing.T) {
	k, l, a := listedModules(false)
	l.FtraceMap(a, []lt.FtraceFunc{{Name: "alpha_init", IP: 0xffffffffd0000000, Size: 0x20},
		{Name: "alpha_late", IP: 0xffffffffd0000040, Size: 0x10}})
	l.Trampoline(0, 0x100)
	l.Trampoline(0xffffffffc0400000, 0x100)
	l.BPF("bpf_prog_6deef7357e7b4530_sd_fw_egress", 0xffffffffa0001000, 0xffffffffa0001080)
	l.BPF("bpf_prog_0000000000000000", 0xffffffffa0002000, 0xffffffffa0002010)
	ls := lister(k)
	want := strings.Join([]string{
		"0xffffd0000000 T 32 true ftrace alpha alpha_init",
		"0xffffd0000040 T 16 true ftrace alpha alpha_late",
		"0xffffc0400000 t 256 false ftrace __builtin__ftrace ftrace_trampoline",
	}, "\n")
	if got := rendered(ls.FtraceSymbols()); got != want {
		t.Errorf("ftrace:\n%s\nwant\n%s", got, want)
	}
	want = "0xffffa0001000 t 128 false bpf bpf bpf_prog_6deef7357e7b4530_sd_fw_egress\n" +
		"0xffffa0002000 t 16 false bpf bpf bpf_prog_0000000000000000"
	if got := rendered(ls.BPFSymbols()); got != want {
		t.Errorf("bpf:\n%s\nwant\n%s", got, want)
	}
}

func TestABrokenListKeepsItsEntriesAndIsReported(t *testing.T) {
	k, l, _ := listedModules(false)
	first := l.BPF("bpf_prog_1111111111111111", 0xffffffffa0001000, 0xffffffffa0001080)
	l.BPF("bpf_prog_2222222222222222", 0xffffffffa0002000, 0xffffffffa0002080)
	k.Mem.U64(first+lt.BPFKsymLnode, 0xffff800000000000)
	ls := lister(k)
	syms := ls.BPFSymbols()
	if len(syms) != 1 || syms[0].Name != "bpf_prog_1111111111111111" {
		t.Errorf("rows %q", rendered(syms))
	}
	if f := ls.Report()["bpf_kallsyms list"]; f.Count != 1 {
		t.Errorf("failures %v", ls.Report())
	}
}

func TestListsAbsentFromTheTableGiveNothing(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	ls := lister(k)
	if len(ls.FtraceSymbols()) != 0 || len(ls.BPFSymbols()) != 0 || len(ls.Report()) != 0 {
		t.Errorf("%v %v %v", ls.FtraceSymbols(), ls.BPFSymbols(), ls.Report())
	}
}
