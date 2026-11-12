package generator

import (
	"errors"
	"reflect"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/btf"
	"github.com/aoiflux/libvapour/symbols/btf/btftest"
	"github.com/aoiflux/libvapour/symbols/kallsyms"
)

const shift = 0x1a000000

var banner = []byte("Linux version 6.17.0 (builder@host) #1 SMP\n\x00")

func kernelBTF(t *testing.T) *btf.Spec {
	t.Helper()
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	u64 := b.Int("long long unsigned int", 8, 0)
	head := b.Struct("list_head", 16)
	b.Struct("task_struct", 32, btftest.Member{Name: "pid", Type: i32},
		btftest.Member{Name: "tasks", Type: b.Ptr(head), BitOffset: 64})
	runqueues := b.Var("runqueues", u64, 1)
	counter := b.Var("counter", i32, 0)
	b.Datasec(percpuSection, 64, [3]uint32{runqueues, 0x10, 8}, [3]uint32{counter, 0x20, 4})
	b.Var("twice", i32, 0)
	b.Var("twice", u64, 0)
	return parse(t, b)
}

func sym(name string, typ byte, address uint64) kallsyms.Symbol {
	return kallsyms.Symbol{Name: name, Type: typ, Address: address, Offset: -1}
}

func kernel(t *testing.T, symbols ...kallsyms.Symbol) LinuxKernel {
	t.Helper()
	base := []kallsyms.Symbol{
		sym("linux_banner", 'R', 0xffffffff82000100+shift),
		sym("__per_cpu_start", 'D', 0xffffffff83000000+shift),
		sym("runqueues", 'D', 0xffffffff83000010+shift),
		sym("counter", 'd', 0xffffffff83000028+shift),
		sym("twice", 'd', 0xffffffff83000040+shift),
	}
	return LinuxKernel{Banner: banner, Symbols: append(base, symbols...), Rule: kallsyms.RuleRelative,
		VirtualShift: shift, BTF: kernelBTF(t), PointerSize: 8, Limits: limits.Default()}
}

func addresses(d symbols.Declaration) map[string]symbols.Address {
	out := map[string]symbols.Address{}
	for _, a := range d.Addresses {
		out[a.Name] = a
	}
	return out
}

func TestALinkAddressUndoesTheMoveExceptForAbsolutePerCPUValues(t *testing.T) {
	for _, c := range []struct {
		s    kallsyms.Symbol
		rule kallsyms.AddressRule
		want uint64
		ok   bool
	}{
		{kallsyms.Symbol{Address: 0xffffffff9a000000, Offset: -5}, kallsyms.RuleRelative, 0xffffffff9a000000 - shift, true},
		{kallsyms.Symbol{Address: 0xffffffff9a000000, Offset: 5}, kallsyms.RuleRelative, 0xffffffff9a000000 - shift, true},
		{kallsyms.Symbol{Address: 0x2c000, Offset: 0x2c000}, kallsyms.RuleAbsolutePercpu, 0x2c000, true},
		{kallsyms.Symbol{Address: 0xffffffff9a000000, Offset: -5}, kallsyms.RuleAbsolutePercpu, 0xffffffff9a000000 - shift, true},
		{kallsyms.Symbol{Address: 0x1000, Offset: -5}, kallsyms.RuleRelative, 0, false},
	} {
		got, ok := linkAddress(c.s, c.rule, shift)
		if got != c.want || ok != c.ok {
			t.Errorf("%+v under %v: %#x %v, want %#x %v", c.s, c.rule, got, ok, c.want, c.ok)
		}
	}
}

func TestANameKeepsOneAddressOrIsLeftOut(t *testing.T) {
	k := kernel(t,
		sym("dup_same", 't', 0xffffffff81000000+shift), sym("dup_same", 't', 0xffffffff81000000+shift),
		sym("statics", 't', 0xffffffff81001000+shift), sym("statics", 't', 0xffffffff81002000+shift),
		sym("one_global", 't', 0xffffffff81003000+shift), sym("one_global", 'T', 0xffffffff81004000+shift),
		sym("two_weak", 'W', 0xffffffff81005000+shift), sym("two_weak", 'w', 0xffffffff81006000+shift),
		sym("bad\xff", 'T', 0xffffffff81007000+shift),
		sym("low", 'T', 0x10),
		sym("", 'T', 0xffffffff81008000+shift),
	)
	d, report, err := AssembleLinux(k)
	if err != nil {
		t.Fatal(err)
	}
	got := addresses(d)
	if got["dup_same"].Address != 0xffffffff81000000 || got["one_global"].Address != 0xffffffff81004000 {
		t.Fatalf("addresses %+v %+v", got["dup_same"], got["one_global"])
	}
	for _, name := range []string{"statics", "two_weak", "bad\xff", "low", ""} {
		if _, ok := got[name]; ok {
			t.Errorf("%q kept", name)
		}
	}
	if !reflect.DeepEqual(report.Ambiguous, []string{"statics", "two_weak"}) || report.NotUTF8 != 1 ||
		report.Unplaced != 1 || report.Names != 11 {
		t.Fatalf("report %+v", report)
	}
}

func TestPerCPUVariablesTakeTheirBTFTypes(t *testing.T) {
	d, report, err := AssembleLinux(kernel(t))
	if err != nil {
		t.Fatal(err)
	}
	got := addresses(d)
	if a := got["runqueues"]; a.Type == nil || a.Type.Name != "long long unsigned int" ||
		a.Address != 0xffffffff83000010 {
		t.Fatalf("runqueues %+v", a)
	}
	if a := got["counter"]; a.Type != nil {
		t.Fatalf("a variable away from its section offset was typed: %+v", a)
	}
	if a := got["twice"]; a.Type != nil {
		t.Fatalf("variables that disagree gave a type: %+v", a)
	}
	if report.Typed != 1 || report.Misplaced != 1 || report.Untyped != 1 {
		t.Fatalf("report %+v", report)
	}
	table, err := symbols.Build("linux", d)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := table.LookupSymbol("runqueues"); err != nil || s.Address != 0xffffffff83000010 {
		t.Fatalf("runqueues: %+v %v", s, err)
	}
	if f, err := table.Field("task_struct", "tasks"); err != nil || f.Offset != 8 || !f.Type.IsPointer {
		t.Fatalf("task_struct.tasks: %+v %v", f, err)
	}
	if b, ok := table.LinuxBanner(); !ok || string(b) != string(banner) {
		t.Fatalf("banner %q", b)
	}
}

func TestAbsolutePerCPUSymbolsArePlacedWithoutTheMove(t *testing.T) {
	k := kernel(t)
	k.Rule = kallsyms.RuleAbsolutePercpu
	k.Symbols = []kallsyms.Symbol{
		sym("linux_banner", 'R', 0xffffffff82000100+shift),
		{Name: "__per_cpu_start", Type: 'A', Address: 0, Offset: 0},
		{Name: "runqueues", Type: 'D', Address: 0x10, Offset: 0x10},
	}
	d, report, err := AssembleLinux(k)
	if err != nil {
		t.Fatal(err)
	}
	if a := addresses(d)["runqueues"]; a.Address != 0x10 || a.Type == nil || report.Typed != 1 {
		t.Fatalf("runqueues %+v, report %+v", a, report)
	}
}

func TestAssemblyRefusesInputsNoTableComesFrom(t *testing.T) {
	cases := map[string]struct {
		edit func(*LinuxKernel)
		want error
	}{
		"empty banner":     {func(k *LinuxKernel) { k.Banner = nil }, ErrBanner},
		"banner nul":       {func(k *LinuxKernel) { k.Banner = []byte("Linux\x00version\n\x00") }, ErrBanner},
		"banner not utf-8": {func(k *LinuxKernel) { k.Banner = []byte("Linux \xff\n") }, ErrBanner},
		"rule":             {func(k *LinuxKernel) { k.Rule = 0 }, ErrAddressRule},
		"no btf":           {func(k *LinuxKernel) { k.BTF = nil }, ErrNoBTF},
		"pointer":          {func(k *LinuxKernel) { k.PointerSize = 16 }, ErrPointerSize},
		"no banner symbol": {func(k *LinuxKernel) { k.Symbols = k.Symbols[1:] }, ErrBannerSymbol},
		"two banners": {func(k *LinuxKernel) {
			k.Symbols = append(k.Symbols, sym("linux_banner", 'R', 0xffffffff82000200+shift))
		}, ErrBannerSymbol},
	}
	for name, c := range cases {
		k := kernel(t)
		c.edit(&k)
		if _, _, err := AssembleLinux(k); !errors.Is(err, c.want) {
			t.Errorf("%s: error %v, want %v", name, err, c.want)
		}
	}
	k := kernel(t)
	k.Banner = []byte("Linux version 6.17.0\n")
	if _, _, err := AssembleLinux(k); err != nil {
		t.Errorf("a banner without a NUL: %v", err)
	}
}
