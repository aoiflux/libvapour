package modulelist

import (
	"testing"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

var placed = []Module{
	{Entry: 0x10, Base: 0xfffff80001000000, Size: 0x100000, Name: "ntoskrnl.exe"},
	{Entry: 0x20, Base: 0xfffff80003000000, Size: 0x6000, Name: "kdcom.dll"},
	{Entry: 0x30, Base: 0xfffff80003000000, Size: 0x6000, Name: "", NameUnreadable: true},
	{Entry: 0x40, Base: 0xfffff80004000000, SizeUnreadable: true, Name: "lost.sys"},
	{Entry: 0x50, Base: 0xfffffffffffff000, Size: 0x2000, Name: "top.sys"},
}

func TestARangeHoldsItsFirstByteAndNotTheByteAfterIt(t *testing.T) {
	for _, tc := range []struct {
		at   uint64
		want []uint64
	}{
		{0xfffff80001000000, []uint64{0x10}},
		{0xfffff800010fffff, []uint64{0x10}},
		{0xfffff80001100000, nil},
		{0xfffff80003000010, []uint64{0x20, 0x30}},
		{0xfffff80004000000, nil},
		{0xffffffffffffffff, []uint64{0x50}},
		{0x10, nil},
	} {
		got := Containing(placed, tc.at)
		if len(got) != len(tc.want) {
			t.Errorf("0x%x: %+v, want entries %x", tc.at, got, tc.want)
			continue
		}
		for i := range got {
			if got[i].Entry != tc.want[i] {
				t.Errorf("0x%x: entry 0x%x, want 0x%x", tc.at, got[i].Entry, tc.want[i])
			}
		}
	}
}

func TestPlacedDropsAndNamesTheModulesWithoutARange(t *testing.T) {
	ctx, diags := windowsContext(sparse{}, symbols.NewTable("s", 8), nil)
	mods := append([]Module{{Entry: 0x60, BaseUnreadable: true}}, placed...)
	if got := Placed(ctx, "t", mods); len(got) != 4 {
		t.Errorf("%d placed, want 4", len(got))
	}
	want := "t: loader entries at 0x60, 0x40: base or size does not read: no address is attributed to them"
	if !hasDiag(*diags, want) {
		t.Errorf("diagnostics %q, want %q", *diags, want)
	}
}

func TestTheDisplayNameDropsTheLastExtension(t *testing.T) {
	for in, want := range map[string]string{
		"ntoskrnl.exe": "ntoskrnl", "a.b.sys": "a.b", "...": "...", ".sys": ".sys", "..sys": "..sys",
		`\x\y.sys`: `\x\y`, `dir.d\file`: `dir.d\file`, "dir.d/file": "dir.d/file", "plain": "plain", "": "",
	} {
		if got := DisplayName(Module{Name: in}); got != want {
			t.Errorf("DisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}

func symbolTable() *symbols.Table {
	t := symbols.NewTable("k", 8)
	t.AddSymbol(symbols.Symbol{Name: "KeExpireTimers", Address: 0xfffff80001000100})
	t.AddSymbol(symbols.Symbol{Name: "KdInit", Address: 0xfffff80003000100})
	t.AddSymbol(symbols.Symbol{Name: "PsLoadedModuleList", Address: 0xfffff80001080000})
	return t
}

func attributionContext(tab symbols.SymbolTable, opts map[string]any) tools.Context {
	return tools.Context{Memory: sparse{}, Symbols: tab, Profile: profiles.WindowsX64Profile{}, Options: opts}
}

func TestSymbolsNameOnlyAddressesInsideTheKernelImage(t *testing.T) {
	a := NewAttributor(attributionContext(symbolTable(), map[string]any{}), placed)
	if !a.SymbolModuleKnown() {
		t.Fatal("the kernel image was not found through PsLoadedModuleList")
	}
	if got := a.At(0xfffff80001000100); len(got) != 1 || got[0] != (Attribution{Module: "ntoskrnl", Symbol: "KeExpireTimers"}) {
		t.Errorf("kernel address: %+v", got)
	}
	got := a.At(0xfffff80003000100)
	want := []Attribution{{Module: "kdcom"}, {Module: "", ModuleUnreadable: true}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("driver address: %+v, want %+v and no kernel symbol", got, want)
	}
	if got := a.At(0x1000); got != nil {
		t.Errorf("an address in no module: %+v", got)
	}
}

func TestTheKernelImageComesFromTheAnchorThenTheBaseThenTheListHead(t *testing.T) {
	tab := symbolTable()
	anchored := NewAttributorAnchoredAt(attributionContext(tab, map[string]any{}), placed, 0xfffff80003000004)
	if got := anchored.At(0xfffff80003000100); got[0].Symbol != "KdInit" {
		t.Errorf("anchored in kdcom: %+v, want the table's names there", got)
	}
	based := NewAttributor(attributionContext(tab, map[string]any{tools.OptionKernelBase: uint64(0xfffff80003000000)}), placed)
	if got := based.At(0xfffff80003000100); got[0].Symbol != "KdInit" {
		t.Errorf("kernel base at kdcom: %+v", got)
	}
	bare := symbols.NewTable("bare", 8)
	none := NewAttributor(attributionContext(bare, map[string]any{}), placed)
	if none.SymbolModuleKnown() {
		t.Error("a kernel image was found with no anchor, base or list head")
	}
	if got := none.At(0xfffff80001000100); len(got) != 1 || got[0].Symbol != "" || got[0].Module != "ntoskrnl" {
		t.Errorf("unknown kernel image: %+v", got)
	}
}
