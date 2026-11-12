package networkoperations

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	text0   = uint64(0xffffffff81000000)
	textEnd = text0 + 0x100000
	modBase = uint64(0xffffffffc0000000)
	mask48  = uint64(1)<<48 - 1
)

func fnptr() symbols.TypeRef {
	return symbols.TypeRef{IsPointer: true, Element: &symbols.TypeRef{Name: "void"}}
}

type fixture struct {
	k    *lt.Kernel
	mods *lt.Modules
}

func newFixture() *fixture {
	k := lt.NewKernel(1700000000, 0)
	mods := lt.AddModuleTypes(k)
	k.Table.AddStruct(symbols.StructType{Name: "seq_operations", Size: 0x20, Fields: []symbols.Field{
		{Name: "show", Offset: 0x18, Type: fnptr()}, {Name: "start", Offset: 0, Type: fnptr()},
		{Name: "stop", Offset: 8, Type: fnptr()}, {Name: "next", Offset: 0x10, Type: fnptr()},
	}})
	k.Table.AddSymbol(symbols.Symbol{Name: "_text", Address: text0})
	k.Table.AddSymbol(symbols.Symbol{Name: "_etext", Address: textEnd})
	for i, name := range []string{"seq_start", "seq_stop", "seq_next", "seq_show"} {
		k.Table.AddSymbol(symbols.Symbol{Name: name, Address: text0 + 0x100*uint64(i+1)})
	}
	return &fixture{k: k, mods: mods}
}

func (f *fixture) table(name string, start, stop, next, show uint64) uint64 {
	at := f.k.Alloc(0x20)
	for i, v := range []uint64{start, stop, next, show} {
		f.k.Mem.U64(at+8*uint64(i), v)
	}
	f.k.Table.AddSymbol(symbols.Symbol{Name: name, Address: at})
	return at
}

func plain(f *fixture, name string) uint64 {
	return f.table(name, text0+0x100, text0+0x200, text0+0x300, text0+0x400)
}

func TestRunListsEveryMemberInStructOrderWithItsOwner(t *testing.T) {
	f := newFixture()
	tcp := plain(f, "tcp4_seq_ops")
	ctx, diags := f.k.Context(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var members []string
	for _, r := range rows {
		members = append(members, r.Member)
		if r.Table != "tcp4_seq_ops" || r.ProcFile != "/proc/net/tcp" || r.TableAddress != tcp&mask48 ||
			r.TableModule != "kernel" || r.Module != "kernel" || r.Verdict != VerdictExpected {
			t.Errorf("row %+v", r)
		}
	}
	if want := []string{"start", "stop", "next", "show"}; !slices.Equal(members, want) {
		t.Errorf("members %v, want %v", members, want)
	}
	if rows[3].Symbol != "seq_show" || rows[3].TargetAddress != (text0+0x400)&mask48 {
		t.Errorf("show row %+v", rows[3])
	}
	joined := strings.Join(*diags, "\n")
	if !strings.Contains(joined, "not in the symbol table, so not checked: tcp6_seq_ops") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestRunJudgesEachTarget(t *testing.T) {
	f := newFixture()
	rk := f.mods.Add("rootkit", modBase, 0x8000, []lt.ModuleSymbol{{Name: "hide_show", Value: modBase + 0x100}}, 1)
	f.mods.List(rk)
	f.table("udp_seq_ops", 0, modBase+0x100, text0+0x301, 0xffffffffa0000000)
	ctx, _ := f.k.Context(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		module, symbol string
		v              Verdict
	}{
		{"", "", VerdictNotSet},
		{"rootkit", "hide_show", VerdictOtherModule},
		{"kernel", "", VerdictMidFunction},
		{"", "", VerdictNoOwner},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v", rows)
	}
	for i, w := range want {
		if rows[i].Module != w.module || rows[i].Symbol != w.symbol || rows[i].Verdict != w.v {
			t.Errorf("row %d: %+v, want %+v", i, rows[i], w)
		}
	}
}

func TestRunAcceptsAModuleTableWithItsOwnFunctions(t *testing.T) {
	f := newFixture()
	mod := f.mods.Add("af_packet", modBase, 0x8000, []lt.ModuleSymbol{{Name: "packet_seq_show", Value: modBase + 0x200}}, 1)
	f.mods.Region(mod, lt.RegionData, modBase+0x4000, 0x1000)
	f.mods.List(mod)
	at := modBase + 0x4000
	f.k.Mem.Map(at, 0x20)
	for i, v := range []uint64{text0 + 0x100, text0 + 0x200, text0 + 0x300, modBase + 0x200} {
		f.k.Mem.U64(at+8*uint64(i), v)
	}
	f.k.Table.AddSymbol(symbols.Symbol{Name: "packet_seq_ops", Address: at})
	ctx, _ := f.k.Context(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.TableModule != "af_packet" || r.Verdict != VerdictExpected {
			t.Errorf("row %+v", r)
		}
	}
	if rows[3].Module != "af_packet" || rows[3].Symbol != "packet_seq_show" {
		t.Errorf("show row %+v", rows[3])
	}
}

func TestRunMarksATableThatDoesNotRead(t *testing.T) {
	f := newFixture()
	f.k.Table.AddSymbol(symbols.Symbol{Name: "raw_seq_ops", Address: 0xffff888077000000})
	ctx, diags := f.k.Context(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 || rows[0].Verdict != VerdictTableUnread {
		t.Errorf("rows %+v", rows)
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "raw_seq_ops at 0x888077000000: start does not read") {
		t.Errorf("diagnostics %q", *diags)
	}
	ctx, _ = f.k.Context(map[string]any{"strict": true})
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "strict mode") {
		t.Errorf("strict: %v", err)
	}
}

func TestRunRefusesWithoutTheTypeOrAnyTable(t *testing.T) {
	f := newFixture()
	ctx, _ := f.k.Context(nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoTables) {
		t.Errorf("no tables: %v", err)
	}
	k := lt.NewKernel(1700000000, 0)
	k.Table.AddSymbol(symbols.Symbol{Name: "tcp4_seq_ops", Address: k.Alloc(0x20)})
	ctx, _ = k.Context(nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoOperationsType) {
		t.Errorf("no type: %v", err)
	}
}
