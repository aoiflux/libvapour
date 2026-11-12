package syscalllist

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const (
	mask     = 1<<48 - 1
	shift    = 0x2000000
	tableAt  = kerntest.Data + 0x40000
	ia32At   = kerntest.Data + 0x50000
	handlers = kerntest.Text + 0x2000
	niAt     = kerntest.Text + 0x100
	modAt    = kerntest.ModuleArea + 0x10000
	modBase  = kerntest.ModuleArea + 0x40000
)

type sysFixture struct {
	*kerntest.Fixture
	entries  []uint64
	ia32     []uint64
	padding  int
	declared bool
}

// Entry values are link-time addresses; 0 stays 0.
func newSys(n int) *sysFixture {
	f := &sysFixture{Fixture: kerntest.NewFixture(shift), padding: 2}
	for i := range n {
		f.entries = append(f.entries, handlers+uint64(i)*0x40)
	}
	return f
}

func (f *sysFixture) layout(name string, at uint64, entries []uint64) {
	i := f.Types
	typ := kerntest.Arr(0, kerntest.Ptr(kerntest.Fn()))
	if f.declared {
		typ = kerntest.Arr(uint64(len(entries)), kerntest.Ptr(kerntest.Fn()))
	}
	i.Symbol(name, at, typ)
	i.Symbol(name+"_next", at+uint64(len(entries)+f.padding)*8, kerntest.Base("int"))
	f.Mem.Map(at+f.Shift, uint64(len(entries)+f.padding)*8+8)
	for n, e := range entries {
		if e != 0 && e >= kerntest.Text && e < kerntest.Etext {
			e += f.Shift
		}
		f.Mem.U64(at+f.Shift+uint64(n)*8, e)
	}
}

func (f *sysFixture) context(t testing.TB, opts map[string]any) (tools.Context, *[]string) {
	t.Helper()
	f.layout("sys_call_table", tableAt, f.entries)
	if f.ia32 != nil {
		f.layout("ia32_sys_call_table", ia32At, f.ia32)
	}
	i := f.Types
	for n := range f.entries {
		i.Symbol("__x64_sys_call"+string(rune('a'+n%26))+strings.Repeat("x", n/26), handlers+uint64(n)*0x40, kerntest.Fn())
	}
	for _, name := range []string{"__do_sys_ni_syscall", "__ia32_sys_ni_syscall", "__x64_sys_ni_syscall"} {
		i.Symbol(name, niAt, kerntest.Fn())
	}
	return f.Context(t, opts)
}

func run(t *testing.T, f *sysFixture, opts map[string]any) ([]Row, []string) {
	t.Helper()
	ctx, diags := f.context(t, opts)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return rows, *diags
}

func TestTheTableEndsBeforeTheNextSymbolWithoutTrailingNulls(t *testing.T) {
	f := newSys(5)
	f.entries[2] = niAt
	rows, diags := run(t, f, nil)
	if len(rows) != 5 {
		t.Fatalf("%d rows, want 5: %+v", len(rows), rows)
	}
	for i, r := range rows {
		if r.TableName != "sys_call_table" || r.TableAddress != (tableAt+shift)&mask || r.Index != uint64(i) ||
			r.Module != linuxmodule.KernelOwner || !r.Dispatches {
			t.Errorf("row %d %+v", i, r)
		}
	}
	if rows[0].HandlerAddress != (handlers+shift)&mask || rows[0].HandlerSymbol != "__x64_sys_calla" {
		t.Errorf("first row %+v", rows[0])
	}
	if rows[2].HandlerSymbol != "__x64_sys_ni_syscall" {
		t.Errorf("an alias shared by several stubs is named %q", rows[2].HandlerSymbol)
	}
	if len(diags) != 0 {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestADeclaredLengthIsUsedAsIs(t *testing.T) {
	f := newSys(4)
	f.entries = append(f.entries, 0)
	f.declared = true
	rows, _ := run(t, f, nil)
	if len(rows) != 5 || rows[4].HandlerAddress != 0 || rows[4].Module != "" || rows[4].HandlerSymbol != "" {
		t.Fatalf("rows %+v", rows)
	}
}

func TestHandlersOutsideTheKernelAreNamedByModuleOrLeftUnowned(t *testing.T) {
	f := newSys(4)
	f.AddModule(kerntest.ModuleSpec{At: modAt, Name: "rk", Base: modBase, TextSize: 0x1000})
	f.entries[1] = modBase + 0x10
	f.entries[3] = 0xffffffffdead0000
	rows, _ := run(t, f, nil)
	if r := rows[1]; r.Module != "rk" || r.HandlerAddress != (modBase+0x10)&mask {
		t.Errorf("hooked entry %+v", r)
	}
	if r := rows[3]; r.Module != "" || r.HandlerSymbol != "" {
		t.Errorf("unowned entry %+v", r)
	}
}

func TestASwitchDispatcherMarksTheTableAsNotDispatching(t *testing.T) {
	f := newSys(2)
	f.Types.Symbol("x64_sys_call", kerntest.Text+0x10, kerntest.Fn())
	rows, _ := run(t, f, nil)
	if len(rows) != 2 || rows[0].Dispatches {
		t.Errorf("rows %+v", rows)
	}
}

func TestTheIa32TablePrefersIa32Names(t *testing.T) {
	f := newSys(2)
	f.ia32 = []uint64{niAt, niAt, niAt}
	rows, _ := run(t, f, nil)
	if len(rows) != 5 {
		t.Fatalf("rows %+v", rows)
	}
	for _, r := range rows[2:] {
		if r.TableName != "ia32_sys_call_table" || r.HandlerSymbol != "__ia32_sys_ni_syscall" || r.TableAddress != (ia32At+shift)&mask {
			t.Errorf("ia32 row %+v", r)
		}
	}
}

func TestMissingTableAndNoLength(t *testing.T) {
	ctx, _ := kerntest.NewFixture(0).Context(t, nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoTable) {
		t.Errorf("no table: %v", err)
	}
	f := newSys(3)
	f.entries = []uint64{0, 0, 0}
	ctx, _ = f.context(t, nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoSize) {
		t.Errorf("all null: %v", err)
	}
}

func TestUnreadableEntriesAreCountedAndFailStrictMode(t *testing.T) {
	f := newSys(600)
	ctx, diags := f.context(t, nil)
	f.Mem.Unmap(tableAt + shift + 0x1000)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 512 || !strings.Contains(strings.Join(*diags, "\n"), "90 entries unreadable") {
		t.Errorf("rows %d, diagnostics %q", len(rows), *diags)
	}
	ctx, _ = f.context(t, map[string]any{"strict": true})
	f.Mem.Unmap(tableAt + shift + 0x1000)
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "strict mode") {
		t.Errorf("strict mode: %v", err)
	}
}

func TestTheTableCapCutsTheTable(t *testing.T) {
	f := newSys(8)
	ctx, diags := f.context(t, nil)
	ctx.Limits = limits.Limits{MaxTableEntries: 3}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || !strings.Contains(strings.Join(*diags, "\n"), "cut to 3") {
		t.Errorf("rows %d, diagnostics %q", len(rows), *diags)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Error("strict mode accepted a cut table")
	}
}

func TestFourBytePointersReadTheI386Table(t *testing.T) {
	const (
		text  = 0xc1000000
		table = 0xc3000000
	)
	types := kerntest.NewTypes(4)
	kerntest.AddModuleTypes(types)
	types.Symbol("_text", text, kerntest.Arr(0, kerntest.Base("char")))
	types.Symbol("_etext", text+0x1000000, kerntest.Arr(0, kerntest.Base("char")))
	types.Symbol("sys_call_table", table, kerntest.Arr(0, kerntest.Ptr(kerntest.Fn())))
	types.Symbol("after", table+12, kerntest.Base("int"))
	types.Symbol("ia32_sys_call", text+0x500, kerntest.Fn())
	types.Symbol("__x64_sys_read", text+0x100, kerntest.Fn())
	types.Symbol("__ia32_sys_read", text+0x100, kerntest.Fn())
	mem := kerntest.NewMemory()
	mem.U32(table, text+0x100)
	mem.U32(table+4, text+0x100)
	mem.U32(table+8, 0)
	ctx, _ := kerntest.Context(mem, types.Table(t), nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].HandlerSymbol != "__ia32_sys_read" || rows[0].Dispatches || rows[0].HandlerAddress != text+0x100 {
		t.Errorf("rows %+v", rows)
	}
}

func TestTrimmedLength(t *testing.T) {
	cases := []struct {
		words []uint64
		ok    []bool
		want  uint64
	}{
		{nil, nil, 0},
		{[]uint64{1, 0, 0}, []bool{true, true, true}, 1},
		{[]uint64{1, 0, 2}, []bool{true, true, true}, 3},
		{[]uint64{1, 0, 0}, []bool{true, false, true}, 2},
		{[]uint64{0, 0}, []bool{false, true}, 1},
		{[]uint64{0, 0}, []bool{true, true}, 0},
	}
	for _, c := range cases {
		if got := trimmedLength(c.words, c.ok); got != c.want {
			t.Errorf("%v %v: %d, want %d", c.words, c.ok, got, c.want)
		}
	}
}
