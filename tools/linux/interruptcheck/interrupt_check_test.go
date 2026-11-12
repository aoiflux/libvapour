package interruptcheck

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const (
	mask      = 1<<48 - 1
	idtAt     = kerntest.Data + 0x10800
	descrAt   = kerntest.Data + 0x20000
	aliasAt   = 0xfffffe0000000000
	initStart = 0xffffffff84000000
	initEnd   = initStart + 0x100000
	handlers  = kerntest.Text + 0x1000
	stride    = 0x10
	modAt     = kerntest.ModuleArea + 0x10000
	modBase   = kerntest.ModuleArea + 0x40000
)

type gateSpec struct {
	offset   uint64
	selector uint16
	typ      uint8
	dpl      uint8
	ist      uint8
	present  bool
}

// Built from the SDM figures directly, so the decoder is checked against the
// manual and not against itself.
func encode(g gateSpec, size int) []byte {
	b := make([]byte, size)
	b[0], b[1] = byte(g.offset), byte(g.offset>>8)
	b[2], b[3] = byte(g.selector), byte(g.selector>>8)
	if size == 16 {
		b[4] = g.ist & 7
	}
	b[5] = g.typ&0xf | g.dpl&3<<5
	if g.present {
		b[5] |= 0x80
	}
	b[6], b[7] = byte(g.offset>>16), byte(g.offset>>24)
	if size == 16 {
		for i := range 4 {
			b[8+i] = byte(g.offset >> (32 + 8*i))
		}
	}
	return b
}

type idtFixture struct {
	*kerntest.Fixture
	noDescr  bool
	gateSize uint64
	gates    [vectors]gateSpec
}

func newIDT() *idtFixture {
	f := &idtFixture{Fixture: kerntest.NewFixture(0), gateSize: 16}
	for v := range vectors {
		f.gates[v] = gateSpec{offset: handlers + uint64(v)*stride, selector: 0x10, typ: 0xe, present: true}
	}
	f.gates[3].dpl, f.gates[8].ist = 3, 1
	return f
}

func (f *idtFixture) context(t testing.TB, opts map[string]any) (tools.Context, *[]string) {
	t.Helper()
	i := f.Types
	i.Symbol("idt_table", idtAt, kerntest.Arr(vectors, kerntest.Struct("gate_struct")))
	i.Struct("gate_struct", f.gateSize, map[string]kerntest.F{"offset_low": {Off: 0, Type: kerntest.Base("short unsigned int")}})
	i.Struct("desc_ptr", 10, map[string]kerntest.F{
		"size": {Off: 0, Type: kerntest.Base("short unsigned int")}, "address": {Off: 2, Type: kerntest.Base("long unsigned int")},
	})
	i.Symbol("_sinittext", initStart, kerntest.Arr(0, kerntest.Base("char")))
	i.Symbol("_einittext", initEnd, kerntest.Arr(0, kerntest.Base("char")))
	i.Symbol("asm_exc_divide_error", handlers, kerntest.Fn())
	for v := range vectors {
		g := encode(f.gates[v], 16)
		f.Mem.Write(idtAt+uint64(v)*16, g)
		f.Mem.Write(aliasAt+uint64(v)*16, g)
	}
	if !f.noDescr {
		i.Symbol("idt_descr", descrAt, kerntest.Struct("desc_ptr"))
		f.Mem.U16(descrAt, vectors*16-1)
		f.Mem.U64(descrAt+2, aliasAt)
	}
	return f.Context(t, opts)
}

func run(t *testing.T, f *idtFixture, opts map[string]any) ([]Row, []string) {
	t.Helper()
	ctx, diags := f.context(t, opts)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return rows, *diags
}

func TestACleanTableGivesOneKernelRowPerVector(t *testing.T) {
	rows, diags := run(t, newIDT(), nil)
	if len(rows) != vectors {
		t.Fatalf("%d rows, want %d", len(rows), vectors)
	}
	for v, r := range rows {
		if r.Index != uint64(v) || r.Placement != InKernel || r.Module != linuxmodule.KernelOwner || r.Source != FromLoaded ||
			r.Differs || r.Type != GateInterrupt || r.Selector != 0x10 || !r.Present {
			t.Fatalf("row %d %+v", v, r)
		}
		if want := (handlers + uint64(v)*stride) & mask; r.Address != want {
			t.Fatalf("row %d address %#x, want %#x", v, r.Address, want)
		}
	}
	if rows[0].Symbol != "asm_exc_divide_error" || rows[1].Symbol != "" {
		t.Errorf("symbols %q %q", rows[0].Symbol, rows[1].Symbol)
	}
	if rows[3].DPL != 3 || rows[8].IST != 1 || rows[0].DPL != 0 || rows[0].IST != 0 {
		t.Errorf("dpl/ist %+v %+v", rows[3], rows[8])
	}
	if len(diags) != 0 {
		t.Errorf("diagnostics on a clean table: %q", diags)
	}
}

func TestHandlersArePlacedByWhereTheyLie(t *testing.T) {
	f := newIDT()
	f.AddModule(kerntest.ModuleSpec{At: modAt, Name: "rk", Base: modBase, TextSize: 0x1000})
	f.gates[14].offset = modBase + 0x20
	f.gates[22].offset = initStart + 22*9
	f.gates[0x80].offset = 0xffffffffdead0000
	rows, _ := run(t, f, nil)
	if r := rows[14]; r.Placement != InModule || r.Module != "rk" || r.Address != (modBase+0x20)&mask {
		t.Errorf("module gate %+v", r)
	}
	if r := rows[22]; r.Placement != InKernelInit || r.Module != linuxmodule.KernelOwner {
		t.Errorf("init gate %+v", r)
	}
	if r := rows[0x80]; r.Placement != Unowned || r.Module != "" || r.Symbol != "" {
		t.Errorf("unowned gate %+v", r)
	}
}

func TestALoadedCopyThatDiffersIsDecodedAndMarked(t *testing.T) {
	f := newIDT()
	ctx, diags := f.context(t, nil)
	f.Mem.Write(aliasAt+14*16, encode(gateSpec{offset: 0xffffffffdead0000, selector: 0x10, typ: 0xe, present: true}, 16))
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r := rows[14]; !r.Differs || r.Source != FromLoaded || r.Placement != Unowned {
		t.Errorf("differing gate %+v", r)
	}
	if rows[13].Differs {
		t.Errorf("an equal gate is marked: %+v", rows[13])
	}
	if !contains(*diags, "1 gates differ") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestWithoutIdtDescrTheRowsComeFromIdtTable(t *testing.T) {
	f := newIDT()
	f.noDescr = true
	rows, diags := run(t, f, nil)
	if len(rows) != vectors || rows[0].Source != FromTable {
		t.Fatalf("rows %d, first %+v", len(rows), rows[0])
	}
	if !contains(diags, "no idt_descr symbol") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestAWrongLimitIsReported(t *testing.T) {
	f := newIDT()
	ctx, diags := f.context(t, nil)
	f.Mem.U16(descrAt, 0x7ff)
	if _, err := Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !contains(*diags, "limit 0x7ff") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestUnreadableGatesAreCountedAndFailStrictMode(t *testing.T) {
	f := newIDT()
	f.noDescr = true
	ctx, diags := f.context(t, nil)
	f.Mem.Unmap(idtAt + 0x800)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 128 || !contains(*diags, "128 gates unreadable") {
		t.Errorf("rows %d, diagnostics %q", len(rows), *diags)
	}
	ctx, _ = f.context(t, map[string]any{"strict": true})
	f.Mem.Unmap(idtAt + 0x800)
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "strict mode") {
		t.Errorf("strict mode: %v", err)
	}
}

func TestMissingTableAndWrongGateSize(t *testing.T) {
	f := kerntest.NewFixture(0)
	ctx, _ := f.Context(t, nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoTable) {
		t.Errorf("no idt_table: %v", err)
	}
	g := newIDT()
	g.gateSize = 8
	ctx, _ = g.context(t, nil)
	if _, err := Run(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("8-byte gate_struct with 8-byte pointers: %v", err)
	}
}

func TestLegacyGatesAreEightBytesWithTaskGates(t *testing.T) {
	const (
		text  = 0xc1000000
		etext = 0xc2000000
		table = 0xc3000000
	)
	types := kerntest.NewTypes(4)
	kerntest.AddModuleTypes(types)
	types.Symbol("_text", text, kerntest.Arr(0, kerntest.Base("char")))
	types.Symbol("_etext", etext, kerntest.Arr(0, kerntest.Base("char")))
	types.Symbol("idt_table", table, kerntest.Arr(vectors, kerntest.Struct("gate_struct")))
	mem := kerntest.NewMemory()
	for v := range vectors {
		mem.Write(table+uint64(v)*8, encode(gateSpec{offset: text + uint64(v)*8, selector: 0x60, typ: 0xe, present: true, ist: 5}, 8))
	}
	mem.Write(table+8*8, encode(gateSpec{offset: 0x1234, selector: 0xf8, typ: 0x5, present: true}, 8))
	ctx, _ := kerntest.Context(mem, types.Table(t), nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != vectors {
		t.Fatalf("%d rows", len(rows))
	}
	if r := rows[0]; r.Type != GateInterrupt || r.Selector != 0x60 || r.IST != 0 || r.Placement != InKernel || r.Address != text {
		t.Errorf("legacy gate %+v", r)
	}
	if r := rows[8]; r.Type != GateTask || r.Address != 0 || r.Placement != NoHandler || r.Selector != 0xf8 {
		t.Errorf("task gate %+v", r)
	}
}

func TestDecodeFollowsTheManualsLayouts(t *testing.T) {
	cases := []struct {
		typ  uint8
		size int
		want GateType
	}{
		{0xe, 16, GateInterrupt}, {0xf, 16, GateTrap}, {0x5, 16, GateInvalid}, {0x6, 16, GateInvalid},
		{0x7, 16, GateInvalid}, {0xc, 16, GateInvalid}, {0x0, 16, GateInvalid},
		{0xe, 8, GateInterrupt}, {0xf, 8, GateTrap}, {0x5, 8, GateTask}, {0x6, 8, GateInterrupt16},
		{0x7, 8, GateTrap16}, {0xc, 8, GateInvalid},
	}
	for _, c := range cases {
		b := encode(gateSpec{offset: 0xffffffff81234567, selector: 0x10, typ: c.typ, dpl: 2, ist: 6, present: true}, c.size)
		g, err := DecodeGate(b, uint64(c.size))
		if err != nil {
			t.Fatal(err)
		}
		if g.Type != c.want {
			t.Errorf("type %#x size %d: %s, want %s", c.typ, c.size, g.Type, c.want)
		}
		if g.DPL != 2 || !g.Present || g.Selector != 0x10 {
			t.Errorf("type %#x size %d: %+v", c.typ, c.size, g)
		}
		wantOff, wantIST := uint64(0xffffffff81234567), uint8(6)
		if c.size == 8 {
			wantOff, wantIST = 0x81234567, 0
		}
		if c.want == GateTask {
			wantOff = 0
		}
		if g.Offset != wantOff || g.IST != wantIST {
			t.Errorf("type %#x size %d: offset %#x ist %d", c.typ, c.size, g.Offset, g.IST)
		}
	}
	b := encode(gateSpec{typ: 0xe, present: true}, 16)
	b[5] |= 0x10
	if g, _ := DecodeGate(b, 16); g.Type != GateInvalid {
		t.Errorf("S bit set: %s", g.Type)
	}
	if _, err := DecodeGate(b[:15], 16); !errors.Is(err, ErrShortGate) {
		t.Errorf("short gate: %v", err)
	}
	if _, err := DecodeGate(b, 12); !errors.Is(err, ErrUnsupported) {
		t.Errorf("12-byte gate: %v", err)
	}
}

func contains(diags []string, s string) bool {
	for _, d := range diags {
		if strings.Contains(d, s) {
			return true
		}
	}
	return false
}
