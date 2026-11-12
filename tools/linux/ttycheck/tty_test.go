package ttycheck

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const (
	drivers   = Data + 0x4000
	heap      = 0xffff888000000000
	hookMod   = ModuleArea + 0x10000
	hookText  = ModuleArea + 0x20000
	recvBuf   = Text + 0x300
	recvBuf2  = Text + 0x340
	drvSize   = 0xc0
	ttySize   = 0x290
	opsSize   = 0x90
	offNum    = 0x34
	offTTYs   = 0x88
	offLink   = 0xb0
	offDName  = 0x20
	offIndex  = 0x04
	offDriver = 0x10
	offLdisc  = 0x28
	offTName  = 0x160
)

type world struct {
	f    *Fixture
	next uint64
}

func newWorld(withRecv2 bool) *world {
	f := NewFixture(0)
	f.Types.Struct("tty_driver", drvSize, map[string]F{
		"name": {Off: offDName, Type: Ptr(Base("char"))}, "num": {Off: offNum, Type: Base("unsigned int")},
		"ttys":        {Off: offTTYs, Type: Ptr(Ptr(Struct("tty_struct")))},
		"tty_drivers": {Off: offLink, Type: Struct("list_head")},
	})
	f.Types.Struct("tty_struct", ttySize, map[string]F{
		"index": {Off: offIndex, Type: Base("int")}, "driver": {Off: offDriver, Type: Ptr(Struct("tty_driver"))},
		"ldisc": {Off: offLdisc, Type: Ptr(Struct("tty_ldisc"))}, "name": {Off: offTName, Type: Arr(64, Base("char"))},
	})
	f.Types.Struct("tty_ldisc", 16, map[string]F{"ops": {Off: 0, Type: Ptr(Struct("tty_ldisc_ops"))}})
	ops := map[string]F{"name": {Off: 0, Type: Ptr(Base("char"))}, "receive_buf": {Off: 0x60, Type: Ptr(Fn())}}
	if withRecv2 {
		ops["receive_buf2"] = F{Off: 0x78, Type: Ptr(Fn())}
	}
	f.Types.Struct("tty_ldisc_ops", opsSize, ops)
	f.Types.Symbol("tty_drivers", drivers, Struct("list_head"))
	f.Types.Symbol("n_tty_receive_buf", recvBuf, Fn())
	f.Types.Symbol("n_tty_receive_buf2", recvBuf2, Fn())
	f.Mem.U64(drivers, drivers)
	f.Mem.U64(drivers+8, drivers)
	f.AddModule(ModuleSpec{At: hookMod, Name: "hook", Base: hookText, TextSize: 0x1000})
	return &world{f: f, next: heap}
}

func (w *world) alloc(n uint64) uint64 {
	at := w.next
	w.f.Mem.Map(at, n)
	w.next += (n + 0xfff) &^ 0xfff
	return at
}

func (w *world) str(s string) uint64 {
	at := w.alloc(uint64(len(s)) + 1)
	w.f.Mem.Str(at, s)
	return at
}

func (w *world) driver(name string, slots []uint64, table bool) uint64 {
	m := w.f.Mem
	d := w.alloc(drvSize)
	m.U64(d+offDName, w.str(name))
	m.U32(d+offNum, uint32(len(slots)))
	if table {
		t := w.alloc(uint64(len(slots))*8 + 8)
		for i, s := range slots {
			m.U64(t+uint64(i)*8, s)
		}
		m.U64(d+offTTYs, t)
	}
	prev := readWord(m, drivers+8)
	m.U64(d+offLink, drivers)
	m.U64(d+offLink+8, prev)
	m.U64(prev, d+offLink)
	m.U64(drivers+8, d+offLink)
	return d
}

func (w *world) ops(name string, recv, recv2 uint64) uint64 {
	o := w.alloc(opsSize)
	w.f.Mem.U64(o, w.str(name))
	w.f.Mem.U64(o+0x60, recv)
	w.f.Mem.U64(o+0x78, recv2)
	return o
}

func (w *world) tty(name string, index int32, ops uint64) uint64 {
	m := w.f.Mem
	t := w.alloc(ttySize)
	m.U32(t+offIndex, uint32(index))
	m.Str(t+offTName, name)
	if ops != 0 {
		l := w.alloc(16)
		m.U64(l, ops)
		m.U64(t+offLdisc, l)
	}
	return t
}

func (w *world) own(tty, drv uint64) { w.f.Mem.U64(tty+offDriver, drv) }

func readWord(m *Memory, at uint64) uint64 {
	b, err := m.ReadAt(at, 8)
	if err != nil {
		panic(err)
	}
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func TestRowsPerHandlerOfEachTTYInSlotOrder(t *testing.T) {
	w := newWorld(true)
	nTTY := w.ops("n_tty", recvBuf, recvBuf2)
	hooked := w.ops("n_tty", hookText+0x10, 0)
	t0 := w.tty("tty0", 0, nTTY)
	t2 := w.tty("tty2", 2, hooked)
	t3 := w.tty("tty3", 3, 0)
	vt := w.driver("tty", []uint64{t0, 0, t2, t3}, true)
	for _, tt := range []uint64{t0, t2, t3} {
		w.own(tt, vt)
	}
	w.driver("pts", []uint64{0, 0}, false)
	ctx, diags := w.f.Context(t, nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mask := uint64(1<<48 - 1)
	want := []Row{
		{TTY: "tty0", TTYAddress: t0 & mask, Driver: "tty", DriverAddress: vt & mask, Discipline: "n_tty",
			OpsAddress: nTTY & mask, Handler: HandlerReceive, Address: recvBuf & mask, Module: linuxmodule.KernelOwner,
			Symbol: "n_tty_receive_buf", ModuleFound: true},
		{TTY: "tty0", TTYAddress: t0 & mask, Driver: "tty", DriverAddress: vt & mask, Discipline: "n_tty",
			OpsAddress: nTTY & mask, Handler: HandlerReceive2, Address: recvBuf2 & mask, Module: linuxmodule.KernelOwner,
			Symbol: "n_tty_receive_buf2", ModuleFound: true},
		{TTY: "tty2", TTYAddress: t2 & mask, Driver: "tty", DriverAddress: vt & mask, Discipline: "n_tty",
			OpsAddress: hooked & mask, Handler: HandlerReceive, Address: (hookText + 0x10) & mask, Module: "hook",
			ModuleAddress: hookMod & mask, ModuleFound: true},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows\n got %+v\nwant %+v", rows, want)
	}
	if len(*diags) != 0 {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestWithoutReceiveBuf2OnlyReceiveBufIsRead(t *testing.T) {
	w := newWorld(false)
	t0 := w.tty("ttyS0", 0, w.ops("n_tty", recvBuf, recvBuf2))
	d := w.driver("ttyS", []uint64{t0}, true)
	w.own(t0, d)
	ctx, _ := w.f.Context(t, nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Handler != HandlerReceive {
		t.Errorf("rows %+v", rows)
	}
}

func TestASlotWhoseTTYIsNotItsOwnGivesNoRow(t *testing.T) {
	w := newWorld(true)
	ops := w.ops("n_tty", recvBuf, 0)
	wrongIndex := w.tty("tty0", 5, ops)
	wrongDriver := w.tty("tty1", 1, ops)
	d := w.driver("tty", []uint64{wrongIndex, wrongDriver}, true)
	w.own(wrongIndex, d)
	w.own(wrongDriver, heap+0x100000)
	ctx, diags := w.f.Context(t, map[string]any{"strict": true})
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 || len(*diags) != 1 || !strings.Contains((*diags)[0], "2 slots hold a tty whose index") {
		t.Errorf("rows %+v diags %q", rows, *diags)
	}
}

func TestUnreadableSlotsAreCountedAndFailStrictMode(t *testing.T) {
	w := newWorld(true)
	d := w.driver("tty", []uint64{heap + 0x7000000, 0}, true)
	_ = d
	ctx, diags := w.f.Context(t, nil)
	if _, err := Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(*diags) != 1 || !strings.Contains((*diags)[0], "1 of 2 slots or their ttys do not read") {
		t.Errorf("diags %q", *diags)
	}
	ctx, _ = w.f.Context(t, map[string]any{"strict": true})
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "strict mode") {
		t.Errorf("strict err = %v", err)
	}
}

func TestSlotsStopAtMaxTableEntries(t *testing.T) {
	w := newWorld(true)
	ops := w.ops("n_tty", recvBuf, 0)
	var slots []uint64
	for i := range 3 {
		slots = append(slots, w.tty("tty", int32(i), ops))
	}
	d := w.driver("tty", slots, true)
	for _, s := range slots {
		w.own(s, d)
	}
	ctx, diags := w.f.Context(t, nil)
	ctx.Limits = limits.Limits{MaxTableEntries: 2}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || len(*diags) == 0 || !strings.Contains((*diags)[0], "only the first 2") {
		t.Errorf("rows %d diags %q", len(rows), *diags)
	}
}

func TestABrokenDriverListIsReported(t *testing.T) {
	w := newWorld(true)
	d := w.driver("tty", nil, true)
	w.f.Mem.U64(d+offLink, heap+0x7000000)
	ctx, diags := w.f.Context(t, nil)
	if _, err := Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(*diags) == 0 || !strings.Contains((*diags)[0], "tty_drivers at") {
		t.Errorf("diags %q", *diags)
	}
}

func TestNoDriverList(t *testing.T) {
	f := NewFixture(0)
	ctx, _ := f.Context(t, nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoDrivers) {
		t.Errorf("err = %v, want ErrNoDrivers", err)
	}
}

func FuzzDriverTable(f *testing.F) {
	f.Add(uint32(2), uint64(0), uint64(heap), int32(0), uint64(recvBuf))
	f.Add(uint32(1<<20), uint64(heap+8), uint64(1), int32(-1), uint64(0))
	f.Fuzz(func(t *testing.T, num uint32, slot0, slot1 uint64, index int32, recv uint64) {
		w := newWorld(true)
		ops := w.ops("n_tty", recv, recv)
		tt := w.tty("tty0", index, ops)
		d := w.driver("tty", []uint64{slot0, tt, slot1}, true)
		w.own(tt, d)
		w.f.Mem.U32(d+offNum, num)
		ctx, _ := w.f.Context(t, nil)
		ctx.Limits = limits.Limits{MaxTableEntries: 64}
		rows, err := Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 2*min(int(num), 64) {
			t.Fatalf("%d rows from %d slots", len(rows), num)
		}
	})
}
