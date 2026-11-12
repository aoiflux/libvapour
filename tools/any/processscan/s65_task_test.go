package processscan

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	lxBase     = uint64(0xffff8d7e00000000)
	lxSize     = 4 << 20
	lxTaskSize = uint64(0x300)
	lxPtraced  = uint64(0x200)
	lxPtraceE  = uint64(0x210)
	lxPID      = uint64(0x100)
	lxTGID     = uint64(0x104)
	lxLeader   = uint64(0x120)
	lxReal     = uint64(0x128)
	lxParent   = uint64(0x130)
	lxExit     = uint64(0x140)
	lxComm     = uint64(0x160)
	lxBaseVar  = uint64(0x3ff000)
	lxInitTask = uint64(0x3fe000)
)

type flat []byte

func (f flat) ReadAt(at, size uint64) ([]byte, error) {
	if at >= uint64(len(f)) || at+size > uint64(len(f)) || at+size < at {
		return nil, memory.ErrOutOfBounds
	}
	return f[at : at+size], nil
}

func (f flat) Size() uint64 { return uint64(len(f)) }

type directMap struct{ phys flat }

func (d directMap) ReadAt(at, size uint64) ([]byte, error) {
	if at < lxBase {
		return nil, memory.ErrUnmapped
	}
	return d.phys.ReadAt(at-lxBase, size)
}

func (d directMap) Size() uint64 { return 1<<64 - 1 }

type lxTask struct {
	pid, tgid  uint32
	leader     uint64
	parent     uint64
	exit       uint32
	comm       string
	traced     bool
	noCommNUL  bool
	userParent bool
}

type lxWorld struct {
	phys  flat
	table *symbols.Table
}

func newLxWorld() *lxWorld {
	w := &lxWorld{phys: make(flat, lxSize), table: symbols.NewTable("s65linux", 8)}
	i := func(n string) symbols.TypeRef { return symbols.TypeRef{Name: n} }
	p := symbols.TypeRef{Name: "task_struct", IsPointer: true, Element: &symbols.TypeRef{Name: "task_struct"}}
	w.table.AddStruct(symbols.StructType{Name: "task_struct", Size: lxTaskSize, Fields: []symbols.Field{
		{Name: "ptraced", Offset: lxPtraced, Type: i("list_head")}, {Name: "ptrace_entry", Offset: lxPtraceE, Type: i("list_head")},
		{Name: "pid", Offset: lxPID, Type: i("int")}, {Name: "tgid", Offset: lxTGID, Type: i("int")},
		{Name: "group_leader", Offset: lxLeader, Type: p}, {Name: "real_parent", Offset: lxReal, Type: p},
		{Name: "parent", Offset: lxParent, Type: p}, {Name: "exit_state", Offset: lxExit, Type: i("int")},
		{Name: "comm", Offset: lxComm, Type: symbols.TypeRef{Name: "char", IsArray: true, ArrayLength: 16}},
	}})
	w.table.AddSymbol(symbols.Symbol{Name: "page_offset_base", Address: lxBase + lxBaseVar})
	w.put64(lxBaseVar, lxBase)
	w.put32(lxInitTask+lxTGID, 0)
	return w
}

func (w *lxWorld) put64(at, v uint64) { binary.LittleEndian.PutUint64(w.phys[at:], v) }
func (w *lxWorld) put32(at uint64, v uint32) {
	binary.LittleEndian.PutUint32(w.phys[at:], v)
}

func (w *lxWorld) add(at uint64, t lxTask) {
	va := lxBase + at
	for _, h := range []uint64{lxPtraced, lxPtraceE} {
		w.put64(at+h, va+h)
		w.put64(at+h+8, va+h)
	}
	if t.traced {
		w.put64(at+lxPtraced, lxBase+0x123450)
	}
	w.put32(at+lxPID, t.pid)
	w.put32(at+lxTGID, t.tgid)
	leader := t.leader
	if leader == 0 {
		leader = va
	}
	w.put64(at+lxLeader, leader)
	parent := t.parent
	if parent == 0 {
		parent = lxBase + lxInitTask
	}
	if t.userParent {
		parent = 0x7ffd00001000
	}
	w.put64(at+lxReal, parent)
	w.put64(at+lxParent, parent)
	w.put32(at+lxExit, t.exit)
	comm := make([]byte, 16)
	copy(comm, t.comm)
	if t.noCommNUL {
		for i := range comm {
			comm[i] = 'x'
		}
	}
	copy(w.phys[at+lxComm:], comm)
}

func (w *lxWorld) ctx(options map[string]any) (tools.Context, *[]string) {
	diags := &[]string{}
	opts := map[string]any{"diagnostics": diags, tools.OptionPhysicalMemory: memory.MemoryReader(w.phys)}
	for k, v := range options {
		opts[k] = v
	}
	return tools.Context{Memory: directMap{w.phys}, Symbols: w.table, Profile: profiles.LinuxX64Profile{}, Options: opts}, diags
}

func lxScene(w *lxWorld) {
	w.add(0x10000, lxTask{pid: 1, tgid: 1, comm: "systemd"})
	w.add(0x20000, lxTask{pid: 900, tgid: 900, comm: "bash", parent: lxBase + 0x10000})
	w.add(0x30000, lxTask{pid: 901, tgid: 900, comm: "worker", leader: lxBase + 0x20000, parent: lxBase + 0x10000})
	w.add(0x40000, lxTask{pid: 950, tgid: 950, comm: "gone", exit: 0x10})
	// The ptraced head ends at the 1 MiB sweep window's edge.
	w.add(0x100000-lxPtraced-8, lxTask{pid: 960, tgid: 960, comm: "edge"})
}

func TestTheTaskScanFindsTasksAndThreads(t *testing.T) {
	w := newLxWorld()
	lxScene(w)
	ctx, diags := w.ctx(nil)
	rows, err := RunLinux(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Fatalf("rows %+v diags %q", rows, *diags)
	}
	want := []LinuxTask{
		{Offset: 0x10000, Address: lxBase + 0x10000, PID: 1, TID: 1, PPID: 0, Comm: "systemd"},
		{Offset: 0x20000, Address: lxBase + 0x20000, PID: 900, TID: 900, PPID: 1, Comm: "bash"},
		{Offset: 0x30000, Address: lxBase + 0x30000, PID: 900, TID: 901, PPID: 1, Comm: "worker"},
		{Offset: 0x40000, Address: lxBase + 0x40000, PID: 950, TID: 950, Comm: "gone", ExitState: ExitDead},
		{Offset: 0x100000 - lxPtraced - 8, Address: lxBase + 0x100000 - lxPtraced - 8, PID: 960, TID: 960, Comm: "edge"},
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d %+v, want %+v", i, rows[i], want[i])
		}
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "any.process.scan: 5 tasks from") {
		t.Errorf("diags %q", *diags)
	}
}

func TestEachTaskRuleRefusesOnItsOwn(t *testing.T) {
	for _, tc := range []struct {
		task lxTask
		rule string
	}{
		{lxTask{pid: 0, tgid: 0, comm: "idle"}, "ids 1"},
		{lxTask{pid: pidLimit, tgid: pidLimit, comm: "big"}, "ids 1"},
		{lxTask{pid: 8, tgid: 9, comm: "selfleader"}, "group leader 1"},
		{lxTask{pid: 8, tgid: 8, comm: "thread", leader: lxBase + 0x90000}, "group leader 1"},
		{lxTask{pid: 8, tgid: 9, comm: "userleader", leader: 0x7ffd00000000}, "group leader 1"},
		{lxTask{pid: 8, tgid: 8, comm: "orphan", userParent: true}, "parents 1"},
		{lxTask{pid: 8, tgid: 8, comm: "state", exit: 0x40}, "exit state 1"},
		{lxTask{pid: 8, tgid: 8, noCommNUL: true}, "name 1"},
	} {
		w := newLxWorld()
		w.add(0x50000, tc.task)
		ctx, diags := w.ctx(nil)
		rows, err := RunLinux(ctx)
		if err != nil || len(rows) != 0 || !strings.Contains(strings.Join(*diags, "\n"), tc.rule) {
			t.Errorf("%+v: rows %+v err %v diags %q", tc.task, rows, err, *diags)
		}
	}
}

func TestATracedTaskIsNoCandidate(t *testing.T) {
	w := newLxWorld()
	w.add(0x50000, lxTask{pid: 8, tgid: 8, comm: "traced", traced: true})
	ctx, diags := w.ctx(nil)
	if rows, _ := RunLinux(ctx); len(rows) != 0 || !strings.Contains(strings.Join(*diags, "\n"), "0 candidates") {
		t.Errorf("rows %+v diags %q", rows, *diags)
	}
}

func TestTheTaskScanPIDSet(t *testing.T) {
	w := newLxWorld()
	lxScene(w)
	ctx, _ := w.ctx(map[string]any{"pid": uint64(900)})
	rows, _ := RunLinux(ctx)
	if len(rows) != 2 || rows[0].TID != 900 || rows[1].TID != 901 {
		t.Errorf("rows %+v", rows)
	}
}

func TestTheTaskScanNeedsItsInputs(t *testing.T) {
	w := newLxWorld()
	ctx, _ := w.ctx(nil)
	delete(ctx.Options, tools.OptionPhysicalMemory)
	if _, err := RunLinux(ctx); !errors.Is(err, ErrNoPhysicalMemory) {
		t.Errorf("no physical: %v", err)
	}
	w = newLxWorld()
	w.table.AddStruct(symbols.StructType{Name: "task_struct", Size: lxTaskSize})
	ctx, _ = w.ctx(nil)
	if _, err := RunLinux(ctx); !errors.Is(err, ErrNoTaskMember) {
		t.Errorf("no member: %v", err)
	}
	w = newLxWorld()
	w.put64(lxBaseVar, 0)
	ctx, _ = w.ctx(nil)
	if _, err := RunLinux(ctx); !errors.Is(err, ErrNoDirectMap) {
		t.Errorf("no base: %v", err)
	}
	w = newLxWorld()
	w.table = symbols.NewTable("x", 4)
	ctx, _ = w.ctx(nil)
	if _, err := RunLinux(ctx); !errors.Is(err, ErrPointerSize) {
		t.Errorf("4-byte pointers: %v", err)
	}
	ctx.Profile = profiles.WindowsX64Profile{}
	if _, err := RunLinux(ctx); err == nil {
		t.Error("RunLinux took a windows profile")
	}
}
