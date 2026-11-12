package linuxwalk_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const (
	tasksAt   = base + 0x10000
	signalsAt = base + 0x40000
)

func taskAt(i int) uint64   { return tasksAt + uint64(i)*0x100 }
func signalAt(i int) uint64 { return signalsAt + uint64(i)*0x40 }

type world struct {
	mem *kerntest.Memory
	ty  *kerntest.Types
}

func newWorld(l layout) world {
	w := world{mem: kerntest.NewMemory(), ty: kerntest.NewTypes(8)}
	listTypes(w.ty)
	taskTypes(w.ty, l)
	w.mem.Map(signalsAt, page)
	writeTask(w.mem, task{addr: initTask, signal: signalAt(63)})
	return w
}

// processes writes leaders with pid i+1 and links them on init_task.tasks.
func (w world) processes(n int) []uint64 {
	var out []uint64
	for i := range n {
		at := taskAt(i)
		writeTask(w.mem, task{addr: at, pid: int32(i + 1), tgid: int32(i + 1), signal: signalAt(i)})
		out = append(out, at)
	}
	ring(w.mem, append([]uint64{initTask + taskTasks}, links(out, taskTasks)...)...)
	return out
}

func (w world) reader(t testing.TB) linuxwalk.Reader {
	return reader(t, w.mem, w.ty, limits.Limits{})
}

func TestTasksFollowTheProcessList(t *testing.T) {
	w := newWorld(viaSignal)
	want := w.processes(3)
	got, err := w.reader(t).Tasks(false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Tasks, want) || got.Head != initTask+taskTasks {
		t.Errorf("tasks %#x head %#x, want %#x", got.Tasks, got.Head, want)
	}
	if slices.Contains(got.Tasks, initTask) || got.Walks[0].Broken() || got.Walks[1].Broken() || len(got.Invalid) != 0 {
		t.Errorf("walk %+v", got)
	}
}

func TestTasksJoinBothDirectionsAcrossABreak(t *testing.T) {
	w := newWorld(viaSignal)
	p := w.processes(4)
	w.mem.U64(p[1]+taskTasks, 0)
	got, err := w.reader(t).Tasks(false, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint64{p[0], p[1], p[3], p[2]}
	if !slices.Equal(got.Tasks, want) {
		t.Errorf("tasks %#x, want %#x", got.Tasks, want)
	}
	if got.Walks[0].End != linuxwalk.LinkUnreadable || got.Walks[1].End != linuxwalk.Closed {
		t.Errorf("ends %q and %q", got.Walks[0].End, got.Walks[1].End)
	}
	var diags []string
	got.Report(func(f string, a ...any) { diags = append(diags, f) }, "tool")
	if len(diags) != 2 {
		t.Errorf("%d diagnostics, want one for the break and one for the unpaired link", len(diags))
	}
}

func TestTasksLeaveOutImplausibleTasks(t *testing.T) {
	w := newWorld(viaSignal)
	p := w.processes(6)
	writeTask(w.mem, task{addr: p[1], pid: 0, tgid: 0, signal: signalAt(1)})
	writeTask(w.mem, task{addr: p[2], pid: -5, tgid: 3, signal: signalAt(2)})
	writeTask(w.mem, task{addr: p[3], pid: 4 * 1024 * 1024, tgid: 4, signal: signalAt(3)})
	writeTask(w.mem, task{addr: p[4], pid: 5, tgid: 5, signal: 0})

	edge := base + 0x80000 - 0x20
	w.mem.Map(edge, 0x20)
	w.mem.U64(p[4]+taskTasks, edge+taskTasks)
	w.mem.U64(edge+taskTasks, p[5]+taskTasks)
	w.mem.U64(edge+taskTasks+8, p[4]+taskTasks)
	w.mem.U64(p[5]+taskTasks+8, edge+taskTasks)

	got, err := w.reader(t).Tasks(false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Tasks, []uint64{p[0], p[5]}) {
		t.Errorf("tasks %#x", got.Tasks)
	}
	want := map[string]int{linuxwalk.ReasonIDRange: 3, linuxwalk.ReasonSignal: 1, linuxwalk.ReasonUnreadable: 1}
	for why, n := range want {
		if got.Invalid[why] != n {
			t.Errorf("%q: %d, want %d", why, got.Invalid[why], n)
		}
	}
	if !slices.IsSorted(got.Reasons()) || len(got.Reasons()) != 3 {
		t.Errorf("reasons %q", got.Reasons())
	}
	if why, err := w.reader(t).TaskInvalid(p[4]); err != nil || why != linuxwalk.ReasonSignal {
		t.Errorf("TaskInvalid = %q, %v", why, err)
	}
	if why, err := w.reader(t).TaskInvalid(p[0]); err != nil || why != "" {
		t.Errorf("TaskInvalid on a good task = %q, %v", why, err)
	}
}

func TestTasksApplyTheFilterToPlausibleTasks(t *testing.T) {
	w := newWorld(viaSignal)
	p := w.processes(3)
	var asked []uint64
	got, err := w.reader(t).Tasks(false, func(at uint64) (bool, error) {
		asked = append(asked, at)
		return at == p[1], nil
	})
	if err != nil || !slices.Equal(got.Tasks, []uint64{p[0], p[2]}) || !slices.Equal(asked, p) {
		t.Errorf("tasks %#x asked %#x err %v", got.Tasks, asked, err)
	}
	stop := errors.New("stop")
	if _, err := w.reader(t).Tasks(false, func(uint64) (bool, error) { return false, stop }); !errors.Is(err, stop) {
		t.Errorf("filter error lost: %v", err)
	}
}

func threadsOf(w world, leader uint64, l layout, threads []uint64) {
	var nodes []uint64
	switch l {
	case viaSignal:
		at := readU64(w.mem, leader+taskSignal)
		nodes = append([]uint64{at + signalHead}, links(append([]uint64{leader}, threads...), taskThreadNode)...)
	case viaGroup:
		nodes = links(append([]uint64{leader}, threads...), taskThreadGroup)
	}
	ring(w.mem, nodes...)
}

func readU64(mem *kerntest.Memory, at uint64) uint64 {
	b, err := mem.ReadAt(at, 8)
	if err != nil {
		return 0
	}
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func TestTasksListThreadsAfterTheirLeader(t *testing.T) {
	for _, l := range []layout{viaSignal, viaGroup} {
		w := newWorld(l)
		p := w.processes(2)
		th := []uint64{taskAt(10), taskAt(11), taskAt(12)}
		writeTask(w.mem, task{addr: th[0], pid: 11, tgid: 1, signal: signalAt(0)})
		writeTask(w.mem, task{addr: th[1], pid: 12, tgid: 1, signal: signalAt(0)})
		writeTask(w.mem, task{addr: th[2], pid: 13, tgid: 9, signal: signalAt(0)})
		threadsOf(w, p[0], l, th)
		threadsOf(w, p[1], l, nil)
		got, err := w.reader(t).Tasks(true, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := []uint64{p[0], th[0], th[1], p[1]}
		if !slices.Equal(got.Tasks, want) {
			t.Errorf("layout %d: tasks %#x, want %#x", l, got.Tasks, want)
		}
		if got.Invalid[linuxwalk.ReasonNotInGroup] != 1 || got.ThreadListsBroken != 0 {
			t.Errorf("layout %d: invalid %v broken %d", l, got.Invalid, got.ThreadListsBroken)
		}
		one, err := w.reader(t).Threads(p[0])
		if err != nil || !slices.Equal(one.Tasks, th[:2]) {
			t.Errorf("layout %d: Threads = %#x, %v", l, one.Tasks, err)
		}
	}
}

func TestTasksCountBrokenThreadLists(t *testing.T) {
	w := newWorld(viaSignal)
	p := w.processes(2)
	threadsOf(w, p[0], viaSignal, nil)
	w.mem.U64(signalAt(0)+signalHead, 0)
	threadsOf(w, p[1], viaSignal, nil)
	got, err := w.reader(t).Tasks(true, nil)
	if err != nil || !slices.Equal(got.Tasks, p) || got.ThreadListsBroken != 1 {
		t.Errorf("tasks %#x broken %d err %v", got.Tasks, got.ThreadListsBroken, err)
	}
}

func TestTasksRefuseUnknownLayouts(t *testing.T) {
	w := newWorld(noThreads)
	w.processes(1)
	if _, err := w.reader(t).Tasks(true, nil); !errors.Is(err, linuxwalk.ErrUnsupported) {
		t.Errorf("no thread list: %v", err)
	}
	if _, err := w.reader(t).Tasks(false, nil); err != nil {
		t.Errorf("no thread list, threads not asked: %v", err)
	}

	ty := kerntest.NewTypes(8)
	listTypes(ty)
	taskTypes(ty, viaSignal)
	ty.Symbol("init_task", 0, kerntest.Struct("task_struct"))
	if _, err := reader(t, kerntest.NewMemory(), ty, limits.Limits{}).InitTask(); !errors.Is(err, linuxwalk.ErrNoInitTask) {
		t.Errorf("init_task at 0: %v", err)
	}
	ty = kerntest.NewTypes(8)
	listTypes(ty)
	if _, err := reader(t, kerntest.NewMemory(), ty, limits.Limits{}).Tasks(false, nil); !errors.Is(err, linuxwalk.ErrUnsupported) {
		t.Errorf("no task_struct: %v", err)
	}
}

func TestTasksCapEachWalk(t *testing.T) {
	w := newWorld(viaSignal)
	w.processes(5)
	got, err := reader(t, w.mem, w.ty, limits.Limits{MaxListEntries: 3}).Tasks(false, nil)
	if err != nil || len(got.Tasks) != 5 || got.Walks[0].End != linuxwalk.Capped || got.Walks[1].End != linuxwalk.Capped {
		t.Errorf("tasks %d, ends %q %q, err %v", len(got.Tasks), got.Walks[0].End, got.Walks[1].End, err)
	}
}
