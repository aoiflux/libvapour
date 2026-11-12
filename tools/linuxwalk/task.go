package linuxwalk

import (
	"errors"
	"fmt"
	"sort"

	"github.com/aoiflux/libvapour/symbols"
)

// S01 T7: PID_MAX_LIMIT, taking the larger value over CONFIG_BASE_SMALL.
const (
	pidLimitWide   = 4 * 1024 * 1024
	pidLimitNarrow = 0x8000
)

const (
	ReasonUnreadable = "its task_struct does not read"
	ReasonIDRange    = "its pid or tgid is out of range"
	ReasonSignal     = "its signal is null or does not read"
	ReasonNotInGroup = "its tgid is not its leader's"
)

type TaskFilter func(task uint64) (skip bool, err error)

type TaskWalk struct {
	Head              uint64
	Tasks             []uint64
	Walks             [2]List
	Invalid           map[string]int
	ThreadListsBroken int
}

func (w *TaskWalk) leave(why string, n int) {
	if w.Invalid == nil {
		w.Invalid = map[string]int{}
	}
	w.Invalid[why] += n
}

func (w TaskWalk) Reasons() []string {
	out := make([]string, 0, len(w.Invalid))
	for why := range w.Invalid {
		out = append(out, why)
	}
	sort.Strings(out)
	return out
}

func (w TaskWalk) Report(diag func(format string, args ...any), tool string) {
	for i, l := range w.Walks {
		dir := Direction(i)
		if l.Broken() {
			diag("%s: init_task.tasks at %#x: the %s walk ends after %d tasks at %#x: %s",
				tool, w.Head, dir, len(l.Entries), l.At, l.End)
		}
		if l.Unpaired > 0 {
			diag("%s: init_task.tasks at %#x: %d links of the %s walk do not lead back",
				tool, w.Head, l.Unpaired, dir)
		}
	}
	for _, why := range w.Reasons() {
		diag("%s: %d tasks are left out: %s", tool, w.Invalid[why], why)
	}
	if w.ThreadListsBroken > 0 {
		diag("%s: %d thread lists end before they close; threads past each break are not listed",
			tool, w.ThreadListsBroken)
	}
}

type taskShape struct {
	size   uint64
	pid    symbols.IntField
	tgid   symbols.IntField
	signal uint64
	limit  int64
}

func (r Reader) taskShape() (taskShape, error) {
	var s taskShape
	var err error
	if s.size, err = r.size("task_struct"); err != nil {
		return s, err
	}
	if s.pid, err = r.intField("task_struct", "pid"); err != nil {
		return s, err
	}
	if s.tgid, err = r.intField("task_struct", "tgid"); err != nil {
		return s, err
	}
	if s.signal, err = r.offset("task_struct", "signal"); err != nil {
		return s, err
	}
	if s.signal+r.width() > s.size {
		return s, fmt.Errorf("linuxwalk: task_struct.signal: past the %d-byte structure: %w", s.size, ErrUnsupported)
	}
	s.limit = pidLimitNarrow
	if r.width() > 4 {
		s.limit = pidLimitWide
	}
	return s, nil
}

func (r Reader) check(s taskShape, task uint64) (tgid int64, why string) {
	b, ok := r.read(task, s.size)
	if !ok {
		return 0, ReasonUnreadable
	}
	pid, err := s.pid.Decode(b)
	if err != nil {
		return 0, ReasonUnreadable
	}
	tg, err := s.tgid.Decode(b)
	if err != nil {
		return 0, ReasonUnreadable
	}
	p, t := signed(pid, s.pid.Width), signed(tg, s.tgid.Width)
	if p <= 0 || t <= 0 || p >= s.limit || t >= s.limit {
		return 0, ReasonIDRange
	}
	signal := r.form(r.word(b, s.signal))
	if _, ok := r.read(signal, 1); signal == 0 || !ok {
		return 0, ReasonSignal
	}
	return t, ""
}

func (r Reader) TaskInvalid(task uint64) (string, error) {
	if err := r.ready(); err != nil {
		return "", err
	}
	s, err := r.taskShape()
	if err != nil {
		return "", err
	}
	_, why := r.check(s, task)
	return why, nil
}

var ErrNoInitTask = errors.New("no init_task")

func (r Reader) InitTask() (uint64, error) {
	if err := r.ready(); err != nil {
		return 0, err
	}
	s, err := r.Sym.LookupSymbol("init_task")
	if err != nil {
		return 0, fmt.Errorf("linuxwalk: init_task: %w: %w", ErrNoInitTask, err)
	}
	if at := r.form(s.Address); at != 0 {
		return at, nil
	}
	return 0, fmt.Errorf("linuxwalk: init_task: at address 0: %w", ErrNoInitTask)
}

func (r Reader) Tasks(threads bool, skip TaskFilter) (TaskWalk, error) {
	var w TaskWalk
	if err := r.ready(); err != nil {
		return w, err
	}
	s, err := r.taskShape()
	if err != nil {
		return w, err
	}
	tasks, err := r.offset("task_struct", "tasks")
	if err != nil {
		return w, err
	}
	initTask, err := r.InitTask()
	if err != nil {
		return w, err
	}
	w.Head = initTask + tasks
	seen := map[uint64]struct{}{r.form(initTask): {}}
	var groups threadLayout
	if threads {
		if groups, err = r.threadLayout(); err != nil {
			return w, err
		}
	}
	for i, dir := range []Direction{Forward, Backward} {
		if w.Walks[i], err = r.List(w.Head, "task_struct", "tasks", dir); err != nil {
			return w, err
		}
		for _, t := range w.Walks[i].Entries {
			if _, dup := seen[t]; dup {
				continue
			}
			seen[t] = struct{}{}
			tgid, why := r.check(s, t)
			if why != "" {
				w.leave(why, 1)
				continue
			}
			if skip != nil {
				drop, err := skip(t)
				if err != nil {
					return w, err
				}
				if drop {
					continue
				}
			}
			w.Tasks = append(w.Tasks, t)
			if !threads {
				continue
			}
			group, err := r.threads(s, groups, t, tgid, seen)
			if err != nil {
				w.ThreadListsBroken++
				continue
			}
			w.Tasks = append(w.Tasks, group.Tasks...)
			for why, n := range group.Invalid {
				w.leave(why, n)
			}
			if group.Walks[0].Broken() {
				w.ThreadListsBroken++
			}
		}
	}
	return w, nil
}

func (r Reader) Threads(leader uint64) (TaskWalk, error) {
	if err := r.ready(); err != nil {
		return TaskWalk{}, err
	}
	s, err := r.taskShape()
	if err != nil {
		return TaskWalk{}, err
	}
	groups, err := r.threadLayout()
	if err != nil {
		return TaskWalk{}, err
	}
	leader = r.form(leader)
	b, ok := r.read(leader, s.size)
	if !ok {
		return TaskWalk{}, fmt.Errorf("linuxwalk: task_struct at %#x: does not read", leader)
	}
	tg, err := s.tgid.Decode(b)
	if err != nil {
		return TaskWalk{}, fmt.Errorf("linuxwalk: task_struct at %#x: %w", leader, err)
	}
	return r.threads(s, groups, leader, signed(tg, s.tgid.Width), map[uint64]struct{}{leader: {}})
}

type threadLayout struct {
	viaSignal bool
	head      uint64
	member    string
}

// S01 T4 and T5: signal->thread_head where the table has it, else the
// v4.19-era thread_group ring through the leader.
func (r Reader) threadLayout() (threadLayout, error) {
	if r.has("task_struct", "signal") && r.has("task_struct", "thread_node") && r.has("signal_struct", "thread_head") {
		head, err := r.offset("signal_struct", "thread_head")
		return threadLayout{viaSignal: true, head: head, member: "thread_node"}, err
	}
	if r.has("task_struct", "thread_group") {
		head, err := r.offset("task_struct", "thread_group")
		return threadLayout{head: head, member: "thread_group"}, err
	}
	return threadLayout{}, fmt.Errorf("linuxwalk: task_struct: no signal->thread_head and no thread_group: %w", ErrUnsupported)
}

func (r Reader) threads(s taskShape, g threadLayout, leader uint64, tgid int64, seen map[uint64]struct{}) (TaskWalk, error) {
	w := TaskWalk{}
	base := leader
	if g.viaSignal {
		signal, ok := r.pointer(leader + s.signal)
		if !ok || signal == 0 {
			return w, fmt.Errorf("linuxwalk: task_struct at %#x: %s", leader, ReasonSignal)
		}
		base = signal
	}
	w.Head = base + g.head
	var err error
	if w.Walks[0], err = r.List(w.Head, "task_struct", g.member, Forward); err != nil {
		return w, err
	}
	for _, t := range w.Walks[0].Entries {
		if t == leader {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		tg, why := r.check(s, t)
		if why == "" && tg != tgid {
			why = ReasonNotInGroup
		}
		if why != "" {
			w.leave(why, 1)
			continue
		}
		w.Tasks = append(w.Tasks, t)
	}
	return w, nil
}
