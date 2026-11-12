package processpidhash

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.process.list_pid_hash"

const OptionDecorateComm = "linux.process.list_pid_hash.decorate_comm"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the Linux tasks reachable from the PID numbers of the initial PID namespace",
		},
		RunAny,
	)
}

type Task struct {
	TaskAddress    uint64
	PID, TID, PPID int64
	Comm           string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type tally struct {
	count int
	first string
}

func (t *tally) add(format string, args ...any) {
	if t.count == 0 {
		t.first = fmt.Sprintf(format, args...)
	}
	t.count++
}

type pidShape struct {
	tasks, links, head, node, kind uint64
}

func Run(ctx tools.Context) ([]Task, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	decorate, err := ctx.BoolOption(OptionDecorateComm)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	k := linuxobj.New(ctx)
	shape, err := resolve(k)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	ns, err := k.Symbol("init_pid_ns")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	idr, err := k.Member("pid_namespace", "idr")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	at := ns.Address + idr.Offset
	tree, err := k.Walker().IDR(at)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if tree.Revisited > 0 || tree.Unread > 0 || tree.Inconsistent > 0 || tree.Mismatched > 0 || tree.Capped {
		ctx.AddDiagnostic("%s: init_pid_ns.idr at %#x: %d nodes revisited, %d not read, %d with a wrong shift, %d misplaced, capped %v",
			Name, at, tree.Revisited, tree.Unread, tree.Inconsistent, tree.Mismatched, tree.Capped)
	}

	var rows []Task
	var unread, mismatch tally
	for i, pid := range tree.Entries {
		nr := uint64(0)
		if i < len(tree.Indexes) {
			nr = tree.Indexes[i]
		}
		t, ok, err := taskOf(k, shape, pid)
		if err != nil {
			unread.add("pid at %#x: %v", pid, err)
			continue
		}
		if !ok {
			continue
		}
		f, err := k.TaskFields(t, decorate)
		if err != nil {
			unread.add("task_struct at %#x: %v", t.Addr, err)
			continue
		}
		// S61 H4: copy_process stores pid_nr, the initial-namespace number
		// the IDR is indexed by, in task->pid.
		if uint64(f.TID) != nr {
			mismatch.add("pid at %#x: index %d, task_struct at %#x has pid %d", pid, nr, t.Addr, f.TID)
			continue
		}
		rows = append(rows, Task{TaskAddress: t.Addr, PID: f.PID, TID: f.TID, PPID: f.PPID, Comm: f.Name})
	}
	if ctx.StrictMode() {
		for _, t := range []tally{unread, mismatch} {
			if t.count > 0 {
				return nil, fmt.Errorf("%s: strict mode: %d pids left out, first: %s", Name, unread.count+mismatch.count, t.first)
			}
		}
	}
	if unread.count > 0 {
		ctx.AddDiagnostic("%s: %d pids whose task does not read, first: %s", Name, unread.count, unread.first)
	}
	if mismatch.count > 0 {
		ctx.AddDiagnostic("%s: %d pids whose task has another pid, left out, first: %s", Name, mismatch.count, mismatch.first)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].PID != rows[j].PID {
			return rows[i].PID < rows[j].PID
		}
		return rows[i].TID < rows[j].TID
	})
	return rows, nil
}

func resolve(k *linuxobj.Kernel) (pidShape, error) {
	if !k.Has("pid_namespace", "idr") {
		return pidShape{}, fmt.Errorf("symbol table has no pid_namespace.idr: %w", linuxobj.ErrUnsupported)
	}
	var s pidShape
	tasks, err := k.Member("pid", "tasks")
	if err != nil {
		return s, err
	}
	links, err := k.Member("task_struct", "pid_links")
	if err != nil {
		return s, err
	}
	if s.head, err = k.SizeOf("hlist_head"); err != nil {
		return s, err
	}
	if s.node, err = k.SizeOf("hlist_node"); err != nil {
		return s, err
	}
	s.tasks, s.links = tasks.Offset, links.Offset
	s.kind = pidTypePID(k)
	return s, nil
}

// S61 H1: PIDTYPE_PID leads the pid_type enumeration at every tag.
func pidTypePID(k *linuxobj.Kernel) uint64 {
	enums, ok := k.Symbols().(interface {
		EnumValue(enumName, valueName string) (int64, error)
	})
	if !ok {
		return 0
	}
	if v, err := enums.EnumValue("pid_type", "PIDTYPE_PID"); err == nil && v >= 0 {
		return uint64(v)
	}
	return 0
}

// S61 H3: pid_task takes the first node of pid->tasks[type] and the task
// that holds it in pid_links[type].
func taskOf(k *linuxobj.Kernel, s pidShape, pid uint64) (linuxobj.Task, bool, error) {
	first, err := k.PointerAt(k.Memory(), pid+s.tasks+s.kind*s.head)
	if err != nil {
		return linuxobj.Task{}, false, err
	}
	if first == 0 {
		return linuxobj.Task{}, false, nil
	}
	in := s.links + s.kind*s.node
	if k.Canonical(first) < in {
		return linuxobj.Task{}, false, fmt.Errorf("node at %#x: below its offset in task_struct", first)
	}
	return linuxobj.Task{Addr: k.Canonical(first) - in}, true, nil
}
