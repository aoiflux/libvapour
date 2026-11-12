package processtracing

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.process.list_tracing"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the Linux tasks that are traced under ptrace or trace others, with tracer, tracees and options",
		},
		RunAny,
	)
}

type Row struct {
	Process   string
	PID, TID  int64
	Traced    bool
	TracerTID int64
	Tracees   []int64
	Options   string
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

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	k := linuxobj.New(ctx)
	walk, err := k.Walker().Tasks(true, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)

	var out []Row
	var skipped, broken, unnamed tally
	for _, addr := range walk.Tasks {
		r, held, err := task(k, linuxobj.Task{Addr: addr}, &broken, &unnamed)
		if err != nil {
			skipped.add("task_struct at %#x: %v", addr, err)
			continue
		}
		if held {
			out = append(out, r)
		}
	}
	unlisted := crossCheck(out)
	if skipped.count > 0 && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: %d tasks not read, first: %s", Name, skipped.count, skipped.first)
	}
	for _, f := range []struct {
		what string
		t    tally
	}{
		{"tasks not read", skipped},
		{"ptraced lists end before they close", broken},
		{"tasks with ptrace bits that have no name, shown in hex", unnamed},
		{"traced tasks missing from their tracer's ptraced list", unlisted},
	} {
		if f.t.count > 0 {
			ctx.AddDiagnostic("%s: %d %s, first: %s", Name, f.t.count, f.what, f.t.first)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].TID < out[j].TID
	})
	return out, nil
}

// S61 4.1 step 2: a task belongs in the listing when PT_PTRACED is set or its
// ptraced list holds a tracee.
func task(k *linuxobj.Kernel, t linuxobj.Task, broken, unnamed *tally) (Row, bool, error) {
	traced, err := k.IsBeingPtraced(t)
	if err != nil {
		return Row{}, false, err
	}
	tracing, err := k.IsPtracing(t)
	if err != nil {
		return Row{}, false, err
	}
	if !traced && !tracing {
		return Row{}, false, nil
	}
	r := Row{Traced: traced}
	if r.Process, err = k.Comm(t); err != nil {
		return r, false, err
	}
	if r.PID, err = k.TGID(t); err != nil {
		return r, false, err
	}
	if r.TID, err = k.PID(t); err != nil {
		return r, false, err
	}
	if r.TracerTID, _, err = k.PtraceTracerTID(t); err != nil {
		return r, false, err
	}
	if tracing {
		tracees, walk, err := k.PtraceTraceeTIDs(t)
		if err != nil {
			return r, false, err
		}
		if walk.Broken() {
			broken.add("task_struct at %#x: after %d tracees at %#x: %s", t.Addr, len(walk.Entries), walk.At, walk.End)
		}
		r.Tracees = tracees
	}
	names, rest, _, err := k.PtraceFlags(t)
	if err != nil {
		return r, false, err
	}
	r.Options = names
	if rest != 0 {
		unnamed.add("task_struct at %#x: bits %#x", t.Addr, rest)
		r.Options = strings.TrimPrefix(r.Options+fmt.Sprintf("|%#x", rest), "|")
	}
	return r, true, nil
}

// S61 T3: while a task is traced its parent is the tracer and its
// ptrace_entry is on the tracer's ptraced list.
func crossCheck(rows []Row) tally {
	tracees := map[int64]map[int64]bool{}
	for _, r := range rows {
		set := map[int64]bool{}
		for _, tid := range r.Tracees {
			set[tid] = true
		}
		tracees[r.TID] = set
	}
	var missing tally
	for _, r := range rows {
		if r.Traced && r.TracerTID != 0 && !tracees[r.TracerTID][r.TID] {
			missing.add("tid %d traced by tid %d", r.TID, r.TracerTID)
		}
	}
	return missing
}
