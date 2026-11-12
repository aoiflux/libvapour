package threadkernel

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.thread.list_kernel"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List each Linux kernel thread's thread function and the module and symbol that hold it",
		},
		RunAny,
	)
}

type Thread struct {
	TID             int64
	Name            string
	FunctionAddress uint64
	Module          string
	Symbol          string
	OwnerFound      bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

// S61 W4: /proc prints a kernel thread's name into 64 bytes, so at most 63
// bytes of full_name show.
const shownName = 64

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

type shape struct {
	private, threadfn uint64
	fullName          bool
}

func Run(ctx tools.Context) ([]Thread, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	k := linuxobj.New(ctx)
	var s shape
	for _, m := range []struct {
		typ, member string
		to          *uint64
	}{{"task_struct", "worker_private", &s.private}, {"kthread", "threadfn", &s.threadfn}} {
		f, err := k.Member(m.typ, m.member)
		if err != nil {
			return nil, fmt.Errorf("%s: symbol table has no %s.%s: %w", Name, m.typ, m.member, linuxobj.ErrUnsupported)
		}
		*m.to = f.Offset
	}
	s.fullName = k.Has("kthread", "full_name")
	model, err := k.Modules()
	if err != nil {
		return nil, fmt.Errorf("%s: kernel modules: %w", Name, err)
	}
	views, err := model.Views()
	if err != nil {
		return nil, fmt.Errorf("%s: kernel modules: %w", Name, err)
	}
	views.Report(ctx.AddDiagnostic, Name)
	if views.Lossy() && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: the module views left modules out", Name)
	}
	known := views.Known()
	walk, err := k.Walker().Tasks(true, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)

	var out []Thread
	var skipped, unnamed tally
	for _, addr := range walk.Tasks {
		r, held, err := thread(k, s, linuxobj.Task{Addr: addr}, &unnamed)
		if err != nil {
			skipped.add("task_struct at %#x: %v", addr, err)
			continue
		}
		if !held {
			continue
		}
		o := model.Lookup(known, r.FunctionAddress, k.SymbolsAt)
		if o.Found {
			r.Module, r.Symbol = o.Names()
			r.OwnerFound = true
		}
		out = append(out, r)
	}
	if skipped.count > 0 {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: strict mode: %d kernel threads not read, first: %s", Name, skipped.count, skipped.first)
		}
		ctx.AddDiagnostic("%s: %d kernel threads not read, first: %s", Name, skipped.count, skipped.first)
	}
	if unnamed.count > 0 {
		ctx.AddDiagnostic("%s: %d full names did not read, comm shown, first: %s", Name, unnamed.count, unnamed.first)
	}
	return out, nil
}

// S61 W1, W2: a PF_KTHREAD task's worker_private is its struct kthread, and
// threadfn is set only for a thread kthread() started.
func thread(k *linuxobj.Kernel, s shape, t linuxobj.Task, unnamed *tally) (Thread, bool, error) {
	kernel, err := k.IsKernelThread(t)
	if err != nil || !kernel {
		return Thread{}, false, err
	}
	kt, err := k.PointerAt(k.Memory(), t.Addr+s.private)
	if err != nil {
		return Thread{}, false, err
	}
	if kt == 0 {
		return Thread{}, false, nil
	}
	fn, err := k.PointerAt(k.Memory(), kt+s.threadfn)
	if err != nil {
		return Thread{}, false, fmt.Errorf("kthread at %#x: threadfn: %w", kt, err)
	}
	if fn == 0 {
		return Thread{}, false, nil
	}
	r := Thread{FunctionAddress: fn}
	if r.TID, err = k.PID(t); err != nil {
		return r, false, err
	}
	if r.Name, err = k.Comm(t); err != nil {
		return r, false, err
	}
	if s.fullName {
		full, err := k.Pointer(k.Memory(), kt, "kthread", "full_name")
		if err != nil {
			return r, false, err
		}
		if full != 0 {
			name, err := k.StringAt(full, shownName)
			if err != nil {
				unnamed.add("kthread at %#x: full_name at %#x: %v", kt, full, err)
			} else {
				r.Name = name[:min(len(name), shownName-1)]
			}
		}
	}
	return r, true, nil
}
