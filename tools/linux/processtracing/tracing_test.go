package processtracing

import (
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	ptPtraced   = 1 << 0
	ptSeized    = 1 << 16
	ptTraceFork = 1 << 4
)

func TestTracerAndTraceeAreListedWithTheirLinks(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	tracer := k.AddTask(lt.Task{PID: 50, TGID: 50, Comm: "gdb"})
	tracee := k.AddTask(lt.Task{PID: 60, TGID: 60, Comm: "target", Parent: tracer, Ptrace: ptPtraced | ptSeized | ptTraceFork})
	plain := k.AddTask(lt.Task{PID: 70, TGID: 70, Comm: "bash"})
	k.Circle(tracer+lt.TaskPtraced, tracee+lt.TaskPtraceEntry)
	k.LinkTasks(tracer, tracee, plain)
	ctx, diags := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || len(*diags) != 0 {
		t.Fatalf("rows %+v diagnostics %v", rows, *diags)
	}
	if r := rows[0]; r.TID != 50 || r.Traced || r.TracerTID != 0 || !slices.Equal(r.Tracees, []int64{60}) || r.Options != "" {
		t.Errorf("tracer row %+v", r)
	}
	if r := rows[1]; r.TID != 60 || !r.Traced || r.TracerTID != 50 || r.Tracees != nil ||
		r.Options != "PT_PTRACED|PT_TRACE_FORK|PT_SEIZED" {
		t.Errorf("tracee row %+v", r)
	}
}

func TestATraceeMissingFromItsTracersListIsReported(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	tracer := k.AddTask(lt.Task{PID: 50, TGID: 50, Comm: "gdb"})
	other := k.AddTask(lt.Task{PID: 55, TGID: 55, Comm: "other", Parent: tracer, Ptrace: ptPtraced})
	tracee := k.AddTask(lt.Task{PID: 60, TGID: 60, Comm: "target", Parent: tracer, Ptrace: ptPtraced | 1<<29})
	k.Circle(tracer+lt.TaskPtraced, other+lt.TaskPtraceEntry)
	k.LinkTasks(tracer, other, tracee)
	ctx, diags := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[2].Options != "PT_PTRACED|0x20000000" {
		t.Fatalf("rows %+v", rows)
	}
	joined := strings.Join(*diags, "\n")
	for _, want := range []string{"1 traced tasks missing from their tracer's ptraced list, first: tid 60 traced by tid 50",
		"1 tasks with ptrace bits that have no name"} {
		if !strings.Contains(joined, want) {
			t.Errorf("diagnostics %v lack %q", *diags, want)
		}
	}
}

func TestAnUnreadableTaskFailsOnlyInStrictMode(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	task := k.AddTask(lt.Task{PID: 60, TGID: 60, Comm: "target", Ptrace: ptPtraced})
	k.LinkTasks(task)
	k.Table.AddStruct(withoutPtraced(t, k))
	ctx, diags := k.Context(nil)
	if rows, err := Run(ctx); err != nil || len(rows) != 0 || len(*diags) == 0 {
		t.Errorf("rows %+v err %v diagnostics %v", rows, err, *diags)
	}
	strict, _ := k.Context(map[string]any{"strict": true})
	if _, err := Run(strict); err == nil || !strings.HasPrefix(err.Error(), Name+": strict mode: 1 tasks not read") {
		t.Errorf("strict: %v", err)
	}
}

func withoutPtraced(t *testing.T, k *lt.Kernel) symbols.StructType {
	t.Helper()
	st, err := k.Table.Struct("task_struct")
	if err != nil {
		t.Fatal(err)
	}
	var kept []symbols.Field
	for _, f := range st.Fields {
		if f.Name != "ptraced" {
			kept = append(kept, f)
		}
	}
	st.Fields = kept
	return st
}
