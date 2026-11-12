package boottime

import (
	"strings"
	"testing"
	"time"

	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func TestOneRowPerTimeNamespaceSortedByInode(t *testing.T) {
	k := lt.NewKernel(1787405196, 396665099)
	lt.AddTimeNamespaceTypes(k)
	host := k.AddTimeNamespace(0xEFFFFFFA, 0, 0)
	inner := k.AddTimeNamespace(0xF0000200, 3600, 0)
	var tasks []uint64
	for i, ns := range []uint64{inner, host, host, 0} {
		task := k.AddTask(lt.Task{PID: int32(10 + i), TGID: int32(10 + i), Comm: "t"})
		if ns != 0 {
			k.SetTaskTimeNS(task, ns)
		} else {
			k.Mem.U64(task+lt.TaskNsproxy, 0)
		}
		tasks = append(tasks, task)
	}
	k.LinkTasks(tasks...)
	ctx, diags := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	boot := time.Unix(1787405196, 396665099).UTC()
	want := []Row{
		{Namespace: 0xEFFFFFFA, NamespaceAddress: host, Tasks: 2, BootTime: boot},
		{Namespace: 0xF0000200, NamespaceAddress: inner, BootOffset: time.Hour, Tasks: 1, BootTime: boot.Add(-time.Hour)},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v (diagnostics %v)", rows, *diags)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d: %+v, want %+v", i, rows[i], want[i])
		}
	}
	if len(*diags) != 0 {
		t.Errorf("diagnostics %v", *diags)
	}
}

func TestOneHostRowWithoutTimeNamespaces(t *testing.T) {
	k := lt.NewKernel(1600000000, 7)
	ctx, _ := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Namespace != 0 || !rows[0].BootTime.Equal(time.Unix(1600000000, 7)) {
		t.Errorf("rows %+v", rows)
	}
}

func TestAnInconsistentClockIsReported(t *testing.T) {
	k := lt.NewKernel(1600000000, 0)
	k.AddClockChecks(4, false, true)
	ctx, diags := k.Context(nil)
	if _, err := Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(*diags) != 1 || !strings.Contains((*diags)[0], "offs_real is not the negated wall_to_monotonic") {
		t.Errorf("diagnostics %v", *diags)
	}
	strict, _ := k.Context(map[string]any{"strict": true})
	if _, err := Run(strict); err == nil || !strings.HasPrefix(err.Error(), Name+": timekeeper at 0x") {
		t.Errorf("strict: %v", err)
	}
	k.AddClockChecks(5, true, true)
	ctx, diags = k.Context(nil)
	if _, err := Run(ctx); err != nil || len(*diags) != 1 || !strings.Contains((*diags)[0], "sequence 5 is odd") {
		t.Errorf("odd sequence: %v %v", err, *diags)
	}
}

func TestUnreadableNamespacesAreCountedAndStrictModeFails(t *testing.T) {
	k := lt.NewKernel(1600000000, 0)
	lt.AddTimeNamespaceTypes(k)
	host := k.AddTimeNamespace(0xEFFFFFFA, 0, 0)
	ok := k.AddTask(lt.Task{PID: 1, TGID: 1, Comm: "a"})
	bad := k.AddTask(lt.Task{PID: 2, TGID: 2, Comm: "b"})
	k.SetTaskTimeNS(ok, host)
	k.SetTaskTimeNS(bad, 0xffff888777000000)
	k.LinkTasks(ok, bad)
	ctx, diags := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || rows[0].Tasks != 1 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if len(*diags) != 1 || !strings.Contains((*diags)[0], "1 tasks without a readable time namespace") {
		t.Errorf("diagnostics %v", *diags)
	}
	strict, _ := k.Context(map[string]any{"strict": true})
	if _, err := Run(strict); err == nil {
		t.Error("strict mode passed an unreadable namespace")
	}
}

func TestNoTimekeeperIsAnError(t *testing.T) {
	k := lt.NewKernel(1600000000, 0)
	tk, _ := k.Table.LookupSymbol("tk_core")
	k.Mem.Unmap(tk.Address)
	ctx, _ := k.Context(nil)
	if _, err := Run(ctx); err == nil || !strings.HasPrefix(err.Error(), Name+": ") {
		t.Errorf("%v", err)
	}
}
