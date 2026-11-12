package processcapabilities

import (
	"strings"
	"testing"

	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const full = 1<<41 - 1

func TestEveryTaskShowsItsObjectiveSets(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	root := k.AddCred(lt.Cred{EUID: 0, Caps: [5]uint64{0, full, full, full, 0}})
	user := k.AddCred(lt.Cred{EUID: 1000, Caps: [5]uint64{1 << 12, 1<<12 | 1<<13, 1 << 13, full, 1 << 12}})
	leader := k.AddTask(lt.Task{PID: 10, TGID: 10, Comm: "sshd", Cred: root})
	thread := k.AddTask(lt.Task{PID: 11, TGID: 10, Comm: "sshd", Cred: user})
	k.LinkTasks(leader)
	k.LinkThreads(leader, thread)
	ctx, diags := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil || len(*diags) != 0 {
		t.Fatalf("err %v diagnostics %v", err, *diags)
	}
	want := []Process{
		{Process: "sshd", PID: 10, TID: 10, Permitted: "CAP_FULL_SET", Effective: "CAP_FULL_SET", Bounding: "CAP_FULL_SET"},
		{Process: "sshd", PID: 10, TID: 11, EUID: 1000, Inheritable: "CAP_NET_ADMIN", Permitted: "CAP_NET_ADMIN, CAP_NET_RAW",
			Effective: "CAP_NET_RAW", Bounding: "CAP_FULL_SET", Ambient: "CAP_NET_ADMIN"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d %+v, want %+v", i, rows[i], want[i])
		}
	}
}

func TestAmbientOutsidePermittedAndInheritableIsReported(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	bad := k.AddCred(lt.Cred{Caps: [5]uint64{0, 1 << 12, 0, full, 1 << 21}})
	task := k.AddTask(lt.Task{PID: 10, TGID: 10, Comm: "x", Cred: bad})
	k.LinkTasks(task)
	ctx, diags := k.Context(nil)
	if rows, err := Run(ctx); err != nil || len(rows) != 1 || len(*diags) != 1 ||
		!strings.Contains((*diags)[0], "ambient bits 0x200000") {
		t.Errorf("rows %+v err %v diagnostics %v", rows, err, *diags)
	}
}

func TestANullRealCredFailsTheTaskOnlyInStrictMode(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	task := k.AddTask(lt.Task{PID: 10, TGID: 10, Comm: "x"})
	k.Mem.U64(task+lt.TaskRealCred, 0)
	k.LinkTasks(task)
	ctx, diags := k.Context(nil)
	if rows, err := Run(ctx); err != nil || len(rows) != 0 || len(*diags) != 1 {
		t.Errorf("rows %+v err %v diagnostics %v", rows, err, *diags)
	}
	strict, _ := k.Context(map[string]any{"strict": true})
	if _, err := Run(strict); err == nil || !strings.HasPrefix(err.Error(), Name+": strict mode: 1 tasks not read") {
		t.Errorf("strict: %v", err)
	}
}
