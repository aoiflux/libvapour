package processpidhash

import (
	"strings"
	"testing"

	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func table(t *testing.T) (*lt.Kernel, map[uint64]uint64) {
	t.Helper()
	k := lt.NewKernel(1700000000, 0)
	lt.AddPIDTypes(k)
	leader := k.AddTask(lt.Task{PID: 7, TGID: 7, Comm: "bash"})
	thread := k.AddTask(lt.Task{PID: 9, TGID: 7, Comm: "bash"})
	worker := k.AddTask(lt.Task{PID: 3, TGID: 3, Comm: "kworker", Flags: 0x00200000})
	return k, map[uint64]uint64{7: k.AddPID(leader), 9: k.AddPID(thread), 3: k.AddPID(worker), 5: k.AddPID(0)}
}

func TestEveryNumberWithATaskGivesARow(t *testing.T) {
	k, pids := table(t)
	k.AddPIDNamespace(pids)
	ctx, diags := k.Context(map[string]any{OptionDecorateComm: true})
	rows, err := Run(ctx)
	if err != nil || len(*diags) != 0 {
		t.Fatalf("err %v diagnostics %v", err, *diags)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.Comm)
		if r.TaskAddress == 0 {
			t.Errorf("row %+v has no task address", r)
		}
	}
	if strings.Join(got, " ") != "[kworker] bash {bash}" || rows[2].PID != 7 || rows[2].TID != 9 {
		t.Errorf("rows %+v", rows)
	}
}

func TestATaskWhosePIDIsNotItsIndexIsLeftOut(t *testing.T) {
	k, pids := table(t)
	pids[12] = pids[9]
	delete(pids, 9)
	k.AddPIDNamespace(pids)
	ctx, diags := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 2 || len(*diags) != 1 || !strings.Contains((*diags)[0], "index 12") {
		t.Fatalf("rows %+v err %v diagnostics %v", rows, err, *diags)
	}
	strict, _ := k.Context(map[string]any{"strict": true})
	if _, err := Run(strict); err == nil || !strings.HasPrefix(err.Error(), Name+": strict mode: 1 pids left out") {
		t.Errorf("strict: %v", err)
	}
}

func TestAKernelWithoutAPIDNamespaceIDRIsRefused(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	lt.AddPIDTypes(k)
	ctx, _ := k.Context(nil)
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "pid_namespace.idr") {
		t.Errorf("err %v", err)
	}
}
