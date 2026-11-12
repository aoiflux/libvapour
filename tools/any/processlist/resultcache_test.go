package processlist

import (
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func linuxTasksWithPIDs(options map[string]any, pids ...int32) tools.Context {
	k := lt.NewKernel(1700000000, 0)
	tasks := make([]uint64, len(pids))
	for i, pid := range pids {
		tasks[i] = k.AddTask(lt.Task{PID: pid, TGID: pid, Comm: "task", MM: k.Alloc(0x100)})
	}
	k.LinkTasks(tasks...)
	ctx, _ := k.Context(options)
	return ctx
}

func TestALinuxListNarrowedToOneProcessIsNotHandedToAWholeListRequest(t *testing.T) {
	ctx := linuxTasksWithPIDs(map[string]any{"pid": uint64(1234)}, 1, 1234, 4321)

	narrowed, err := Run(ctx)
	if err != nil {
		t.Fatalf("Run with pid 1234: %v", err)
	}
	if len(narrowed) != 1 || narrowed[0].PID != 1234 {
		t.Fatalf("pid 1234 kept %+v", narrowed)
	}
	whole, err := Run(ctx.WithoutPIDFilter())
	if err != nil {
		t.Fatalf("Run without the filter: %v", err)
	}
	if len(whole) != 3 {
		t.Fatalf("without the filter: %d processes %+v, want all 3", len(whole), whole)
	}
	again, err := Run(ctx)
	if err != nil {
		t.Fatalf("Run with pid 1234 again: %v", err)
	}
	if len(again) != 1 || again[0].PID != 1234 {
		t.Fatalf("pid 1234 again kept %+v", again)
	}
}

func TestALinuxListNarrowedToOneSetIsNotHandedToAnotherSet(t *testing.T) {
	options := map[string]any{}
	ctx := linuxTasksWithPIDs(options, 1, 1234, 4321)
	for _, tc := range []struct {
		pid  any
		want []uint64
	}{
		{uint64(1234), []uint64{1234}},
		{"1234,4321", []uint64{1234, 4321}},
		{nil, []uint64{1, 1234, 4321}},
		{"4321,1234", []uint64{1234, 4321}},
		{uint64(1234), []uint64{1234}},
		{"4321", []uint64{4321}},
	} {
		if tc.pid == nil {
			delete(options, "pid")
		} else {
			options["pid"] = tc.pid
		}
		got, err := Run(ctx)
		if err != nil {
			t.Fatalf("pid %#v: %v", tc.pid, err)
		}
		var pids []uint64
		for _, p := range got {
			pids = append(pids, p.PID)
		}
		if !slices.Equal(pids, tc.want) {
			t.Errorf("pid %#v: Run lists %v, want %v", tc.pid, pids, tc.want)
		}
	}
}

func TestLinuxNeverListsTaskZeroEvenWhenThePIDOptionNamesIt(t *testing.T) {
	for _, tc := range []struct {
		pid  any
		want []uint64
	}{
		{"0,1", []uint64{1}},
		{uint64(0), nil},
	} {
		ctx := linuxTasksWithPIDs(map[string]any{"pid": tc.pid}, 1, 0, 4321)
		got, err := Run(ctx)
		if err != nil {
			t.Fatalf("pid %#v: %v", tc.pid, err)
		}
		var pids []uint64
		for _, p := range got {
			pids = append(pids, p.PID)
		}
		if !slices.Equal(pids, tc.want) {
			t.Errorf("pid %#v: Run lists %v, want %v", tc.pid, pids, tc.want)
		}
	}
}
