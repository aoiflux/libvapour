package linuxobj_test

import (
	"testing"

	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

func TestPtraceFlagNamesFollowPTOptFlagShift(t *testing.T) {
	for v, want := range map[uint64]string{
		0:                     "",
		1:                     "PT_PTRACED",
		1 | 1<<16:             "PT_PTRACED|PT_SEIZED",
		1 | 1<<3 | 1<<(3+4):   "PT_PTRACED|PT_TRACESYSGOOD|PT_TRACE_EXEC",
		1<<(3+20) | 1<<(3+21): "PT_EXITKILL|PT_SUSPEND_SECCOMP",
		1<<30 | 1<<31 | 1<<1:  "PT_DTRACE|PT_BLOCKSTEP|PT_SINGLESTEP",
	} {
		got, rest := linuxobj.PtraceFlagNames(v)
		if got != want || rest != 0 {
			t.Errorf("%#x: %q rest %#x, want %q", v, got, rest, want)
		}
	}
	if got, rest := linuxobj.PtraceFlagNames(1 | 1<<2 | 1<<20); got != "PT_PTRACED" || rest != 1<<2|1<<20 {
		t.Errorf("unnamed bits: %q rest %#x", got, rest)
	}
}

func TestATracerListsItsTraceesAndEachNamesItsTracer(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	tracer := k.AddTask(lt.Task{PID: 100, TGID: 100, Comm: "tracer"})
	a := k.AddTask(lt.Task{PID: 200, TGID: 200, Comm: "a", Ptrace: 1 | 1<<16 | 1<<(3+3)})
	b := k.AddTask(lt.Task{PID: 201, TGID: 200, Comm: "b", Ptrace: 1})
	idle := k.AddTask(lt.Task{PID: 300, TGID: 300, Comm: "idle"})
	for _, x := range []uint64{a, b} {
		k.Mem.U64(x+lt.TaskParent, tracer)
	}
	k.Circle(tracer+lt.TaskPtraced, b+lt.TaskPtraceEntry, a+lt.TaskPtraceEntry)
	kk := fixtureKernel(t, k)

	if ok, err := kk.IsPtracing(linuxobj.Task{Addr: tracer}); err != nil || !ok {
		t.Errorf("tracer: %t %v", ok, err)
	}
	if ok, err := kk.IsPtracing(linuxobj.Task{Addr: idle}); err != nil || ok {
		t.Errorf("idle task traces: %t %v", ok, err)
	}
	tids, walk, err := kk.PtraceTraceeTIDs(linuxobj.Task{Addr: tracer})
	if err != nil || walk.End != linuxwalk.Closed || len(tids) != 2 || tids[0] != 201 || tids[1] != 200 {
		t.Errorf("tracees %v, %s, %v", tids, walk.End, err)
	}
	if tid, ok, err := kk.PtraceTracerTID(linuxobj.Task{Addr: a}); err != nil || !ok || tid != 100 {
		t.Errorf("tracer of a: %d %t %v", tid, ok, err)
	}
	if _, ok, err := kk.PtraceTracerTID(linuxobj.Task{Addr: idle}); err != nil || ok {
		t.Errorf("an untraced task has a tracer: %t %v", ok, err)
	}
	if traced, err := kk.IsBeingPtraced(linuxobj.Task{Addr: b}); err != nil || !traced {
		t.Errorf("b traced %t %v", traced, err)
	}
	names, rest, traced, err := kk.PtraceFlags(linuxobj.Task{Addr: a})
	if err != nil || !traced || rest != 0 || names != "PT_PTRACED|PT_TRACE_CLONE|PT_SEIZED" {
		t.Errorf("flags %q %#x %t %v", names, rest, traced, err)
	}
	if _, _, traced, _ := kk.PtraceFlags(linuxobj.Task{Addr: idle}); traced {
		t.Error("a zero ptrace word is traced")
	}
	k.Mem.U64(a+lt.TaskParent, 0)
	if _, ok, err := kk.PtraceTracerTID(linuxobj.Task{Addr: a}); err != nil || ok {
		t.Errorf("a null parent names a tracer: %t %v", ok, err)
	}
}
