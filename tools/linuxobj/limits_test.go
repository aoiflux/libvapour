package linuxobj_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func fdtOf(t *testing.T, kk *linuxobj.Kernel, task uint64) uint64 {
	t.Helper()
	files, err := kk.PointerAt(kk.Memory(), task+lt.FSTaskFiles)
	if err != nil {
		t.Fatal(err)
	}
	fdt, err := kk.PointerAt(kk.Memory(), files+lt.FSFilesFdt)
	if err != nil {
		t.Fatal(err)
	}
	return fdt
}

func TestTaskFDsReadsATableOfNrOpenSlots(t *testing.T) {
	k := newFSKernel()
	task := k.AddTask(lt.Task{PID: 10, TGID: 10, Comm: "cat"})
	k.LinkTasks(task)
	k.SetTaskFiles(task, 4, map[uint64]uint64{0: k.AddFile(0, 0, 0)})
	ctx, _ := k.Context(nil)
	kk := linuxobj.New(ctx)
	const nrOpen = 1 << 20
	k.Mem.U32(fdtOf(t, kk, task)+lt.FSFdtMaxFDs, nrOpen)
	if tab, ok, err := kk.TaskFDs(linuxobj.Task{Addr: task}); !ok || err != nil || tab.Count != nrOpen {
		t.Errorf("max_fds=%d: got %+v ok=%v err=%v, want the table", nrOpen, tab, ok, err)
	}
}

func TestFDTablesStopAtMaxTableEntries(t *testing.T) {
	k := newFSKernel()
	task := k.AddTask(lt.Task{PID: 10, TGID: 10, Comm: "cat"})
	k.LinkTasks(task)
	k.SetTaskFiles(task, 4, map[uint64]uint64{0: k.AddFile(0, 0, 0)})
	ctx, _ := k.Context(nil)
	ctx.Limits = limits.Limits{MaxTableEntries: 4}
	kk := linuxobj.New(ctx)
	if _, ok, err := kk.TaskFDs(linuxobj.Task{Addr: task}); !ok || err != nil {
		t.Errorf("4 slots at limit 4: TaskFDs ok=%v err=%v, want the table", ok, err)
	}
	k.Mem.U32(fdtOf(t, kk, task)+lt.FSFdtMaxFDs, 5)
	if _, ok, err := kk.TaskFDs(linuxobj.Task{Addr: task}); ok || err != nil {
		t.Errorf("5 slots at limit 4: TaskFDs ok=%v err=%v, want no table", ok, err)
	}
}

func TestDentryWalksStopAtTheirLimits(t *testing.T) {
	k := newFSKernel()
	root := k.AddDentry("/", 0, 0)
	etc := k.AddDentry("etc", root, 0)
	passwd := k.AddDentry("passwd", etc, 0)
	long := k.AddDentry("a-name-of-twenty-two", root, 0)
	ctx, _ := k.Context(nil)
	ctx.Limits = limits.Limits{MaxPathSteps: 2, MaxNameBytes: 16}
	kk := linuxobj.New(ctx)
	if got, err := kk.DentryPath(etc); err != nil || got != "/etc" {
		t.Errorf("etc path = %q, %v", got, err)
	}
	if got, err := kk.DentryPath(passwd); err != nil || got != "/etc/passwd" {
		t.Errorf("passwd path at the step limit = %q, %v", got, err)
	}
	deeper := k.AddDentry("x", passwd, 0)
	_, err := kk.DentryPath(deeper)
	if !errors.Is(err, linuxobj.ErrWalkBound) || !strings.Contains(err.Error(), "MaxPathSteps 2") {
		t.Errorf("too-deep path: err %v", err)
	}
	_, err = kk.DentryName(long)
	if !errors.Is(err, linuxobj.ErrWalkBound) || !strings.Contains(err.Error(), "MaxNameBytes 16") {
		t.Errorf("too-long name: err %v", err)
	}
}
