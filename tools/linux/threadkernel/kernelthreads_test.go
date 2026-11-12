package threadkernel

import (
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	pfKthread      = 0x00200000
	kthreadFn      = 0x10
	kthreadName    = 0x18
	kthreadSize    = 0x40
	moduleAt       = 0xffffffffc0100000
	moduleFunction = moduleAt + 0x500
	strayFunction  = 0xffffffffc0900000
)

func kernel(t *testing.T) *lt.Kernel {
	t.Helper()
	k := lt.NewKernel(1700000000, 0)
	k.Table.AddStruct(symbols.StructType{Name: "kthread", Size: kthreadSize, Fields: []symbols.Field{
		{Name: "threadfn", Offset: kthreadFn, Type: symbols.TypeRef{IsPointer: true, Element: &symbols.TypeRef{Name: "void"}}},
		{Name: "full_name", Offset: kthreadName, Type: symbols.TypeRef{Name: "char", IsPointer: true, Element: &symbols.TypeRef{Name: "char"}}},
	}})
	m := lt.AddModuleTypes(k)
	mod := m.Add("nfsd", moduleAt, 0x1000, []lt.ModuleSymbol{{Name: "nfsd_worker", Value: moduleAt + 0x400}}, 1)
	m.List(mod)
	m.Kset(mod)
	m.Area(moduleAt, moduleAt+0x1000)
	return k
}

func kthread(k *lt.Kernel, tid int32, comm string, fn uint64, full string) uint64 {
	task := k.AddTask(lt.Task{PID: tid, TGID: tid, Comm: comm, Flags: pfKthread})
	kt := k.Alloc(kthreadSize)
	k.Mem.U64(kt+kthreadFn, fn)
	if full != "" {
		k.Mem.U64(kt+kthreadName, k.Str(full))
	}
	k.Mem.U64(task+lt.TaskWorkerPriv, kt)
	return task
}

func TestEachKernelThreadNamesItsFunctionAndOwner(t *testing.T) {
	k := kernel(t)
	a := kthread(k, 40, "nfsd", moduleFunction, "")
	b := kthread(k, 41, "irq/122-pciehp-", strayFunction, "irq/122-pciehp-very-long-name")
	idle := kthread(k, 2, "kthreadd", 0, "")
	user := k.AddTask(lt.Task{PID: 100, TGID: 100, Comm: "bash", MM: k.Alloc(0x100)})
	k.LinkTasks(idle, a, b, user)
	ctx, diags := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows %+v diagnostics %v", rows, *diags)
	}
	if r := rows[0]; r.TID != 40 || r.Name != "nfsd" || r.FunctionAddress != moduleFunction || !r.OwnerFound ||
		r.Module != "nfsd" || r.Symbol != "nfsd_worker+0x100" {
		t.Errorf("module thread %+v", r)
	}
	if r := rows[1]; r.TID != 41 || r.Name != "irq/122-pciehp-very-long-name" || r.OwnerFound || r.Module != "" {
		t.Errorf("stray thread %+v", r)
	}
}

func TestAKernelWithoutThreadFunctionsIsRefused(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	ctx, _ := k.Context(nil)
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "kthread.threadfn") {
		t.Errorf("err %v", err)
	}
}

func TestAFullNameIsCutWhereProcShowsIt(t *testing.T) {
	k := kernel(t)
	long := strings.Repeat("x", 80)
	k.LinkTasks(kthread(k, 50, "x", moduleFunction, long))
	ctx, _ := k.Context(nil)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || rows[0].Name != long[:63] {
		t.Errorf("rows %+v err %v", rows, err)
	}
}
