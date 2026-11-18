package threadkernel

import (
	"bytes"
	"testing"

	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const fuzzNameArea = 0x100

// The function pointer, the full name's bytes and a patch anywhere in the
// struct kthread: a row has a function, a name no longer than /proc shows
// (S61 W4), and an owner only from the module that holds the function.
func FuzzKernelThreadOfAPatchedKthread(f *testing.F) {
	f.Add(uint64(moduleFunction), []byte("nfsd-worker\x00"), uint8(0), []byte{})
	f.Add(uint64(strayFunction), make([]byte, fuzzNameArea), uint8(kthreadName), bytes.Repeat([]byte{0xff}, 4))
	f.Add(uint64(moduleAt+0x1000), []byte("x"), uint8(kthreadFn), make([]byte, 8))
	f.Fuzz(func(t *testing.T, fn uint64, name []byte, at uint8, patch []byte) {
		k := kernel(t)
		task := k.AddTask(lt.Task{PID: 40, TGID: 40, Comm: "nfsd", Flags: pfKthread})
		kt := k.Alloc(kthreadSize)
		buffer := k.Alloc(fuzzNameArea)
		k.Mem.Write(buffer, name[:min(len(name), fuzzNameArea)])
		k.Mem.U64(kt+kthreadFn, fn)
		k.Mem.U64(kt+kthreadName, buffer)
		off := uint64(at) % kthreadSize
		k.Mem.Write(kt+off, patch[:min(uint64(len(patch)), kthreadSize-off)])
		k.Mem.U64(task+lt.TaskWorkerPriv, kt)
		k.LinkTasks(task)
		ctx, _ := k.Context(nil)
		rows, err := Run(ctx)
		if err != nil || len(rows) > 1 {
			t.Fatalf("rows %+v, %v", rows, err)
		}
		for _, r := range rows {
			inModule := r.FunctionAddress >= moduleAt && r.FunctionAddress-moduleAt < 0x1000
			switch {
			case r.FunctionAddress == 0 || r.TID != 40:
				t.Fatalf("row %+v", r)
			case len(r.Name) > shownName-1:
				t.Fatalf("name of %d bytes", len(r.Name))
			case inModule && (!r.OwnerFound || r.Module != "nfsd"):
				t.Fatalf("a function inside nfsd placed %+v", r)
			case !r.OwnerFound && (r.Module != "" || r.Symbol != ""):
				t.Fatalf("an unowned function names an owner: %+v", r)
			}
		}
	})
}
