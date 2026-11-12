package linuxobj_test

import (
	"bytes"
	"testing"

	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func FuzzTaskName(f *testing.F) {
	f.Add([]byte("bash\x00"))
	f.Add([]byte("0123456789abcdefXYZ"))
	f.Add([]byte{0xff, 0, 1})
	f.Fuzz(func(t *testing.T, raw []byte) {
		k := lt.NewKernel(1700000000, 0)
		task := k.AddTask(lt.Task{PID: 1, TGID: 1})
		comm := make([]byte, linuxobj.TaskCommLen)
		copy(comm, raw)
		k.Mem.Write(task+lt.TaskComm, comm)
		ctx, _ := k.Context(nil)
		got, err := linuxobj.New(ctx).Comm(linuxobj.Task{Addr: task})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) > linuxobj.TaskCommLen || bytes.IndexByte([]byte(got), 0) >= 0 {
			t.Fatalf("comm %q from %q", got, comm)
		}
	})
}

// FuzzTaskSummary writes arbitrary bytes over a task and the objects it points
// at: every reader must return, and the summary must keep the task's own IDs.
func FuzzTaskSummary(f *testing.F) {
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 0x200), bytes.Repeat([]byte{0x41}, 0x80), bytes.Repeat([]byte{0}, 0x100))
	f.Fuzz(func(t *testing.T, task, cred, mm []byte) {
		k := lt.NewKernel(1700000000, 0)
		lt.AddFS(k)
		pgd := k.Alloc(0x1000)
		mmAddr := k.AddMM(lt.MM{PGD: pgd})
		credAddr := k.AddCred(lt.Cred{UID: 1})
		addr := k.AddTask(lt.Task{PID: 3, TGID: 3, Comm: "x", MM: mmAddr, Cred: credAddr})
		k.Mem.Write(addr, task[:min(len(task), int(lt.TaskSize))])
		k.Mem.Write(credAddr, cred[:min(len(cred), int(lt.CredSize))])
		k.Mem.Write(mmAddr, mm[:min(len(mm), int(lt.FSMMSize))])
		ctx, _ := k.Context(nil)
		ctx.Memory = &lt.Translating{Memory: k.Mem, Tables: map[uint64]uint64{pgd: 0x5000}}
		kern := linuxobj.New(ctx)
		tk := linuxobj.Task{Addr: addr}
		s, err := kern.TaskFields(tk, true)
		if err != nil {
			t.Fatalf("a mapped task gave no summary: %v", err)
		}
		tid, _ := kern.PID(tk)
		if s.TID != tid {
			t.Fatalf("summary tid %d, task %d", s.TID, tid)
		}
		_, _, _, _ = kern.ProcessLayer(tk)
		_, _, _ = kern.TaskCred(tk)
	})
}
