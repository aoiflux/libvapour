package processpidhash

import (
	"bytes"
	"encoding/binary"
	"testing"

	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

// The patch lands in one struct pid or one task_struct, so the tasks heads,
// the pid_links nodes and the task's own pid all get hit. S61 H4 makes the
// index the task's pid, so no pid and no task can give two rows.
func FuzzPIDTableOfAPatchedWorld(f *testing.F) {
	f.Add(uint8(0), uint16(0), make([]byte, 8))
	f.Add(uint8(4), uint16(lt.TaskPID), binary.LittleEndian.AppendUint32(nil, 9))
	f.Add(uint8(5), uint16(lt.TaskPIDLinks), bytes.Repeat([]byte{0xff}, 8))
	f.Add(uint8(3), uint16(0), binary.LittleEndian.AppendUint64(nil, 0x70))
	f.Fuzz(func(t *testing.T, target uint8, at uint16, patch []byte) {
		k := lt.NewKernel(1700000000, 0)
		lt.AddPIDTypes(k)
		tasks := []uint64{
			k.AddTask(lt.Task{PID: 7, TGID: 7, Comm: "bash"}),
			k.AddTask(lt.Task{PID: 9, TGID: 7, Comm: "bash"}),
			k.AddTask(lt.Task{PID: 3, TGID: 3, Comm: "kworker"}),
		}
		pids := map[uint64]uint64{7: k.AddPID(tasks[0]), 9: k.AddPID(tasks[1]), 3: k.AddPID(tasks[2]), 5: k.AddPID(0)}
		k.AddPIDNamespace(pids)
		objects := []struct{ at, size uint64 }{
			{pids[7], lt.PIDSize}, {pids[9], lt.PIDSize}, {pids[3], lt.PIDSize}, {pids[5], lt.PIDSize},
			{tasks[0], lt.TaskSize}, {tasks[1], lt.TaskSize}, {tasks[2], lt.TaskSize},
		}
		o := objects[int(target)%len(objects)]
		off := uint64(at) % o.size
		k.Mem.Write(o.at+off, patch[:min(uint64(len(patch)), o.size-off)])
		ctx, _ := k.Context(nil)
		rows, err := Run(ctx)
		if err != nil {
			t.Fatalf("a lenient run failed: %v", err)
		}
		seenTID, seenTask := map[int64]bool{}, map[uint64]bool{}
		for i, r := range rows {
			if seenTID[r.TID] || seenTask[r.TaskAddress] {
				t.Fatalf("pid %d or task %#x twice: %+v", r.TID, r.TaskAddress, rows)
			}
			seenTID[r.TID], seenTask[r.TaskAddress] = true, true
			if r.TaskAddress == 0 || r.TID < 0 {
				t.Fatalf("row %+v", r)
			}
			if i > 0 && (rows[i-1].PID > r.PID || rows[i-1].PID == r.PID && rows[i-1].TID >= r.TID) {
				t.Fatalf("rows out of pid order: %+v", rows)
			}
		}
	})
}
