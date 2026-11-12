package processscan

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzTaskScan(f *testing.F) {
	f.Add(make([]byte, lxTaskSize), uint16(0))
	f.Fuzz(func(t *testing.T, data []byte, shift uint16) {
		w := newLxWorld()
		at := uint64(0x50000) + uint64(shift&0x7ff)*8
		w.add(at, lxTask{pid: 8, tgid: 8, comm: "seed"})
		for i, b := range data {
			if uint64(i) >= lxTaskSize {
				break
			}
			w.phys[at+uint64(i)] = b
		}
		ctx, _ := w.ctx(nil)
		rows, err := RunLinux(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			body := w.phys[r.Offset : r.Offset+lxTaskSize]
			pid := int32(binary.LittleEndian.Uint32(body[lxPID:]))
			tgid := int32(binary.LittleEndian.Uint32(body[lxTGID:]))
			leader := binary.LittleEndian.Uint64(body[lxLeader:])
			if pid < 1 || tgid < 1 || pid >= pidLimit || tgid >= pidLimit {
				t.Fatalf("ids %d %d", pid, tgid)
			}
			if (leader == r.Address) != (pid == tgid) || leader>>63 != 1 {
				t.Fatalf("leader 0x%x pid %d tgid %d", leader, pid, tgid)
			}
			if binary.LittleEndian.Uint64(body[lxReal:])>>63 != 1 || binary.LittleEndian.Uint64(body[lxParent:])>>63 != 1 {
				t.Fatal("parent outside the kernel half")
			}
			if _, ok := exitStates[binary.LittleEndian.Uint32(body[lxExit:])]; !ok {
				t.Fatal("exit state")
			}
			if bytes.IndexByte(body[lxComm:lxComm+16], 0) < 0 {
				t.Fatal("comm without NUL")
			}
		}
	})
}
