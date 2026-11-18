package consolehistory

import (
	"bytes"
	"testing"
)

// Bytes patched anywhere into a heap that holds two histories: rows come only
// from the host process, inside its heap, in address order.
func FuzzScanHistoriesOfAPatchedHeap(f *testing.F) {
	f.Add(uint32(0x10), bytes.Repeat([]byte{0xff}, 4))
	f.Add(uint32(0x200), make([]byte, 8))
	f.Add(uint32(0x400), []byte("\x31\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, at uint32, patch []byte) {
		h := newHeap(t, 19045)
		owner := h.record(4242)
		h.history("powershell.exe", []string{"Get-ChildItem"}, 0)
		h.history("cmd.exe", []string{"whoami", "net user"}, owner)
		copy(h.buf[int(at%uint32(len(h.buf))):], patch)
		rows, err := Run(runContext(t, h, 19045))
		if err != nil {
			return
		}
		end := heapStart + uint64(len(h.buf))
		for i, r := range rows {
			if r.PID != hostPID {
				t.Fatalf("row from pid %d %q", r.PID, r.Process)
			}
			if r.Address < heapStart || r.Address >= end {
				t.Fatalf("history at 0x%x lies outside the heap", r.Address)
			}
			if i > 0 && rows[i-1].Address >= r.Address {
				t.Fatalf("rows out of address order: 0x%x then 0x%x", rows[i-1].Address, r.Address)
			}
		}
	})
}
