package processlist

import (
	"encoding/binary"
	"testing"
)

func FuzzActiveListWalk(f *testing.F) {
	seed := newS25Image(ordinaryList()[:2]...)
	for _, at := range seed.procs {
		b, _ := seed.mem.ReadAt(at, s25ProcStride)
		f.Add(b, true)
	}
	f.Add(make([]byte, 0x600), false)
	f.Fuzz(func(t *testing.T, body []byte, sanity bool) {
		if len(body) > int(2*s25ProcStride) {
			body = body[:2*s25ProcStride]
		}
		im := newS25Image(ordinaryList()[:2]...)
		im.mem.put(s25At(0), body)
		ctx, _ := im.ctx(map[string]any{optionActiveOnlyFilter: true, optionSanityFilter: sanity})
		rows, err := Run(ctx)
		if err != nil {
			return
		}
		check := NewProcessCheck(ctx)
		system, _ := im.mem.ReadAt(s25SystemPtr, 8)
		for _, p := range rows {
			if _, err := check.Check(im.mem, p.EPROCESS); err != nil {
				t.Fatalf("row at 0x%x fails the process check: %v", p.EPROCESS, err)
			}
			if p.EPROCESS == binary.LittleEndian.Uint64(system) {
				t.Fatalf("the system process at 0x%x is active", p.EPROCESS)
			}
			exit, _ := im.mem.ReadAt(p.EPROCESS+s25Exited, 8)
			threads, _ := im.mem.ReadAt(p.EPROCESS+s25Threads, 4)
			if binary.LittleEndian.Uint64(exit) != 0 || binary.LittleEndian.Uint32(threads) == 0 {
				t.Fatalf("row at 0x%x has exited or has no threads", p.EPROCESS)
			}
		}
	})
}
