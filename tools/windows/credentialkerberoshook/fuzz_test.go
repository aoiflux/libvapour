package credentialkerberoshook

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/disasm"
)

func FuzzDecodeEntry(f *testing.F) {
	f.Add(make([]byte, entrySize))
	f.Add(cleanEntry(23).bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		e, ok := decodeEntry(b)
		if ok != (len(b) >= entrySize) {
			t.Fatalf("ok %v for %d bytes", ok, len(b))
		}
		if !ok {
			return
		}
		last := -1
		for _, p := range e.routines {
			if p.address == 0 {
				t.Fatal("a zero routine was kept")
			}
			at := -1
			for i, s := range slotOffsets {
				if s.slot == p.slot {
					at = i
				}
			}
			if at <= last {
				t.Fatalf("routines out of order: %+v", e.routines)
			}
			last = at
			if got := binary.LittleEndian.Uint64(b[slotOffsets[at].offset:]); got != p.address {
				t.Fatalf("%s: 0x%x, want 0x%x", p.slot, p.address, got)
			}
		}
	})
}

func FuzzHeadFromLocateCode(f *testing.F) {
	for _, m := range measuredLocate {
		f.Add(codeBytes(m.code), m.view+m.rva)
	}
	f.Add([]byte{0xc3}, uint64(0))
	f.Fuzz(func(t *testing.T, code []byte, at uint64) {
		head, ok := headFromLocateCode(code, at)
		if !ok {
			return
		}
		targets := map[uint64]bool{}
		for off, n := 0, 0; off < len(code) && off < locateWindow && n < locateInstructions; n++ {
			in, ok := disasm.Decode(code[off:], at+uint64(off), disasm.Mode64)
			if !ok {
				break
			}
			if tgt, rel := in.RIPRelativeTarget(); rel {
				targets[tgt] = true
			}
			off += in.Len
		}
		if !targets[head.count] || !targets[head.array] || head.source != SourceCode {
			t.Fatalf("head %+v not from a RIP-relative operand in the window", head)
		}
	})
}
