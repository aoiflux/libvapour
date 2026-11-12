package servicerecord

import (
	"encoding/binary"
	"strings"
	"testing"
)

func fuzzMemory(data []byte, base uint64) *sparse {
	m := newSparse()
	m.put(base, data)
	return m
}

func FuzzDecodeRecord(f *testing.F) {
	for i, l := range layouts {
		w := newWorld(l)
		w.record(running(fixtureHeap, "svc", 1))
		b, _ := w.mem.ReadAt(fixtureHeap, l.span())
		names, _ := w.mem.ReadAt(fixtureStrings, 0x40)
		f.Add(b, names, uint8(i))
	}
	f.Fuzz(func(t *testing.T, data, names []byte, which uint8) {
		l := layouts[int(which)%len(layouts)]
		m := fuzzMemory(data, fixtureHeap)
		m.put(fixtureStrings, names)
		rec, why := decode(m, l, fixtureHeap, fixtureImage)
		if why != "" {
			return
		}
		s := rec.status
		if s.currentState < stateStopped || s.currentState > stateLast || s.serviceType&typeKind == 0 ||
			s.serviceType&^typeKnownBits != 0 || rec.startType > 4 || rec.errorControl > 3 || rec.sequence == 0 ||
			rec.name == "" || strings.ContainsAny(rec.name, `/\`) || len([]rune(rec.name)) > maxNameUnits {
			t.Fatalf("accepted a record that breaks a rule: %+v", rec)
		}
		if l.imagePointer && (len(data) < 8 || !fixtureImage.holds(binary.LittleEndian.Uint64(data))) {
			t.Fatal("accepted an object record without an image pointer")
		}
	})
}

func FuzzWalkList(f *testing.F) {
	for i, l := range layouts {
		w := newWorld(l)
		h := w.list("a", "b", "c")
		b, _ := w.mem.ReadAt(fixtureHeap, 0x600)
		hb, _ := w.mem.ReadAt(h.address, 0x100)
		f.Add(b, hb, uint8(i))
	}
	f.Fuzz(func(t *testing.T, heap, headBytes []byte, which uint8) {
		l := layouts[int(which)%len(layouts)]
		m := fuzzMemory(heap, fixtureHeap)
		m.put(fixtureImageStart+0x20000, headBytes)
		const limit = 64
		w := walkList(m, l, head{address: fixtureImageStart + 0x20000, form: l.head}, fixtureImage, limit)
		if len(w.records) > limit {
			t.Fatalf("%d records past the cap", len(w.records))
		}
		seen := map[uint64]bool{}
		for _, r := range w.records {
			if seen[r.address] {
				t.Fatalf("record 0x%x repeats", r.address)
			}
			seen[r.address] = true
		}
		_ = w.headProblems(head{form: l.head})
		_ = searchHeads(m, addressRange{start: fixtureImageStart + 0x20000, end: fixtureImageStart + 0x21000})
	})
}
