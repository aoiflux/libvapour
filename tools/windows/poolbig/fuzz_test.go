package poolbig

import (
	"encoding/binary"
	"testing"
)

// Any table contents: no panic, at most one row per slot, and every row
// carries a nonzero Key, bit 0 of its address clear and Freed equal to that
// bit of the stored Va.
func FuzzTableRead(f *testing.F) {
	seed := fx26100.memory(4, map[int]fxEntry{0: {va: vaA, tag: "CM10", kind: 0x100}, 1: {va: vaB | 1, tag: "Mdl "}})
	f.Add(seed.buf[fxTable:fxTable+4*32], uint32(4), true)
	f.Add(make([]byte, 48), uint32(2), false)
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0x41}, uint32(9), false)
	f.Fuzz(func(t *testing.T, raw []byte, slots uint32, flags bool) {
		b := fx19045
		if flags {
			b = fx26100
		}
		slots = slots%64 + 1
		m := b.memory(int(slots), nil)
		copy(m.buf[fxTable:], raw)
		ctx, _ := fxContext(b.table(), m, map[string]any{OptionShowFree: true})
		rows, err := Run(ctx)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(rows) > int(slots) {
			t.Fatalf("%d rows from %d slots", len(rows), slots)
		}
		for _, r := range rows {
			at := fxTable + r.Slot*b.stride
			va := binary.LittleEndian.Uint64(m.buf[at:])
			key := binary.LittleEndian.Uint32(m.buf[at+8:])
			if key == 0 || r.Address&freedBit != 0 || r.Freed != (va&freedBit != 0) || r.Address != va&^freedBit {
				t.Fatalf("row %+v from Va 0x%x Key 0x%x", r, va, key)
			}
		}
	})
}
