package tracingbpf

import "testing"

// The image is untrusted: whatever a program, its aux structure and the
// registry node hold, the tool ends with at most one row per slot.
func FuzzProgramDecoder(f *testing.F) {
	seed := newFixture(true)
	standard(seed)
	p, _ := seed.mem.ReadAt(progAt(0), 0x1000)
	node, _ := seed.mem.ReadAt(xaNode, nodeSlots+64*8)
	f.Add(p, node)
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, program, slots []byte) {
		fx := newFixture(true)
		standard(fx)
		fx.mem.Write(progAt(0), program)
		fx.mem.Write(xaNode, slots)
		rows, _, err := fx.run(t, nil)
		if err == nil && len(rows) > 64 {
			t.Fatalf("%d rows from a node of 64 slots", len(rows))
		}
	})
}
