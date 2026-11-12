package networkhooks

import (
	"encoding/binary"
	"testing"
)

func FuzzHookChain(f *testing.F) {
	seed := make([]byte, 0x40)
	binary.LittleEndian.PutUint16(seed, 2)
	f.Add(seed)
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, block []byte) {
		if len(block) > 0x4000 {
			return
		}
		fx := newFixture()
		at := fx.k.Alloc(uint64(len(block)) + 1)
		fx.k.Mem.Write(at, block)
		fx.k.Mem.U64(fx.ipv4(0), at)
		ctx, _ := fx.k.Context(nil)
		rows, err := Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		padded := append(append([]byte(nil), block...), 0, 0)
		count := int(binary.LittleEndian.Uint16(padded))
		if len(rows) > min(count, maxChainEntries) {
			t.Fatalf("%d rows from a chain of %d", len(rows), count)
		}
	})
}
