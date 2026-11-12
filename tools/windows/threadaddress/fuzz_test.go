package threadaddress

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/tools/any/memoryranges"
)

// Arbitrary range bounds and address: a returned range holds the address,
// and none is returned when no range does.
func FuzzHolding(f *testing.F) {
	f.Add(make([]byte, 32), uint64(0))
	f.Add([]byte{0, 0x10, 0, 0, 0, 0, 0, 0, 0xff, 0x1f, 0, 0, 0, 0, 0, 0}, uint64(0x1800))
	f.Fuzz(func(t *testing.T, bounds []byte, address uint64) {
		var ranges []memoryranges.Mapping
		for len(bounds) >= 16 && len(ranges) < 64 {
			ranges = append(ranges, memoryranges.Mapping{Start: binary.LittleEndian.Uint64(bounds),
				End: binary.LittleEndian.Uint64(bounds[8:])})
			bounds = bounds[16:]
		}
		r, ok := Holding(ranges, address)
		if ok && (address < r.Start || address > r.End) {
			t.Fatalf("0x%x held by 0x%x-0x%x", address, r.Start, r.End)
		}
		if !ok {
			for _, m := range ranges {
				if m.Start <= address && address <= m.End {
					t.Fatalf("0x%x not held, but 0x%x-0x%x holds it", address, m.Start, m.End)
				}
			}
		}
	})
}
