package wow64

import (
	"testing"
)

func FuzzLoader32(f *testing.F) {
	f.Add(make([]byte, 64), uint8(0))
	f.Fuzz(func(t *testing.T, data []byte, which uint8) {
		s := space([]uint32{0x400000, 0x77000000}, true)
		for i, b := range data {
			s[ldr32+uint64(i)%0x40+uint64(i/0x40)*0x1000] = b
		}
		ctx := context(sparse{}, table(which&1 == 0))
		bases, _, _ := BasesRecovering(ctx, s, peb32, List(which%3))
		if len(bases) > ctx.Bounds().MaxListEntries {
			t.Fatalf("%d bases", len(bases))
		}
		for b := range bases {
			if b > highest32BitAddress {
				t.Fatalf("base 0x%x is not 32-bit", b)
			}
		}
	})
}
