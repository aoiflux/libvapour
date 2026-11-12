package poolscan

import (
	"testing"
	"unicode/utf8"
)

// Any descriptor and any characters: no panic, and never more characters
// than MaxNameBytes allows.
func FuzzCountedString(f *testing.F) {
	f.Add([]byte{8, 0, 8, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0}, []byte("a\x00b\x00c\x00d\x00"))
	f.Add([]byte{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, []byte{})
	f.Add([]byte{3, 0}, []byte{0xd8, 0x00, 0xdc})
	f.Fuzz(func(t *testing.T, descriptor, chars []byte) {
		img := newImage(1)
		ctx, _ := img.context(fxTable())
		ctx.Limits.MaxNameBytes = 64
		c := newCountedString(ctx, "_FILE_OBJECT", "FileName")
		body := uint64(fxPoolAt)
		copy(img.mem.buf[body+0x20:body+0x30], descriptor)
		copy(img.mem.buf[fxStringsAt:fxPoolAt], chars)
		name := c.read(img.mem, body)
		if n := utf8.RuneCountInString(name); n > 32 {
			t.Fatalf("%d characters from at most 64 bytes", n)
		}
	})
}
