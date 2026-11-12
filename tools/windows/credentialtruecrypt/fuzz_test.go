package credentialtruecrypt

import (
	"encoding/binary"
	"testing"
)

func FuzzFindCounted(f *testing.F) {
	f.Add(counted("correct horse"), uint8(4))
	f.Add(append(counted("ab"), counted("abcdef")...), uint8(1))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}, uint8(4))
	f.Fuzz(func(t *testing.T, data []byte, floor uint8) {
		minLength := uint64(floor)%MaxLength + 1
		end := uint64(0)
		for _, h := range FindCounted(data, minLength, MaxLength) {
			n := uint64(len(h.Text))
			if h.Offset%lengthBytes != 0 || h.Offset < end {
				t.Fatalf("hit at %d: unaligned or inside the previous hit ending at %d", h.Offset, end)
			}
			if n < minLength || n > MaxLength || uint64(binary.LittleEndian.Uint32(data[h.Offset:])) != n {
				t.Fatalf("hit at %d: length %d does not match its count or range", h.Offset, n)
			}
			if string(data[h.Offset+lengthBytes:h.Offset+lengthBytes+n]) != h.Text || data[h.Offset+lengthBytes+n] != 0 ||
				!printable([]byte(h.Text)) {
				t.Fatalf("hit at %d: text %q is not the printable bytes before a NUL", h.Offset, h.Text)
			}
			end = h.Offset + lengthBytes + n + 1
		}
	})
}
