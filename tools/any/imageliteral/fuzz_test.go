package imageliteral

import (
	"bytes"
	"testing"
)

func FuzzFoldedMatch(f *testing.F) {
	f.Add([]byte("xxEvIlxx"), []byte("evil"), true, uint64(8))
	f.Add([]byte("aaaa"), []byte("aa"), false, uint64(3))
	f.Fuzz(func(t *testing.T, window, lit []byte, fold bool, step uint64) {
		if len(lit) == 0 {
			return
		}
		s := search{literals: [][]byte{lit}, given: []string{string(lit)}, fold: fold, limit: ^uint64(0),
			step: max(step%64, 1), perChunk: 1 << 10}
		if fold {
			s.literals[0] = foldASCII(lit)
		}
		var out []Finding
		s.window(0, window, &out)
		for _, h := range out {
			if h.Offset >= s.step || h.Offset+h.Length > uint64(len(window)) {
				t.Fatalf("hit %+v outside window of %d with step %d", h, len(window), s.step)
			}
			got := window[h.Offset : h.Offset+h.Length]
			if fold {
				got, lit = foldASCII(got), foldASCII(lit)
			}
			if !bytes.Equal(got, lit) {
				t.Fatalf("hit %q is not %q", got, lit)
			}
		}
	})
}
