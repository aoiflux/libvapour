package syscalllist

import (
	"encoding/binary"
	"testing"
)

func FuzzTrimmedLength(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0}, []byte{1})
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, raw, readable []byte) {
		words := make([]uint64, len(raw)/8)
		for i := range words {
			words[i] = binary.LittleEndian.Uint64(raw[i*8:])
		}
		ok := make([]bool, len(readable))
		for i, b := range readable {
			ok[i] = b&1 == 1
		}
		n := trimmedLength(words, ok)
		if n > uint64(min(len(words), len(ok))) {
			t.Fatalf("length %d over %d entries", n, min(len(words), len(ok)))
		}
		for i := n; i < uint64(min(len(words), len(ok))); i++ {
			if !ok[i] || words[i] != 0 {
				t.Fatalf("entry %d trimmed but not a null that read", i)
			}
		}
		if n > 0 && ok[n-1] && words[n-1] == 0 {
			t.Fatalf("last kept entry %d is a null that read", n-1)
		}
	})
}

func FuzzSyscallTable(f *testing.F) {
	f.Add([]byte{0, 0x20, 0, 0x81, 0xff, 0xff, 0xff, 0xff}, uint8(2))
	f.Add([]byte{}, uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, padding uint8) {
		fx := newSys(0)
		fx.padding = int(padding % 8)
		for i := 0; i+8 <= len(raw) && i < 64*8; i += 8 {
			fx.entries = append(fx.entries, binary.LittleEndian.Uint64(raw[i:]))
		}
		if len(fx.entries) == 0 {
			fx.entries = []uint64{0}
		}
		ctx, _ := fx.context(t, nil)
		rows, err := Run(ctx)
		if err != nil {
			return
		}
		if len(rows) > len(fx.entries)+fx.padding {
			t.Fatalf("%d rows from %d entries", len(rows), len(fx.entries))
		}
		for i, r := range rows {
			if r.Index != uint64(i) || r.HandlerAddress > mask || (r.Module == "" && r.HandlerSymbol != "") {
				t.Fatalf("row %+v", r)
			}
		}
	})
}
