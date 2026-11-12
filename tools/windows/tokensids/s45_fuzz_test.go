package tokensids

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
)

func FuzzSIDBytes(f *testing.F) {
	f.Add(testsupport.S45SIDBytes(5, 21, 1, 2, 3, 500))
	f.Add(testsupport.S45SIDBytes(0x123456789abc))
	f.Add([]byte{1, 15, 0, 0, 0, 0, 0, 5})
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := decodeSID(b)
		if err != nil {
			return
		}
		enc := s.bytes()
		if !bytes.Equal(enc, b[:len(enc)]) {
			t.Fatalf("%x encodes back as %x", b, enc)
		}
		again, err := decodeSID(enc)
		if err != nil || again.String() != s.String() {
			t.Fatalf("%s does not decode back: %v", s, err)
		}
	})
}

type flatMemory struct {
	base uint64
	data []byte
}

func (m flatMemory) ReadAt(offset, size uint64) ([]byte, error) {
	if offset < m.base || offset-m.base > uint64(len(m.data)) || size > uint64(len(m.data))-(offset-m.base) {
		return nil, errors.New("unmapped")
	}
	return m.data[offset-m.base : offset-m.base+size], nil
}

func (m flatMemory) Size() uint64 { return m.base + uint64(len(m.data)) }

const fuzzBase = uint64(0xfffff80000000000)

func FuzzTokenEntries(f *testing.F) {
	seed := make([]byte, 0x2000)
	binary.LittleEndian.PutUint64(seed[testsupport.S45EprocessTokenOffset:], fuzzBase+0x1000)
	tok := seed[0x1000:]
	binary.LittleEndian.PutUint32(tok[testsupport.S45GroupCountOffset:], 1)
	binary.LittleEndian.PutUint64(tok[testsupport.S45GroupsOffset:], fuzzBase+0x1000+testsupport.S45VariablePartOffset)
	binary.LittleEndian.PutUint64(tok[testsupport.S45VariablePartOffset:], fuzzBase+0x1800)
	copy(tok[0x800:], testsupport.S45SIDBytes(5, 18))
	f.Add(seed)
	table := fuzzTable()
	const limit = 64
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx := tools.Context{Memory: flatMemory{base: fuzzBase, data: data}, Symbols: table, Profile: profiles.WindowsX64Profile{}}
		ctx.Limits.MaxRowsPerObject = limit
		r, err := NewTokenReader(ctx)
		if err != nil {
			t.Fatal(err)
		}
		tk, err := r.Token(fuzzBase)
		if err != nil {
			return
		}
		for _, a := range tk.Arrays {
			if a.Err != nil {
				continue
			}
			if a.Count > limit {
				t.Fatalf("%s count %d passes the limit %d", a.Array, a.Count, limit)
			}
			for i := uint32(0); i < a.Count; i++ {
				e, err := r.entryAt(a, i)
				if err == nil && len(e.value.sub) > maxSubAuthorities {
					t.Fatalf("%d sub-authorities", len(e.value.sub))
				}
			}
		}
	})
}
