package executioncompatcachememory

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/util"
)

func FuzzDecodeElement(f *testing.F) {
	f.Add(make([]byte, elementSize))
	f.Add([]byte{1, 2, 3})
	layout := util.UnicodeStringLayout{LengthOffset: 0, MaximumLengthOffset: 2, BufferOffset: 8, Size: 16}
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := decodeElement(b, layout)
		if err != nil && !errors.Is(err, ErrShort) && !errors.Is(err, ErrKeyLayout) {
			t.Fatalf("foreign error %v", err)
		}
		if err == nil && (e.keyLength%2 != 0 || e.keyLength > e.keyMaximum) {
			t.Fatalf("accepted key %d of %d", e.keyLength, e.keyMaximum)
		}
	})
}

func FuzzDecodeEntryData(f *testing.F) {
	f.Add(make([]byte, dataObjectSize))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := decodeEntryData(b); err != nil && (!errors.Is(err, ErrShort) || len(b) >= dataObjectSize) {
			t.Fatalf("%d bytes: %v", len(b), err)
		}
	})
}

// The fuzz bytes overwrite the store and the first element, so the walks meet
// any links, counts and pointers.
func FuzzCacheWalk(f *testing.F) {
	seed := newS41Cache(three)
	store := must(seed.mem.ReadAt(storeAddr, 0x80))
	el := must(seed.mem.ReadAt(seed.nodes[0], 0x60))
	f.Add(append(store, el...))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		c := newS41Cache(three)
		c.limits = limits.Limits{MaxListEntries: 64, MaxTableEntries: 64}
		split := min(len(b), 0x80)
		c.mem.write(storeAddr, b[:split])
		c.mem.write(c.nodes[0], b[split:min(len(b), split+0x60)])
		rows, _ := collect(c.ctx(false), handleAddr)
		if len(rows) > 128 {
			t.Fatalf("%d rows past both limits", len(rows))
		}
		seen := map[uint64]bool{}
		for _, r := range rows {
			if seen[r.Address] {
				t.Fatalf("element 0x%x listed twice", r.Address)
			}
			seen[r.Address] = true
		}
	})
}
