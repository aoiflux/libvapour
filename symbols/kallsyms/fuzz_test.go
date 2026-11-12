package kallsyms

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

// Whatever the names and offsets hold, a decoded table has the count the
// kernel states, is in address order, places _stext where VMCOREINFO says,
// and gives no name longer than MaxNameBytes.
func FuzzDecode(f *testing.F) {
	tb := relativeKernel()
	var names, offsets []byte
	for _, r := range tb.records {
		names = append(names, r...)
	}
	for _, o := range tb.offsets {
		offsets = binary.LittleEndian.AppendUint32(offsets, uint32(o))
	}
	f.Add(names, offsets, uint8(len(tb.records)), false)
	f.Add(append([]byte{0x81, 0x01}, make([]byte, 0x81)...), []byte{0, 0, 0, 0}, uint8(1), true)
	f.Fuzz(func(t *testing.T, names, offsets []byte, count uint8, absolute bool) {
		base := uint64(textBase)
		s, seeds := table{records: [][]byte{names}, base: base, stext: base}.build()
		binary.LittleEndian.PutUint32(s[tablesAt], uint32(count))
		s[offsetsAt] = toPage(append([]byte(nil), offsets...))
		if absolute {
			seeds.Stext = base + 0x10
		}
		got, err := Decode(s, seeds, limits.Limits{MaxNameBytes: 600})
		if err != nil {
			return
		}
		if len(got.Symbols) != int(count) {
			t.Fatalf("%d symbols for a count of %d", len(got.Symbols), count)
		}
		stext := false
		for i, sym := range got.Symbols {
			if len(sym.Name)+1 > 600 || i > 0 && sym.Address < got.Symbols[i-1].Address || sym.Size < 0 {
				t.Fatalf("symbol %d: %+v", i, sym)
			}
			stext = stext || sym.Name == "_stext" && sym.Address == seeds.Stext
		}
		if !stext {
			t.Fatal("decoded without an _stext where vmcoreinfo puts it")
		}
	})
}
