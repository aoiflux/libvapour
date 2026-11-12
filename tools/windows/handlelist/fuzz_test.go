package handlelist

import (
	"encoding/binary"
	"testing"
)

// FuzzHandleTable fills a top page and a leaf page with arbitrary bytes under
// an arbitrary TableCode level and NextHandleNeedingPool.
func FuzzHandleTable(f *testing.F) {
	seed := make([]byte, 0x2000)
	binary.LittleEndian.PutUint64(seed, fxPages+0x1000)
	copy(seed[0x1000+0x10:], encodeEntry(fxObjects, 0x1f0003))
	f.Add(seed, uint8(1), uint32(1024))
	f.Add(seed[:0x100], uint8(0), uint32(0))
	f.Fuzz(func(t *testing.T, data []byte, level uint8, next uint32) {
		fx := newS66Fixture(true)
		fx.objectType(7, "Event")
		top := fx.newPage()
		leaf := fx.newPage()
		fx.mem.write(top, data[:min(len(data), 0x1000)])
		if len(data) > 0x1000 {
			fx.mem.write(leaf, data[0x1000:min(len(data), 0x2000)])
		}
		rows, _ := fx.walk(fx.handleTable(fxEprocess, fxTable, top|uint64(level&3), next))
		last := uint64(0)
		for _, r := range rows {
			if r.HandleValue == 0 || r.HandleValue%4 != 0 || r.HandleValue <= last {
				t.Fatalf("handle value 0x%x after 0x%x", r.HandleValue, last)
			}
			if r.HandleValue%(fxEntriesPer*4) == 0 {
				t.Fatalf("handle value 0x%x is a page's first entry", r.HandleValue)
			}
			if r.Object&0xf != 0 {
				t.Fatalf("header 0x%x is not 16-byte aligned", r.Object)
			}
			if top := r.Object >> 47; top != 0 && top != 0x1ffff {
				t.Fatalf("header 0x%x is not canonical", r.Object)
			}
			if r.GrantedAccess >= 1<<25 {
				t.Fatalf("access 0x%x wider than its 25 bits", r.GrantedAccess)
			}
			if (r.TypeName == "") != r.NameUnreadable {
				t.Fatalf("row %+v: an untyped row must be flagged and only it", r)
			}
			last = r.HandleValue
		}
	})
}
