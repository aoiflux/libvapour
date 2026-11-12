package filedump

import (
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

func FuzzCacheViews(f *testing.F) {
	seed := func(vacbs ...testsupport.S19Vacb) []byte {
		raw := make([]byte, 0, len(vacbs)*testsupport.S19VacbSize)
		for _, v := range vacbs {
			entry := make([]byte, testsupport.S19VacbSize)
			put := func(at int, x uint64) {
				for i := range 8 {
					entry[at+i] = byte(x >> (8 * i))
				}
			}
			put(0, v.Base)
			put(8, v.CacheMap)
			put(0x10, v.Overlay)
			put(0x20, fxHeader)
			raw = append(raw, entry...)
		}
		return raw
	}
	f.Add(seed(testsupport.S19Vacb{Base: fxView, CacheMap: fxMap, Overlay: 3}), uint64(0x1800), uint64(viewGranule))
	f.Add(seed(testsupport.S19Vacb{Base: fxView, CacheMap: fxMap}, testsupport.S19Vacb{Base: fxView + 0x1000, CacheMap: fxMap,
		Overlay: viewGranule}), uint64(3*viewGranule), uint64(4*viewGranule))

	fx := buildFixture()
	room := (fxView - fxHeader - testsupport.S19VacbHeaderSize) / testsupport.S19VacbSize * testsupport.S19VacbSize
	f.Fuzz(func(t *testing.T, vacbs []byte, fileSize, sectionSize uint64) {
		fx.withCacheMap(fileSize, sectionSize)
		fx.pm.WriteAt(fx.k.at(fxHeader+testsupport.S19VacbHeaderSize), make([]byte, room))
		vacbs = vacbs[:min(uint64(len(vacbs)), room)]
		fx.pm.WriteAt(fx.k.at(fxHeader+testsupport.S19VacbHeaderSize), vacbs)
		c := newCacheReader(fx.context())
		if c.err != nil {
			t.Fatal(c.err)
		}
		size, err := c.check(mustFields(t, fx), fxMap, fxSOP)
		if err != nil {
			return
		}
		last := int64(-1)
		for _, v := range c.views(fxMap, size) {
			if v.address%viewGranule != 0 || v.offset%viewGranule != 0 || v.size == 0 || v.size > viewGranule {
				t.Fatalf("view %+v", v)
			}
			if v.offset+v.size > size || int64(v.offset) <= last {
				t.Fatalf("view %+v of a 0x%x-byte file after offset 0x%x", v, size, last)
			}
			last = int64(v.offset)
		}
	})
}

func mustFields(t *testing.T, fx *fixture) fields {
	t.Helper()
	f, err := resolveFields(fx.table)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
