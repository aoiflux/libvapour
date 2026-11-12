package subsection

import (
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

func FuzzWalkSubsections(f *testing.F) {
	seed := newFixture(false, 8)
	seed.sub(testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Next: fxSub2, Ptes: 4, FullSectors: 3})
	seed.sub(testsupport.S19Subsection{Address: fxSub2, Base: fxArray2, Ptes: 4, Sector: 4, FullSectors: 1, EndOffset: 0x234})
	seed.pm.WriteU64(fxArray1, testsupport.S19ValidPTE(0x8000))
	raw, _ := seed.pm.ReadAt(fxCA, 0x6000)
	f.Add(raw)
	image := newFixture(true, 4)
	image.sub(testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Ptes: 3, Sector: 2, FullSectors: 9, EndOffset: 0x10})
	raw, _ = image.pm.ReadAt(fxCA, 0x6000)
	f.Add(raw)

	f.Fuzz(func(t *testing.T, data []byte) {
		fx := newFixture(false, 0)
		fx.pm.WriteAt(fxCA, data[:min(len(data), 0x6000)])
		pages, _ := fx.resolver(t, nil).AvailablePages(fxCA)
		flags, _ := fx.pm.ReadAt(fxCA+0x38, 1)
		unit := dataSector
		if flags[0]&(1<<5) != 0 {
			unit = imageSector
		}
		segment, _ := fx.pm.ReadAt(fxCA, 8)
		budget := ^uint64(0)
		if at := uint64(segment[0]) | uint64(segment[1])<<8 | uint64(segment[2])<<16; at+12 <= fxMemSize &&
			segment[3]|segment[4]|segment[5]|segment[6]|segment[7] == 0 {
			b, _ := fx.pm.ReadAt(at+8, 4)
			budget = uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24
		}
		if uint64(len(pages)) > budget {
			t.Fatalf("%d pages from a segment of %d ptes", len(pages), budget)
		}
		for _, p := range pages {
			if p.PageSize == 0 || p.PageSize > prototypePage || p.PhysicalOffset%prototypePage != 0 {
				t.Fatalf("page %+v", p)
			}
			if p.FileOffset%unit != 0 {
				t.Fatalf("file offset 0x%x is not a multiple of the 0x%x sector", p.FileOffset, unit)
			}
		}
	})
}
