package layers

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

var fuzzModes = []PagingMode{ModeX64, ModeLA57, ModeX86PAE, ModeX86NonPAE, LinuxMode(ModeX64, 46, 1<<47)}

func fuzzSeed() []byte {
	img := make([]byte, 0x8000)
	put := func(at, v uint64) { binary.LittleEndian.PutUint64(img[at:], v) }
	put(0x1000+8*0x1f0, 0x2000|fP)
	put(0x1000+8*0x1ed, 0x1000|fP)
	put(0x2000, 0x3000|fP)
	put(0x3000+8, 0x200000|fP|fPS)
	put(0x3000+16, 0x4000|fTr)
	put(0x4000, 0x5000|fP)
	put(0x4000+8, 0x6000|fTr)
	put(0x4000+16, 0x0000000300000000|4<<5)
	return img
}

func FuzzTranslate(f *testing.F) {
	f.Add(fuzzSeed(), uint64(0x1000), uint64(0xfffff80000000000), uint8(0))
	f.Add(fuzzSeed(), uint64(0x1000), uint64(0xfffff80000201234), uint8(0))
	f.Add(fuzzSeed(), uint64(0x1000), uint64(0xfffff80000400000), uint8(4))
	f.Add(fuzzSeed()[:0x2000], uint64(0x1020), uint64(0xc0001000), uint8(2))
	f.Fuzz(func(t *testing.T, phys []byte, cr3, va uint64, which uint8) {
		m := fuzzModes[int(which)%len(fuzzModes)]
		img := &physImage{buf: phys, holes: map[uint64]bool{}}
		tr := &IntelTranslator{Physical: img, CR3: cr3, Mode: m}
		pa, err := tr.Translate(va)
		if err != nil {
			if _, ok := missOf(err); !ok {
				t.Fatalf("%s: 0x%x: an error that is not a miss: %v", m.Name(), va, err)
			}
			return
		}
		if pa&(pageBytes-1) != va&(pageBytes-1) {
			t.Fatalf("%s: 0x%x translated to 0x%x, another page offset", m.Name(), va, pa)
		}
		limit := m.frameMask
		if m.pse36 {
			limit |= bitRange(39, 32)
		}
		if pa&^(pageBytes-1)&^limit != 0 {
			t.Fatalf("%s: 0x%x translated to 0x%x, outside the frame field", m.Name(), va, pa)
		}
		if _, err := tr.LeafEntry(va); err != nil {
			t.Fatalf("%s: 0x%x translated but has no leaf entry: %v", m.Name(), va, err)
		}
	})
}

func FuzzFrameMap(f *testing.F) {
	f.Add(fuzzSeed(), uint64(0x1000), uint8(0))
	f.Add(fuzzSeed(), uint64(0x1000), uint8(1))
	f.Add(fuzzSeed()[:0x3000], uint64(0x1000), uint8(3))
	f.Fuzz(func(t *testing.T, phys []byte, cr3 uint64, which uint8) {
		if len(phys) > 0x40000 {
			return
		}
		m := fuzzModes[int(which)%len(fuzzModes)]
		img := &physImage{buf: phys, holes: map[uint64]bool{}}
		fm, ferr := MapFrames(img, cr3, m, limits.Default())
		tr := &IntelTranslator{Physical: img, CR3: cr3, Mode: m}
		var runs []MappedRun
		_, merr := tr.Mapping(func(r MappedRun) error {
			if len(runs) < 64 {
				runs = append(runs, r)
			}
			return nil
		})
		if (ferr == nil) != (merr == nil) {
			t.Fatalf("%s: frame map %v, listing %v", m.Name(), ferr, merr)
		}
		if ferr != nil {
			return
		}
		for _, r := range runs {
			if got, err := tr.Translate(r.Virtual); err != nil || got != r.Physical {
				t.Fatalf("%s: listed 0x%x -> 0x%x, translates to 0x%x, %v", m.Name(), r.Virtual, r.Physical, got, err)
			}
			if !fm.Contains(r.Physical) {
				t.Fatalf("%s: listed frame 0x%x is not in the frame map", m.Name(), r.Physical)
			}
			low, err := fm.LowestAddresses([]AddressQuery{{Physical: r.Physical, Keys: AnyPageKey}})
			if err != nil || !low[0].Mapped || low[0].Virtual > r.Virtual {
				t.Fatalf("%s: 0x%x is listed at 0x%x, lowest %+v, %v", m.Name(), r.Physical, r.Virtual, low, err)
			}
		}
	})
}

func FuzzImageCodeViews(f *testing.F) {
	seed := make([]byte, 0x4000)
	writeImage(seed, 0, "ntkrnlmp.pdb", peMagic64)
	f.Add(seed)
	f.Add(seed[:0x1000])
	f.Fuzz(func(t *testing.T, raw []byte) {
		recs, err := ImageCodeViews(&physImage{buf: raw, holes: map[uint64]bool{}}, 0)
		if err != nil && len(recs) > 0 {
			t.Fatal("records with an error")
		}
		for _, r := range recs {
			if r.PDBPath == "" || len(r.PDBPath) > rsdsMaxPath || bytes.IndexByte([]byte(r.PDBPath), 0) >= 0 {
				t.Fatalf("path %q", r.PDBPath)
			}
		}
	})
}
