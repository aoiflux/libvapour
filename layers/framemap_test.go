package layers

import (
	"reflect"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
)

func frames(t *testing.T, img *physImage, root uint64, mode PagingMode) *FrameMap {
	t.Helper()
	f, err := MapFrames(img, root, mode, limits.Default())
	if err != nil {
		t.Fatalf("MapFrames: %v", err)
	}
	return f
}

func TestTheFrameMapHoldsWhatLeavesMap(t *testing.T) {
	img := newPhys(0x800000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(kva+0x3000, 0x80000)
	pt.page(kva+0x5000, 0x80000)
	pt.page(0x10000, 0x81000)
	pt.set(2, kva+0x200000, 0x400000|fP|fPS)
	f := frames(t, img, 0x1000, ModeX64)

	if !f.Contains(0x80123) || !f.Contains(0x81fff) || !f.Contains(0x5ff000) || f.Contains(0x82000) || f.Contains(0x7ff000) {
		t.Fatal("Contains does not follow the leaves")
	}
	if f.Len() != 2+512 {
		t.Fatalf("Len %d", f.Len())
	}
	if f.Mappings(0x80000) != 2 || f.Mappings(0x81000) != 1 || f.Mappings(0x401000) != 1 || f.Mappings(0x82000) != 0 {
		t.Fatal("Mappings")
	}
	if got := f.SecondAddressBytes(0x80a40); !reflect.DeepEqual(got, []byte{0x3a, 0x5a}) {
		t.Fatalf("SecondAddressBytes %x", got)
	}
	if got := f.SecondAddressBytes(0x407b00); !reflect.DeepEqual(got, []byte{0x7b}) {
		t.Fatalf("large-page SecondAddressBytes %x", got)
	}
	if f.Tables != 7 || f.UnreadableTables != 0 || f.RecursiveEntries != 0 {
		t.Fatalf("counts %+v", f)
	}
	var nilMap *FrameMap
	if nilMap.Contains(0) || nilMap.Len() != 0 {
		t.Fatal("a nil map holds frames")
	}
}

func TestLowestAddressesFollowKeys(t *testing.T) {
	img := newPhys(0x800000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(kva+0x3000, 0x80000)
	pt.page(0x10000, 0x80000)
	pt.set(2, kva+0x200000, 0x400000|fP|fPS)
	f := frames(t, img, 0x1000, ModeX64)
	got, err := f.LowestAddresses([]AddressQuery{
		{Physical: 0x80010, Keys: AnyPageKey},
		{Physical: 0x80010, Keys: 1 << 3},
		{Physical: 0x80010, Keys: 1 << 4},
		{Physical: 0x407b00, Keys: AnyPageKey},
		{Physical: 0x407b00, Keys: 1 << 6},
		{Physical: 0x90000, Keys: AnyPageKey},
	})
	want := []LowestAddress{{0x10010, true}, {kva + 0x3010, true}, {}, {kva + 0x207b00, true}, {}, {}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestTheSelfMapIsFollowedOncePerLevel(t *testing.T) {
	img := newPhys(0x800000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(kva, 0x80000)
	img.put8(0x1000+8*0x1ed, 0x1000|fP|fRW)
	f := frames(t, img, 0x1000, ModeX64)
	if f.RecursiveEntries != 1 || f.Tables != 4 {
		t.Fatalf("counts %+v", f)
	}
	for _, table := range []uint64{0x1000, 0x2000, 0x3000, 0x4000} {
		if !f.Contains(table) {
			t.Errorf("table 0x%x is not mapped as data", table)
		}
	}
	got, err := f.LowestAddresses([]AddressQuery{{Physical: 0x4000, Keys: AnyPageKey}})
	selfBase := ModeX64.canonical(0x1ed << 39)
	if err != nil || !got[0].Mapped || got[0].Virtual < selfBase || got[0].Virtual >= selfBase+1<<39 {
		t.Fatalf("lowest %+v, %v", got, err)
	}
	var runs []MappedRun
	if _, err := pt.translator().Mapping(func(r MappedRun) error { runs = append(runs, r); return nil }); err != nil {
		t.Fatal(err)
	}
	for _, r := range runs {
		for off := uint64(0); off < r.Size; off += 0x1000 {
			if !f.Contains(r.Physical + off) {
				t.Fatalf("listed 0x%x is not in the frame map", r.Physical+off)
			}
		}
	}
}

func TestAPartlyHeldLargePageIsCountedAndNotMapped(t *testing.T) {
	img := newPhys(0x800000)
	img.segments = []memory.Segment{{PhysicalBase: 0, Length: 0x500000}}
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.set(2, kva, 0x400000|fP|fPS)
	pt.set(2, kva+0x200000, 0x400000|fP|fPS)
	f := frames(t, img, 0x1000, ModeX64)
	if f.PartialLargePages != 1 || f.Contains(0x400000) {
		t.Fatalf("counts %+v", f)
	}
}

func TestTheFrameMapIsBoundedByMaxImageBytes(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(kva, 0x80000)
	l := limits.Limits{MaxImageBytes: 0x10000, MaxArtifactBytes: 0x1000, RowPreviewBytes: 0x100}
	if _, err := MapFrames(img, 0x1000, ModeX64, l); err == nil {
		t.Fatal("a 1-MByte image fit a 64-KByte limit")
	}
}

func TestTheFrameMapSkipsUnreadableAndRepeatedTables(t *testing.T) {
	img := newPhys(0x800000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(kva, 0x80000)
	pt.set(2, kva+0x200000, 0x7000000|fP)
	same := pt.table(3, kva+0x400000)
	for i := range uint64(512) {
		img.put8(same+8*i, 0x90000|fP)
	}
	f := frames(t, img, 0x1000, ModeX64)
	if f.UnreadableTables != 1 || f.RepeatedTables != 1 || f.Contains(0x90000) || !f.Contains(0x80000) {
		t.Fatalf("counts %+v", f)
	}
	if _, err := MapFrames(img, 0x7000000, ModeX64, limits.Default()); err == nil {
		t.Fatal("an unreadable root mapped")
	}
}

func TestThirtyTwoBitFrames(t *testing.T) {
	img := newPhys(0x100000)
	img.put4(0x1000+4*0x300, uint32(0x2000|fP))
	img.put4(0x2000+4*0x7, uint32(0x80000|fP))
	f := frames(t, img, 0x1000, ModeX86NonPAE)
	if !f.Contains(0x80000) || !reflect.DeepEqual(f.SecondAddressBytes(0x80200), []byte{0x72}) {
		t.Fatal("4-byte entries")
	}
	got, _ := f.LowestAddresses([]AddressQuery{{Physical: 0x80200, Keys: AnyPageKey}})
	if got[0] != (LowestAddress{0xc0007200, true}) {
		t.Fatalf("lowest %+v", got)
	}
}
