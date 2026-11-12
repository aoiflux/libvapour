package layers

import (
	"errors"
	"reflect"
	"testing"

	"github.com/aoiflux/libvapour/memory"
)

func runsOf(t *testing.T, tr *IntelTranslator) ([]MappedRun, MappingStats) {
	t.Helper()
	var runs []MappedRun
	stats, err := tr.Mapping(func(r MappedRun) error {
		runs = append(runs, r)
		return nil
	})
	if err != nil {
		t.Fatalf("Mapping: %v", err)
	}
	return runs, stats
}

func TestTheListingJoinsRunsContiguousInBothSpaces(t *testing.T) {
	img := newPhys(0x800000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(0x10000, 0x80000)
	pt.page(0x11000, 0x81000)
	pt.page(0x12000, 0x90000)
	pt.set(2, kva, 0x400000|fP|fPS)
	pt.page(kva+0x200000, 0x600000)
	pt.page(kva+0x201000, 0x601000)
	pt.set(3, kva+0x202000, 0x602000|fTr)
	runs, stats := runsOf(t, pt.translator())
	want := []MappedRun{
		{0x10000, 0x80000, 0x2000},
		{0x12000, 0x90000, 0x1000},
		{kva, 0x400000, 0x203000},
	}
	if !reflect.DeepEqual(runs, want) {
		t.Fatalf("runs %x, want %x", runs, want)
	}
	if stats.Tables != 7 || stats.UnreadableTables != 0 {
		t.Fatalf("stats %+v", stats)
	}
	for _, r := range runs {
		for off := uint64(0); off < r.Size; off += 0x1000 {
			translateOK(t, pt.translator(), r.Virtual+off, r.Physical+off)
		}
	}
}

func TestTheListingDoesNotJoinAcrossTheCanonicalGap(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(0x00007ffffffff000, 0x80000)
	pt.page(0xffff800000000000, 0x81000)
	runs, _ := runsOf(t, pt.translator())
	want := []MappedRun{{0x00007ffffffff000, 0x80000, 0x1000}, {0xffff800000000000, 0x81000, 0x1000}}
	if !reflect.DeepEqual(runs, want) {
		t.Fatalf("runs %x", runs)
	}
}

func TestTheListingHoldsOnlyWhatTheImageHolds(t *testing.T) {
	img := newPhys(0x800000)
	img.segments = []memory.Segment{{PhysicalBase: 0, Length: 0x100000}, {PhysicalBase: 0x500000, Length: 0x100000}}
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(0x10000, 0x80000)
	pt.page(0x11000, 0x300000)
	pt.set(2, kva, 0x400000|fP|fPS)
	pt.set(2, kva+0x200000, 0x7000000|fP)
	runs, stats := runsOf(t, pt.translator())
	if len(runs) != 1 || runs[0] != (MappedRun{0x10000, 0x80000, 0x1000}) {
		t.Fatalf("runs %x", runs)
	}
	if stats.UncapturedPages != 2 || stats.UnreadableTables != 1 {
		t.Fatalf("stats %+v", stats)
	}
}

func TestATableOfOneRepeatedEntryIsLeftOut(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(kva, 0x80000)
	pt.page(kva+0x200000, 0x81000)
	same := pt.table(3, kva+0x200000)
	for i := range uint64(512) {
		img.put8(same+8*i, 0x81000|fP)
	}
	pt.table(3, kva+0x400000)
	runs, stats := runsOf(t, pt.translator())
	if len(runs) != 1 || stats.RepeatedTables != 1 {
		t.Fatalf("runs %x, stats %+v", runs, stats)
	}
}

func TestARootOfOneValueIsAnError(t *testing.T) {
	img := newPhys(0x10000)
	img.fill(0x1000, 0)
	if _, err := (&IntelTranslator{Physical: img, CR3: 0x1000}).Mapping(func(MappedRun) error { return nil }); err == nil {
		t.Fatal("an empty root listed")
	}
	if _, err := (&IntelTranslator{Physical: img, CR3: 0x20000}).Mapping(func(MappedRun) error { return nil }); !errors.Is(err, ErrPageNotCaptured) {
		t.Fatalf("a root past the image: %v", err)
	}
}

func TestTheCallersErrorStopsTheListing(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(0x10000, 0x80000)
	pt.page(0x20000, 0x90000)
	stop := errors.New("stop")
	calls := 0
	_, err := pt.translator().Mapping(func(MappedRun) error { calls++; return stop })
	if !errors.Is(err, stop) || calls != 1 {
		t.Fatalf("err %v after %d calls", err, calls)
	}
}

func TestAThirtyTwoBitListingHasNoGap(t *testing.T) {
	img := newPhys(0x100000)
	img.put4(0x1000+4*0x1ff, uint32(0x2000|fP))
	img.put4(0x2000+4*0x3ff, uint32(0x80000|fP))
	img.put4(0x1000+4*0x200, uint32(0x3000|fP))
	img.put4(0x3000, uint32(0x81000|fP))
	runs, _ := runsOf(t, &IntelTranslator{Physical: img, CR3: 0x1000, Mode: ModeX86NonPAE})
	if want := []MappedRun{{0x7ffff000, 0x80000, 0x2000}}; !reflect.DeepEqual(runs, want) {
		t.Fatalf("runs %x", runs)
	}
}
