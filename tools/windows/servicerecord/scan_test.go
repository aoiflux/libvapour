package servicerecord

import (
	"errors"
	"strings"
	"testing"
)

var fixtureHeapRange = addressRange{start: fixtureHeap, end: fixtureHeap + 0x10000}

func TestTheScanKeepsHeapAlignedTagsOnly(t *testing.T) {
	l := layoutNamed("26100")
	w := newWorld(l)
	w.record(running(fixtureHeap, "a", 1))
	w.record(running(fixtureHeap+0x208, "b", 2))
	c := scanRegions(w.mem, []addressRange{fixtureHeapRange}, scanBounds{})
	if got := c.byTag[tagObject]; len(got) != 1 || got[0] != fixtureHeap {
		t.Errorf("candidates %#x, want only 0x%x", got, uint64(fixtureHeap))
	}
}

func TestTheScanSkipsUnreadPagesAndHonoursItsBounds(t *testing.T) {
	l := layoutNamed("14393")
	w := newWorld(l)
	for i := uint64(0); i < 4; i++ {
		w.record(running(fixtureHeap+i*pageSize, "s", uint32(i+1)))
	}
	w.mem.drop(fixtureHeap + pageSize)
	c := scanRegions(w.mem, []addressRange{fixtureHeapRange}, scanBounds{})
	if n := len(c.byTag[tagStruct]); n != 3 || len(c.cuts) != 0 {
		t.Errorf("candidates %d, cuts %v; want 3 and none", n, c.cuts)
	}
	c = scanRegions(w.mem, []addressRange{fixtureHeapRange}, scanBounds{regionBytes: 3 * pageSize})
	if n := len(c.byTag[tagStruct]); n != 2 || len(c.cuts) != 1 || !strings.Contains(c.cuts[0], "scanned to") {
		t.Errorf("byte bound: candidates %d, cuts %v", n, c.cuts)
	}
	c = scanRegions(w.mem, []addressRange{fixtureHeapRange}, scanBounds{hits: 1})
	if n := len(c.byTag[tagStruct]); n != 1 || len(c.cuts) != 1 || !strings.Contains(c.cuts[0], "tag hits stopped") {
		t.Errorf("hit bound: candidates %d, cuts %v", n, c.cuts)
	}
}

func TestTheFitPicksTheLayoutThatAcceptsTheRecords(t *testing.T) {
	for _, name := range []string{"14393", "19041", "26100"} {
		l := layoutNamed(name)
		w := newWorld(l)
		w.list("a", "b", "c")
		c := scanRegions(w.mem, []addressRange{fixtureHeapRange}, scanBounds{})
		f := fitLayouts(w.mem, c, fixtureImage)
		if f.layout.name != name || len(f.records) != 3 || f.problem(target{}) != nil {
			t.Errorf("layout %s: fitted %s with %d records, problem %v", name, f.layout.name, len(f.records), f.problem(target{}))
		}
	}
}

func TestTheOtherObjectLayoutFailsOnTheState(t *testing.T) {
	w := newWorld(layoutNamed("26100"))
	w.list("a", "b")
	c := scanRegions(w.mem, []addressRange{fixtureHeapRange}, scanBounds{})
	other := layoutNamed("19041")
	for _, at := range c.byTag[tagObject] {
		if _, why := decode(w.mem, other, at, fixtureImage); why != rejectState {
			t.Errorf("record at 0x%x under 19041: rejection %q, want %q", at, why, rejectState)
		}
	}
}

func TestTwoLayoutsThatFitEquallyAreRefused(t *testing.T) {
	a, b := layoutNamed("19041"), layoutNamed("26100")
	w := newWorld(b)
	w.record(running(fixtureHeap, "svc", 1))
	w.mem.u32(fixtureHeap+a.status, 0x20)
	w.mem.u32(fixtureHeap+a.status+4, 4)
	c := scanRegions(w.mem, []addressRange{fixtureHeapRange}, scanBounds{})
	f := fitLayouts(w.mem, c, fixtureImage)
	if err := f.problem(target{pid: 600}); !errors.Is(err, ErrLayoutAmbiguous) {
		t.Errorf("problem %v, want %v", err, ErrLayoutAmbiguous)
	}
}

func TestNoAcceptedRecordIsNoRecords(t *testing.T) {
	f := fitLayouts(newSparse(), candidates{byTag: map[uint32][]uint64{}}, fixtureImage)
	if err := f.problem(target{}); !errors.Is(err, ErrNoServiceRecords) {
		t.Errorf("problem %v, want %v", err, ErrNoServiceRecords)
	}
}
