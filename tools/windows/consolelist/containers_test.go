package consolelist

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

func TestAStringOfSevenCharactersOrFewerLivesInline(t *testing.T) {
	f, l := layout19041Fixture(t)
	at := f.alloc(l.text.size)
	f.wide(at, "cmd.exe")
	w, err := l.wideString(f.space(), at, 0)
	if err != nil || w.Text != "cmd.exe" || !w.Inline || w.At != at {
		t.Fatalf("string %+v, %v", w, err)
	}
	at2 := f.alloc(l.text.size)
	f.wide(at2, "conhost.exe")
	w, err = l.wideString(f.space(), at2, 0)
	if err != nil || w.Text != "conhost.exe" || w.Inline || w.At == at2 {
		t.Fatalf("string %+v, %v", w, err)
	}
}

func TestAStringOutOfShapeIsRefused(t *testing.T) {
	f, l := layout19041Fixture(t)
	s := f.space()
	cases := []struct {
		name     string
		length   int64
		capacity int64
		pointer  uint64
		err      error
	}{
		{"capacity below the inline buffer", 1, 3, 0, ErrStringShape},
		{"length past capacity", 9, 8, 0, ErrStringShape},
		{"negative length", -1, 7, 0, ErrStringShape},
		{"buffer outside the process", 8, 8, 0x1000, ErrOutside},
		{"buffer running off its region", 8, 1 << 30, fixtureHeap, ErrOutside},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at := f.alloc(l.text.size)
			f.m.u64(at, tc.pointer)
			f.m.u64(at+uint64(l.text.length.off), uint64(tc.length))
			f.m.u64(at+uint64(l.text.capacity.off), uint64(tc.capacity))
			if _, err := l.wideString(s, at, 0); !errors.Is(err, tc.err) {
				t.Errorf("err %v, want %v", err, tc.err)
			}
		})
	}
}

func TestAStringPastMaxTextBytesIsNotRead(t *testing.T) {
	f, l := layout19041Fixture(t)
	at := f.alloc(l.text.size)
	f.wide(at, strings.Repeat("x", 40))
	if _, err := l.wideString(f.space(), at, 64); !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v", err)
	}
}

func TestAListWalkStopsAtMaxListEntries(t *testing.T) {
	f, l := layout19041Fixture(t)
	holder := f.alloc(16)
	f.ring(holder, holder+8, 5, l.node.size)
	if _, err := l.walkList(f.space(), holder, 0, prim{off: 8, size: 8}, 3); !errors.Is(err, ErrListLong) {
		t.Errorf("err %v", err)
	}
	got, err := l.walkList(f.space(), holder, 0, prim{off: 8, size: 8}, 5)
	if err != nil || len(got.Nodes) != 5 {
		t.Errorf("walk %+v, %v", got, err)
	}
}

func TestAListWhoseHeadDoesNotNameTheLastNodeIsBroken(t *testing.T) {
	f, l := layout19041Fixture(t)
	holder := f.alloc(16)
	nodes := f.ring(holder, holder+8, 2, l.node.size)
	head, _ := f.space().pointer(holder)
	f.m.u64(head+pointerBytes, nodes[0])
	if _, err := l.walkList(f.space(), holder, 0, prim{off: 8, size: 8}, 0); !errors.Is(err, ErrListLink) {
		t.Errorf("err %v", err)
	}
}

func TestAnEmptyVectorMayBeThreeNulls(t *testing.T) {
	f, l := layout19041Fixture(t)
	at := f.alloc(24)
	v, err := l.vectorAt(f.space(), at, l.text.size)
	if err != nil || v.count(l.text.size) != 0 {
		t.Errorf("vector %+v, %v", v, err)
	}
}

func TestTheSearchReadsOnlyThePresentRunsAndAlignedPositions(t *testing.T) {
	f, _ := layout19041Fixture(t)
	f.m.u32(fixtureHeap+0x10, 50)
	f.m.u32(fixtureHeap+0x22, 50)
	f.m.u32(fixtureHeap+0x3000, 50)
	s := f.space().WithSearch([]Region{{Start: fixtureHeap, End: fixtureHeap + 0x1000}})
	p, _ := Pattern(50, 4)
	hits, stats, err := s.FindAligned([][]byte{p}, 4, limits.Default())
	if err != nil || len(hits) != 1 || hits[0] != fixtureHeap+0x10 || stats.PagesRead != 1 {
		t.Errorf("hits %x, stats %+v, %v", hits, stats, err)
	}
}

func TestTheSearchCountsPagesThatDoNotRead(t *testing.T) {
	m := newSparse()
	m.write(0x10000, make([]byte, pageBytes))
	s := NewSpace(m, []Region{{Start: 0x10000, End: 0x13000}})
	p, _ := Pattern(0, 8)
	hits, stats, err := s.FindAligned([][]byte{p}, 8, limits.Default())
	if err != nil || len(hits) != pageBytes/8 || stats.PagesRead != 1 || stats.PagesUnread != 2 {
		t.Errorf("%d hits, stats %+v, %v", len(hits), stats, err)
	}
}

func TestTheSearchStopsAtItsBudgets(t *testing.T) {
	m := newSparse()
	m.write(0x10000, make([]byte, 4*pageBytes))
	s := NewSpace(m, []Region{{Start: 0x10000, End: 0x14000}})
	p, _ := Pattern(0, 8)
	b := limits.Default()
	b.MaxRegionScanBytes = 2 * pageBytes
	if _, stats, err := s.FindAligned([][]byte{p}, 8, b); !errors.Is(err, ErrScanBudget) || stats.PagesRead != 2 {
		t.Errorf("stats %+v, %v", stats, err)
	}
	b = limits.Default()
	b.MaxMatchesPerChunk = 3
	if hits, _, err := s.FindAligned([][]byte{p}, 8, b); !errors.Is(err, ErrMatchBudget) || len(hits) != 3 {
		t.Errorf("%d hits, %v", len(hits), err)
	}
}

func TestAPatternMustFitItsWidth(t *testing.T) {
	if _, ok := Pattern(0x10000, 2); ok {
		t.Error("0x10000 fits two bytes")
	}
	if p, ok := Pattern(0x0400000032, 8); !ok || string(p) != "\x32\x00\x00\x00\x04\x00\x00\x00" {
		t.Errorf("pattern %x", p)
	}
}

func TestAPointerMustLandInARegion(t *testing.T) {
	s := NewSpace(newSparse(), []Region{{Start: 0x1000, End: 0x2000}, {Start: 0x3000, End: 0x4000}})
	for _, tc := range []struct {
		at, n uint64
		want  bool
	}{{0x1000, 0x1000, true}, {0x1ff8, 16, false}, {0x2000, 1, false}, {0x3ff8, 8, true}, {^uint64(0), 2, false}} {
		if got := s.Holds(tc.at, tc.n); got != tc.want {
			t.Errorf("Holds(0x%x, %d) = %v", tc.at, tc.n, got)
		}
	}
}
