package memory

import (
	"bytes"
	"errors"
	"testing"
)

func TestMappedRangesJoinTouchingSegments(t *testing.T) {
	r, err := NewSegmentedReader(image(make([]byte, 0x400)), []Segment{
		{0x3000, 0x300, 0x100}, {0x1000, 0, 0x100}, {0x1100, 0x100, 0x100}, {0x1300, 0x200, 0x100},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := MappedRanges(r)
	want := []Range{{0x1000, 0x1200}, {0x1300, 0x1400}, {0x3000, 0x3100}}
	if len(got) != len(want) {
		t.Fatalf("ranges %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("range %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	if g := MappedRanges(image(make([]byte, 5))); len(g) != 1 || g[0] != (Range{0, 5}) {
		t.Errorf("flat reader: %+v", g)
	}
	if MappedRanges(image(nil)) != nil || MappedRanges(nil) != nil {
		t.Error("an empty reader has ranges")
	}
}

func TestEveryShortRecordIsWholeInTheWindowWhereItStarts(t *testing.T) {
	const step, overlap, n = 16, 3, 100
	data := image(pattern(n, 9))
	owners := map[uint64]int{}
	cov := ScanWindows(data, step, overlap, func(base uint64, w []byte) bool {
		if uint64(len(w)) > step+overlap {
			t.Fatalf("window of %d bytes", len(w))
		}
		for i := 0; i < min(step, len(w)); i++ {
			at := base + uint64(i)
			want := data[at:min(at+overlap+1, n)]
			if !bytes.HasPrefix(w[i:], want) {
				t.Fatalf("record at 0x%x not whole", at)
			}
			owners[at]++
		}
		return false
	})
	if cov.Windows != (n+step-1)/step || cov.Unreadable != 0 || cov.Incomplete() != nil {
		t.Errorf("coverage %+v", cov)
	}
	for at := uint64(0); at < n; at++ {
		if owners[at] != 1 {
			t.Fatalf("offset 0x%x owned by %d windows", at, owners[at])
		}
	}
}

func TestWindowsCrossTouchingSegmentsButNotHoles(t *testing.T) {
	file := image([]byte("....ABCD....EF"))
	r, err := NewSegmentedReader(file, []Segment{{0x100, 4, 2}, {0x102, 6, 2}, {0x200, 12, 2}})
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	cov := ScanWindows(r, 8, 8, func(base uint64, w []byte) bool {
		seen = append(seen, string(w))
		return false
	})
	if len(seen) != 2 || seen[0] != "ABCD" || seen[1] != "EF" || cov.Incomplete() != nil {
		t.Errorf("windows %q coverage %+v", seen, cov)
	}
}

func TestAnUnreadableWindowIsCountedAndSkipped(t *testing.T) {
	r := failingAt{image(make([]byte, 64)), Range{20, 21}}
	var bases []uint64
	cov := ScanWindows(r, 16, 0, func(base uint64, _ []byte) bool {
		bases = append(bases, base)
		return false
	})
	if cov.Windows != 3 || cov.Unreadable != 1 || len(bases) != 3 || bases[1] != 32 {
		t.Fatalf("coverage %+v bases %v", cov, bases)
	}
	if err := cov.Incomplete(); !errors.Is(err, ErrIncompleteScan) {
		t.Errorf("incomplete: %v", err)
	}
	none := ScanWindows(failingAt{image(make([]byte, 8)), Range{0, 8}}, 4, 0, func(uint64, []byte) bool { return false })
	if err := none.Incomplete(); !errors.Is(err, ErrIncompleteScan) || none.Windows != 0 {
		t.Errorf("nothing read: %+v %v", none, err)
	}
}

func TestAScanStopsWhenTheVisitorSaysSo(t *testing.T) {
	calls := 0
	cov := ScanWindows(image(make([]byte, 100)), 10, 0, func(uint64, []byte) bool {
		calls++
		return calls == 2
	})
	if calls != 2 || cov.Windows != 2 {
		t.Errorf("calls %d coverage %+v", calls, cov)
	}
}

func TestAZeroStepScansNothingAndSaysSo(t *testing.T) {
	cov := ScanWindows(image(make([]byte, 10)), 0, 4, func(uint64, []byte) bool {
		t.Fatal("visited")
		return true
	})
	if cov.Incomplete() == nil {
		t.Error("a zero step reported a complete scan")
	}
}

func TestAWindowAtTheTopOfTheAddressSpaceEnds(t *testing.T) {
	top := ^uint64(0) - 9
	r, err := NewSegmentedReader(image(make([]byte, 9)), []Segment{{top, 0, 9}})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	cov := ScanWindows(r, 4, ^uint64(0), func(base uint64, w []byte) bool {
		n++
		if base+uint64(len(w)) != top+9 {
			t.Errorf("window at 0x%x of %d bytes", base, len(w))
		}
		return false
	})
	if n != 3 || cov.Incomplete() != nil {
		t.Errorf("%d windows, %+v", n, cov)
	}
}
