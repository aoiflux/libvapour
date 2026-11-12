package memory

import (
	"bytes"
	"errors"
	"testing"
)

func TestSegmentsServeTheirFileBytesAtTheirPhysicalAddresses(t *testing.T) {
	file := image(pattern(0x300, 1))
	r, err := NewSegmentedReader(file, []Segment{
		{PhysicalBase: 0x2000, FileOffset: 0x200, Length: 0x100},
		{PhysicalBase: 0x1000, FileOffset: 0x000, Length: 0x100},
		{PhysicalBase: 0x1100, FileOffset: 0x100, Length: 0x100},
		{PhysicalBase: 0x9000, FileOffset: 0x000, Length: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Size() != 0x2100 || len(r.Segments()) != 3 || r.Segments()[0].PhysicalBase != 0x1000 {
		t.Fatalf("size 0x%x segments %+v", r.Size(), r.Segments())
	}
	got, err := r.ReadAt(0x10f0, 0x20)
	if err != nil || !bytes.Equal(got, file[0xf0:0x110]) {
		t.Fatalf("read across adjacent segments: %v", err)
	}
	if got, err := r.ReadAt(0x2000, 0x100); err != nil || !bytes.Equal(got, file[0x200:]) {
		t.Fatalf("read of a whole segment: %v", err)
	}
	for _, span := range []Range{{0, 1}, {0x11f0, 0x1210}, {0x1200, 0x2000}} {
		if _, err := r.ReadAt(span.Start, span.End-span.Start); !errors.Is(err, ErrUnmapped) {
			t.Errorf("read 0x%x..0x%x: %v, want ErrUnmapped", span.Start, span.End, err)
		}
	}
	if _, err := r.ReadAt(0x20ff, 2); !errors.Is(err, ErrOutOfBounds) {
		t.Errorf("read past the top: %v", err)
	}
	if b, err := r.ReadAt(0x5000, 0); err != nil || len(b) != 0 {
		t.Errorf("empty read in a hole: %v", err)
	}
	if !r.ImmutableSnapshot() {
		t.Error("snapshot claim of the backing lost")
	}
	r.Segments()[0].Length = 1
	if r.Segments()[0].Length != 0x100 {
		t.Error("Segments gave out the reader's own list")
	}
}

func TestSegmentListsThatCannotBeServedAreRefused(t *testing.T) {
	file := image(make([]byte, 0x100))
	cases := map[string][]Segment{
		"overlap":          {{0x1000, 0, 0x80}, {0x1040, 0x80, 0x80}},
		"same base":        {{0x1000, 0, 0x10}, {0x1000, 0x10, 0x10}},
		"past the file":    {{0x1000, 0x80, 0x81}},
		"file offset wrap": {{0x1000, ^uint64(0), 2}},
		"address wrap":     {{^uint64(0) - 1, 0, 4}},
	}
	for name, segs := range cases {
		if _, err := NewSegmentedReader(file, segs); !errors.Is(err, ErrSegments) {
			t.Errorf("%s: %v, want ErrSegments", name, err)
		}
	}
	if _, err := NewSegmentedReader(nil, nil); !errors.Is(err, ErrSegments) {
		t.Errorf("no backing: %v", err)
	}
}

func TestAReadOfAHoleAllocatesNothing(t *testing.T) {
	r, err := NewSegmentedReader(image(make([]byte, 16)), []Segment{{0, 0, 8}, {1 << 40, 8, 8}})
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(10, func() {
		if _, err := r.ReadAt(0, 1<<40); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("hole read: %v", err)
		}
	})
	if allocs > 4 {
		t.Errorf("%v allocations for a refused 1 TiB read", allocs)
	}
}

type shortBacking struct{ image }

func (s shortBacking) ReadAt(offset, size uint64) ([]byte, error) {
	b, err := s.image.ReadAt(offset, size)
	if err != nil || len(b) == 0 {
		return b, err
	}
	return b[:len(b)-1], nil
}

func TestAShortBackingReadIsAnError(t *testing.T) {
	r, err := NewSegmentedReader(shortBacking{image(make([]byte, 16))}, []Segment{{0, 0, 16}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadAt(0, 16); !errors.Is(err, ErrOutOfBounds) {
		t.Errorf("short backing read: %v", err)
	}
}
