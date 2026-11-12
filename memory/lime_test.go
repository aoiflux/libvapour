package memory

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

func openLimeFile(file image) (*SegmentedReader, error) {
	return openLime(file, limits.Default().MaxTableEntries)
}

func TestLimeRangesAppearAtTheirAddressesWithAnInclusiveEnd(t *testing.T) {
	a, b := pattern(0x1fff, 1), pattern(0x100, 2)
	r, err := openLimeFile(limeFile([]limeRange{{0x100000, b}, {0x1000, a}}))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.ReadAt(0x1000, 0x1fff); err != nil || !bytes.Equal(got, a) {
		t.Errorf("first range: %v", err)
	}
	if got, err := r.ReadAt(0x100000, 0x100); err != nil || !bytes.Equal(got, b) {
		t.Errorf("second range: %v", err)
	}
	if _, err := r.ReadAt(0x2fff, 1); !errors.Is(err, ErrUnmapped) {
		t.Errorf("byte after the inclusive end: %v", err)
	}
	if r.Size() != 0x100100 || len(r.Segments()) != 2 || len(r.containerNotes()) != 0 {
		t.Errorf("size 0x%x segments %d", r.Size(), len(r.Segments()))
	}
}

func TestZeroBytesAfterTheLastRangeAreAcceptedAndNoted(t *testing.T) {
	file := append(limeFile([]limeRange{{0x1000, pattern(16, 1)}}), make([]byte, 5000)...)
	r, err := openLimeFile(file)
	if err != nil || len(r.containerNotes()) != 1 {
		t.Fatalf("padded file: %v, notes %q", err, r.containerNotes())
	}
}

func TestLimeFilesThatBreakTheRangeHeaderAreRefused(t *testing.T) {
	le := binary.LittleEndian
	two := []limeRange{{0x1000, pattern(16, 1)}, {0x2000, pattern(16, 2)}}
	second := limeHeaderBytes + 16
	edit := func(f func(image)) image {
		file := limeFile(two)
		f(file)
		return file
	}
	cases := map[string]image{
		"version":          edit(func(f image) { le.PutUint32(f[second+4:], 2) }),
		"damaged magic":    edit(func(f image) { f[second] ^= 1 }),
		"end before start": edit(func(f image) { le.PutUint64(f[second+limeEndAt:], 0xfff) }),
		"range past file":  edit(func(f image) { le.PutUint64(f[second+limeEndAt:], 0x2010) }),
		"whole space":      edit(func(f image) { le.PutUint64(f[second+limeStartAt:], 0); le.PutUint64(f[second+limeEndAt:], ^uint64(0)) }),
		"overlap": edit(func(f image) {
			le.PutUint64(f[second+limeStartAt:], 0x1008)
			le.PutUint64(f[second+limeEndAt:], 0x1017)
		}),
		"short header tail": append(limeFile(two), 1, 2, 3),
		"no range":          image(make([]byte, 0)),
	}
	for name, file := range cases {
		if _, err := openLimeFile(file); !errors.Is(err, ErrLime) {
			t.Errorf("%s: %v, want ErrLime", name, err)
		}
	}
	if _, err := openLime(limeFile(two), 1); !errors.Is(err, ErrLime) {
		t.Errorf("range cap: %v", err)
	}
}
