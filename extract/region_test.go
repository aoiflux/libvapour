package extract

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

// pages maps a page address to its fill byte; a missing page fails to read,
// and a read that touches one fails whole, as a translating reader does.
type pages struct {
	fill  map[uint64]byte
	reads int
}

func (p *pages) ReadAt(addr, size uint64) ([]byte, error) {
	p.reads++
	out := make([]byte, size)
	for i := uint64(0); i < size; i++ {
		v, ok := p.fill[(addr+i)&^(pageSize-1)]
		if !ok {
			return nil, fmt.Errorf("page 0x%x not mapped", (addr+i)&^(pageSize-1))
		}
		out[i] = v
	}
	return out, nil
}

func (p *pages) Size() uint64 { return ^uint64(0) }

func TestRegionSizeIsInclusive(t *testing.T) {
	for _, c := range []struct {
		start, end, size uint64
		ok               bool
	}{
		{0x1000, 0x1FFF, 0x1000, true},
		{0x1000, 0x1000, 1, true},
		{0x1000, 0xFFF, 0, false},
		{0, ^uint64(0), 0, false},
		{1, ^uint64(0), ^uint64(0), true},
	} {
		size, ok := RegionSize(c.start, c.end)
		if size != c.size || ok != c.ok {
			t.Errorf("RegionSize(0x%x, 0x%x) = 0x%x %v", c.start, c.end, size, ok)
		}
	}
}

func TestReadPaddedFastPathAndPerPage(t *testing.T) {
	p := &pages{fill: map[uint64]byte{0x1000: 1, 0x2000: 2, 0x3000: 3}}
	b, gaps := ReadPadded(p, 0x1800, 0x2000)
	if len(gaps) != 0 || p.reads != 1 || b[0] != 1 || b[0x800] != 2 || b[0x1FFF] != 3 {
		t.Errorf("mapped range: %d reads, gaps %v", p.reads, gaps)
	}
	p = &pages{fill: map[uint64]byte{0x1000: 1, 0x3000: 3}}
	b, gaps = ReadPadded(p, 0x1800, 0x2000)
	if len(b) != 0x2000 || b[0x7FF] != 1 || b[0x800] != 0 || b[0x17FF] != 0 || b[0x1800] != 3 {
		t.Errorf("bytes around the hole: % x", []byte{b[0x7FF], b[0x800], b[0x17FF], b[0x1800]})
	}
	if len(gaps) != 1 || gaps[0] != (Gap{Start: 0x2000, Length: 0x1000}) {
		t.Errorf("gaps %v", gaps)
	}
	if p.reads != 4 {
		t.Errorf("%d reads, want the whole range then three page pieces", p.reads)
	}
}

func TestReadPaddedMergesAdjacentGaps(t *testing.T) {
	b, gaps := ReadPadded(&pages{fill: map[uint64]byte{0x4000: 4}}, 0x1000, 0x4000)
	if len(gaps) != 1 || gaps[0] != (Gap{0x1000, 0x3000}) || b[0x3000] != 4 {
		t.Errorf("gaps %v", gaps)
	}
}

func TestReadPaddedEdges(t *testing.T) {
	if b, g := ReadPadded(nil, 0x1000, 0x10); len(b) != 0x10 || len(g) != 1 || g[0] != (Gap{0x1000, 0x10}) {
		t.Errorf("nil reader: %d bytes, gaps %v", len(b), g)
	}
	if b, g := ReadPadded(&pages{}, 0x1000, 0); len(b) != 0 || g != nil {
		t.Errorf("empty read: %d bytes, gaps %v", len(b), g)
	}
	top := ^uint64(0) - 0xFFF
	b, g := ReadPadded(&pages{}, top, 0x2000)
	if uint64(len(b)) != 0xFFF || g.PaddedBytes() != 0xFFF {
		t.Errorf("range past the top: %d bytes, gaps %v", len(b), g)
	}
}

func TestGapMapQueries(t *testing.T) {
	g := GapMap{{0x2000, 0x1000}, {0x5000, 0x2000}}
	if g.PaddedBytes() != 0x3000 {
		t.Errorf("PaddedBytes %d", g.PaddedBytes())
	}
	for va, want := range map[uint64]bool{0x1FFF: false, 0x2000: true, 0x2FFF: true, 0x3000: false, 0x6FFF: true, 0x7000: false} {
		if g.Contains(va) != want {
			t.Errorf("Contains(0x%x) = %v", va, !want)
		}
	}
	got := g.Runs(0x1000, 0x7000)
	want := []Run{{0, 0x1000}, {0x2000, 0x2000}, {0x6000, 0x1000}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Runs %v, want %v", got, want)
	}
	if r := g.Runs(0x2000, 0x1000); len(r) != 0 {
		t.Errorf("runs inside a gap: %v", r)
	}
	if r := (GapMap{}).Runs(0x10, 0x20); len(r) != 1 || r[0] != (Run{0, 0x20}) {
		t.Errorf("no gaps: %v", r)
	}
}

func TestOptionsLimit(t *testing.T) {
	if got := (Options{}).Limit(); got != uint64(limits.Default().MaxArtifactBytes) {
		t.Errorf("default %d", got)
	}
	if got := (Options{MaxSize: 10}).Limit(); got != 10 {
		t.Errorf("MaxSize %d", got)
	}
	if got := (Options{MaxSize: 10, Unlimited: true}).Limit(); got != 0 {
		t.Errorf("Unlimited %d", got)
	}
}

func TestRegionCopiesAndReportsGaps(t *testing.T) {
	p := &pages{fill: map[uint64]byte{0x10000: 0xA, 0x12000: 0xC}}
	var out bytes.Buffer
	res, err := Region(p, 0x10000, 0x12FFF, &out, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0x3000 || out.Bytes()[0] != 0xA || out.Bytes()[0x1000] != 0 || out.Bytes()[0x2000] != 0xC {
		t.Errorf("artefact %d bytes", out.Len())
	}
	if res.Start != 0x10000 || res.End != 0x12FFF || res.Size != 0x3000 || res.Captured != 0x2000 || res.Complete() {
		t.Errorf("result %+v", res)
	}
	if len(res.Gaps) != 1 || res.Gaps[0] != (Gap{0x11000, 0x1000}) {
		t.Errorf("gaps %v", res.Gaps)
	}
}

func TestRegionAcrossChunks(t *testing.T) {
	fill := map[uint64]byte{}
	for a := uint64(0); a < 3*copyChunk; a += pageSize {
		if a != copyChunk-pageSize && a != copyChunk {
			fill[a] = byte(a >> 12)
		}
	}
	var out bytes.Buffer
	res, err := Region(&pages{fill: fill}, 0, 3*copyChunk-1, &out, Options{Unlimited: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Size != 3*copyChunk || uint64(out.Len()) != res.Size || res.Captured != res.Size-2*pageSize {
		t.Errorf("result %+v", res)
	}
	if len(res.Gaps) != 1 || res.Gaps[0] != (Gap{copyChunk - pageSize, 2 * pageSize}) {
		t.Errorf("gap across the chunk edge not merged: %v", res.Gaps)
	}
}

type failing struct{}

func (failing) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestRegionRefusals(t *testing.T) {
	p := &pages{fill: map[uint64]byte{0: 1}}
	var out bytes.Buffer
	for _, c := range []struct {
		name string
		run  func() error
		want error
	}{
		{"nil reader", func() error { _, err := Region(nil, 0, 1, &out, Options{}); return err }, ErrNoReader},
		{"nil writer", func() error { _, err := Region(p, 0, 1, nil, Options{}); return err }, ErrNoWriter},
		{"reversed", func() error { _, err := Region(p, 2, 1, &out, Options{}); return err }, ErrInvalidRange},
		{"whole space", func() error { _, err := Region(p, 0, ^uint64(0), &out, Options{Unlimited: true}); return err }, ErrInvalidRange},
		{"over limit", func() error { _, err := Region(p, 0, 0x1000, &out, Options{MaxSize: 0x1000}); return err }, ErrRegionTooLarge},
	} {
		if err := c.run(); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if out.Len() != 0 {
		t.Errorf("%d bytes written by refused calls", out.Len())
	}
	if _, err := Region(p, 0, 0xFFF, failing{}, Options{}); err == nil || errors.Is(err, ErrRegionTooLarge) {
		t.Errorf("write error: %v", err)
	}
}
