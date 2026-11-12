package extract

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
)

const (
	pageSize = uint64(0x1000)
	// Bounds the bytes held per write; a whole page multiple so a chunk edge
	// never splits a page.
	copyChunk = 256 * pageSize
)

var (
	// Refused, not truncated: a cut artefact would pass for a whole one.
	ErrRegionTooLarge = errors.New("extract: region over the size limit")

	ErrInvalidRange = errors.New("extract: region ends before it starts")

	ErrNoReader = errors.New("extract: no reader")

	ErrNoWriter = errors.New("extract: no writer")
)

type Gap struct {
	Start  uint64
	Length uint64
}

func (g Gap) End() uint64 { return g.Start + g.Length }

type GapMap []Gap

func (g GapMap) PaddedBytes() uint64 {
	var n uint64
	for _, x := range g {
		n += x.Length
	}
	return n
}

type Run struct {
	Offset uint64
	Length uint64
}

// A scanner matches within runs only, so no hit is built from padding.
func (g GapMap) Runs(start, size uint64) []Run {
	end := clipEnd(start, size)
	var out []Run
	cursor := start
	for _, x := range g {
		lo, hi := max(x.Start, start), min(x.End(), end)
		if lo >= hi {
			continue
		}
		if lo > cursor {
			out = append(out, Run{Offset: cursor - start, Length: lo - cursor})
		}
		cursor = max(cursor, hi)
	}
	if cursor < end {
		out = append(out, Run{Offset: cursor - start, Length: end - cursor})
	}
	return out
}

func (g GapMap) Contains(va uint64) bool {
	i := sort.Search(len(g), func(i int) bool { return g[i].End() > va })
	return i < len(g) && g[i].Start <= va
}

// Pages arrive in address order, so a new gap either extends the last one or
// starts after it.
func (g *GapMap) add(start, length uint64) {
	if length == 0 {
		return
	}
	if n := len(*g); n > 0 && (*g)[n-1].End() == start {
		(*g)[n-1].Length += length
		return
	}
	*g = append(*g, Gap{Start: start, Length: length})
}

// MaxSize 0 means Limits.MaxArtifactBytes: a corrupt range must not ask for an
// unbounded write.
type Options struct {
	MaxSize   uint64
	Unlimited bool
}

func (o Options) Limit() uint64 {
	switch {
	case o.Unlimited:
		return 0
	case o.MaxSize > 0:
		return o.MaxSize
	}
	return uint64(limits.Default().MaxArtifactBytes)
}

type Result struct {
	Start    uint64
	End      uint64
	Size     uint64
	Captured uint64
	Gaps     GapMap
}

func (r Result) Complete() bool { return len(r.Gaps) == 0 }

// end is the last byte of the region, as address-range listings give it.
func RegionSize(start, end uint64) (uint64, bool) {
	if end < start {
		return 0, false
	}
	size := end - start + 1
	return size, size != 0
}

// Write errors abort. Read errors become gaps: unreadable pages are normal in
// a capture.
func Region(r memory.MemoryReader, start, end uint64, w io.Writer, opts Options) (Result, error) {
	res := Result{Start: start, End: end}
	if r == nil {
		return res, ErrNoReader
	}
	if w == nil {
		return res, ErrNoWriter
	}
	size, ok := RegionSize(start, end)
	if !ok {
		return res, fmt.Errorf("%w: 0x%x-0x%x", ErrInvalidRange, start, end)
	}
	if limit := opts.Limit(); limit > 0 && size > limit {
		return res, fmt.Errorf("%w: %d bytes, limit %d", ErrRegionTooLarge, size, limit)
	}
	for done := uint64(0); done < size; {
		n := min(copyChunk, size-done)
		b, gaps := ReadPadded(r, start+done, n)
		if _, err := w.Write(b); err != nil {
			return res, err
		}
		res.Size += n
		res.Captured += n - gaps.PaddedBytes()
		for _, g := range gaps {
			res.Gaps.add(g.Start, g.Length)
		}
		done += n
	}
	return res, nil
}

// Read per page, so one missing page loses only that page. A range that would
// pass the top of the address space is cut there.
func ReadPadded(r memory.MemoryReader, addr, size uint64) ([]byte, GapMap) {
	size = clipEnd(addr, size) - addr
	out := make([]byte, size)
	var gaps GapMap
	if size == 0 {
		return out, nil
	}
	if r == nil {
		gaps.add(addr, size)
		return out, gaps
	}
	if b, err := r.ReadAt(addr, size); err == nil && uint64(len(b)) == size {
		copy(out, b)
		return out, nil
	}
	for off := uint64(0); off < size; {
		n := min(pageSize-(addr+off)%pageSize, size-off)
		b, err := r.ReadAt(addr+off, n)
		if err == nil && uint64(len(b)) == n {
			copy(out[off:], b)
		} else {
			gaps.add(addr+off, n)
		}
		off += n
	}
	return out, gaps
}

func clipEnd(start, size uint64) uint64 {
	if size > ^uint64(0)-start {
		return ^uint64(0)
	}
	return start + size
}
