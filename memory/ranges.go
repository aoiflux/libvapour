package memory

import (
	"errors"
	"fmt"
	"slices"
)

type Range struct {
	Start, End uint64
}

var ErrIncompleteScan = errors.New("memory: scan windows unreadable")

type segmentLister interface {
	Segments() []Segment
}

// A reader that names its segments is scanned only where it holds bytes;
// any other reader is taken to hold its whole size.
func MappedRanges(r MemoryReader) []Range {
	if r == nil {
		return nil
	}
	lister, ok := r.(segmentLister)
	if !ok {
		if r.Size() == 0 {
			return nil
		}
		return []Range{{0, r.Size()}}
	}
	segs := lister.Segments()
	slices.SortFunc(segs, func(a, b Segment) int {
		switch {
		case a.PhysicalBase < b.PhysicalBase:
			return -1
		case a.PhysicalBase > b.PhysicalBase:
			return 1
		}
		return 0
	})
	var out []Range
	for _, s := range segs {
		end := s.PhysicalBase + s.Length
		if s.Length == 0 || end < s.PhysicalBase {
			continue
		}
		if n := len(out); n > 0 && s.PhysicalBase <= out[n-1].End {
			out[n-1].End = max(out[n-1].End, end)
			continue
		}
		out = append(out, Range{s.PhysicalBase, end})
	}
	return out
}

type Coverage struct {
	Windows, Unreadable int
	firstAt             uint64
	firstErr            error
}

func (c Coverage) Incomplete() error {
	if c.firstErr == nil {
		return nil
	}
	if c.Windows == 0 {
		return fmt.Errorf("%w: none of %d windows read, first at 0x%x: %w", ErrIncompleteScan, c.Unreadable, c.firstAt, c.firstErr)
	}
	return fmt.Errorf("%w: %d of %d windows, first at 0x%x: %w", ErrIncompleteScan, c.Unreadable, c.Windows+c.Unreadable, c.firstAt, c.firstErr)
}

func (c *Coverage) failed(at uint64, err error) {
	if c.firstErr == nil {
		c.firstAt, c.firstErr = at, err
	}
}

// Windows start step bytes apart and run overlap bytes further, so a record
// of up to overlap+1 bytes lies whole in the window where it starts. A
// window never crosses a hole, and one that cannot be read is counted and
// skipped.
func ScanWindows(r MemoryReader, step, overlap uint64, visit func(offset uint64, window []byte) (stop bool)) Coverage {
	var c Coverage
	if r == nil || step == 0 {
		c.failed(0, errors.New("memory: scan needs a reader and a nonzero step"))
		return c
	}
	span := step + overlap
	if span < step {
		span = ^uint64(0)
	}
	for _, rg := range MappedRanges(r) {
		for at := rg.Start; at < rg.End; {
			n := min(span, rg.End-at)
			window, err := r.ReadAt(at, n)
			if err != nil {
				c.Unreadable++
				c.failed(at, err)
			} else {
				c.Windows++
				if visit(at, window) {
					return c
				}
			}
			if rg.End-at <= step {
				break
			}
			at += step
		}
	}
	return c
}
