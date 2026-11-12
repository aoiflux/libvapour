package memory

import (
	"errors"
	"fmt"
	"slices"
	"sort"
)

type Segment struct {
	PhysicalBase uint64
	FileOffset   uint64
	Length       uint64
}

var ErrSegments = errors.New("memory: segment list unusable")

type SegmentedReader struct {
	backing  MemoryReader
	segments []Segment
	top      uint64
	notes    []string
	repairs  []string
}

func NewSegmentedReader(backing MemoryReader, segments []Segment) (*SegmentedReader, error) {
	if backing == nil {
		return nil, fmt.Errorf("%w: no backing reader", ErrSegments)
	}
	held := make([]Segment, 0, len(segments))
	for _, s := range segments {
		if s.Length == 0 {
			continue
		}
		if s.PhysicalBase+s.Length < s.PhysicalBase {
			return nil, fmt.Errorf("%w: 0x%x bytes at physical 0x%x pass the top of the address space", ErrSegments, s.Length, s.PhysicalBase)
		}
		if s.FileOffset+s.Length < s.FileOffset || s.FileOffset+s.Length > backing.Size() {
			return nil, fmt.Errorf("%w: 0x%x bytes at file offset 0x%x pass the end of the file (0x%x)", ErrSegments, s.Length, s.FileOffset, backing.Size())
		}
		held = append(held, s)
	}
	slices.SortFunc(held, func(a, b Segment) int {
		switch {
		case a.PhysicalBase < b.PhysicalBase:
			return -1
		case a.PhysicalBase > b.PhysicalBase:
			return 1
		}
		return 0
	})
	var top uint64
	for i, s := range held {
		if i > 0 && s.PhysicalBase < top {
			return nil, fmt.Errorf("%w: physical 0x%x is held twice", ErrSegments, s.PhysicalBase)
		}
		top = s.PhysicalBase + s.Length
	}
	return &SegmentedReader{backing: backing, segments: held, top: top}, nil
}

func (r *SegmentedReader) ReadAt(offset uint64, size uint64) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil
	}
	if err := checkSpan(offset, size, r.top); err != nil {
		return nil, err
	}
	end := offset + size
	first := sort.Search(len(r.segments), func(i int) bool {
		s := r.segments[i]
		return s.PhysicalBase+s.Length > offset
	})
	// Coverage is proved before the buffer exists, so a request for a hole
	// costs nothing however large it is.
	last, at := first, offset
	for ; at < end; last++ {
		if last == len(r.segments) || r.segments[last].PhysicalBase > at {
			return nil, fmt.Errorf("memory: physical 0x%x: %w", at, ErrUnmapped)
		}
		s := r.segments[last]
		at = s.PhysicalBase + s.Length
	}
	buf := make([]byte, 0, size)
	at = offset
	for _, s := range r.segments[first:last] {
		n := min(end, s.PhysicalBase+s.Length) - at
		part, err := r.backing.ReadAt(s.FileOffset+(at-s.PhysicalBase), n)
		if err != nil {
			return nil, fmt.Errorf("memory: physical 0x%x: %w", at, err)
		}
		if uint64(len(part)) != n {
			return nil, fmt.Errorf("memory: physical 0x%x: backing returned 0x%x of 0x%x bytes: %w", at, len(part), n, ErrOutOfBounds)
		}
		buf = append(buf, part...)
		at += n
	}
	return buf, nil
}

func (r *SegmentedReader) Size() uint64 { return r.top }

func (r *SegmentedReader) ImmutableSnapshot() bool { return IsImmutableSnapshot(r.backing) }

func (r *SegmentedReader) Segments() []Segment { return slices.Clone(r.segments) }

func (r *SegmentedReader) containerNotes() []string { return slices.Concat(r.repairs, r.notes) }

func (r *SegmentedReader) containerRepairs() []string { return slices.Clone(r.repairs) }
