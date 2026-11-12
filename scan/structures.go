package scan

import (
	"fmt"

	"github.com/aoiflux/libvapour/memory"
)

type PoolHit struct {
	Tag    string
	Header PoolHeader
}

type ScanStats struct {
	TagHits          int
	Passed           int
	Rejected         HeaderRejections
	PageCrossing     int
	PageCrossingHits []PoolHit
	DuplicateCopies  int
	MappedCopies     int
	Accepted         int
}

func FindFilteredStructs[T any](
	reader memory.MemoryReader,
	layout PoolHeaderLayout,
	filters []PoolFilter,
	decode func(c PoolFilter, bodyOffset uint64, header PoolHeader) (T, bool),
	workers int,
) ([]T, ScanStats, error) {
	placed, stats, err := FindFilteredStructsPlaced(reader, layout, filters, decode, workers)
	return Rows(placed), stats, err
}

func FindFilteredStructsIn[T any](
	reader memory.MemoryReader,
	matches []TagMatch,
	layout PoolHeaderLayout,
	filters []PoolFilter,
	decode func(c PoolFilter, bodyOffset uint64, header PoolHeader) (T, bool),
) ([]T, ScanStats, error) {
	placed, stats, err := FindFilteredStructsInPlaced(reader, matches, layout, filters, decode)
	return Rows(placed), stats, err
}

func FindFilteredStructsPlaced[T any](
	reader memory.MemoryReader,
	layout PoolHeaderLayout,
	filters []PoolFilter,
	decode func(c PoolFilter, bodyOffset uint64, header PoolHeader) (T, bool),
	workers int,
) ([]Placed[T], ScanStats, error) {
	tags := make([]string, len(filters))
	for i, f := range filters {
		tags[i] = f.Tag
	}
	matches, err := SweepTags(reader, tags, workers)
	if err != nil {
		return nil, ScanStats{}, err
	}
	return FindFilteredStructsInPlaced(reader, matches, layout, filters, decode)
}

// A hit is taken by the first filter, in the order given, whose header checks
// and decoder accept it: one allocation is one structure.
func FindFilteredStructsInPlaced[T any](
	reader memory.MemoryReader,
	matches []TagMatch,
	layout PoolHeaderLayout,
	filters []PoolFilter,
	decode func(c PoolFilter, bodyOffset uint64, header PoolHeader) (T, bool),
) ([]Placed[T], ScanStats, error) {
	var stats ScanStats
	if reader == nil {
		return nil, stats, ErrNilReader
	}
	if layout.table == nil {
		return nil, stats, ErrNoPoolHeader
	}
	minimum := make([]uint64, len(filters))
	for i, f := range filters {
		m, err := layout.MinimumSize(f)
		if err != nil {
			return nil, stats, fmt.Errorf("pool tag %q: %w", f.Tag, err)
		}
		minimum[i] = m
	}
	var rows []Placed[T]
	for _, m := range matches {
		wanted := false
		for _, f := range filters {
			wanted = wanted || f.Tag == m.Tag
		}
		if !wanted {
			continue
		}
		stats.TagHits++
		if m.Offset < layout.TagOffset {
			stats.Rejected.Alignment++
			continue
		}
		at := m.Offset - layout.TagOffset
		var first headerVerdict = -1
		passed, crossing := false, false
		for i, f := range filters {
			if f.Tag != m.Tag {
				continue
			}
			h, v := layout.judge(reader, at, f, minimum[i])
			if first < 0 {
				first = v
			}
			switch v {
			case headerPastPage:
				crossing = true
				continue
			case headerPassed:
			default:
				continue
			}
			passed = true
			row, ok := decode(f, at+layout.Size, h)
			if !ok {
				continue
			}
			rows = append(rows, Placed[T]{Row: row, Place: Place{Pool: at, Body: at + layout.Size},
				size: h.bytes(layout.Alignment)})
			break
		}
		switch {
		case passed:
			stats.Passed++
		case crossing:
			stats.PageCrossing++
			if h, err := layout.read(reader, at); err == nil {
				stats.PageCrossingHits = append(stats.PageCrossingHits, PoolHit{Tag: m.Tag, Header: h})
			}
		default:
			stats.Rejected.count(first)
		}
	}
	rows, copies := settleCopies(reader, rows, layout.residency, layout.everyCopy)
	stats.DuplicateCopies, stats.MappedCopies = copies.withheld, copies.mapped
	if err := placeRows(rows, layout.residency); err != nil {
		return nil, stats, fmt.Errorf("place pool allocations: %w", err)
	}
	InPlaceOrder(rows)
	stats.Accepted = len(rows)
	return rows, stats, nil
}
