package scan

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
)

type ObjectScanStats struct {
	TagHits              int
	Rejected             HeaderRejections
	HeaderUnreadable     int
	PageCrossing         int
	BlockSizeBounded     int
	PointerCountRejected int
	InfoMaskRejected     int
	TypeIndexRejected    int
	TypeIndexAccepted    int
	TypeIndexFailed      int
	TypeTagRejected      int
	BodyRejected         int
	DuplicateCopies      int
	MappedCopies         int
	// Always zero: an allocation that would run past its page is refused as
	// page-crossing before an object header is looked for.
	PastPage   int
	MultiValid int
	Accepted   int
}

func (s *ObjectScanStats) Add(o ObjectScanStats) {
	s.TagHits += o.TagHits
	s.Rejected.add(o.Rejected)
	s.HeaderUnreadable += o.HeaderUnreadable
	s.PageCrossing += o.PageCrossing
	s.BlockSizeBounded += o.BlockSizeBounded
	s.PointerCountRejected += o.PointerCountRejected
	s.InfoMaskRejected += o.InfoMaskRejected
	s.TypeIndexRejected += o.TypeIndexRejected
	s.TypeIndexAccepted += o.TypeIndexAccepted
	s.TypeIndexFailed += o.TypeIndexFailed
	s.TypeTagRejected += o.TypeTagRejected
	s.BodyRejected += o.BodyRejected
	s.DuplicateCopies += o.DuplicateCopies
	s.MappedCopies += o.MappedCopies
	s.PastPage += o.PastPage
	s.MultiValid += o.MultiValid
	s.Accepted += o.Accepted
}

func (s ObjectScanStats) Describe() string {
	parts := []string{fmt.Sprintf("%d accepted", s.Accepted)}
	add := func(n int, what string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, what))
		}
	}
	add(s.Rejected.total(), "refused by the pool header")
	add(s.PageCrossing, "past their page")
	add(s.BlockSizeBounded, "too small for the body")
	add(s.HeaderUnreadable, "with an unreadable object header")
	add(s.InfoMaskRejected, "with no object header where InfoMask places one")
	add(s.PointerCountRejected, "with impossible reference counts")
	add(s.TypeIndexRejected, "of another TypeIndex")
	add(s.TypeTagRejected, "of another body type")
	add(s.BodyRejected, "refused by the body check")
	add(s.TypeIndexFailed, "kept with a failed TypeIndex")
	add(s.MultiValid, "with more than one object header")
	add(s.DuplicateCopies, "withheld as copies")
	add(s.MappedCopies, "reported as further mapped copies")
	return strings.Join(parts, ", ")
}

func FindExecutiveObjects[T any](reader memory.MemoryReader, filter PoolFilter, layout ObjectLayout,
	identity ObjectIdentity, decode func(bodyOffset uint64) (T, bool), workers int) ([]T, ObjectScanStats, error) {
	placed, stats, err := FindExecutiveObjectsPlaced(reader, filter, layout, identity, decode, workers)
	return Rows(placed), stats, err
}

func FindExecutiveObjectsPlaced[T any](reader memory.MemoryReader, filter PoolFilter, layout ObjectLayout,
	identity ObjectIdentity, decode func(bodyOffset uint64) (T, bool), workers int) ([]Placed[T], ObjectScanStats, error) {
	matches, err := SweepTags(reader, []string{filter.Tag}, workers)
	if err != nil {
		return nil, ObjectScanStats{}, err
	}
	return FindEveryExecutiveObjectPlaced(reader, matches, filter, layout, identity,
		func(_, body uint64) (T, bool) { return decode(body) })
}

func FindEveryExecutiveObject[T any](reader memory.MemoryReader, matches []TagMatch, filter PoolFilter,
	layout ObjectLayout, identity ObjectIdentity, decode func(poolHeader, bodyOffset uint64) (T, bool)) ([]T, ObjectScanStats, error) {
	placed, stats, err := FindEveryExecutiveObjectPlaced(reader, matches, filter, layout, identity, decode)
	return Rows(placed), stats, err
}

type objectVerdict int

const (
	objectNone objectVerdict = iota
	objectUnreadable
	objectInfoMask
	objectCounts
	objectTypeIndex
	objectTypeTag
	objectBody
	objectAccepted
)

func FindEveryExecutiveObjectPlaced[T any](reader memory.MemoryReader, matches []TagMatch, filter PoolFilter,
	layout ObjectLayout, identity ObjectIdentity, decode func(poolHeader, bodyOffset uint64) (T, bool)) ([]Placed[T], ObjectScanStats, error) {
	var stats ObjectScanStats
	if reader == nil {
		return nil, stats, ErrNilReader
	}
	if layout.table == nil {
		return nil, stats, ErrNoObjectHeader
	}
	minimum, err := layout.MinimumSize(filter)
	if err != nil {
		return nil, stats, fmt.Errorf("pool tag %q: %w", filter.Tag, err)
	}
	need := minimum - min(minimum, layout.PoolHeaderSize+layout.BodyOffset)
	reach := layout.reach(identity)
	step := max(layout.Alignment, 1)
	var rows []Placed[T]
	for _, m := range matches {
		if m.Tag != filter.Tag {
			continue
		}
		stats.TagHits++
		if m.Offset < layout.PoolTagOffset {
			stats.Rejected.Alignment++
			continue
		}
		at := m.Offset - layout.PoolTagOffset
		h, v := layout.pool.judge(reader, at, filter, minimum)
		switch v {
		case headerPassed:
		case headerPastPage:
			stats.PageCrossing++
			continue
		default:
			stats.Rejected.count(v)
			continue
		}
		end := at + h.bytes(layout.Alignment)
		best := objectNone
		var found []Placed[T]
		for d := uint64(0); d <= reach; d += step {
			header := at + layout.PoolHeaderSize + d
			if header+layout.BodyOffset+need > end {
				break
			}
			switch layout.placement(reader, identity, header, d) {
			case placementUnreadable:
				best = max(best, objectUnreadable)
				continue
			case placementInfoMask:
				best = max(best, objectInfoMask)
				continue
			case placementCounts:
				best = max(best, objectCounts)
				continue
			}
			p, verdict := judgeObject(reader, layout, identity, at, header, decode)
			best = max(best, verdict)
			if verdict == objectAccepted {
				p.size = h.bytes(layout.Alignment)
				p.named = layout.nameReads(reader, header)
				found = append(found, p)
			}
		}
		switch best {
		case objectNone:
			stats.BlockSizeBounded++
		case objectUnreadable:
			stats.HeaderUnreadable++
		case objectInfoMask:
			stats.InfoMaskRejected++
		case objectCounts:
			stats.PointerCountRejected++
		case objectTypeIndex:
			stats.TypeIndexRejected++
		case objectTypeTag:
			stats.TypeTagRejected++
		case objectBody:
			stats.BodyRejected++
		}
		if len(found) == 0 {
			continue
		}
		p, ties := bestCandidate(found)
		if ties > 1 {
			stats.MultiValid++
		}
		if p.TypeIndexFailed {
			stats.TypeIndexFailed++
		} else if p.keys != 0 {
			stats.TypeIndexAccepted++
		}
		rows = append(rows, p)
	}
	rows, copies := settleCopies(reader, rows, layout.residency, layout.everyCopy)
	stats.DuplicateCopies, stats.MappedCopies = copies.withheld, copies.mapped
	if err := placeRows(rows, layout.residency); err != nil {
		return nil, stats, fmt.Errorf("place %q objects: %w", filter.Tag, err)
	}
	InPlaceOrder(rows)
	stats.Accepted = len(rows)
	return rows, stats, nil
}

// A header whose TypeIndex decodes beats one that could not be tested, which
// beats a kept mismatch; among equals the nearest whose name reads wins, else
// the nearest. A nearer unnamed header can be stale bytes inside the object.
func bestCandidate[T any](found []Placed[T]) (Placed[T], int) {
	rank := func(p Placed[T]) int {
		switch {
		case p.TypeIndexFailed:
			return 0
		case p.keys == 0:
			return 1
		}
		return 2
	}
	best, ties := 0, 0
	for i, p := range found {
		switch r := rank(p); {
		case r > rank(found[best]):
			best, ties = i, 1
		case r == rank(found[best]):
			ties++
			if p.named && !found[best].named {
				best = i
			}
		}
	}
	return found[best], ties
}

// TypeIndex decides when the frame's addresses let it be decoded; the body
// type tag decides otherwise, and also guards a kept TypeIndex mismatch.
func judgeObject[T any](reader memory.MemoryReader, layout ObjectLayout, id ObjectIdentity, pool, header uint64,
	decode func(poolHeader, bodyOffset uint64) (T, bool)) (Placed[T], objectVerdict) {
	body := header + layout.BodyOffset
	var keys uint16
	failed := false
	if id.Index.resolved {
		k, _, tested := id.Index.passingKeys(reader, layout.residency, header)
		if tested && k == 0 {
			if !id.KeepIndexMismatch || !id.Tag.Resolved || !id.Tag.Accepts(reader, body) {
				return Placed[T]{}, objectTypeIndex
			}
			failed = true
		}
		keys = k
	}
	if !id.Tag.Accepts(reader, body) {
		return Placed[T]{}, objectTypeTag
	}
	row, ok := decode(pool, body)
	if !ok {
		return Placed[T]{}, objectBody
	}
	return Placed[T]{Row: row, Place: Place{Pool: pool, Body: body}, TypeIndexFailed: failed, keys: keys}, objectAccepted
}
