package memory

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
)

var ErrLime = errors.New("memory: lime capture unusable")

// The range header of the lime format's published description, version 1
// (S71 L1).
const (
	limeMagic       = 0x4C694D45
	limeVersion     = 1
	limeHeaderBytes = 32
	limeStartAt     = 8
	limeEndAt       = 16
)

type limeDetector struct{ l limits.Limits }

func (limeDetector) Name() string { return "lime" }

func (d limeDetector) Detect(backing MemoryReader) (MemoryReader, bool, error) {
	if backing.Size() < 4 {
		return nil, false, nil
	}
	head, err := readFull(backing, 0, 4)
	if err != nil || binary.LittleEndian.Uint32(head) != limeMagic {
		return nil, false, nil
	}
	r, err := openLime(backing, d.l.MaxTableEntries)
	if err != nil {
		return nil, true, err
	}
	return r, true, nil
}

func openLime(backing MemoryReader, maxRanges int) (*SegmentedReader, error) {
	size := backing.Size()
	var segs []Segment
	var pos uint64
	trailing := uint64(0)
	for pos < size {
		if size-pos < limeHeaderBytes {
			trailing = size - pos
			break
		}
		h, err := readFull(backing, pos, limeHeaderBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: header at 0x%x: %w", ErrLime, pos, err)
		}
		if binary.LittleEndian.Uint32(h) != limeMagic {
			trailing = size - pos
			break
		}
		if v := binary.LittleEndian.Uint32(h[4:]); v != limeVersion {
			return nil, fmt.Errorf("%w: header at 0x%x has version %d, only %d is described", ErrLime, pos, v, limeVersion)
		}
		start, end := binary.LittleEndian.Uint64(h[limeStartAt:]), binary.LittleEndian.Uint64(h[limeEndAt:])
		if end < start || end-start == ^uint64(0) {
			return nil, fmt.Errorf("%w: header at 0x%x names range 0x%x to 0x%x", ErrLime, pos, start, end)
		}
		length := end - start + 1
		data := pos + limeHeaderBytes
		if length > size-data {
			return nil, fmt.Errorf("%w: range at 0x%x needs 0x%x bytes, 0x%x remain", ErrLime, pos, length, size-data)
		}
		if len(segs) == maxRanges {
			return nil, fmt.Errorf("%w: more than %d ranges, the MaxTableEntries limit", ErrLime, maxRanges)
		}
		segs = append(segs, Segment{PhysicalBase: start, FileOffset: data, Length: length})
		pos = data + length
	}
	if len(segs) == 0 {
		return nil, fmt.Errorf("%w: no range", ErrLime)
	}
	var note string
	if trailing > 0 {
		if err := zeroTail(backing, pos); err != nil {
			return nil, err
		}
		note = fmt.Sprintf("lime: 0x%x zero bytes after the last range at 0x%x", trailing, pos)
	}
	r, err := NewSegmentedReader(backing, segs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLime, err)
	}
	if note != "" {
		r.repairs = append(r.repairs, note)
	}
	return r, nil
}

// Read a page at a time: after a damaged header the tail can be most of the
// file, and the first nonzero page ends the check.
func zeroTail(backing MemoryReader, pos uint64) error {
	zero := make([]byte, 4096)
	for at := pos; at < backing.Size(); {
		n := min(uint64(len(zero)), backing.Size()-at)
		b, err := readFull(backing, at, n)
		if err != nil {
			return fmt.Errorf("%w: bytes after the last range at 0x%x: %w", ErrLime, at, err)
		}
		if !bytes.Equal(b, zero[:n]) {
			return fmt.Errorf("%w: bytes at 0x%x after the last range at 0x%x are not a range header", ErrLime, at, pos)
		}
		at += n
	}
	return nil
}
