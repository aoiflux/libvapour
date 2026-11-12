package scan

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

// The optional headers in InfoMask bit order. Bits 4 to 6 are all 16 bytes
// on the measured builds, so their order does not move any offset.
var optionalHeaders = [8]string{
	"_OBJECT_HEADER_CREATOR_INFO",
	"_OBJECT_HEADER_NAME_INFO",
	"_OBJECT_HEADER_HANDLE_INFO",
	"_OBJECT_HEADER_QUOTA_INFO",
	"_OBJECT_HEADER_PROCESS_INFO",
	"_OBJECT_HEADER_AUDIT_INFO",
	"_OBJECT_HEADER_EXTENDED_INFO",
	"_OBJECT_HEADER_PADDING_INFO",
}

const (
	nameInfoBit = 1 << 1
	paddingBit  = 1 << 7
	// Padding cache-aligns the body, so it stays below one 64-byte line.
	cacheLine = 64
)

type ObjectLayout struct {
	PoolTagOffset      uint64
	PoolHeaderSize     uint64
	PointerCountOffset uint64
	InfoMaskOffset     uint64
	BodyOffset         uint64
	Alignment          uint64
	MaxOptionalLen     uint64

	pool         PoolHeaderLayout
	table        symbols.SymbolTable
	hasInfoMask  bool
	nameOffset   uint64
	hasNameByte  bool
	pointerCount symbols.IntField
	hasPointers  bool
	handleCount  symbols.IntField
	hasHandles   bool
	optional     [8]uint64
	optionalSet  [8]bool
	residency    Residency
	everyCopy    bool
	namer        ObjectNamer
	nameReader   memory.MemoryReader
}

func ResolveObjectLayout(sym symbols.SymbolTable) (ObjectLayout, error) {
	pool, err := ResolvePoolHeaderLayout(sym)
	if err != nil {
		return ObjectLayout{}, err
	}
	body, err := sym.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return ObjectLayout{}, fmt.Errorf("%w: Body: %v", ErrNoObjectHeader, err)
	}
	l := ObjectLayout{
		PoolTagOffset:  pool.TagOffset,
		PoolHeaderSize: pool.Size,
		BodyOffset:     body.Offset,
		Alignment:      pool.Alignment,
		pool:           pool,
		table:          sym,
	}
	if f, err := sym.Field("_OBJECT_HEADER", "InfoMask"); err == nil {
		l.InfoMaskOffset, l.hasInfoMask = f.Offset, true
	}
	if f, err := symbols.ResolveIntField(sym, "_OBJECT_HEADER", "PointerCount"); err == nil {
		l.PointerCountOffset, l.pointerCount, l.hasPointers = f.Offset, f, true
	} else if f, err := sym.Field("_OBJECT_HEADER", "PointerCount"); err == nil {
		l.PointerCountOffset = f.Offset
		l.pointerCount = symbols.IntField{Offset: f.Offset, Width: uint64(sym.PointerSize())}
		l.hasPointers = true
	}
	if f, err := symbols.ResolveIntField(sym, "_OBJECT_HEADER", "HandleCount"); err == nil {
		l.handleCount, l.hasHandles = f, true
	}
	var longest uint64
	for bit, name := range optionalHeaders {
		if st, err := sym.Struct(name); err == nil && st.Size > 0 {
			l.optional[bit], l.optionalSet[bit] = st.Size, true
			if bit != 7 {
				longest += st.Size
			}
		}
	}
	switch {
	case l.hasInfoMask:
		l.MaxOptionalLen = longest + cacheLine - l.Alignment
	default:
		// Tables before InfoMask give each optional header a one-byte
		// distance, so none lies farther back than a byte reaches.
		l.MaxOptionalLen = 0xff &^ (l.Alignment - 1)
		if f, err := sym.Field("_OBJECT_HEADER", "NameInfoOffset"); err == nil {
			l.nameOffset, l.hasNameByte = f.Offset, true
		}
	}
	return l, nil
}

func (l ObjectLayout) WithResidency(r Residency) ObjectLayout {
	l.residency = r
	l.pool.residency = r
	return l
}

// PreferringNamed makes the scan choose, among equally ranked object headers
// of one allocation, the nearest whose name reads through kernel (S31 4.4
// step 5). A table without name info leaves the layout as it was.
func (l ObjectLayout) PreferringNamed(kernel memory.MemoryReader) ObjectLayout {
	if namer, ok := NewObjectNamer(l.table); ok && kernel != nil {
		l.namer, l.nameReader = namer, kernel
	}
	return l
}

func (l ObjectLayout) nameReads(reader memory.MemoryReader, header uint64) bool {
	if l.nameReader == nil {
		return false
	}
	name, present, readable := l.namer.ReadName(reader, l.nameReader, l.nameReader, header)
	return present && readable && name != ""
}

func (l ObjectLayout) ReportingEveryCopy() ObjectLayout {
	l.everyCopy = true
	l.pool.everyCopy = true
	return l
}

func (l ObjectLayout) MinimumSize(f PoolFilter) (uint64, error) {
	body, err := bodySize(l.table, f)
	if err != nil {
		return 0, err
	}
	return max(l.PoolHeaderSize+l.BodyOffset+body, f.MinSize), nil
}

// From the table's type sizes; the scan prefers the kernel's own
// ObpInfoMaskToOffset when the identity carries it.
func (l ObjectLayout) OptionalHeaderLength(mask uint64) (length uint64, hasPadding bool, ok bool) {
	for bit := range 7 {
		if mask&(1<<bit) == 0 {
			continue
		}
		if !l.optionalSet[bit] {
			return 0, false, false
		}
		length += l.optional[bit]
	}
	return length, mask&paddingBit != 0, true
}

func (l ObjectLayout) PaddingInfoSize() (uint64, bool) {
	return l.optional[7], l.optionalSet[7]
}

func (l ObjectLayout) optionalLength(id ObjectIdentity, mask byte) (uint64, bool) {
	if id.hasMasks {
		return uint64(id.masks[mask&^paddingBit]), true
	}
	n, _, ok := l.OptionalHeaderLength(uint64(mask &^ paddingBit))
	return n, ok
}

func (l ObjectLayout) reach(id ObjectIdentity) uint64 {
	if !l.hasInfoMask {
		return l.MaxOptionalLen
	}
	reach := l.MaxOptionalLen
	if id.hasMasks {
		var longest uint64
		for _, v := range id.masks[:paddingBit] {
			longest = max(longest, uint64(v))
		}
		reach = max(reach, longest+cacheLine-l.Alignment)
	}
	return reach
}

type headerPlacement int

const (
	placementFits headerPlacement = iota
	placementUnreadable
	placementInfoMask
	placementCounts
)

// The distance from the end of the pool header to the object header is the
// length of the optional headers InfoMask names plus, with the padding bit,
// the PaddingAmount stored just in front of them.
func (l ObjectLayout) placement(reader memory.MemoryReader, id ObjectIdentity, header, distance uint64) headerPlacement {
	if l.hasInfoMask {
		b, err := reader.ReadAt(header+l.InfoMaskOffset, 1)
		if err != nil || len(b) != 1 {
			return placementUnreadable
		}
		mask := b[0]
		length, ok := l.optionalLength(id, mask)
		if !ok {
			return placementInfoMask
		}
		if mask&paddingBit != 0 {
			info, known := l.PaddingInfoSize()
			if !known || header < length+info {
				return placementInfoMask
			}
			raw, err := reader.ReadAt(header-length-info, 4)
			if err != nil || len(raw) != 4 {
				return placementUnreadable
			}
			// PaddingAmount counts the padding info's own bytes too.
			pad := uint64(binary.LittleEndian.Uint32(raw))
			if pad < info || pad >= cacheLine {
				return placementInfoMask
			}
			length += pad
		}
		if length != distance {
			return placementInfoMask
		}
	} else if l.hasNameByte {
		b, err := reader.ReadAt(header+l.nameOffset, 1)
		if err != nil || len(b) != 1 {
			return placementUnreadable
		}
		if uint64(b[0]) > distance {
			return placementInfoMask
		}
	}
	return l.counts(reader, header)
}

// A reference count below zero, or more handles than references, cannot be
// a header: every handle holds a reference.
func (l ObjectLayout) counts(reader memory.MemoryReader, header uint64) headerPlacement {
	if !l.hasPointers {
		return placementFits
	}
	p, err := l.pointerCount.Read(reader, header)
	if err != nil {
		return placementUnreadable
	}
	pointers := signed(p, l.pointerCount.Width)
	if pointers < 0 {
		return placementCounts
	}
	if l.hasHandles {
		h, err := l.handleCount.Read(reader, header)
		if err != nil {
			return placementUnreadable
		}
		handles := signed(h, l.handleCount.Width)
		if handles < 0 || handles > pointers {
			return placementCounts
		}
	}
	return placementFits
}

func signed(v, width uint64) int64 {
	if width == 0 || width >= 8 {
		return int64(v)
	}
	shift := 64 - 8*width
	return int64(v<<shift) >> shift
}

// No pool header carrying one of the tags lies where the scan would look for
// the one in front of this object header.
func (l ObjectLayout) Unaccounted(reader memory.MemoryReader, tags []string, objectHeader uint64) bool {
	step := max(l.Alignment, 1)
	for d := uint64(0); d <= l.reach(ObjectIdentity{}); d += step {
		if objectHeader < d+l.PoolHeaderSize {
			break
		}
		at := objectHeader - d - l.PoolHeaderSize + l.PoolTagOffset
		b, err := reader.ReadAt(at, 4)
		if err != nil || len(b) != 4 {
			continue
		}
		for _, t := range tags {
			if string(b) == t {
				return false
			}
		}
	}
	return true
}
