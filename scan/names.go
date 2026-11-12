package scan

import (
	"encoding/binary"
	"errors"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/util"
)

var errUnreadableName = errors.New("scan: object name not readable")

// With InfoMask the name info's distance in front of the header is
// ObpInfoMaskToOffset[InfoMask & 3]: only the creator info can lie between
// them. Tables without InfoMask carry the distance in NameInfoOffset.
type ObjectNamer struct {
	name       uint64
	infoMask   uint64
	hasMask    bool
	masks      uint64
	nameOffset uint64
	unicode    util.UnicodeStringLayout
}

func NewObjectNamer(sym symbols.SymbolTable) (ObjectNamer, bool) {
	if sym == nil {
		return ObjectNamer{}, false
	}
	name, err := sym.Field("_OBJECT_HEADER_NAME_INFO", "Name")
	if err != nil {
		return ObjectNamer{}, false
	}
	n := ObjectNamer{name: name.Offset, unicode: util.ResolveUnicodeStringLayout(sym)}
	if mask, err := sym.Field("_OBJECT_HEADER", "InfoMask"); err == nil {
		table, err := sym.LookupSymbol("ObpInfoMaskToOffset")
		if err != nil {
			return ObjectNamer{}, false
		}
		n.infoMask, n.hasMask, n.masks = mask.Offset, true, table.Address
		return n, true
	}
	if off, err := sym.Field("_OBJECT_HEADER", "NameInfoOffset"); err == nil {
		n.nameOffset = off.Offset
		return n, true
	}
	return ObjectNamer{}, false
}

func (n ObjectNamer) Name(headerReader, stringReader, tableReader memory.MemoryReader, headerAddr uint64) string {
	name, _, _ := n.ReadName(headerReader, stringReader, tableReader, headerAddr)
	return name
}

func (n ObjectNamer) Lookup(headerReader, stringReader, tableReader memory.MemoryReader, headerAddr uint64) (string, bool) {
	name, present, readable := n.ReadName(headerReader, stringReader, tableReader, headerAddr)
	return name, present && readable
}

func (n ObjectNamer) ReadName(headerReader, stringReader, tableReader memory.MemoryReader, headerAddr uint64) (name string, present, readable bool) {
	info, present, readable := n.nameInfo(headerReader, tableReader, headerAddr)
	if !present || !readable {
		return "", present, readable
	}
	s, err := n.readString(headerReader, stringReader, info+n.name)
	if err != nil {
		return "", true, false
	}
	return s, true, true
}

func (n ObjectNamer) NameInfo(headerReader, tableReader memory.MemoryReader, headerAddr uint64) (info uint64, present, readable bool) {
	return n.nameInfo(headerReader, tableReader, headerAddr)
}

func (n ObjectNamer) nameInfo(headerReader, tableReader memory.MemoryReader, headerAddr uint64) (uint64, bool, bool) {
	if headerReader == nil {
		return 0, false, false
	}
	if !n.hasMask {
		b, err := headerReader.ReadAt(headerAddr+n.nameOffset, 1)
		if err != nil || len(b) != 1 {
			return 0, false, false
		}
		if b[0] == 0 {
			return 0, false, true
		}
		if headerAddr < uint64(b[0]) {
			return 0, true, false
		}
		return headerAddr - uint64(b[0]), true, true
	}
	b, err := headerReader.ReadAt(headerAddr+n.infoMask, 1)
	if err != nil || len(b) != 1 {
		return 0, false, false
	}
	if b[0]&nameInfoBit == 0 {
		return 0, false, true
	}
	if tableReader == nil {
		return 0, true, false
	}
	d, err := tableReader.ReadAt(n.masks+uint64(b[0]&(nameInfoBit|(nameInfoBit-1))), 1)
	if err != nil || len(d) != 1 || d[0] == 0 || headerAddr < uint64(d[0]) {
		return 0, true, false
	}
	return headerAddr - uint64(d[0]), true, true
}

// The counted string's descriptor lies with the header; its characters are
// in kernel space.
func (n ObjectNamer) readString(headerReader, stringReader memory.MemoryReader, at uint64) (string, error) {
	width := uint64(8)
	if n.unicode.Size == 8 {
		width = 4
	}
	lb, err := headerReader.ReadAt(at+n.unicode.LengthOffset, 2)
	if err != nil || len(lb) != 2 {
		return "", errUnreadableName
	}
	length := uint64(binary.LittleEndian.Uint16(lb))
	if length == 0 {
		return "", nil
	}
	bb, err := headerReader.ReadAt(at+n.unicode.BufferOffset, width)
	if err != nil || uint64(len(bb)) != width {
		return "", errUnreadableName
	}
	var raw [8]byte
	copy(raw[:], bb)
	buffer := binary.LittleEndian.Uint64(raw[:])
	if buffer == 0 || stringReader == nil {
		return "", errUnreadableName
	}
	b, err := stringReader.ReadAt(buffer, length)
	if err != nil {
		return "", err
	}
	return util.DecodeCountedUTF16LE(b), nil
}
