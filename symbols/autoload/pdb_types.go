package autoload

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
)

// Leaf kinds from cvinfo.h.
const (
	lfModifier  = 0x1001
	lfPointer   = 0x1002
	lfProcedure = 0x1008
	lfMFunction = 0x1009
	lfFieldList = 0x1203
	lfBitfield  = 0x1205
	lfBClass    = 0x1400
	lfVBClass   = 0x1401
	lfIVBClass  = 0x1402
	lfIndex     = 0x1404
	lfVFuncTab  = 0x1409
	lfEnumerate = 0x1502
	lfArray     = 0x1503
	lfClass     = 0x1504
	lfStructure = 0x1505
	lfUnion     = 0x1506
	lfEnum      = 0x1507
	lfMember    = 0x150d
	lfSTMember  = 0x150e
	lfMethod    = 0x150f
	lfNestType  = 0x1510
	lfOneMethod = 0x1511
	lfInterface = 0x1519

	propForward    = 0x0080
	propUniqueName = 0x0200

	typeHeaderMin = 56
	padLeafFirst  = 0xf0
)

type typeGraph struct {
	begin, end uint32
	records    [][]byte
	maxDepth   int
	tooDeep    bool
	// Forward references name their definition by unique name where the
	// record has one, else by name.
	defined map[string]uint32
}

func (g *typeGraph) depthLimit() int {
	if g.maxDepth > 0 {
		return g.maxDepth
	}
	return limits.DefaultMaxRecursionDepth
}

// The header gives the index range and the record bytes; the records must
// fill those bytes exactly and be as many as the range, as each record has
// the next index.
func readTypeStream(s []byte) (*typeGraph, error) {
	if len(s) < typeHeaderMin {
		return nil, fmt.Errorf("autoload: pdb type stream is %d bytes, shorter than its %d-byte header", len(s), typeHeaderMin)
	}
	headerSize := uint64(binary.LittleEndian.Uint32(s[4:]))
	begin := binary.LittleEndian.Uint32(s[8:])
	end := binary.LittleEndian.Uint32(s[12:])
	recordBytes := uint64(binary.LittleEndian.Uint32(s[16:]))
	if headerSize < typeHeaderMin || headerSize+recordBytes > uint64(len(s)) {
		return nil, fmt.Errorf("autoload: pdb type stream header of %d bytes and %d record bytes do not fit its %d bytes", headerSize, recordBytes, len(s))
	}
	if begin > end || uint64(end-begin) > recordBytes/4 {
		return nil, fmt.Errorf("autoload: pdb type stream index range %#x-%#x cannot be held in %d record bytes", begin, end, recordBytes)
	}
	g := &typeGraph{begin: begin, end: end, records: make([][]byte, 0, end-begin)}
	data := s[headerSize : headerSize+recordBytes]
	for at := 0; at < len(data); {
		if at+4 > len(data) {
			return nil, fmt.Errorf("autoload: pdb type record at byte %d is cut short", at)
		}
		n := int(binary.LittleEndian.Uint16(data[at:]))
		if n < 2 || at+2+n > len(data) {
			return nil, fmt.Errorf("autoload: pdb type record at byte %d claims %d bytes", at, n)
		}
		g.records = append(g.records, data[at+2:at+2+n])
		at += 2 + n
	}
	if uint64(len(g.records)) != uint64(end-begin) {
		return nil, fmt.Errorf("autoload: pdb type stream holds %d records, its index range %#x-%#x names %d", len(g.records), begin, end, end-begin)
	}
	g.indexDefinitions()
	return g, nil
}

func (g *typeGraph) record(index uint32) ([]byte, uint16) {
	if index < g.begin || index >= g.end {
		return nil, 0
	}
	r := g.records[index-g.begin]
	return r[2:], binary.LittleEndian.Uint16(r)
}

type udtHeader struct {
	kind       uint16
	property   uint16
	count      uint16
	fieldList  uint32
	underlying uint32
	size       uint64
	name       string
	uniqueName string
}

// LF_CLASS, LF_STRUCTURE and LF_INTERFACE share one layout (lfClass), LF_UNION
// and LF_ENUM have their own; the size leaf, absent for an enum, precedes the
// name, and a unique name follows it when the property says so.
func (g *typeGraph) udt(index uint32) (udtHeader, bool) {
	body, kind := g.record(index)
	h := udtHeader{kind: kind}
	var rest []byte
	switch kind {
	case lfClass, lfStructure, lfInterface:
		if len(body) < 16 {
			return h, false
		}
		h.fieldList = binary.LittleEndian.Uint32(body[4:])
		rest = body[16:]
	case lfUnion:
		if len(body) < 8 {
			return h, false
		}
		h.fieldList = binary.LittleEndian.Uint32(body[4:])
		rest = body[8:]
	case lfEnum:
		if len(body) < 12 {
			return h, false
		}
		h.underlying = binary.LittleEndian.Uint32(body[4:])
		h.fieldList = binary.LittleEndian.Uint32(body[8:])
		rest = body[12:]
	default:
		return h, false
	}
	h.count = binary.LittleEndian.Uint16(body)
	h.property = binary.LittleEndian.Uint16(body[2:])
	if kind != lfEnum {
		size, _, n, ok := readNumeric(rest)
		if !ok {
			return h, false
		}
		h.size, rest = size, rest[n:]
	}
	name, n, ok := readName(rest)
	if !ok {
		return h, false
	}
	h.name = name
	if h.property&propUniqueName != 0 {
		if unique, _, ok := readName(rest[n:]); ok {
			h.uniqueName = unique
		}
	}
	return h, true
}

func (h udtHeader) key() string {
	if h.uniqueName != "" {
		return "u:" + h.uniqueName
	}
	return "n:" + h.name
}

func (g *typeGraph) indexDefinitions() {
	g.defined = map[string]uint32{}
	for i := range g.records {
		index := g.begin + uint32(i)
		if h, ok := g.udt(index); ok && h.property&propForward == 0 {
			if _, seen := g.defined[h.key()]; !seen {
				g.defined[h.key()] = index
			}
		}
	}
}

func (g *typeGraph) definition(index uint32) (udtHeader, bool) {
	h, ok := g.udt(index)
	if !ok || h.property&propForward == 0 {
		return h, ok
	}
	if def, found := g.defined[h.key()]; found {
		return g.udt(def)
	}
	return h, false
}

type fieldMember struct {
	name   string
	offset uint64
	typ    uint32
	value  int64
}

// Members follow one another with no length of their own, so a member kind
// whose layout is not known ends the list. LF_INDEX continues it in another
// record; a continuation seen twice is a cycle and ends it too.
func (g *typeGraph) fieldList(index uint32) (members, enumerates []fieldMember, whole bool) {
	seen := map[uint32]bool{}
	for {
		body, kind := g.record(index)
		if kind != lfFieldList || seen[index] {
			return members, enumerates, false
		}
		seen[index] = true
		next, done, ok := g.walkFieldList(body, &members, &enumerates)
		if !ok {
			return members, enumerates, false
		}
		if done {
			return members, enumerates, true
		}
		index = next
	}
}

func (g *typeGraph) walkFieldList(b []byte, members, enumerates *[]fieldMember) (next uint32, done, ok bool) {
	for p := 0; p < len(b); {
		if b[p] >= padLeafFirst {
			p += max(1, int(b[p]&0x0f))
			continue
		}
		if p+2 > len(b) {
			return 0, false, false
		}
		leaf := binary.LittleEndian.Uint16(b[p:])
		rest := b[p+2:]
		var used int
		switch leaf {
		case lfMember:
			if len(rest) < 6 {
				return 0, false, false
			}
			offset, _, n, okNum := readNumeric(rest[6:])
			if !okNum {
				return 0, false, false
			}
			name, m, okName := readName(rest[6+n:])
			if !okName {
				return 0, false, false
			}
			*members = append(*members, fieldMember{name: name, offset: offset, typ: binary.LittleEndian.Uint32(rest[2:])})
			used = 6 + n + m
		case lfEnumerate:
			if len(rest) < 2 {
				return 0, false, false
			}
			value, _, n, okNum := readNumeric(rest[2:])
			if !okNum {
				return 0, false, false
			}
			name, m, okName := readName(rest[2+n:])
			if !okName {
				return 0, false, false
			}
			*enumerates = append(*enumerates, fieldMember{name: name, value: int64(value)})
			used = 2 + n + m
		case lfIndex:
			if len(rest) < 6 {
				return 0, false, false
			}
			return binary.LittleEndian.Uint32(rest[2:]), false, true
		case lfBClass:
			if len(rest) < 6 {
				return 0, false, false
			}
			_, _, n, okNum := readNumeric(rest[6:])
			if !okNum {
				return 0, false, false
			}
			used = 6 + n
		case lfVBClass, lfIVBClass:
			if len(rest) < 10 {
				return 0, false, false
			}
			_, _, n1, ok1 := readNumeric(rest[10:])
			if !ok1 {
				return 0, false, false
			}
			_, _, n2, ok2 := readNumeric(rest[10+n1:])
			if !ok2 {
				return 0, false, false
			}
			used = 10 + n1 + n2
		case lfVFuncTab:
			used = 6
		case lfSTMember, lfMethod, lfNestType:
			if len(rest) < 6 {
				return 0, false, false
			}
			_, m, okName := readName(rest[6:])
			if !okName {
				return 0, false, false
			}
			used = 6 + m
		case lfOneMethod:
			if len(rest) < 6 {
				return 0, false, false
			}
			used = 6
			if prop := (binary.LittleEndian.Uint16(rest) >> 2) & 7; prop == 4 || prop == 6 {
				used += 4
			}
			if len(rest) < used {
				return 0, false, false
			}
			_, m, okName := readName(rest[used:])
			if !okName {
				return 0, false, false
			}
			used += m
		default:
			return 0, false, false
		}
		if used > len(rest) {
			return 0, false, false
		}
		p += 2 + used
	}
	return 0, true, true
}

// The rendering follows modifiers through to the type they qualify, and
// stops at the format's operator limit and at the depth limit, which only a
// cycle reaches in a stream whose records refer to earlier ones.
func (g *typeGraph) typeRef(index uint32) symbols.TypeRef {
	return g.render(index, 0)
}

func (g *typeGraph) render(index uint32, depth int) symbols.TypeRef {
	if depth > g.depthLimit() {
		g.tooDeep = true
		return symbols.TypeRef{}
	}
	if index < g.begin {
		return simpleTypeRef(index)
	}
	body, kind := g.record(index)
	operator := func(build func(elem *symbols.TypeRef) symbols.TypeRef, inner uint32) symbols.TypeRef {
		if depth >= symbols.MaxTypeOperators {
			return symbols.TypeRef{}
		}
		elem := g.render(inner, depth+1)
		return build(&elem)
	}
	switch kind {
	case lfModifier:
		if len(body) >= 4 {
			return g.render(binary.LittleEndian.Uint32(body), depth+1)
		}
	case lfPointer:
		if len(body) >= 4 {
			return operator(func(e *symbols.TypeRef) symbols.TypeRef { return symbols.TypeRef{IsPointer: true, Element: e} },
				binary.LittleEndian.Uint32(body))
		}
	case lfArray:
		if len(body) >= 8 {
			elemIndex := binary.LittleEndian.Uint32(body)
			total, _, _, ok := readNumeric(body[8:])
			if !ok {
				break
			}
			count := uint64(0)
			if w := g.width(elemIndex, depth+1); w > 0 {
				count = total / w
			}
			return operator(func(e *symbols.TypeRef) symbols.TypeRef {
				return symbols.TypeRef{IsArray: true, ArrayLength: count, Element: e}
			}, elemIndex)
		}
	case lfBitfield:
		if len(body) >= 6 && body[4] > 0 {
			length, position := body[4], body[5]
			return operator(func(e *symbols.TypeRef) symbols.TypeRef {
				return symbols.TypeRef{BitOffset: position, BitLength: length, Element: e}
			}, binary.LittleEndian.Uint32(body))
		}
	case lfClass, lfStructure, lfInterface, lfUnion:
		if h, ok := g.udt(index); ok {
			return symbols.TypeRef{Name: h.name}
		}
	case lfEnum:
		if h, ok := g.definition(index); ok {
			return g.render(h.underlying, depth+1)
		}
	}
	return symbols.TypeRef{}
}

func (g *typeGraph) width(index uint32, depth int) uint64 {
	if depth > g.depthLimit() {
		g.tooDeep = true
		return 0
	}
	if index < g.begin {
		return simpleTypeWidth(index)
	}
	body, kind := g.record(index)
	switch kind {
	case lfModifier, lfBitfield:
		if len(body) >= 4 {
			return g.width(binary.LittleEndian.Uint32(body), depth+1)
		}
	case lfPointer:
		if len(body) >= 8 {
			attr := binary.LittleEndian.Uint32(body[4:])
			if size := uint64(attr>>13) & 0x3f; size != 0 {
				return size
			}
			switch attr & 0x1f {
			case 0x0a:
				return 4
			case 0x0c:
				return 8
			}
		}
	case lfArray:
		if len(body) >= 8 {
			if total, _, _, ok := readNumeric(body[8:]); ok {
				return total
			}
		}
	case lfClass, lfStructure, lfInterface, lfUnion:
		if h, ok := g.definition(index); ok {
			return h.size
		}
	case lfEnum:
		if h, ok := g.definition(index); ok {
			return g.width(h.underlying, depth+1)
		}
	}
	return 0
}

type pdbMember struct {
	Offset uint64
	Type   symbols.TypeRef
}

type pdbRecord struct {
	Size   uint64
	Fields map[string]pdbMember
	index  uint32
}

type pdbEnum struct {
	Size      uint64
	Base      string
	Constants map[string]int64
	index     uint32
}

// One name can have several definitions: a header's partial view of a
// structure beside the full one, or the compiler's placeholder name for every
// anonymous type. The definition with the most members is the fullest view
// and is kept; then the larger, then the earlier in the stream.
func fuller(members int, size uint64, index uint32, heldMembers int, heldSize uint64, heldIndex uint32) bool {
	if members != heldMembers {
		return members > heldMembers
	}
	if size != heldSize {
		return size > heldSize
	}
	return index < heldIndex
}

// The compiler gives every anonymous structure and union one of these names,
// so a record under it would stand for an arbitrary one of them.
var placeholderNames = map[string]bool{"<unnamed-tag>": true, "<anonymous-tag>": true}

func collectRecords(g *typeGraph) map[string]pdbRecord {
	out := map[string]pdbRecord{}
	for i := range g.records {
		index := g.begin + uint32(i)
		h, ok := g.udt(index)
		if !ok || h.kind == lfEnum || h.property&propForward != 0 || placeholderNames[h.name] {
			continue
		}
		members, _, _ := g.fieldList(h.fieldList)
		r := pdbRecord{Size: h.size, Fields: make(map[string]pdbMember, len(members)), index: index}
		for _, m := range members {
			if _, dup := r.Fields[m.name]; !dup {
				r.Fields[m.name] = pdbMember{Offset: m.offset, Type: g.typeRef(m.typ)}
			}
		}
		if held, seen := out[h.name]; seen && !fuller(len(r.Fields), r.Size, index, len(held.Fields), held.Size, held.index) {
			continue
		}
		out[h.name] = r
	}
	return out
}

// An enumerator list that does not read whole would give the enum constants
// it does not have, so such an enum is left out.
func collectEnumerations(g *typeGraph) map[string]pdbEnum {
	out := map[string]pdbEnum{}
	for i := range g.records {
		index := g.begin + uint32(i)
		h, ok := g.udt(index)
		if !ok || h.kind != lfEnum || h.property&propForward != 0 {
			continue
		}
		_, enumerates, whole := g.fieldList(h.fieldList)
		if !whole {
			continue
		}
		e := pdbEnum{
			Size:      g.width(h.underlying, 0),
			Base:      g.typeRef(h.underlying).Name,
			Constants: make(map[string]int64, len(enumerates)),
			index:     index,
		}
		for _, c := range enumerates {
			if _, dup := e.Constants[c.name]; !dup {
				e.Constants[c.name] = c.value
			}
		}
		if held, seen := out[h.name]; seen && !fuller(len(e.Constants), e.Size, index, len(held.Constants), held.Size, held.index) {
			continue
		}
		out[h.name] = e
	}
	return out
}
