package autoload

import (
	"bytes"
	"encoding/binary"

	"github.com/aoiflux/libvapour/symbols"
)

// Numeric leaf prefixes from cvinfo.h: a value below LF_NUMERIC is the number
// itself, and the integer leaves that follow carry it in the next bytes.
const (
	leafNumeric   = 0x8000
	leafChar      = 0x8000
	leafShort     = 0x8001
	leafUShort    = 0x8002
	leafLong      = 0x8003
	leafULong     = 0x8004
	leafQuadword  = 0x8009
	leafUQuadword = 0x800a
)

func readNumeric(b []byte) (value uint64, signed bool, n int, ok bool) {
	if len(b) < 2 {
		return 0, false, 0, false
	}
	leaf := binary.LittleEndian.Uint16(b)
	if leaf < leafNumeric {
		return uint64(leaf), false, 2, true
	}
	need := map[uint16]int{leafChar: 1, leafShort: 2, leafUShort: 2, leafLong: 4, leafULong: 4, leafQuadword: 8, leafUQuadword: 8}[leaf]
	if need == 0 || len(b) < 2+need {
		return 0, false, 0, false
	}
	v := b[2:]
	switch leaf {
	case leafChar:
		return uint64(int64(int8(v[0]))), true, 3, true
	case leafShort:
		return uint64(int64(int16(binary.LittleEndian.Uint16(v)))), true, 4, true
	case leafUShort:
		return uint64(binary.LittleEndian.Uint16(v)), false, 4, true
	case leafLong:
		return uint64(int64(int32(binary.LittleEndian.Uint32(v)))), true, 6, true
	case leafULong:
		return uint64(binary.LittleEndian.Uint32(v)), false, 6, true
	case leafQuadword:
		return binary.LittleEndian.Uint64(v), true, 10, true
	}
	return binary.LittleEndian.Uint64(v), false, 10, true
}

func readName(b []byte) (string, int, bool) {
	end := bytes.IndexByte(b, 0)
	if end < 0 {
		return "", 0, false
	}
	return string(b[:end]), end + 1, true
}

type primitive struct {
	name  string
	width uint64
}

// Integers are named by width and signedness, so a name has one width in
// every table whatever the source's data model called the type.
var primitiveKinds = map[uint32]primitive{
	0x03: {"void", 0},
	0x08: {"int", 4},
	0x10: {"char", 1},
	0x20: {"unsigned char", 1},
	0x68: {"char", 1},
	0x69: {"unsigned char", 1},
	0x70: {"char", 1},
	0x71: {"wchar_t", 2},
	0x7a: {"unsigned short", 2},
	0x7b: {"unsigned int", 4},
	0x7c: {"unsigned char", 1},
	0x11: {"short", 2},
	0x21: {"unsigned short", 2},
	0x72: {"short", 2},
	0x73: {"unsigned short", 2},
	0x12: {"int", 4},
	0x22: {"unsigned int", 4},
	0x74: {"int", 4},
	0x75: {"unsigned int", 4},
	0x13: {"long long", 8},
	0x23: {"unsigned long long", 8},
	0x76: {"long long", 8},
	0x77: {"unsigned long long", 8},
	0x30: {"bool", 1},
	0x40: {"float", 4},
	0x45: {"float", 4},
	0x41: {"double", 8},
}

// Sizes of the kinds the table has no scalar for, so an array of them still
// gets its element count.
var unnamedKindWidths = map[uint32]uint64{
	0x14: 16, 0x24: 16, 0x78: 16, 0x79: 16,
	0x31: 2, 0x32: 4, 0x33: 8, 0x34: 16,
	0x42: 10, 0x43: 16, 0x44: 6, 0x46: 2,
	0x50: 8, 0x51: 16, 0x52: 20, 0x53: 32, 0x54: 12, 0x55: 8, 0x56: 4,
}

var simplePointerWidths = map[uint32]uint64{1: 2, 2: 4, 3: 4, 4: 4, 5: 6, 6: 8, 7: 16}

func simpleTypeRef(index uint32) symbols.TypeRef {
	kind, mode := index&0xff, (index>>8)&0xf
	named := symbols.TypeRef{Name: primitiveKinds[kind].name}
	if mode == 0 {
		return named
	}
	return symbols.TypeRef{IsPointer: true, Element: &named}
}

func simpleTypeWidth(index uint32) uint64 {
	kind, mode := index&0xff, (index>>8)&0xf
	if mode != 0 {
		return simplePointerWidths[mode]
	}
	if p, ok := primitiveKinds[kind]; ok {
		return p.width
	}
	return unnamedKindWidths[kind]
}

var declaredScalars = map[string]symbols.Scalar{
	"void":               {Name: "void", Kind: symbols.ScalarVoid},
	"bool":               {Name: "bool", Width: 1, Kind: symbols.ScalarBool},
	"char":               {Name: "char", Width: 1, Kind: symbols.ScalarChar, Signed: true},
	"unsigned char":      {Name: "unsigned char", Width: 1, Kind: symbols.ScalarChar},
	"wchar_t":            {Name: "wchar_t", Width: 2, Kind: symbols.ScalarInteger},
	"short":              {Name: "short", Width: 2, Kind: symbols.ScalarInteger, Signed: true},
	"unsigned short":     {Name: "unsigned short", Width: 2, Kind: symbols.ScalarInteger},
	"int":                {Name: "int", Width: 4, Kind: symbols.ScalarInteger, Signed: true},
	"unsigned int":       {Name: "unsigned int", Width: 4, Kind: symbols.ScalarInteger},
	"long":               {Name: "long", Width: 4, Kind: symbols.ScalarInteger, Signed: true},
	"unsigned long":      {Name: "unsigned long", Width: 4, Kind: symbols.ScalarInteger},
	"long long":          {Name: "long long", Width: 8, Kind: symbols.ScalarInteger, Signed: true},
	"unsigned long long": {Name: "unsigned long long", Width: 8, Kind: symbols.ScalarInteger},
	"float":              {Name: "float", Width: 4, Kind: symbols.ScalarFloat, Signed: true},
	"double":             {Name: "double", Width: 8, Kind: symbols.ScalarFloat, Signed: true},
}
