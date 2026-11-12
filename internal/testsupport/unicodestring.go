package testsupport

import (
	"strings"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/symbols"
)

// Paths past what a UNICODE_STRING's 16-bit Length can count (S79 D8), one
// ASCII and one with characters outside the Basic Latin block.
var (
	LongPath    = `C:\` + strings.Repeat(`dir\`, 5000)
	LongCJKName = `\Device\HarddiskVolume3\` + strings.Repeat("文档\\", 150)
)

const (
	UnicodeStringAt = uint64(0x1000)
	UnicodeTextAt   = uint64(0x2000)
)

// _UNICODE_STRING on x64 and _STRING32 (S79 T2).
const (
	unicodeLengthAt    = uint64(0)
	unicodeMaximumAt   = uint64(2)
	unicodeBufferAt    = uint64(8)
	unicodeBuffer32At  = uint64(4)
	unicodeStringBytes = uint64(0x10)
)

func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		out[2*i], out[2*i+1] = byte(u), byte(u>>8)
	}
	return out
}

func NewUnicodeStringMemory(text string) *PagedMemory {
	return unicodeStringMemory(text, unicodeBufferAt, 8)
}

func NewUnicodeString32Memory(text string) *PagedMemory {
	return unicodeStringMemory(text, unicodeBuffer32At, 4)
}

// The counts are 16 bits, so text longer than 65,535 bytes is stored whole
// with counts that wrap, as a damaged or crafted string would carry.
func unicodeStringMemory(text string, bufferAt uint64, pointerSize int) *PagedMemory {
	raw := utf16LE(text)
	p := NewPagedMemory(int(UnicodeTextAt) + len(raw) + int(pageSize))
	p.WriteAt(UnicodeTextAt, raw)
	p.WriteU16(UnicodeStringAt+unicodeLengthAt, uint16(len(raw)))
	p.WriteU16(UnicodeStringAt+unicodeMaximumAt, uint16(len(raw)))
	if pointerSize == 4 {
		p.WriteU32(UnicodeStringAt+bufferAt, uint32(UnicodeTextAt))
	} else {
		p.WriteU64(UnicodeStringAt+bufferAt, UnicodeTextAt)
	}
	return p
}

func UnicodeStringSymbols() *symbols.Table {
	t := symbols.NewTable("unicode-string", 8)
	t.AddStruct(unicodeStringType())
	return t
}

func unicodeStringType() symbols.StructType {
	return symbols.StructType{Name: "_UNICODE_STRING", Size: unicodeStringBytes, Fields: []symbols.Field{
		{Name: "Length", Offset: unicodeLengthAt, Type: symbols.TypeRef{Name: "unsigned short"}},
		{Name: "MaximumLength", Offset: unicodeMaximumAt, Type: symbols.TypeRef{Name: "unsigned short"}},
		{Name: "Buffer", Offset: unicodeBufferAt, Type: symbols.TypeRef{Name: "wchar_t", IsPointer: true}},
	}}
}
