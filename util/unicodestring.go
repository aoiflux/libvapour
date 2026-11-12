package util

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

// Length is a USHORT, so no string is longer. The value is odd: a Length of
// 0xFFFF is read whole and its unpaired last byte shows as U+FFFD.
const MaxUnicodeStringBytes = uint64(0xFFFF)

type UnicodeStringLayout struct {
	LengthOffset        uint64
	MaximumLengthOffset uint64
	BufferOffset        uint64
	Size                uint64
}

type UnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uint64
	Value         string
}

func (u UnicodeString) Chars() int { return int(u.Length) / 2 }

// The buffer's capacity in UTF-16 units, less the unit a terminating NUL takes.
func (u UnicodeString) MaxChars() int {
	if u.MaximumLength < 2 {
		return 0
	}
	return int(u.MaximumLength)/2 - 1
}

func (u UnicodeString) Text() string { return CountedText(u.Value) }

// U+2400 SYMBOL FOR NULL: no Windows or Linux name holds it, while a visible
// "\0" could be a real path component.
const VisibleNUL = "␀"

// NULs at the end of a counted string are its terminator. A NUL inside it is
// data, such as an argument separator or a name the Win32 API cannot reach, so
// it is shown, not cut at.
func CountedText(s string) string {
	return strings.ReplaceAll(strings.TrimRight(s, "\x00"), "\x00", VisibleNUL)
}

func DecodeCountedUTF16LE(b []byte) string { return CountedText(DecodeUTF16LE(b)) }

// The structure is two USHORTs and a pointer, the pointer aligned to its size.
func abiUnicodeStringLayout(pointerSize uint64) UnicodeStringLayout {
	return UnicodeStringLayout{LengthOffset: 0, MaximumLengthOffset: 2, BufferOffset: pointerSize, Size: 2 * pointerSize}
}

func ResolveUnicodeStringLayout(table symbols.SymbolTable) UnicodeStringLayout {
	if table == nil {
		return abiUnicodeStringLayout(8)
	}
	pointer := uint64(8)
	if table.PointerSize() == 4 {
		pointer = 4
	}
	layout := abiUnicodeStringLayout(pointer)
	for _, m := range []struct {
		name string
		at   *uint64
	}{
		{"Length", &layout.LengthOffset},
		{"MaximumLength", &layout.MaximumLengthOffset},
		{"Buffer", &layout.BufferOffset},
	} {
		if f, err := table.Field("_UNICODE_STRING", m.name); err == nil {
			*m.at = f.Offset
		}
	}
	if st, err := table.Struct("_UNICODE_STRING"); err == nil && st.Size != 0 {
		layout.Size = st.Size
	}
	return layout
}

// Buffer is the last member, so its width is what the structure has left.
func (l UnicodeStringLayout) bufferWidth() uint64 {
	if l.Size > l.BufferOffset && l.Size-l.BufferOffset == 4 {
		return 4
	}
	if l.Size == 0 && l.BufferOffset == 4 {
		return 4
	}
	return 8
}

func (l UnicodeStringLayout) headerBytes() uint64 {
	return max(l.LengthOffset+2, l.MaximumLengthOffset+2, l.BufferOffset+l.bufferWidth())
}

// reader must be the one for the structure's own address space: a process's
// strings read through the kernel's page tables give another process's bytes.
// maxBytes caps the text read; 0 means the USHORT maximum.
func ReadUnicodeString(reader memory.MemoryReader, addr uint64, layout UnicodeStringLayout, maxBytes uint64) (UnicodeString, error) {
	if reader == nil {
		return UnicodeString{}, fmt.Errorf("util: _UNICODE_STRING at 0x%x: no reader", addr)
	}
	if maxBytes == 0 || maxBytes > MaxUnicodeStringBytes {
		maxBytes = MaxUnicodeStringBytes
	}
	// Only the members are read: the padding after them may sit on a page
	// that is not resident.
	n := layout.headerBytes()
	header, err := reader.ReadAt(addr, n)
	if err != nil {
		return UnicodeString{}, fmt.Errorf("util: _UNICODE_STRING at 0x%x: %w", addr, err)
	}
	if uint64(len(header)) < n {
		return UnicodeString{}, fmt.Errorf("util: _UNICODE_STRING at 0x%x: %d of %d bytes read", addr, len(header), n)
	}
	s := UnicodeString{
		Length:        binary.LittleEndian.Uint16(header[layout.LengthOffset:]),
		MaximumLength: binary.LittleEndian.Uint16(header[layout.MaximumLengthOffset:]),
	}
	if layout.bufferWidth() == 4 {
		s.Buffer = uint64(binary.LittleEndian.Uint32(header[layout.BufferOffset:]))
	} else {
		s.Buffer = binary.LittleEndian.Uint64(header[layout.BufferOffset:])
	}
	if s.Length == 0 {
		return s, nil
	}
	if s.Buffer == 0 {
		return s, fmt.Errorf("util: _UNICODE_STRING at 0x%x: length %d with a null buffer", addr, s.Length)
	}
	// A string longer than the cap is cut, not refused: its start still names
	// the object.
	raw, err := reader.ReadAt(s.Buffer, min(uint64(s.Length), maxBytes))
	if err != nil {
		return s, fmt.Errorf("util: _UNICODE_STRING buffer at 0x%x: %w", s.Buffer, err)
	}
	s.Value = DecodeUTF16LE(raw)
	return s, nil
}

// A NUL inside a counted string is data and is kept.
func DecodeUTF16LE(b []byte) string { return decodeUTF16Units(b, false) }

func DecodeUTF16LEZ(b []byte) string { return decodeUTF16Units(b, true) }

const replacementUnit = 0xFFFD

// An unpaired surrogate is ill-formed and becomes U+FFFD (utf16.Decode does
// this). A final odd byte is part of a code unit, so it is one more U+FFFD; if
// the unit before it is a high surrogate, the two are one cut-short character
// and share one U+FFFD.
func decodeUTF16Units(b []byte, stopAtNUL bool) string {
	units := make([]uint16, 0, (len(b)+1)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if stopAtNUL && u == 0 {
			return string(utf16.Decode(units))
		}
		units = append(units, u)
	}
	if len(b)%2 == 1 {
		if k := len(units); k > 0 && utf16.IsSurrogate(rune(units[k-1])) && units[k-1] < 0xDC00 {
			units[k-1] = replacementUnit
		} else {
			units = append(units, replacementUnit)
		}
	}
	return string(utf16.Decode(units))
}
