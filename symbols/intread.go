package symbols

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
)

// A member read at its declared width only: a wider read takes in the next
// member and gives a wrong value that looks like data. A bitfield shares its
// storage unit with its neighbours, so its bits are cut out of the unit.
type IntField struct {
	Offset    uint64
	Width     uint64
	BitOffset uint8
	BitLength uint8
}

func ResolveIntField(table SymbolTable, typeName string, fieldName string) (IntField, error) {
	if table == nil {
		return IntField{}, fmt.Errorf("symbols: %s.%s: no symbol table", typeName, fieldName)
	}
	f, err := table.Field(typeName, fieldName)
	if err != nil {
		return IntField{}, fmt.Errorf("symbols: %s.%s: %w", typeName, fieldName, err)
	}
	out := IntField{Offset: f.Offset, BitOffset: f.Type.BitOffset, BitLength: f.Type.BitLength}
	if sizer, ok := table.(FieldSizer); ok {
		w, err := sizer.FieldSize(typeName, fieldName)
		if errors.Is(err, ErrPlatformUnknown) {
			return IntField{}, fmt.Errorf("symbols: %s.%s: %w", typeName, fieldName, err)
		}
		if err == nil {
			out.Width = w
		}
	}
	if out.Width == 0 {
		platform := PlatformUnknown
		if p, ok := table.(interface{ Platform() Platform }); ok {
			platform = p.Platform()
		}
		ptr := table.PointerSize()
		w, err := exprWidth(f.Type, uint64(ptr), func(name string) (uint64, error) { return ScalarWidth(platform, name, ptr) })
		if err != nil {
			return IntField{}, fmt.Errorf("symbols: %s.%s: %w", typeName, fieldName, err)
		}
		out.Width = w
	}
	if out.Width == 0 || out.Width > 8 {
		return IntField{}, fmt.Errorf("symbols: %s.%s is %d bytes wide, not a readable integer", typeName, fieldName, out.Width)
	}
	return out, nil
}

func (f IntField) Read(reader memory.MemoryReader, structAddr uint64) (uint64, error) {
	if f.Width == 0 || f.Width > 8 {
		return 0, fmt.Errorf("symbols: member at 0x%x: width %d is not a readable integer", structAddr+f.Offset, f.Width)
	}
	raw, err := readExactly(reader, structAddr+f.Offset, f.Width)
	if err != nil {
		return 0, err
	}
	return bitsOf(littleEndian(raw), f.BitOffset, f.BitLength), nil
}

func (f IntField) Decode(rec []byte) (uint64, error) {
	if f.Width == 0 || f.Width > 8 {
		return 0, fmt.Errorf("symbols: member at +0x%x: width %d is not a readable integer", f.Offset, f.Width)
	}
	if f.Offset > uint64(len(rec)) || f.Width > uint64(len(rec))-f.Offset {
		return 0, fmt.Errorf("symbols: member at +0x%x: %d bytes end past the %d-byte record", f.Offset, f.Width, len(rec))
	}
	return bitsOf(littleEndian(rec[f.Offset:f.Offset+f.Width]), f.BitOffset, f.BitLength), nil
}

// A character array that fills its member has no NUL, and the bytes after it
// belong to the next member (_EPROCESS.ImageFileName is followed by
// PriorityClass), so the read stops at the array's end.
type CharArrayField struct {
	Offset   uint64
	Length   uint64
	Declared bool
}

func ResolveCharArray(table SymbolTable, structName, fieldName string, fallback uint64) (CharArrayField, error) {
	if table == nil {
		return CharArrayField{}, fmt.Errorf("symbols: %s.%s: no symbol table", structName, fieldName)
	}
	f, err := table.Field(structName, fieldName)
	if err != nil {
		return CharArrayField{}, fmt.Errorf("symbols: %s.%s: %w", structName, fieldName, err)
	}
	out := CharArrayField{Offset: f.Offset}
	switch {
	case f.Type.isArray():
		out.Length, out.Declared = f.Type.ArrayLength, true
	case fallback > 0:
		out.Length = fallback
	default:
		return CharArrayField{}, fmt.Errorf("symbols: %s.%s: the table gives no array length and there is no fallback",
			structName, fieldName)
	}
	return out, nil
}

func (f CharArrayField) Read(mem memory.MemoryReader, base uint64) (string, error) {
	if f.Length == 0 {
		return "", fmt.Errorf("symbols: char array at 0x%x: length 0", base+f.Offset)
	}
	raw, err := readExactly(mem, base+f.Offset, f.Length)
	if err != nil {
		return "", fmt.Errorf("symbols: char array at 0x%x: %w", base+f.Offset, err)
	}
	for i, b := range raw {
		if b == 0 {
			return string(raw[:i]), nil
		}
	}
	return string(raw), nil
}
