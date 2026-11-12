package symbols

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/memory"
)

// Lookups are safe from many goroutines at once. AddStruct, AddEnum and
// AddSymbol are not safe while the table is read.
type Table struct {
	name        string
	pointerSize uint8
	pdb         PDBBuild
	hasPDB      bool
	banner      []byte
	platform    Platform

	// Nil when the table declares no scalars: a type's width then follows from
	// its name. Declared, they are the only widths, because a name alone does
	// not fix one (long is 4 bytes on Windows and 8 on Linux).
	scalars map[string]Scalar

	structs    map[string]StructType
	enums      map[string]EnumType
	unreadable map[string]UnusableTypeError
	symbols    map[string]Symbol
	symbolRefs map[string]TypeRef

	byAddress addressIndex
}

func (t *Table) Name() string { return t.name }

func (t *Table) PointerSize() uint8 { return t.pointerSize }

// A table for another build answers every name, with the wrong layout, so a
// caller checks this identity against the image.
func (t *Table) WindowsPDB() (PDBBuild, bool) { return t.pdb, t.hasPDB }

func (t *Table) LinuxBanner() ([]byte, bool) { return t.banner, t.banner != nil }

func (t *Table) Platform() Platform { return t.platform }

func (t *Table) Struct(name string) (StructType, error) {
	if err, ok := t.unreadable[name]; ok {
		return StructType{}, err
	}
	st, ok := t.structs[name]
	if !ok {
		return StructType{}, UnknownTypeError{TypeName: name}
	}
	return st, nil
}

func (t *Table) Field(typeName string, fieldName string) (Field, error) {
	st, err := t.Struct(typeName)
	if err != nil {
		return Field{}, err
	}
	for _, f := range st.Fields {
		if f.Name == fieldName {
			return f, nil
		}
	}
	return Field{}, UnknownFieldError{TypeName: typeName, FieldName: fieldName}
}

func (t *Table) OffsetOf(typeName string, fieldName string) (uint64, error) {
	f, err := t.Field(typeName, fieldName)
	if err != nil {
		return 0, err
	}
	return f.Offset, nil
}

func (t *Table) FieldSize(typeName string, fieldName string) (uint64, error) {
	f, err := t.Field(typeName, fieldName)
	if err != nil {
		return 0, err
	}
	return t.width(f.Type)
}

// A record wins over an enumeration of the same name, as a lookup by that
// name in the table format does.
func (t *Table) LookupType(name string) (Type, error) {
	if err, ok := t.unreadable[name]; ok {
		return Type{}, err
	}
	if st, ok := t.structs[name]; ok {
		return Type{Name: name, Kind: TypeKindStruct, Size: st.Size, Fields: st.Fields}, nil
	}
	if e, ok := t.enums[name]; ok {
		return Type{Name: name, Kind: TypeKindEnum, Size: enumWidth(e), Enum: e.Values}, nil
	}
	return Type{}, UnknownTypeError{TypeName: name}
}

// The name may also be a type expression, such as a symbol's type.
func (t *Table) SizeOf(typeName string) (uint64, error) {
	if err, ok := t.unreadable[typeName]; ok {
		return 0, err
	}
	if st, ok := t.structs[typeName]; ok {
		if st.Size == 0 {
			return 0, UnknownTypeError{TypeName: typeName}
		}
		return st.Size, nil
	}
	if e, ok := t.enums[typeName]; ok {
		return enumWidth(e), nil
	}
	var w uint64
	var err error
	if typeName != "" && escapedFirst(typeName[0]) {
		if ref, perr := parseTypeExpression(typeName); perr == nil {
			w, err = t.width(ref)
		}
	} else {
		w, err = t.namedWidth(typeName)
	}
	if err != nil {
		return 0, err
	}
	if w == 0 {
		return 0, UnknownTypeError{TypeName: typeName}
	}
	return w, nil
}

func (t *Table) EnumValue(enumName string, valueName string) (int64, error) {
	e, ok := t.enums[enumName]
	if !ok {
		return 0, UnknownTypeError{TypeName: enumName}
	}
	for _, v := range e.Values {
		if v.Name == valueName {
			return v.Value, nil
		}
	}
	return 0, UnknownFieldError{TypeName: enumName, FieldName: valueName}
}

func (t *Table) LookupSymbol(name string) (Symbol, error) {
	s, ok := t.symbols[name]
	if !ok {
		return Symbol{}, fmt.Errorf("symbols: no symbol %q", name)
	}
	return s, nil
}

func (t *Table) SymbolTypeRef(name string) (TypeRef, error) {
	if _, ok := t.symbols[name]; !ok {
		return TypeRef{}, fmt.Errorf("symbols: no symbol %q", name)
	}
	ref, ok := t.symbolRefs[name]
	if !ok {
		return TypeRef{}, fmt.Errorf("symbols: symbol %q has no type", name)
	}
	return ref, nil
}

func (t *Table) SymbolNames() []string {
	names := make([]string, 0, len(t.symbols))
	for name := range t.symbols {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (t *Table) TableSymbols() []Symbol {
	out := make([]Symbol, 0, len(t.symbols))
	for _, s := range t.symbols {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (t *Table) width(ref TypeRef) (uint64, error) {
	return exprWidth(ref, uint64(t.pointerSize), t.namedWidth)
}

func (t *Table) namedWidth(name string) (uint64, error) {
	if st, ok := t.structs[name]; ok {
		return st.Size, nil
	}
	if e, ok := t.enums[name]; ok {
		return enumWidth(e), nil
	}
	if t.scalars != nil {
		return t.scalars[name].Width, nil
	}
	return ScalarWidth(t.platform, name, t.pointerSize)
}

// A pointer member holds an address whatever it points to. A record held by
// value, a float and a big-endian scalar are not little-endian integers.
func (t *Table) holdsInteger(ref TypeRef) bool {
	switch op, _ := ref.operators(); op {
	case opPointer, opBitfield:
		return true
	case opArray:
		return false
	}
	if _, ok := t.structs[ref.Name]; ok {
		return false
	}
	s, ok := t.scalars[ref.Name]
	return !ok || s.Kind != ScalarFloat && !s.BigEndian
}

func (t *Table) ReadUint32(reader memory.MemoryReader, offset uint64) (uint32, error) {
	raw, err := readExactly(reader, offset, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(raw), nil
}

func (t *Table) ReadUint64(reader memory.MemoryReader, offset uint64) (uint64, error) {
	raw, err := readExactly(reader, offset, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(raw), nil
}

func (t *Table) ReadPointer(reader memory.MemoryReader, offset uint64) (uint64, error) {
	if t.pointerSize == 4 {
		v, err := t.ReadUint32(reader, offset)
		return uint64(v), err
	}
	return t.ReadUint64(reader, offset)
}

func readExactly(reader memory.MemoryReader, at, n uint64) ([]byte, error) {
	raw, err := reader.ReadAt(at, n)
	if err != nil {
		return nil, err
	}
	if uint64(len(raw)) < n {
		return nil, fmt.Errorf("symbols: read of %d bytes at 0x%x gave %d", n, at, len(raw))
	}
	return raw[:n], nil
}

// A member whose width is unknown is listed in Unsized rather than read at a
// guessed width, and rather than left out, which would look like a member the
// record does not have.
func (t *Table) ReadStruct(reader memory.MemoryReader, typeName string, offset uint64) (StructInstance, error) {
	st, err := t.Struct(typeName)
	if err != nil {
		return StructInstance{}, err
	}
	out := StructInstance{Type: st, Offset: offset, Fields: map[string]uint64{}, RawFields: map[string][]byte{}}
	for _, f := range st.Fields {
		if t.noElements(f.Type) {
			out.RawFields[f.Name] = []byte{}
			continue
		}
		w, _ := t.width(f.Type)
		if w == 0 {
			out.Unsized = append(out.Unsized, f.Name)
			continue
		}
		raw, err := readExactly(reader, offset+f.Offset, w)
		if err != nil {
			return StructInstance{}, err
		}
		if v, ok := t.integer(f.Type, raw); ok {
			out.Fields[f.Name] = v
			continue
		}
		out.RawFields[f.Name] = raw
	}
	sort.Strings(out.Unsized)
	return out, nil
}

// A trailing array of no elements is read as no bytes only when its element
// has a width: a converter that cannot count an array writes 0 too, and that
// member stays unsized.
func (t *Table) noElements(ref TypeRef) bool {
	op, _ := ref.operators()
	if op != opArray || ref.ArrayLength != 0 {
		return false
	}
	w, _ := t.width(ref.inner())
	return w > 0
}

// A value holds 64 bits; a bitfield reaching past bit 64 stays raw rather
// than reading as a wrong number.
func (t *Table) integer(ref TypeRef, raw []byte) (uint64, bool) {
	if !t.holdsInteger(ref) {
		return 0, false
	}
	if ref.BitLength > 0 {
		if int(ref.BitOffset)+int(ref.BitLength) > 64 {
			return 0, false
		}
		return bitsOf(littleEndian(raw[:min(len(raw), 8)]), ref.BitOffset, ref.BitLength), true
	}
	if len(raw) > 8 {
		return 0, false
	}
	return littleEndian(raw), true
}

type PDBBuild struct {
	Database string
	GUID     string
	Age      uint32
}

func (b PDBBuild) String() string {
	id := fmt.Sprintf("%s-%d", b.GUID, b.Age)
	if b.Database == "" {
		return id
	}
	return b.Database + "/" + id
}

func (b PDBBuild) check() error {
	if len(b.GUID) != 32 || strings.ContainsFunc(b.GUID, notHex) {
		return fmt.Errorf("symbols: PDB GUID %q is not 32 hex digits", b.GUID)
	}
	return nil
}

func notHex(r rune) bool {
	return !('0' <= r && r <= '9' || 'a' <= r && r <= 'f' || 'A' <= r && r <= 'F')
}
