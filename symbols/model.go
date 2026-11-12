package symbols

import "github.com/aoiflux/libvapour/memory"

type TypeKind string

const (
	TypeKindStruct TypeKind = "struct"
	TypeKindEnum   TypeKind = "enum"
)

type Type struct {
	Name   string
	Kind   TypeKind
	Size   uint64
	Fields []Field
	Enum   []EnumValue
}

// One level of a type expression. Every level carries the innermost name, so
// a reader that only wants the named type need not walk Element.
type TypeRef struct {
	Name      string
	IsPointer bool
	// A count of 0 is also a trailing array of no elements, so IsArray marks
	// the level; a count above 0 marks it too, for references built in code.
	IsArray     bool
	ArrayLength uint64
	BitOffset   uint8
	BitLength   uint8
	Element     *TypeRef
}

type Field struct {
	Name   string
	Offset uint64
	Type   TypeRef
}

type StructType struct {
	Name   string
	Size   uint64
	Fields []Field
}

type EnumValue struct {
	Name  string
	Value int64
}

type EnumType struct {
	Name   string
	Values []EnumValue
	Size   uint64
}

type Symbol struct {
	Name string
	// The table's own address space: image-relative for Windows, link-time for
	// Linux. A session's wrapper moves it to the running image.
	Address uint64
	Type    string
}

type StructInstance struct {
	Type      StructType
	Offset    uint64
	Fields    map[string]uint64
	RawFields map[string][]byte
	Unsized   []string
}

type SymbolTable interface {
	Name() string
	PointerSize() uint8
	Struct(name string) (StructType, error)
	Field(typeName string, fieldName string) (Field, error)
	LookupSymbol(name string) (Symbol, error)
	ReadUint32(reader memory.MemoryReader, offset uint64) (uint32, error)
	ReadUint64(reader memory.MemoryReader, offset uint64) (uint64, error)
	ReadPointer(reader memory.MemoryReader, offset uint64) (uint64, error)
	ReadStruct(reader memory.MemoryReader, typeName string, offset uint64) (StructInstance, error)
}

type DeterministicLookup interface {
	LookupType(name string) (Type, error)
	OffsetOf(typeName string, fieldName string) (uint64, error)
	SizeOf(typeName string) (uint64, error)
	EnumValue(enumName string, valueName string) (int64, error)
}

type FieldSizer interface {
	FieldSize(typeName string, fieldName string) (uint64, error)
}

// Addresses are in LookupSymbol's space, so an address from the other space
// finds nothing rather than a wrong name.
type SymbolLocator interface {
	SymbolsAt(address uint64) []Symbol
}
