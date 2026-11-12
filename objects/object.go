package objects

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

var ErrNullPointer = errors.New("objects: null pointer")

var errNoSource = errors.New("objects: no reader or no symbol table")

type Object struct {
	Reader   memory.MemoryReader
	Symbols  symbols.SymbolTable
	TypeName string
	Offset   uint64
}

func New(reader memory.MemoryReader, table symbols.SymbolTable, typeName string, offset uint64) Object {
	return Object{Reader: reader, Symbols: table, TypeName: typeName, Offset: offset}
}

type member struct {
	field   symbols.Field
	address uint64
	label   string
}

func (o Object) lookup(name string) (member, error) {
	label := o.TypeName + "." + name
	if o.Reader == nil || o.Symbols == nil {
		return member{}, fmt.Errorf("objects: %s: %w", label, errNoSource)
	}
	f, err := o.Symbols.Field(o.TypeName, name)
	if err != nil {
		return member{}, fmt.Errorf("objects: %s: %w", label, err)
	}
	address := o.Offset + f.Offset
	if address < o.Offset {
		return member{}, fmt.Errorf("objects: %s: offset 0x%x past the end of the address space", label, f.Offset)
	}
	return member{field: f, address: address, label: label}, nil
}

func (m member) failed(what string, err error) error {
	if err == nil {
		return fmt.Errorf("objects: %s at 0x%x: %s", m.label, m.address, what)
	}
	return fmt.Errorf("objects: %s at 0x%x: %s: %w", m.label, m.address, what, err)
}

func plain(t symbols.TypeRef) bool {
	return !t.IsPointer && !t.IsArray && t.ArrayLength == 0 && t.BitLength == 0
}

func (o Object) isRecord(t symbols.TypeRef) bool {
	if !plain(t) {
		return false
	}
	_, err := o.Symbols.Struct(t.Name)
	return err == nil
}

func (o Object) width(name string) uint64 {
	if sizer, ok := o.Symbols.(symbols.FieldSizer); ok {
		if w, err := sizer.FieldSize(o.TypeName, name); err == nil {
			return w
		}
	}
	return 0
}

// A member is read at its own width, never wider: the bytes past it belong to
// the next member, and a value built from them reads as data.
func (o Object) integer(name string, most uint64) (uint64, error) {
	m, err := o.lookup(name)
	if err != nil {
		return 0, err
	}
	switch t := m.field.Type; {
	case t.IsArray || t.ArrayLength > 0:
		return 0, m.failed("an array, not an integer; read it with Bytes", nil)
	case o.isRecord(t):
		return 0, m.failed("a record, not an integer; reach it with Struct", nil)
	}
	f, err := symbols.ResolveIntField(o.Symbols, o.TypeName, name)
	if err != nil {
		return 0, m.failed("width unknown", err)
	}
	if f.Width > most {
		return 0, m.failed(fmt.Sprintf("%d bytes wide, more than %d", f.Width, most), nil)
	}
	v, err := f.Read(o.Reader, o.Offset)
	if err != nil {
		return 0, m.failed("unreadable", err)
	}
	return v, nil
}

func (o Object) Uint32(fieldName string) (uint32, error) {
	v, err := o.integer(fieldName, 4)
	return uint32(v), err
}

func (o Object) Uint64(fieldName string) (uint64, error) {
	return o.integer(fieldName, 8)
}

// A nonzero pointer is not checked as mapped: the first read through it says.
func (o Object) Pointer(fieldName string) (Object, error) {
	m, err := o.lookup(fieldName)
	if err != nil {
		return Object{}, err
	}
	t := m.field.Type
	if !t.IsPointer {
		return Object{}, m.failed("not a pointer", nil)
	}
	if t.Element != nil && !plain(*t.Element) || t.Name == "" {
		return Object{}, m.failed("points to no named type", nil)
	}
	target, err := o.Symbols.ReadPointer(o.Reader, m.address)
	if err != nil {
		return Object{}, m.failed("unreadable", err)
	}
	if target == 0 {
		return Object{}, m.failed("reads 0", ErrNullPointer)
	}
	return Object{Reader: o.Reader, Symbols: o.Symbols, TypeName: t.Name, Offset: target}, nil
}

func (o Object) Struct(fieldName string) (Object, error) {
	m, err := o.lookup(fieldName)
	if err != nil {
		return Object{}, err
	}
	t := m.field.Type
	switch {
	case t.IsPointer:
		return Object{}, m.failed("a pointer; follow it with Pointer", nil)
	case !o.isRecord(t):
		return Object{}, m.failed("not a record held in place", nil)
	}
	return Object{Reader: o.Reader, Symbols: o.Symbols, TypeName: t.Name, Offset: m.address}, nil
}

// A member of width 0 is a trailing array of no declared length, whose bytes
// run on past the record, so only a member with a width bounds the read.
func (o Object) Bytes(fieldName string, length uint64) ([]byte, error) {
	m, err := o.lookup(fieldName)
	if err != nil {
		return nil, err
	}
	if w := o.width(fieldName); w > 0 && length > w {
		return nil, m.failed(fmt.Sprintf("%d bytes asked of a %d-byte member", length, w), nil)
	}
	if length == 0 {
		return []byte{}, nil
	}
	if m.address+length < m.address {
		return nil, m.failed("read past the end of the address space", nil)
	}
	b, err := o.Reader.ReadAt(m.address, length)
	if err != nil {
		return nil, m.failed("unreadable", err)
	}
	if uint64(len(b)) != length {
		return nil, m.failed(fmt.Sprintf("%d of %d bytes read", len(b), length), nil)
	}
	return b, nil
}
