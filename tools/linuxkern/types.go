package linuxkern

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

var ErrNotInteger = errors.New("linuxkern: member is not an integer")

type Member struct {
	Offset uint64
	Field  symbols.Field
	Parent string
}

// S54 L1, T1-T3: the session's tables name members by C base type after
// typedefs (M1); the typedef names cover tables that keep them.
func CWidth(name string, pointerSize uint64) uint64 {
	switch strings.TrimSpace(name) {
	case "char", "signed char", "unsigned char", "_Bool", "bool",
		"u8", "s8", "__u8", "__s8":
		return 1
	case "short int", "short unsigned int", "short", "unsigned short", "signed short",
		"u16", "s16", "__u16", "__s16":
		return 2
	case "int", "unsigned int", "signed int", "unsigned",
		"u32", "s32", "__u32", "__s32":
		return 4
	case "long long int", "long long unsigned int", "long long", "unsigned long long",
		"u64", "s64", "__u64", "__s64":
		return 8
	case "long int", "long unsigned int", "long", "unsigned long",
		"size_t", "ssize_t", "uintptr_t", "ulong", "pointer":
		return pointerSize
	}
	return 0
}

// S54 L1, L2, T1, T2, T4: plain char is unsigned in every kernel built with
// -funsigned-char; enumerations are signed int (L1).
func CUnsigned(name string) bool {
	s := strings.TrimSpace(name)
	if strings.Contains(s, "unsigned") {
		return true
	}
	switch s {
	case "_Bool", "bool", "char", "u8", "u16", "u32", "u64", "__u8", "__u16", "__u32", "__u64",
		"size_t", "uintptr_t", "ulong", "phys_addr_t", "resource_size_t", "pointer":
		return true
	}
	return false
}

func SizeOf(sym symbols.SymbolTable, name string) (uint64, error) {
	if st, err := sym.Struct(name); err == nil && st.Size > 0 {
		return st.Size, nil
	}
	if det, ok := sym.(symbols.DeterministicLookup); ok {
		if n, err := det.SizeOf(name); err == nil && n > 0 {
			return n, nil
		}
	}
	if n := CWidth(name, uint64(sym.PointerSize())); n > 0 {
		return n, nil
	}
	return 0, fmt.Errorf("linuxkern: type %q: no size in the symbol table", name)
}

func HasType(sym symbols.SymbolTable, name string) bool {
	if _, err := sym.Struct(name); err == nil {
		return true
	}
	if det, ok := sym.(symbols.DeterministicLookup); ok {
		if _, err := det.LookupType(name); err == nil {
			return true
		}
	}
	return false
}

type Integer struct {
	symbols.IntField
	Signed bool
}

// S54 4.3. The table's own member width wins over the name: an enumeration
// declared __packed is one byte (M1).
func IntegerMember(sym symbols.SymbolTable, parent string, f symbols.Field, offset uint64) (Integer, error) {
	t := f.Type
	where := parent + "." + f.Name
	if t.IsArray || t.ArrayLength > 0 {
		return Integer{}, fmt.Errorf("%w: %s is an array", ErrNotInteger, where)
	}
	var width uint64
	switch {
	case t.IsPointer:
		width = uint64(sym.PointerSize())
	default:
		if sizer, ok := sym.(symbols.FieldSizer); ok {
			if n, err := sizer.FieldSize(parent, f.Name); err == nil {
				width = n
			}
		}
		if width == 0 {
			width = CWidth(t.Name, uint64(sym.PointerSize()))
		}
		if width == 0 && t.Name != "" {
			width, _ = SizeOf(sym, t.Name)
		}
	}
	if width == 0 || width > 8 {
		return Integer{}, fmt.Errorf("%w: %s is %d bytes wide", ErrNotInteger, where, width)
	}
	in := Integer{IntField: symbols.IntField{Offset: offset, Width: width}}
	if t.BitLength > 0 {
		in.BitOffset, in.BitLength = t.BitOffset, t.BitLength
		if uint64(t.BitOffset)+uint64(t.BitLength) > 8*width {
			return Integer{}, fmt.Errorf("%w: %s: bits %d to %d lie outside its %d-byte unit",
				ErrNotInteger, where, t.BitOffset, uint64(t.BitOffset)+uint64(t.BitLength)-1, width)
		}
		// S54 L3: a bitfield of a plain type never holds a negative value,
		// and the table cannot tell plain int from signed int.
		in.Signed = strings.Contains(t.Name, "signed") && !CUnsigned(t.Name)
		return in, nil
	}
	// A small structure such as atomic_t reads as its bytes; an aggregate has
	// no sign of its own.
	_, notAggregate := sym.Struct(t.Name)
	in.Signed = !t.IsPointer && t.Name != "" && !CUnsigned(t.Name) && notAggregate != nil
	return in, nil
}

func (in Integer) bits() uint {
	if in.BitLength > 0 {
		return uint(in.BitLength)
	}
	return uint(in.Width * 8)
}

func (in Integer) Value(raw uint64) int64 {
	n := in.bits()
	if !in.Signed || n >= 64 {
		return int64(raw)
	}
	return int64(raw<<(64-n)) >> (64 - n)
}

func (in Integer) ReadSigned(mem memory.MemoryReader, base uint64) (int64, error) {
	v, err := in.Read(mem, base)
	if err != nil {
		return 0, err
	}
	return in.Value(v), nil
}

func (k *Kernel) HasType(name string) bool { return HasType(k.Sym, name) }

func (k *Kernel) HasMember(typ, path string) bool {
	_, err := k.Member(typ, path)
	return err == nil
}

func (k *Kernel) TypeSize(name string) (uint64, error) { return SizeOf(k.Sym, name) }

func (k *Kernel) Member(typ, path string) (Member, error) {
	var m Member
	cur := typ
	names := strings.Split(path, ".")
	for i, name := range names {
		f, err := k.Sym.Field(cur, name)
		if err != nil {
			return Member{}, fmt.Errorf("linuxkern: member %s.%s: %w", typ, path, err)
		}
		m.Offset += f.Offset
		m.Field, m.Parent = f, cur
		if i == len(names)-1 {
			break
		}
		if f.Type.IsPointer || f.Type.IsArray || f.Type.ArrayLength > 0 || f.Type.Name == "" {
			return Member{}, fmt.Errorf("linuxkern: member %s.%s: %s.%s is not a structure the path can enter",
				typ, path, cur, name)
		}
		cur = f.Type.Name
	}
	return m, nil
}

func (k *Kernel) integer(typ, path string) (Integer, error) {
	m, err := k.Member(typ, path)
	if err != nil {
		return Integer{}, err
	}
	return IntegerMember(k.Sym, m.Parent, m.Field, m.Offset)
}

func (k *Kernel) Uint(addr uint64, typ, path string) (uint64, error) {
	in, err := k.integer(typ, path)
	if err != nil {
		return 0, err
	}
	return in.Read(k.Mem, addr)
}

func (k *Kernel) Int(addr uint64, typ, path string) (int64, error) {
	in, err := k.integer(typ, path)
	if err != nil {
		return 0, err
	}
	return in.ReadSigned(k.Mem, addr)
}

// S54 4.4: the kernel keeps some addresses in unsigned long members, such as
// mod_tree_root.addr_min.
func PointerMember(sym symbols.SymbolTable, parent string, f symbols.Field) error {
	if f.Type.IsPointer {
		return nil
	}
	in, err := IntegerMember(sym, parent, f, f.Offset)
	if err == nil && !in.Signed && in.BitLength == 0 && in.Width == uint64(sym.PointerSize()) {
		return nil
	}
	return fmt.Errorf("linuxkern: member %s.%s is not a pointer", parent, f.Name)
}

func (k *Kernel) Ptr(addr uint64, typ, path string) (uint64, error) {
	m, err := k.Member(typ, path)
	if err != nil {
		return 0, err
	}
	if err := PointerMember(k.Sym, m.Parent, m.Field); err != nil {
		return 0, err
	}
	return k.ReadPointer(addr + m.Offset)
}

func PointeeSize(sym symbols.SymbolTable, f symbols.Field) uint64 {
	if !f.Type.IsPointer {
		return 0
	}
	elem := symbols.TypeRef{Name: f.Type.Name}
	if f.Type.Element != nil {
		elem = *f.Type.Element
	}
	if elem.IsPointer {
		return uint64(sym.PointerSize())
	}
	if elem.Name == "" || elem.Name == "void" {
		return 0
	}
	n, err := SizeOf(sym, elem.Name)
	if err != nil {
		return 0
	}
	return n
}

func (k *Kernel) PointeeSize(m Member) uint64 { return PointeeSize(k.Sym, m.Field) }

func (k *Kernel) Readable(ptr, size uint64) bool { return Readable(k.Mem, ptr, size) }

func ElementSize(sym symbols.SymbolTable, f symbols.Field) (uint64, error) {
	if !f.Type.IsArray && f.Type.ArrayLength == 0 {
		return 0, fmt.Errorf("linuxkern: member %s is not an array", f.Name)
	}
	elem := symbols.TypeRef{Name: f.Type.Name}
	if f.Type.Element != nil {
		elem = *f.Type.Element
	}
	if elem.IsPointer {
		return uint64(sym.PointerSize()), nil
	}
	return SizeOf(sym, elem.Name)
}

func (k *Kernel) ElementSize(m Member) (uint64, error) { return ElementSize(k.Sym, m.Field) }
