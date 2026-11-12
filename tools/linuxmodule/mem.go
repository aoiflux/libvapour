package linuxmodule

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
)

func (m *Model) form(v uint64) uint64 {
	if m.r.Address == nil {
		return v
	}
	return m.r.Address(v)
}

func (m *Model) bytes(at, n uint64) ([]byte, bool) {
	n = max(n, 1)
	if at+n < at {
		return nil, false
	}
	b, err := m.r.Mem.ReadAt(at, n)
	if err != nil || uint64(len(b)) < n {
		return nil, false
	}
	return b[:n], true
}

func le(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func (m *Model) word(at uint64) (uint64, bool) {
	b, ok := m.bytes(at, m.width)
	if !ok {
		return 0, false
	}
	return le(b), true
}

func (m *Model) pointer(at uint64) (uint64, bool) {
	v, ok := m.word(at)
	return m.form(v), ok
}

func (m *Model) uintAt(at, width uint64) (uint64, bool) {
	b, ok := m.bytes(at, width)
	if !ok {
		return 0, false
	}
	return le(b), true
}

func (m *Model) uintField(base uint64, f symbols.IntField) (uint64, bool) {
	v, err := f.Read(m.r.Mem, base)
	return v, err == nil
}

// cstring reads up to limit bytes at at and stops at the first NUL. cut is
// true when no NUL came within the limit; ok is false when a byte before the
// NUL does not read.
func (m *Model) cstring(at, limit uint64) (s string, cut bool, ok bool) {
	if at == 0 {
		return "", false, false
	}
	var out []byte
	for uint64(len(out)) < limit {
		n := min(limit-uint64(len(out)), pageSize-at%pageSize)
		b, read := m.bytes(at, n)
		if !read {
			return string(out), false, false
		}
		if i := bytes.IndexByte(b, 0); i >= 0 {
			return string(append(out, b[:i]...)), false, true
		}
		out = append(out, b...)
		at += n
	}
	return string(out), true, true
}

const pageSize = 4096

func (m *Model) field(typ, name string) (symbols.Field, error) {
	f, err := m.r.Sym.Field(typ, name)
	if err != nil {
		return symbols.Field{}, fmt.Errorf("linuxmodule: %s.%s: %w: %w", typ, name, ErrUnsupported, err)
	}
	return f, nil
}

func (m *Model) offset(typ, name string) (uint64, error) {
	f, err := m.field(typ, name)
	return f.Offset, err
}

func (m *Model) has(typ, name string) bool {
	_, err := m.r.Sym.Field(typ, name)
	return err == nil
}

// path resolves typ.a.b... through embedded structures.
func (m *Model) path(typ string, names ...string) (uint64, error) {
	var at uint64
	cur := typ
	for i, n := range names {
		f, err := m.field(cur, n)
		if err != nil {
			return 0, err
		}
		at += f.Offset
		if i < len(names)-1 {
			if f.Type.IsPointer || f.Type.Name == "" {
				return 0, fmt.Errorf("linuxmodule: %s.%s does not embed a structure: %w", cur, n, ErrUnsupported)
			}
			cur = f.Type.Name
		}
	}
	return at, nil
}

func (m *Model) size(typ string) (uint64, error) {
	st, err := m.r.Sym.Struct(typ)
	if err != nil || st.Size == 0 {
		return 0, fmt.Errorf("linuxmodule: %s has no size in the symbol table: %w", typ, ErrUnsupported)
	}
	return st.Size, nil
}

// intField sizes a member from the table when it can. A table that gives no
// width falls back to the Linux LP64 or ILP32 widths here, because a table
// with no platform set gets no width from symbols at all.
func (m *Model) intField(typ, name string) (symbols.IntField, error) {
	f, err := m.field(typ, name)
	if err != nil {
		return symbols.IntField{}, err
	}
	out := symbols.IntField{Offset: f.Offset, BitOffset: f.Type.BitOffset, BitLength: f.Type.BitLength}
	if sizer, ok := m.r.Sym.(symbols.FieldSizer); ok {
		if w, err := sizer.FieldSize(typ, name); err == nil && w > 0 && w <= 8 {
			out.Width = w
		}
	}
	if out.Width == 0 {
		out.Width = m.baseWidth(f.Type)
	}
	if out.Width == 0 || out.Width > 8 {
		return symbols.IntField{}, fmt.Errorf("linuxmodule: %s.%s is not a readable integer: %w", typ, name, ErrUnsupported)
	}
	return out, nil
}

func (m *Model) baseWidth(t symbols.TypeRef) uint64 {
	if t.IsPointer {
		return m.width
	}
	switch strings.TrimSpace(t.Name) {
	case "char", "signed char", "unsigned char", "_Bool", "bool", "u8", "s8":
		return 1
	case "short int", "short unsigned int", "u16", "s16":
		return 2
	case "int", "unsigned int", "u32", "s32", "atomic_t":
		return 4
	case "long int", "long unsigned int":
		return m.width
	case "long long int", "long long unsigned int", "u64", "s64":
		return 8
	}
	if st, err := m.r.Sym.Struct(t.Name); err == nil && st.Size > 0 && st.Size <= 8 && len(st.Fields) == 0 {
		return st.Size
	}
	return 0
}

func (m *Model) symbol(name string) (uint64, bool) {
	s, err := m.r.Sym.LookupSymbol(name)
	if err != nil {
		return 0, false
	}
	return m.form(s.Address), true
}
