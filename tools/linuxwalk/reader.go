package linuxwalk

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

var ErrUnsupported = errors.New("linuxwalk: kernel layout not recognised")

type Reader struct {
	Mem     memory.MemoryReader
	Sym     symbols.SymbolTable
	Address func(uint64) uint64
	Limits  limits.Limits
}

func (r Reader) ready() error {
	if r.Mem == nil || r.Sym == nil {
		return errors.New("linuxwalk: reader: no memory or no symbol table")
	}
	if w := r.Sym.PointerSize(); w != 4 && w != 8 {
		return fmt.Errorf("linuxwalk: symbol table: %d-byte pointers: %w", w, ErrUnsupported)
	}
	return nil
}

func (r Reader) form(v uint64) uint64 {
	if r.Address == nil {
		return v
	}
	return r.Address(v)
}

func (r Reader) width() uint64 { return uint64(r.Sym.PointerSize()) }

func (r Reader) bounds() limits.Limits { return r.Limits.Effective() }

func (r Reader) read(at, n uint64) ([]byte, bool) {
	n = max(n, 1)
	if at+n < at {
		return nil, false
	}
	b, err := r.Mem.ReadAt(at, n)
	if err != nil || uint64(len(b)) < n {
		return nil, false
	}
	return b, true
}

// S01 X1: x86 stores words little-endian.
func (r Reader) word(b []byte, at uint64) uint64 {
	if r.width() == 4 {
		return uint64(binary.LittleEndian.Uint32(b[at:]))
	}
	return binary.LittleEndian.Uint64(b[at:])
}

func (r Reader) rawPointer(at uint64) (uint64, bool) {
	b, ok := r.read(at, r.width())
	if !ok {
		return 0, false
	}
	return r.word(b, 0), true
}

func (r Reader) pointer(at uint64) (uint64, bool) {
	v, ok := r.rawPointer(at)
	return r.form(v), ok
}

func (r Reader) member(typ, name string) (symbols.Field, error) {
	f, err := r.Sym.Field(typ, name)
	if err != nil {
		return symbols.Field{}, fmt.Errorf("linuxwalk: %s.%s: %w: %w", typ, name, ErrUnsupported, err)
	}
	return f, nil
}

func (r Reader) offset(typ, name string) (uint64, error) {
	f, err := r.member(typ, name)
	return f.Offset, err
}

func (r Reader) has(typ, name string) bool {
	_, err := r.Sym.Field(typ, name)
	return err == nil
}

func (r Reader) intField(typ, name string) (symbols.IntField, error) {
	f, err := symbols.ResolveIntField(r.Sym, typ, name)
	if err != nil {
		return symbols.IntField{}, fmt.Errorf("linuxwalk: %s.%s: %w: %w", typ, name, ErrUnsupported, err)
	}
	return f, nil
}

func (r Reader) size(typ string) (uint64, error) {
	st, err := r.Sym.Struct(typ)
	if err != nil || st.Size == 0 {
		return 0, fmt.Errorf("linuxwalk: %s: no size in the symbol table: %w", typ, ErrUnsupported)
	}
	return st.Size, nil
}

func signed(v, width uint64) int64 {
	if width == 0 || width >= 8 {
		return int64(v)
	}
	shift := 64 - 8*width
	return int64(v<<shift) >> shift
}
