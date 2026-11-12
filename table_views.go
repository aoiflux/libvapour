package libvapour

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

var errNoTypeLookup = errors.New("libvapour: symbol table gives no type lookups")

// A table states addresses in its own space (S76 4.4); the running kernel sits
// shift bytes further on. Only addresses that moves accepts are in the moving
// image, so constants and stored pointers keep their value.
type movedTable struct {
	inner symbols.SymbolTable
	shift uint64
	moves func(address uint64) bool
}

func (t movedTable) Name() string       { return t.inner.Name() }
func (t movedTable) PointerSize() uint8 { return t.inner.PointerSize() }

func (t movedTable) Struct(name string) (symbols.StructType, error) { return t.inner.Struct(name) }

func (t movedTable) Field(typeName, fieldName string) (symbols.Field, error) {
	return t.inner.Field(typeName, fieldName)
}

func (t movedTable) LookupSymbol(name string) (symbols.Symbol, error) {
	s, err := t.inner.LookupSymbol(name)
	if err == nil && t.moves(s.Address) {
		s.Address += t.shift
	}
	return s, err
}

func (t movedTable) ReadUint32(r memory.MemoryReader, at uint64) (uint32, error) {
	return t.inner.ReadUint32(r, at)
}

func (t movedTable) ReadUint64(r memory.MemoryReader, at uint64) (uint64, error) {
	return t.inner.ReadUint64(r, at)
}

func (t movedTable) ReadPointer(r memory.MemoryReader, at uint64) (uint64, error) {
	return t.inner.ReadPointer(r, at)
}

func (t movedTable) ReadStruct(r memory.MemoryReader, typeName string, at uint64) (symbols.StructInstance, error) {
	return t.inner.ReadStruct(r, typeName, at)
}

// An address names a moved symbol at address-shift and a fixed one at the
// address itself; each half keeps only its own kind, so the answer matches
// what LookupSymbol gives for the same names, wrap-around included.
func (t movedTable) SymbolsAt(address uint64) []symbols.Symbol {
	locator, ok := t.inner.(symbols.SymbolLocator)
	if !ok {
		return nil
	}
	var out []symbols.Symbol
	for _, s := range locator.SymbolsAt(address - t.shift) {
		if t.moves(s.Address) {
			s.Address += t.shift
			out = append(out, s)
		}
	}
	for _, s := range locator.SymbolsAt(address) {
		if !t.moves(s.Address) {
			out = append(out, s)
		}
	}
	return out
}

func (t movedTable) FieldSize(typeName, fieldName string) (uint64, error) {
	return memberSize(t.inner, typeName, fieldName)
}

func (t movedTable) LookupType(name string) (symbols.Type, error) {
	l, err := typeLookup(t.inner)
	if err != nil {
		return symbols.Type{}, err
	}
	return l.LookupType(name)
}

func (t movedTable) OffsetOf(typeName, fieldName string) (uint64, error) {
	l, err := typeLookup(t.inner)
	if err != nil {
		return 0, err
	}
	return l.OffsetOf(typeName, fieldName)
}

func (t movedTable) SizeOf(typeName string) (uint64, error) {
	l, err := typeLookup(t.inner)
	if err != nil {
		return 0, err
	}
	return l.SizeOf(typeName)
}

func (t movedTable) EnumValue(enumName, valueName string) (int64, error) {
	l, err := typeLookup(t.inner)
	if err != nil {
		return 0, err
	}
	return l.EnumValue(enumName, valueName)
}

// The listing stays in the table's own space, as symbols.Symbol documents;
// callers that list symbols add the shift themselves.
func (t movedTable) TableSymbols() []symbols.Symbol {
	if l, ok := t.inner.(interface{ TableSymbols() []symbols.Symbol }); ok {
		return l.TableSymbols()
	}
	return nil
}

func (t movedTable) SymbolNames() []string {
	if l, ok := t.inner.(interface{ SymbolNames() []string }); ok {
		return l.SymbolNames()
	}
	return nil
}

func (t movedTable) SymbolTypeRef(name string) (symbols.TypeRef, error) {
	return symbolTypeRef(t.inner, name)
}

// The kernel table answers every name it has; the extra table only adds
// types the kernel's PDB does not carry (S76 4.7). Symbols come from the
// kernel table alone.
type layeredTable struct {
	kernel symbols.SymbolTable
	extra  symbols.SymbolTable
}

func (t layeredTable) Name() string       { return t.kernel.Name() }
func (t layeredTable) PointerSize() uint8 { return t.kernel.PointerSize() }

func (t layeredTable) owner(typeName string) symbols.SymbolTable {
	if _, err := t.kernel.Struct(typeName); err == nil {
		return t.kernel
	}
	if _, err := t.extra.Struct(typeName); err == nil {
		return t.extra
	}
	return t.kernel
}

func (t layeredTable) Struct(name string) (symbols.StructType, error) {
	return t.owner(name).Struct(name)
}

func (t layeredTable) Field(typeName, fieldName string) (symbols.Field, error) {
	return t.owner(typeName).Field(typeName, fieldName)
}

func (t layeredTable) FieldSize(typeName, fieldName string) (uint64, error) {
	return memberSize(t.owner(typeName), typeName, fieldName)
}

func (t layeredTable) LookupSymbol(name string) (symbols.Symbol, error) {
	return t.kernel.LookupSymbol(name)
}

func (t layeredTable) SymbolsAt(address uint64) []symbols.Symbol {
	if l, ok := t.kernel.(symbols.SymbolLocator); ok {
		return l.SymbolsAt(address)
	}
	return nil
}

func (t layeredTable) ReadUint32(r memory.MemoryReader, at uint64) (uint32, error) {
	return t.kernel.ReadUint32(r, at)
}

func (t layeredTable) ReadUint64(r memory.MemoryReader, at uint64) (uint64, error) {
	return t.kernel.ReadUint64(r, at)
}

func (t layeredTable) ReadPointer(r memory.MemoryReader, at uint64) (uint64, error) {
	return t.kernel.ReadPointer(r, at)
}

func (t layeredTable) ReadStruct(r memory.MemoryReader, typeName string, at uint64) (symbols.StructInstance, error) {
	return t.owner(typeName).ReadStruct(r, typeName, at)
}

func (t layeredTable) lookups() (kernel, extra symbols.DeterministicLookup) {
	kernel, _ = t.kernel.(symbols.DeterministicLookup)
	extra, _ = t.extra.(symbols.DeterministicLookup)
	return kernel, extra
}

func (t layeredTable) LookupType(name string) (symbols.Type, error) {
	k, e := t.lookups()
	return firstAnswer(k, e, func(l symbols.DeterministicLookup) (symbols.Type, error) { return l.LookupType(name) })
}

func (t layeredTable) OffsetOf(typeName, fieldName string) (uint64, error) {
	k, e := t.lookups()
	return firstAnswer(k, e, func(l symbols.DeterministicLookup) (uint64, error) { return l.OffsetOf(typeName, fieldName) })
}

func (t layeredTable) SizeOf(typeName string) (uint64, error) {
	k, e := t.lookups()
	return firstAnswer(k, e, func(l symbols.DeterministicLookup) (uint64, error) { return l.SizeOf(typeName) })
}

func (t layeredTable) EnumValue(enumName, valueName string) (int64, error) {
	k, e := t.lookups()
	return firstAnswer(k, e, func(l symbols.DeterministicLookup) (int64, error) { return l.EnumValue(enumName, valueName) })
}

func (t layeredTable) TableSymbols() []symbols.Symbol {
	if l, ok := t.kernel.(interface{ TableSymbols() []symbols.Symbol }); ok {
		return l.TableSymbols()
	}
	return nil
}

func (t layeredTable) SymbolNames() []string {
	if l, ok := t.kernel.(interface{ SymbolNames() []string }); ok {
		return l.SymbolNames()
	}
	return nil
}

func (t layeredTable) SymbolTypeRef(name string) (symbols.TypeRef, error) {
	return symbolTypeRef(t.kernel, name)
}

// The kernel's answer is kept when it has one, so its error is the one
// reported when neither table knows the name.
func firstAnswer[T any](kernel, extra symbols.DeterministicLookup, ask func(symbols.DeterministicLookup) (T, error)) (T, error) {
	var zero T
	if kernel == nil && extra == nil {
		return zero, errNoTypeLookup
	}
	var kernelErr error = errNoTypeLookup
	if kernel != nil {
		v, err := ask(kernel)
		if err == nil {
			return v, nil
		}
		kernelErr = err
	}
	if extra != nil {
		if v, err := ask(extra); err == nil {
			return v, nil
		}
	}
	return zero, kernelErr
}

func typeLookup(t symbols.SymbolTable) (symbols.DeterministicLookup, error) {
	if l, ok := t.(symbols.DeterministicLookup); ok {
		return l, nil
	}
	return nil, errNoTypeLookup
}

func symbolTypeRef(t symbols.SymbolTable, name string) (symbols.TypeRef, error) {
	if l, ok := t.(interface {
		SymbolTypeRef(string) (symbols.TypeRef, error)
	}); ok {
		return l.SymbolTypeRef(name)
	}
	return symbols.TypeRef{}, fmt.Errorf("libvapour: symbol table gives no symbol types for %s", name)
}

func memberSize(t symbols.SymbolTable, typeName, fieldName string) (uint64, error) {
	if s, ok := t.(symbols.FieldSizer); ok {
		return s.FieldSize(typeName, fieldName)
	}
	return 0, fmt.Errorf("libvapour: symbol table gives no member sizes for %s.%s", typeName, fieldName)
}
