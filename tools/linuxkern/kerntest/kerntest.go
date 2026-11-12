package kerntest

import (
	"encoding/binary"
	"fmt"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// The x86-64 base page (Intel SDM Vol. 3A 4.5).
const PageSize = 0x1000

// Memory is a sparse kernel address space: a page exists once something maps
// or writes it, and a read of a page that does not exist fails.
type Memory struct {
	pages map[uint64][]byte
}

func NewMemory() *Memory { return &Memory{pages: map[uint64][]byte{}} }

func pageOf(va uint64) uint64 { return va &^ (PageSize - 1) }

func (m *Memory) page(va uint64) []byte {
	p, ok := m.pages[pageOf(va)]
	if !ok {
		p = make([]byte, PageSize)
		m.pages[pageOf(va)] = p
	}
	return p
}

func (m *Memory) Map(va, n uint64) {
	if n == 0 {
		return
	}
	last := pageOf(va + n - 1)
	if va+n-1 < va {
		last = pageOf(^uint64(0))
	}
	for p := pageOf(va); ; p += PageSize {
		m.page(p)
		if p == last {
			return
		}
	}
}

func (m *Memory) Unmap(va uint64) { delete(m.pages, pageOf(va)) }

func (m *Memory) Write(va uint64, data []byte) {
	for len(data) > 0 {
		n := copy(m.page(va)[va-pageOf(va):], data)
		data = data[n:]
		va += uint64(n)
	}
}

func (m *Memory) U8(va uint64, v uint8) { m.Write(va, []byte{v}) }

func (m *Memory) U16(va uint64, v uint16) { m.Write(va, binary.LittleEndian.AppendUint16(nil, v)) }

func (m *Memory) U32(va uint64, v uint32) { m.Write(va, binary.LittleEndian.AppendUint32(nil, v)) }

func (m *Memory) U64(va uint64, v uint64) { m.Write(va, binary.LittleEndian.AppendUint64(nil, v)) }

func (m *Memory) Str(va uint64, s string) { m.Write(va, append([]byte(s), 0)) }

func (m *Memory) ReadAt(offset, size uint64) ([]byte, error) {
	if size != 0 && offset+size-1 < offset {
		return nil, fmt.Errorf("kerntest: read at %#x wraps the address space: %w", offset, memory.ErrOutOfBounds)
	}
	out := make([]byte, 0, size)
	for size > 0 {
		p, ok := m.pages[pageOf(offset)]
		if !ok {
			return nil, fmt.Errorf("kerntest: %#x is not mapped: %w", offset, memory.ErrOutOfBounds)
		}
		n := min(PageSize-(offset-pageOf(offset)), size)
		out = append(out, p[offset-pageOf(offset):][:n]...)
		offset += n
		size -= n
	}
	return out, nil
}

func (m *Memory) Size() uint64 { return ^uint64(0) }

type T = symbols.TypeRef

func Base(name string) T { return T{Name: name} }

func Struct(name string) T { return T{Name: name} }

func Union(name string) T { return T{Name: name} }

func Enum(name string) T { return T{Name: name} }

func Ptr(sub T) T { return T{Name: sub.Name, IsPointer: true, Element: &sub} }

func Arr(count uint64, sub T) T {
	return T{Name: sub.Name, IsArray: true, ArrayLength: count, Element: &sub}
}

func Bits(pos, length uint64, base string) T {
	word := Base(base)
	return T{Name: base, BitOffset: uint8(pos), BitLength: uint8(length), Element: &word}
}

func Fn() T { return T{} }

func Void() T { return Base("void") }

// F is one member: its offset, its type, and whether it is an unnamed member
// whose own members read as the outer record's.
type F struct {
	Off       uint64
	Type      T
	Anonymous bool
}

// Types gathers a symbol table declaration: records, enumerations and
// addresses, over the LP64 scalars of the x86-64 psABI (Figure 3.1).
type Types struct {
	ptr     uint64
	records map[string]symbols.Record
	symbols map[string]symbols.Address
	enums   map[string]symbols.EnumType
}

func NewTypes(ptr uint64) *Types {
	return &Types{ptr: ptr, records: map[string]symbols.Record{}, symbols: map[string]symbols.Address{},
		enums: map[string]symbols.EnumType{}}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func (i *Types) record(name string, size uint64, fields map[string]F) {
	r := symbols.Record{Name: name, Width: size}
	for _, n := range sortedKeys(fields) {
		f := fields[n]
		m := symbols.Member{Name: n, Offset: f.Off, Type: f.Type}
		if f.Anonymous {
			m = symbols.Member{Name: n, Offset: f.Off, Embeds: f.Type.Name}
		}
		r.Members = append(r.Members, m)
	}
	i.records[name] = r
}

func (i *Types) Struct(name string, size uint64, fields map[string]F) { i.record(name, size, fields) }

func (i *Types) Union(name string, size uint64, fields map[string]F) { i.record(name, size, fields) }

func (i *Types) Symbol(name string, addr uint64, typ T) {
	i.symbols[name] = symbols.Address{Name: name, Address: addr, Type: &typ}
}

// An enumeration takes the width of the scalar it is based on when that
// scalar is declared, else the size given.
func (i *Types) Enum(name string, size uint64, base string, constants map[string]int64) {
	e := symbols.EnumType{Name: name, Size: size}
	if s, ok := i.scalar(base); ok && s.Width != 0 {
		e.Size = s.Width
	}
	for _, k := range sortedKeys(constants) {
		e.Values = append(e.Values, symbols.EnumValue{Name: k, Value: constants[k]})
	}
	i.enums[name] = e
}

func (i *Types) scalar(name string) (symbols.Scalar, bool) {
	for _, s := range i.scalars() {
		if s.Name == name {
			return s, true
		}
	}
	return symbols.Scalar{}, false
}

// The DWARF base type names of the x86-64 psABI scalars; long and the pointer
// take the table's pointer width, so a 4-byte table models ILP32.
func (i *Types) scalars() []symbols.Scalar {
	return []symbols.Scalar{
		{Name: "_Bool", Width: 1, Kind: symbols.ScalarBool, Signed: true},
		{Name: "char", Width: 1, Kind: symbols.ScalarChar},
		{Name: "signed char", Width: 1, Kind: symbols.ScalarChar, Signed: true},
		{Name: "unsigned char", Width: 1, Kind: symbols.ScalarChar},
		{Name: "short int", Width: 2, Kind: symbols.ScalarInteger, Signed: true},
		{Name: "short unsigned int", Width: 2, Kind: symbols.ScalarInteger},
		{Name: "int", Width: 4, Kind: symbols.ScalarInteger, Signed: true},
		{Name: "unsigned int", Width: 4, Kind: symbols.ScalarInteger},
		{Name: "long int", Width: i.ptr, Kind: symbols.ScalarInteger, Signed: true},
		{Name: "long unsigned int", Width: i.ptr, Kind: symbols.ScalarInteger},
		{Name: "long long int", Width: 8, Kind: symbols.ScalarInteger, Signed: true},
		{Name: "long long unsigned int", Width: 8, Kind: symbols.ScalarInteger},
		{Name: "pointer", Width: i.ptr, Kind: symbols.ScalarInteger},
		{Name: "void", Width: 0, Kind: symbols.ScalarVoid},
	}
}

func (i *Types) Declaration() symbols.Declaration {
	d := symbols.Declaration{PointerWidth: uint8(i.ptr), Scalars: i.scalars()}
	for _, n := range sortedKeys(i.records) {
		d.Records = append(d.Records, i.records[n])
	}
	for _, n := range sortedKeys(i.enums) {
		d.Enumerations = append(d.Enumerations, i.enums[n])
	}
	for _, n := range sortedKeys(i.symbols) {
		d.Addresses = append(d.Addresses, i.symbols[n])
	}
	return d
}

// Table is the built table with a KASLR shift: symbols inside the kernel
// image mapping move by Shift, the rest stay where they were declared.
type Table struct {
	*symbols.Table
	Shift uint64
	syms  []symbols.Symbol
	refs  map[string]symbols.TypeRef
}

func (i *Types) Table(t testing.TB) *Table {
	t.Helper()
	table, err := symbols.Build("kerntest", i.Declaration())
	if err != nil {
		t.Fatalf("kerntest: build the table: %v", err)
	}
	out := &Table{Table: table, refs: map[string]symbols.TypeRef{}}
	for _, n := range sortedKeys(i.symbols) {
		s := i.symbols[n]
		out.syms = append(out.syms, symbols.Symbol{Name: n, Address: s.Address})
		out.refs[n] = *s.Type
	}
	return out
}

// The kernel image mapping starts at __START_KERNEL_map and spans
// KERNEL_IMAGE_SIZE, 1 GiB when KASLR is configured
// (arch/x86/include/asm/page_64_types.h, v4.19 and v6.17).
const (
	startKernelMap  = 0xffffffff80000000
	kernelImageSize = 1 << 30
)

func inImage(addr uint64) bool { return addr-startKernelMap < kernelImageSize }

func (t *Table) LookupSymbol(name string) (symbols.Symbol, error) {
	s, err := t.Table.LookupSymbol(name)
	if err == nil && inImage(s.Address) {
		s.Address += t.Shift
	}
	return s, err
}

func (t *Table) SymbolsAt(address uint64) []symbols.Symbol {
	var out []symbols.Symbol
	if address >= t.Shift {
		for _, s := range t.Table.SymbolsAt(address - t.Shift) {
			if inImage(s.Address) {
				s.Address += t.Shift
				out = append(out, s)
			}
		}
	}
	for _, s := range t.Table.SymbolsAt(address) {
		if !inImage(s.Address) {
			out = append(out, s)
		}
	}
	return out
}

func (t *Table) TableSymbols() []symbols.Symbol { return slices.Clone(t.syms) }

func (t *Table) SymbolTypeRef(name string) (symbols.TypeRef, error) {
	r, ok := t.refs[name]
	if !ok {
		return symbols.TypeRef{}, fmt.Errorf("kerntest: no type for symbol %q", name)
	}
	return r, nil
}

// Context collects diagnostics into the returned slice; opts may add to or
// replace any option.
func Context(mem memory.MemoryReader, table symbols.SymbolTable, opts map[string]any) (tools.Context, *[]string) {
	diags := &[]string{}
	options := map[string]any{"diagnostics": diags}
	for k, v := range opts {
		options[k] = v
	}
	return tools.Context{Memory: mem, Symbols: table, Profile: profiles.LinuxX64Profile{}, Options: options}, diags
}

func Symbols(i *Types) map[string]symbols.Address { return i.symbols }
