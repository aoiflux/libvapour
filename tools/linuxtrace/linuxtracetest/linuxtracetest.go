package linuxtracetest

import (
	"encoding/binary"
	"slices"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// The x86-64 base page (Intel SDM Vol. 3A 4.5).
const pageSize = 0x1000

// Memory is a sparse kernel address space that counts its reads, so a test
// can bound how much a tool reads.
type Memory struct {
	pages map[uint64][]byte
	Reads int
}

func NewMemory() *Memory { return &Memory{pages: map[uint64][]byte{}} }

func base(addr uint64) uint64 { return addr &^ (pageSize - 1) }

func (m *Memory) ReadAt(offset, size uint64) ([]byte, error) {
	m.Reads++
	if offset+size < offset {
		return nil, memory.ErrOutOfBounds
	}
	out := make([]byte, 0, size)
	for size > 0 {
		p, ok := m.pages[base(offset)]
		if !ok {
			return nil, memory.ErrOutOfBounds
		}
		in := offset - base(offset)
		n := min(pageSize-in, size)
		out = append(out, p[in:in+n]...)
		offset, size = offset+n, size-n
	}
	return out, nil
}

func (m *Memory) Size() uint64 { return ^uint64(0) }

func (m *Memory) Map(addr, size uint64) {
	if size == 0 {
		return
	}
	end := addr + size - 1
	if end < addr {
		end = ^uint64(0)
	}
	for p := base(addr); ; p += pageSize {
		if m.pages[p] == nil {
			m.pages[p] = make([]byte, pageSize)
		}
		if p == base(end) {
			return
		}
	}
}

func (m *Memory) Unmap(addr uint64) { delete(m.pages, base(addr)) }

func (m *Memory) Write(addr uint64, data []byte) {
	m.Map(addr, uint64(len(data)))
	for len(data) > 0 {
		n := copy(m.pages[base(addr)][addr-base(addr):], data)
		data, addr = data[n:], addr+uint64(n)
	}
}

func (m *Memory) U64(addr, v uint64) { m.Write(addr, binary.LittleEndian.AppendUint64(nil, v)) }

func (m *Memory) U32(addr uint64, v uint32) { m.Write(addr, binary.LittleEndian.AppendUint32(nil, v)) }

func (m *Memory) U16(addr uint64, v uint16) { m.Write(addr, binary.LittleEndian.AppendUint16(nil, v)) }

func (m *Memory) Str(addr uint64, s string) { m.Write(addr, append([]byte(s), 0)) }

// Link makes the list_head nodes one circular list in the order given
// (include/linux/list.h: next at 0, prev at 8).
func (m *Memory) Link(nodes ...uint64) {
	for n, at := range nodes {
		m.U64(at, nodes[(n+1)%len(nodes)])
		m.U64(at+8, nodes[(n+len(nodes)-1)%len(nodes)])
	}
}

type Type = *symbols.TypeRef

func Base(name string) Type { return &symbols.TypeRef{Name: name} }

func Ptr(to Type) Type { return &symbols.TypeRef{Name: to.Name, IsPointer: true, Element: to} }

func Array(of Type, n uint64) Type {
	return &symbols.TypeRef{Name: of.Name, IsArray: true, ArrayLength: n, Element: of}
}

func Struct(name string) Type { return &symbols.TypeRef{Name: name} }

func Enum(name string) Type { return &symbols.TypeRef{Name: name} }

func Func() Type { return &symbols.TypeRef{} }

type Member struct {
	Name   string
	Offset uint64
	Type   Type
}

func M(name string, offset uint64, t Type) Member { return Member{Name: name, Offset: offset, Type: t} }

// Table gathers a declaration; a later Struct, Enum or Symbol of the same
// name replaces the earlier one.
type Table struct {
	records map[string]symbols.Record
	enums   map[string]symbols.EnumType
	symbols map[string]symbols.Address
}

func NewTable() *Table {
	return &Table{records: map[string]symbols.Record{}, enums: map[string]symbols.EnumType{},
		symbols: map[string]symbols.Address{}}
}

// A member named twice keeps its last declaration.
func (t *Table) Struct(name string, size uint64, members ...Member) {
	byName := map[string]Member{}
	for _, m := range members {
		byName[m.Name] = m
	}
	r := symbols.Record{Name: name, Width: size}
	for _, n := range keys(byName) {
		m := byName[n]
		r.Members = append(r.Members, symbols.Member{Name: n, Offset: m.Offset, Type: *m.Type})
	}
	t.records[name] = r
}

func (t *Table) Enum(name, base string, size uint64, values map[string]int64) {
	e := symbols.EnumType{Name: name, Size: size}
	for _, s := range lp64 {
		if s.Name == base && s.Width != 0 {
			e.Size = s.Width
		}
	}
	for _, n := range keys(values) {
		e.Values = append(e.Values, symbols.EnumValue{Name: n, Value: values[n]})
	}
	t.enums[name] = e
}

func (t *Table) Symbol(name string, addr uint64, typ Type) {
	a := symbols.Address{Name: name, Address: addr}
	if typ != nil {
		ref := *typ
		a.Type = &ref
	}
	t.symbols[name] = a
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// The DWARF base type names of the x86-64 psABI LP64 scalars (Figure 3.1).
var lp64 = []symbols.Scalar{
	{Name: "char", Width: 1, Kind: symbols.ScalarChar, Signed: true},
	{Name: "unsigned char", Width: 1, Kind: symbols.ScalarChar},
	{Name: "short int", Width: 2, Kind: symbols.ScalarInteger, Signed: true},
	{Name: "short unsigned int", Width: 2, Kind: symbols.ScalarInteger},
	{Name: "int", Width: 4, Kind: symbols.ScalarInteger, Signed: true},
	{Name: "unsigned int", Width: 4, Kind: symbols.ScalarInteger},
	{Name: "long int", Width: 8, Kind: symbols.ScalarInteger, Signed: true},
	{Name: "long unsigned int", Width: 8, Kind: symbols.ScalarInteger},
	{Name: "long long int", Width: 8, Kind: symbols.ScalarInteger, Signed: true},
	{Name: "long long unsigned int", Width: 8, Kind: symbols.ScalarInteger},
	{Name: "_Bool", Width: 1, Kind: symbols.ScalarBool},
	{Name: "pointer", Width: 8, Kind: symbols.ScalarInteger},
	{Name: "void", Width: 0, Kind: symbols.ScalarVoid},
}

func (t *Table) Build() (*symbols.Table, error) {
	d := symbols.Declaration{PointerWidth: 8, Scalars: lp64}
	for _, n := range keys(t.records) {
		d.Records = append(d.Records, t.records[n])
	}
	for _, n := range keys(t.enums) {
		d.Enumerations = append(d.Enumerations, t.enums[n])
	}
	for _, n := range keys(t.symbols) {
		d.Addresses = append(d.Addresses, t.symbols[n])
	}
	return symbols.Build("linuxtracetest", d)
}

func Context(mem memory.MemoryReader, table symbols.SymbolTable, diags *[]string, options map[string]any) tools.Context {
	opts := map[string]any{"diagnostics": diags}
	for k, v := range options {
		opts[k] = v
	}
	return tools.Context{Memory: mem, Symbols: table, Profile: profiles.LinuxX64Profile{}, Options: opts}
}

// ListHead declares list_head, hlist_head and hlist_node as
// include/linux/types.h lays them out (v4.19 to v6.17).
func (t *Table) ListHead() {
	t.Struct("list_head", 16, M("next", 0, Ptr(Struct("list_head"))), M("prev", 8, Ptr(Struct("list_head"))))
	t.Struct("hlist_head", 8, M("first", 0, Ptr(Struct("hlist_node"))))
	t.Struct("hlist_node", 16, M("next", 0, Ptr(Struct("hlist_node"))), M("pprev", 8, Ptr(Ptr(Struct("hlist_node")))))
}
