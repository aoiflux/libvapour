package handlelist

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

// mockMemory is a flat buffer for the S30 name tests; kernel addresses fold
// onto it by their low 48 bits.
type mockMemory struct{ buf []byte }

func (m *mockMemory) ReadAt(offset, size uint64) ([]byte, error) {
	offset &= 0x0000ffffffffffff
	if offset > uint64(len(m.buf)) || size > uint64(len(m.buf))-offset {
		return nil, memory.ErrOutOfBounds
	}
	return append([]byte(nil), m.buf[offset:offset+size]...), nil
}

func (m *mockMemory) Size() uint64 { return uint64(len(m.buf)) }

func writeU16(buf []byte, at uint64, v uint16) { binary.LittleEndian.PutUint16(buf[at:], v) }
func writeU32(buf []byte, at uint64, v uint32) { binary.LittleEndian.PutUint32(buf[at:], v) }
func writeU64(buf []byte, at uint64, v uint64) { binary.LittleEndian.PutUint64(buf[at:], v) }

func writeUTF16(buf []byte, at uint64, s string) uint64 {
	units := utf16.Encode([]rune(s))
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[at+uint64(2*i):], u)
	}
	return uint64(2 * len(units))
}

// Build 26100 offsets of S66 HT1 to HT4.
const (
	fxObjectTable = 0x300
	fxTypeIndex   = 0x18
	fxBody        = 0x30
	fxTypeName    = 0x10
	fxTypeSlot    = 0x28
	fxCookie      = 0x69

	fxTypeTable  = 0xfffff80000010000
	fxCookieAt   = 0xfffff80000011000
	fxTypes      = 0xfffff80000020000
	fxStrings    = 0xfffff80000030000
	fxEprocess   = 0xffff900000001000
	fxTable      = 0xffff900000002000
	fxPages      = 0xffff900000100000
	fxObjects    = 0xffffa00000000000
	fxEntrySize  = 0x10
	fxEntriesPer = 0x100
)

// s66Memory holds 4 KB pages at their full virtual address; a page that was
// never written does not read.
type s66Memory struct {
	pages map[uint64][]byte
	next  uint64
}

func (m *s66Memory) ReadAt(at, n uint64) ([]byte, error) {
	out := make([]byte, 0, n)
	for n > 0 {
		page, ok := m.pages[at&^0xfff]
		if !ok {
			return nil, memory.ErrOutOfBounds
		}
		off := at & 0xfff
		take := min(n, 0x1000-off)
		out = append(out, page[off:off+take]...)
		at, n = at+take, n-take
	}
	return out, nil
}

func (m *s66Memory) Size() uint64 { return ^uint64(0) }

func (m *s66Memory) page(at uint64) []byte {
	p, ok := m.pages[at&^0xfff]
	if !ok {
		p = make([]byte, 0x1000)
		m.pages[at&^0xfff] = p
	}
	return p
}

func (m *s66Memory) write(at uint64, b []byte) {
	for i, c := range b {
		m.page(at + uint64(i))[(at+uint64(i))&0xfff] = c
	}
}

func (m *s66Memory) u64(at, v uint64) { m.write(at, binary.LittleEndian.AppendUint64(nil, v)) }

func (m *s66Memory) u32(at uint64, v uint32) { m.write(at, binary.LittleEndian.AppendUint32(nil, v)) }

func (m *s66Memory) text(at uint64, s string) {
	units := utf16.Encode([]rune(s))
	raw := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], u)
	}
	m.write(m.next, raw)
	m.write(at, binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(nil, uint16(len(raw))), uint16(len(raw))))
	m.u64(at+8, m.next)
	m.next += (uint64(len(raw)) + 15) &^ 15
}

type s66Fixture struct {
	mem      *s66Memory
	table    *symbols.Table
	opts     map[string]any
	diags    []string
	types    uint64
	cookie   bool
	nextPage uint64
}

func s66Table(cookie bool) *symbols.Table {
	t := symbols.NewTable("s66", 8)
	ref := func(n string) symbols.TypeRef { return symbols.TypeRef{Name: n} }
	bits := func(n string, off, length uint8) symbols.TypeRef {
		return symbols.TypeRef{Name: n, BitOffset: off, BitLength: length}
	}
	ptr := symbols.TypeRef{Name: "void", IsPointer: true}
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x840, Fields: []symbols.Field{
		{Name: "ObjectTable", Offset: fxObjectTable, Type: symbols.TypeRef{Name: "_HANDLE_TABLE", IsPointer: true}},
	}})
	t.AddStruct(symbols.StructType{Name: "_HANDLE_TABLE", Size: 0x80, Fields: []symbols.Field{
		{Name: "NextHandleNeedingPool", Offset: 0, Type: ref("unsigned int")},
		{Name: "TableCode", Offset: 8, Type: ref("unsigned long long")},
	}})
	t.AddStruct(symbols.StructType{Name: "_HANDLE_TABLE_ENTRY", Size: fxEntrySize, Fields: []symbols.Field{
		{Name: "Unlocked", Offset: 0, Type: bits("unsigned long long", 0, 1)},
		{Name: "ObjectPointerBits", Offset: 0, Type: bits("unsigned long long", 20, 44)},
		{Name: "GrantedAccessBits", Offset: 8, Type: bits("unsigned int", 0, 25)},
		{Name: "NoRightsUpgrade", Offset: 8, Type: bits("unsigned int", 25, 1)},
		{Name: "LeafHandleValue", Offset: 8, Type: ref("_EXHANDLE")},
	}})
	t.AddStruct(symbols.StructType{Name: "_OBJECT_HEADER", Size: 0x38, Fields: []symbols.Field{
		{Name: "TypeIndex", Offset: fxTypeIndex, Type: ref("unsigned char")},
		{Name: "InfoMask", Offset: 0x1a, Type: ref("unsigned char")},
		{Name: "Body", Offset: fxBody, Type: ref("_QUAD")},
	}})
	t.AddStruct(symbols.StructType{Name: "_OBJECT_TYPE", Size: 0xe0, Fields: []symbols.Field{
		{Name: "Name", Offset: fxTypeName, Type: ref("_UNICODE_STRING")},
		{Name: "Index", Offset: fxTypeSlot, Type: ref("unsigned char")},
	}})
	t.AddStruct(symbols.StructType{Name: "_UNICODE_STRING", Size: 16, Fields: []symbols.Field{
		{Name: "Length", Offset: 0, Type: ref("unsigned short")},
		{Name: "MaximumLength", Offset: 2, Type: ref("unsigned short")},
		{Name: "Buffer", Offset: 8, Type: ptr},
	}})
	t.AddSymbol(symbols.Symbol{Name: "ObTypeIndexTable", Address: fxTypeTable})
	if cookie {
		t.AddSymbol(symbols.Symbol{Name: "ObHeaderCookie", Address: fxCookieAt})
	}
	return t
}

func newS66Fixture(cookie bool) *s66Fixture {
	f := &s66Fixture{mem: &s66Memory{pages: map[uint64][]byte{}, next: fxStrings}, table: s66Table(cookie),
		types: fxTypes, cookie: cookie, nextPage: fxPages}
	f.opts = map[string]any{"diagnostics": &f.diags}
	f.mem.page(fxTypeTable)
	if cookie {
		f.mem.write(fxCookieAt, []byte{fxCookie})
	}
	return f
}

func (f *s66Fixture) ctx() tools.Context {
	return tools.Context{Memory: f.mem, Symbols: f.table, Profile: profiles.WindowsX64Profile{}, Options: f.opts}
}

func (f *s66Fixture) objectType(slot uint8, name string) {
	at := f.types
	f.types += 0x100
	f.mem.write(at+fxTypeSlot, []byte{slot})
	f.mem.text(at+fxTypeName, name)
	f.mem.u64(fxTypeTable+8*uint64(slot), at)
}

func (f *s66Fixture) object(header uint64, slot uint8) {
	stored := slot
	if f.cookie {
		stored ^= fxCookie ^ byte(header>>8)
	}
	f.mem.write(header+fxTypeIndex, []byte{stored})
}

func (f *s66Fixture) newPage() uint64 {
	at := f.nextPage
	f.nextPage += 0x1000
	f.mem.page(at)
	return at
}

// leaf makes a page of entries whose first entry names first as its value.
func (f *s66Fixture) leaf(first uint64) uint64 {
	at := f.newPage()
	f.mem.u64(at+8, first)
	return at
}

func encodeEntry(header uint64, access uint32) []byte {
	rec := make([]byte, fxEntrySize)
	binary.LittleEndian.PutUint64(rec, (header&0x0000ffffffffffff)>>4<<20|1)
	binary.LittleEndian.PutUint32(rec[8:], access)
	return rec
}

func (f *s66Fixture) entry(leaf uint64, i int, header uint64, access uint32) {
	f.mem.write(leaf+uint64(i)*fxEntrySize, encodeEntry(header, access))
}

func (f *s66Fixture) handleTable(eprocess, table, code uint64, next uint32) processlist.Process {
	f.mem.u64(eprocess+fxObjectTable, table)
	if table != 0 {
		f.mem.u64(table+8, code)
		f.mem.u32(table, next)
	}
	return processlist.Process{PID: 4, Name: "System", EPROCESS: eprocess}
}

func (f *s66Fixture) walk(procs ...processlist.Process) ([]Handle, error) {
	w, err := NewWalker(f.ctx())
	if err != nil {
		return nil, err
	}
	return w.all(procs)
}
