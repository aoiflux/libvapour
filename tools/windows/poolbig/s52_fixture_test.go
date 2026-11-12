package poolbig

import (
	"encoding/binary"
	"slices"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// Entry layouts of S52 T1 (builds 14393 and 19045: 24 bytes, PoolType) and
// T2 (build 26100: 32 bytes, PoolFlags).
const (
	fxPointerAt = 0x100
	fxSizeAt    = 0x120
	fxTable     = 0x1000
)

type fxBuild struct {
	stride uint64
	flags  bool
}

var (
	fx19045 = fxBuild{stride: 24}
	fx26100 = fxBuild{stride: 32, flags: true}
)

func (b fxBuild) table() *symbols.Table { return b.tableWithout("") }

func (b fxBuild) tableWithout(missing string) *symbols.Table {
	t := symbols.NewTable("s52", 8)
	u := func(name string) symbols.TypeRef { return symbols.TypeRef{Name: name} }
	bits := func(off, n uint8) symbols.TypeRef {
		return symbols.TypeRef{Name: "unsigned int", BitOffset: off, BitLength: n}
	}
	fields := []symbols.Field{
		{Name: "Va", Offset: 0, Type: u("unsigned long long")},
		{Name: "Key", Offset: 8, Type: u("unsigned int")},
		{Name: "Pattern", Offset: 0xc, Type: bits(0, 8)},
		{Name: "SlushSize", Offset: 0xc, Type: bits(20, 12)},
		{Name: "NumberOfBytes", Offset: 0x10, Type: u("unsigned long long")},
	}
	if b.flags {
		fields = append(fields, symbols.Field{Name: "PoolFlags", Offset: 0xc, Type: bits(8, 12)},
			symbols.Field{Name: "ProcessBilled", Offset: 0x18, Type: symbols.TypeRef{Name: "_EPROCESS", IsPointer: true}})
	} else {
		fields = append(fields, symbols.Field{Name: "PoolType", Offset: 0xc, Type: bits(8, 12)})
	}
	if missing != entryType {
		t.AddStruct(symbols.StructType{Name: entryType, Size: b.stride, Fields: fields})
	}
	t.AddEnum(symbols.EnumType{Name: "_POOL_TYPE", Size: 4, Values: []symbols.EnumValue{
		{Name: "NonPagedPool", Value: 0}, {Name: "NonPagedPoolBase", Value: 0}, {Name: "NonPagedPoolExecute", Value: 0},
		{Name: "PagedPool", Value: 1}, {Name: "NonPagedPoolBaseMustSucceed", Value: 2},
		{Name: "NonPagedPoolMustSucceed", Value: 2}, {Name: "PagedPoolCacheAligned", Value: 5},
		{Name: "NonPagedPoolNx", Value: 512},
	}})
	for name, at := range map[string]uint64{tableGlobal: fxPointerAt, sizeGlobal: fxSizeAt} {
		if name != missing {
			t.AddSymbol(symbols.Symbol{Name: name, Address: at})
		}
	}
	return t
}

type fxMemory struct {
	buf   []byte
	holes [][2]uint64
}

func (m *fxMemory) ReadAt(off, size uint64) ([]byte, error) {
	if off > uint64(len(m.buf)) || size > uint64(len(m.buf))-off {
		return nil, memory.ErrOutOfBounds
	}
	for _, h := range m.holes {
		if off < h[1] && off+size > h[0] {
			return nil, memory.ErrUnmapped
		}
	}
	return slices.Clone(m.buf[off : off+size]), nil
}

func (m *fxMemory) Size() uint64 { return uint64(len(m.buf)) }

type fxEntry struct {
	va    uint64
	tag   string
	bytes uint64
	kind  uint64
}

// slots unset stay never used: Key 0, Va 1, as on every measured table.
func (b fxBuild) memory(slots int, entries map[int]fxEntry) *fxMemory {
	m := &fxMemory{buf: make([]byte, fxTable+uint64(slots)*b.stride+0x1000)}
	binary.LittleEndian.PutUint64(m.buf[fxPointerAt:], fxTable)
	binary.LittleEndian.PutUint32(m.buf[fxSizeAt:], uint32(slots))
	for i := range slots {
		at := fxTable + uint64(i)*b.stride
		e, ok := entries[i]
		if !ok {
			binary.LittleEndian.PutUint64(m.buf[at:], 1)
			continue
		}
		var key [4]byte
		copy(key[:], e.tag)
		binary.LittleEndian.PutUint64(m.buf[at:], e.va)
		copy(m.buf[at+8:], key[:])
		binary.LittleEndian.PutUint32(m.buf[at+0xc:], uint32(e.kind)<<8)
		binary.LittleEndian.PutUint64(m.buf[at+0x10:], e.bytes)
	}
	return m
}

func fxContext(t symbols.SymbolTable, m memory.MemoryReader, options map[string]any) (tools.Context, *[]string) {
	var diags []string
	o := map[string]any{"diagnostics": &diags}
	for k, v := range options {
		o[k] = v
	}
	return tools.Context{Memory: m, Symbols: t, Profile: profiles.WindowsX64Profile{}, Options: o}, &diags
}
