package scan

import (
	"encoding/binary"
	"slices"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

// Build 26100 layouts (S31 T1 to T6), in one flat buffer that serves as both
// physical and kernel memory.
const (
	fxHeaderBody   = 0x30
	fxTypeIndex    = 0x18
	fxInfoMask     = 0x1a
	fxHandleCount  = 0x08
	fxProcessSize  = 0x200
	fxCookie       = 0x69
	fxProcessSlot  = 8
	fxThreadSlot   = 9
	fxCookieAt     = 0x100
	fxTypeTableAt  = 0x200
	fxMaskTableAt  = 0xa00
	fxTypesAt      = 0xc00
	fxStringsAt    = 0x1000
	fxFirstPool    = 0x2000
	fxPageSize     = 0x1000
	fxPoolHeader   = 0x10
	fxNonPagedType = 2
	fxPagedType    = 3
)

var fxOptionalSizes = [8]uint64{32, 32, 16, 32, 16, 16, 16, 4}

type flat struct {
	buf   []byte
	holes [][2]uint64
}

func (f *flat) ReadAt(off, size uint64) ([]byte, error) {
	if off > uint64(len(f.buf)) || size > uint64(len(f.buf))-off {
		return nil, memory.ErrOutOfBounds
	}
	for _, h := range f.holes {
		if off < h[1] && off+size > h[0] {
			return nil, memory.ErrUnmapped
		}
	}
	return slices.Clone(f.buf[off : off+size]), nil
}

func (f *flat) Size() uint64 { return uint64(len(f.buf)) }

func (f *flat) u8(at uint64, v byte)    { f.buf[at] = v }
func (f *flat) u16(at uint64, v uint16) { binary.LittleEndian.PutUint16(f.buf[at:], v) }
func (f *flat) u32(at uint64, v uint32) { binary.LittleEndian.PutUint32(f.buf[at:], v) }
func (f *flat) u64(at uint64, v uint64) { binary.LittleEndian.PutUint64(f.buf[at:], v) }

func (f *flat) ustr(at, buffer uint64, s string) {
	u := utf16.Encode([]rune(s))
	for i, c := range u {
		f.u16(buffer+uint64(i)*2, c)
	}
	f.u16(at, uint16(len(u)*2))
	f.u16(at+2, uint16(len(u)*2))
	f.u64(at+8, buffer)
}

func fxTable() *symbols.Table {
	t := symbols.NewTable("fixture", 8)
	u := func(name string) symbols.TypeRef { return symbols.TypeRef{Name: name} }
	bits := func(name string, off, n uint8) symbols.TypeRef {
		return symbols.TypeRef{Name: name, BitOffset: off, BitLength: n}
	}
	t.AddStruct(symbols.StructType{Name: "_POOL_HEADER", Size: 16, Fields: []symbols.Field{
		{Name: "PreviousSize", Offset: 0, Type: bits("unsigned short", 0, 8)},
		{Name: "PoolIndex", Offset: 0, Type: bits("unsigned short", 8, 8)},
		{Name: "BlockSize", Offset: 2, Type: bits("unsigned short", 0, 8)},
		{Name: "PoolType", Offset: 2, Type: bits("unsigned short", 8, 8)},
		{Name: "PoolTag", Offset: 4, Type: u("unsigned int")},
	}})
	t.AddStruct(symbols.StructType{Name: "_OBJECT_HEADER", Size: 0x38, Fields: []symbols.Field{
		{Name: "PointerCount", Offset: 0, Type: u("long long")},
		{Name: "HandleCount", Offset: fxHandleCount, Type: u("long long")},
		{Name: "TypeIndex", Offset: fxTypeIndex, Type: u("unsigned char")},
		{Name: "InfoMask", Offset: fxInfoMask, Type: u("unsigned char")},
		{Name: "Body", Offset: fxHeaderBody, Type: u("_QUAD")},
	}})
	for bit, name := range optionalHeaders {
		st := symbols.StructType{Name: name, Size: fxOptionalSizes[bit]}
		if bit == 1 {
			st.Fields = []symbols.Field{
				{Name: "Directory", Offset: 0, Type: symbols.TypeRef{Name: "_OBJECT_DIRECTORY", IsPointer: true}},
				{Name: "Name", Offset: 8, Type: u("_UNICODE_STRING")},
			}
		}
		if bit == 7 {
			st.Fields = []symbols.Field{{Name: "PaddingAmount", Offset: 0, Type: u("unsigned int")}}
		}
		t.AddStruct(st)
	}
	t.AddStruct(symbols.StructType{Name: "_UNICODE_STRING", Size: 16, Fields: []symbols.Field{
		{Name: "Length", Offset: 0, Type: u("unsigned short")},
		{Name: "MaximumLength", Offset: 2, Type: u("unsigned short")},
		{Name: "Buffer", Offset: 8, Type: symbols.TypeRef{Name: "wchar_t", IsPointer: true}},
	}})
	t.AddStruct(symbols.StructType{Name: "_OBJECT_TYPE", Size: 0xe0, Fields: []symbols.Field{
		{Name: "Name", Offset: 0x10, Type: u("_UNICODE_STRING")},
		{Name: "Index", Offset: 0x28, Type: u("unsigned char")},
	}})
	t.AddStruct(symbols.StructType{Name: "_DISPATCHER_HEADER", Size: 0x18, Fields: []symbols.Field{
		{Name: "Type", Offset: 0, Type: u("unsigned char")},
	}})
	t.AddStruct(symbols.StructType{Name: "_KPROCESS", Size: 0x100, Fields: []symbols.Field{
		{Name: "Header", Offset: 0, Type: u("_DISPATCHER_HEADER")},
	}})
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: fxProcessSize, Fields: []symbols.Field{
		{Name: "Pcb", Offset: 0, Type: u("_KPROCESS")},
	}})
	t.AddStruct(symbols.StructType{Name: "_RTL_ATOM_TABLE", Size: 0x28})
	t.AddSymbol(symbols.Symbol{Name: "ObHeaderCookie", Address: fxCookieAt})
	t.AddSymbol(symbols.Symbol{Name: "ObTypeIndexTable", Address: fxTypeTableAt})
	t.AddSymbol(symbols.Symbol{Name: "ObpInfoMaskToOffset", Address: fxMaskTableAt})
	return t
}

func newFlat(pages int) *flat {
	f := &flat{buf: make([]byte, fxFirstPool+pages*fxPageSize)}
	f.u8(fxCookieAt, fxCookie)
	for i, name := range map[int]string{2: "Type", fxProcessSlot: "Process", fxThreadSlot: "Thread"} {
		obj := uint64(fxTypesAt + i*0x40)
		f.u64(fxTypeTableAt+uint64(i)*8, obj-0x10)
		f.ustr(obj, fxStringsAt+uint64(i)*0x20, name)
		f.u8(obj-0x10+0x28, byte(i))
	}
	f.u64(fxTypeTableAt+8, 0xbad0b0b0)
	for mask := range 256 {
		var n uint64
		for bit := range 8 {
			if mask&(1<<bit) != 0 {
				n += fxOptionalSizes[bit]
			}
		}
		f.u8(fxMaskTableAt+uint64(mask), byte(n))
	}
	return f
}

func optionalLength(mask byte) uint64 {
	var n uint64
	for bit := range 7 {
		if mask&(1<<bit) != 0 {
			n += fxOptionalSizes[bit]
		}
	}
	return n
}

type fxObject struct {
	pool     uint64
	tag      string
	poolType byte
	blocks   byte
	mask     byte
	padding  uint32
	slot     byte
	va       uint64
	pointers int64
	handles  int64
	dispatch byte
}

// The header TypeIndex is encoded for the virtual address the object is
// given, as the kernel stores it.
func (f *flat) object(o fxObject) (header, body uint64) {
	distance := optionalLength(o.mask)
	if o.mask&paddingBit != 0 {
		distance += uint64(o.padding)
	}
	header = o.pool + fxPoolHeader + distance
	body = header + fxHeaderBody
	if o.blocks == 0 {
		o.blocks = byte((fxPoolHeader + distance + fxHeaderBody + fxProcessSize + 15) / 16)
	}
	f.u16(o.pool+2, uint16(o.blocks)|uint16(o.poolType)<<8)
	copy(f.buf[o.pool+4:], o.tag)
	if o.mask&paddingBit != 0 {
		f.u32(header-optionalLength(o.mask)-4, o.padding)
	}
	f.u64(header, uint64(o.pointers))
	f.u64(header+fxHandleCount, uint64(o.handles))
	f.u8(header+fxInfoMask, o.mask)
	va := o.va + (header - o.pool)
	f.u8(header+fxTypeIndex, o.slot^fxCookie^byte(va>>8))
	f.u8(body, o.dispatch)
	return header, body
}

type mapping struct{ frame, va uint64 }

type fxResidency struct{ maps []mapping }

func (r *fxResidency) mapPage(pa, va uint64) {
	r.maps = append(r.maps, mapping{pa &^ (fxPageSize - 1), va &^ (fxPageSize - 1)})
}

func (r *fxResidency) Contains(pa uint64) bool {
	for _, m := range r.maps {
		if m.frame == pa&^(fxPageSize-1) {
			return true
		}
	}
	return false
}

func (r *fxResidency) SecondAddressBytes(pa uint64) []byte {
	var out []byte
	for _, m := range r.maps {
		if m.frame == pa&^(fxPageSize-1) {
			b := byte((m.va>>12)&0xf)<<4 | byte(pa>>8)&0xf
			if !slices.Contains(out, b) {
				out = append(out, b)
			}
		}
	}
	return out
}

func (r *fxResidency) LowestAddresses(qs []layers.AddressQuery) ([]layers.LowestAddress, error) {
	out := make([]layers.LowestAddress, len(qs))
	for i, q := range qs {
		for _, m := range r.maps {
			if m.frame != q.Physical&^(fxPageSize-1) || q.Keys&(1<<((m.va>>12)&0xf)) == 0 {
				continue
			}
			va := m.va + q.Physical&(fxPageSize-1)
			if !out[i].Mapped || va < out[i].Virtual {
				out[i] = layers.LowestAddress{Virtual: va, Mapped: true}
			}
		}
	}
	return out, nil
}

func fxProcessTag(t *symbols.Table) TypeTag {
	return ResolveTypeTag(t, ProcessObject, Member{"_EPROCESS", "Pcb"}, Member{"_KPROCESS", "Header"},
		Member{"_DISPATCHER_HEADER", "Type"})
}

type fxScan struct {
	table    *symbols.Table
	mem      *flat
	layout   ObjectLayout
	identity ObjectIdentity
}

func newScan(mem *flat, residency Residency) fxScan {
	t := fxTable()
	layout, err := ResolveObjectLayout(t)
	if err != nil {
		panic(err)
	}
	if residency != nil {
		layout = layout.WithResidency(residency)
	}
	id, err := ResolveObjectIdentity(t, mem, ProcessFilter, fxProcessTag(t))
	if err != nil {
		panic(err)
	}
	return fxScan{t, mem, layout, id}
}

func (s fxScan) processes() ([]Placed[uint64], ObjectScanStats) {
	rows, stats, err := FindExecutiveObjectsPlaced(s.mem, ProcessFilter, s.layout, s.identity,
		func(body uint64) (uint64, bool) { return body, true }, 2)
	if err != nil {
		panic(err)
	}
	return rows, stats
}
