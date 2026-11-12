package poolscan

import (
	"encoding/binary"
	"slices"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// One flat buffer serves as physical and kernel memory. Layouts follow the
// build 26100 headers of S31 T1 to T3; body members are placed freely, since
// the tool reads them through the table.
const (
	fxMasksAt   = 0x100
	fxStringsAt = 0x400
	fxPoolAt    = 0x1000
	fxHeaderLen = 0x10
	fxBodyAt    = 0x30
	fxNameInfo  = 32
)

var fxOptional = [8]uint64{32, 32, 16, 32, 16, 16, 16, 4}

var fxOptionalNames = [8]string{
	"_OBJECT_HEADER_CREATOR_INFO", "_OBJECT_HEADER_NAME_INFO", "_OBJECT_HEADER_HANDLE_INFO",
	"_OBJECT_HEADER_QUOTA_INFO", "_OBJECT_HEADER_PROCESS_INFO", "_OBJECT_HEADER_AUDIT_INFO",
	"_OBJECT_HEADER_EXTENDED_INFO", "_OBJECT_HEADER_PADDING_INFO",
}

const (
	fxProcessSize = 0x100
	fxThreadSize  = 0x80
	fxFileSize    = 0x60
	fxMutantSize  = 0x38
	fxDriverSize  = 0x40
	fxLinkSize    = 0x20
	fxModuleSize  = 0x80
	fxAtomSize    = 0x28
)

func fxTable() *symbols.Table {
	t := symbols.NewTable("s52", 8)
	u := func(name string) symbols.TypeRef { return symbols.TypeRef{Name: name} }
	ptr := func(name string) symbols.TypeRef { return symbols.TypeRef{Name: name, IsPointer: true} }
	bits := func(off, n uint8) symbols.TypeRef {
		return symbols.TypeRef{Name: "unsigned short", BitOffset: off, BitLength: n}
	}
	add := func(name string, size uint64, fields ...symbols.Field) {
		t.AddStruct(symbols.StructType{Name: name, Size: size, Fields: fields})
	}
	add("_POOL_HEADER", fxHeaderLen,
		symbols.Field{Name: "PreviousSize", Offset: 0, Type: bits(0, 8)},
		symbols.Field{Name: "PoolIndex", Offset: 0, Type: bits(8, 8)},
		symbols.Field{Name: "BlockSize", Offset: 2, Type: bits(0, 8)},
		symbols.Field{Name: "PoolType", Offset: 2, Type: bits(8, 8)},
		symbols.Field{Name: "PoolTag", Offset: 4, Type: u("unsigned int")})
	add("_OBJECT_HEADER", 0x38,
		symbols.Field{Name: "PointerCount", Offset: 0, Type: u("long long")},
		symbols.Field{Name: "HandleCount", Offset: 8, Type: u("long long")},
		symbols.Field{Name: "TypeIndex", Offset: 0x18, Type: u("unsigned char")},
		symbols.Field{Name: "InfoMask", Offset: 0x1a, Type: u("unsigned char")},
		symbols.Field{Name: "Body", Offset: fxBodyAt, Type: u("_QUAD")})
	for bit, name := range fxOptionalNames {
		var fields []symbols.Field
		switch bit {
		case 1:
			fields = []symbols.Field{{Name: "Directory", Offset: 0, Type: ptr("_OBJECT_DIRECTORY")},
				{Name: "Name", Offset: 8, Type: u("_UNICODE_STRING")}}
		case 7:
			fields = []symbols.Field{{Name: "PaddingAmount", Offset: 0, Type: u("unsigned int")}}
		}
		add(name, fxOptional[bit], fields...)
	}
	add("_UNICODE_STRING", 16,
		symbols.Field{Name: "Length", Offset: 0, Type: u("unsigned short")},
		symbols.Field{Name: "MaximumLength", Offset: 2, Type: u("unsigned short")},
		symbols.Field{Name: "Buffer", Offset: 8, Type: ptr("wchar_t")})
	add("_DISPATCHER_HEADER", 0x18, symbols.Field{Name: "Type", Offset: 0, Type: u("unsigned char")})
	add("_KPROCESS", 0x40, symbols.Field{Name: "Header", Offset: 0, Type: u("_DISPATCHER_HEADER")})
	add("_EPROCESS", fxProcessSize,
		symbols.Field{Name: "Pcb", Offset: 0, Type: u("_KPROCESS")},
		symbols.Field{Name: "UniqueProcessId", Offset: 0x40, Type: ptr("void")},
		symbols.Field{Name: "ImageFileName", Offset: 0x80,
			Type: symbols.TypeRef{Name: "unsigned char", IsArray: true, ArrayLength: 15,
				Element: &symbols.TypeRef{Name: "unsigned char"}}})
	add("_KTHREAD", 0x40, symbols.Field{Name: "Header", Offset: 0, Type: u("_DISPATCHER_HEADER")})
	add("_CLIENT_ID", 16,
		symbols.Field{Name: "UniqueProcess", Offset: 0, Type: ptr("void")},
		symbols.Field{Name: "UniqueThread", Offset: 8, Type: ptr("void")})
	add("_ETHREAD", fxThreadSize,
		symbols.Field{Name: "Tcb", Offset: 0, Type: u("_KTHREAD")},
		symbols.Field{Name: "Cid", Offset: 0x48, Type: u("_CLIENT_ID")})
	add("_FILE_OBJECT", fxFileSize,
		symbols.Field{Name: "Type", Offset: 0, Type: u("short")},
		symbols.Field{Name: "FileName", Offset: 0x20, Type: u("_UNICODE_STRING")})
	add("_KMUTANT", fxMutantSize, symbols.Field{Name: "Header", Offset: 0, Type: u("_DISPATCHER_HEADER")})
	add("_DRIVER_OBJECT", fxDriverSize, symbols.Field{Name: "Type", Offset: 0, Type: u("short")})
	add("_OBJECT_SYMBOLIC_LINK", fxLinkSize)
	add("_KLDR_DATA_TABLE_ENTRY", fxModuleSize,
		symbols.Field{Name: "BaseDllName", Offset: 0x48, Type: u("_UNICODE_STRING")})
	add("_RTL_ATOM_TABLE", fxAtomSize)
	t.AddSymbol(symbols.Symbol{Name: "ObpInfoMaskToOffset", Address: fxMasksAt})
	return t
}

type fxMemory struct{ buf []byte }

func (m *fxMemory) ReadAt(off, size uint64) ([]byte, error) {
	if off > uint64(len(m.buf)) || size > uint64(len(m.buf))-off {
		return nil, memory.ErrOutOfBounds
	}
	return slices.Clone(m.buf[off : off+size]), nil
}

func (m *fxMemory) Size() uint64 { return uint64(len(m.buf)) }

func (m *fxMemory) u16(at uint64, v uint16) { binary.LittleEndian.PutUint16(m.buf[at:], v) }
func (m *fxMemory) u64(at uint64, v uint64) { binary.LittleEndian.PutUint64(m.buf[at:], v) }

type fxImage struct {
	mem     *fxMemory
	strings uint64
}

func newImage(pages int) *fxImage {
	img := &fxImage{mem: &fxMemory{buf: make([]byte, fxPoolAt+pages*0x1000)}, strings: fxStringsAt}
	for mask := range 256 {
		var n uint64
		for bit := range 8 {
			if mask&(1<<bit) != 0 {
				n += fxOptional[bit]
			}
		}
		img.mem.buf[fxMasksAt+uint64(mask)] = byte(n)
	}
	return img
}

// ustr writes a counted string descriptor at at, its characters in the
// image's string area.
func (img *fxImage) ustr(at uint64, s string) {
	u := utf16.Encode([]rune(s))
	buffer := img.strings
	for i, c := range u {
		img.mem.u16(buffer+uint64(i)*2, c)
	}
	img.strings += uint64(len(u)*2+15) &^ 15
	img.mem.u16(at, uint16(len(u)*2))
	img.mem.u16(at+2, uint16(len(u)*2))
	img.mem.u64(at+8, buffer)
}

type fxObject struct {
	pool     uint64
	tag      string
	poolType byte
	bodySize uint64
	name     string
	dispatch byte
}

// object writes a pool header, an optional name info when the object is
// named, the object header with counts 1 and 0, and returns the body.
func (img *fxImage) object(o fxObject) uint64 {
	var mask byte
	distance := uint64(0)
	if o.name != "" {
		mask, distance = 0x2, fxNameInfo
	}
	header := o.pool + fxHeaderLen + distance
	body := header + fxBodyAt
	blocks := (fxHeaderLen + distance + fxBodyAt + o.bodySize + 15) / 16
	img.mem.u16(o.pool+2, uint16(blocks)|uint16(o.poolType)<<8)
	copy(img.mem.buf[o.pool+4:], o.tag)
	if o.name != "" {
		img.ustr(header-fxNameInfo+8, o.name)
	}
	img.mem.u64(header, 1)
	img.mem.buf[header+0x1a] = mask
	img.mem.buf[body] = o.dispatch
	return body
}

func (img *fxImage) structure(pool uint64, tag string, size uint64) uint64 {
	img.mem.u16(pool+2, uint16((fxHeaderLen+size+15)/16)|2<<8)
	copy(img.mem.buf[pool+4:], tag)
	return pool + fxHeaderLen
}

func (img *fxImage) context(t symbols.SymbolTable) (tools.Context, *[]string) {
	var diags []string
	return tools.Context{
		Memory:  img.mem,
		Symbols: t,
		Profile: profiles.WindowsX64Profile{},
		Options: map[string]any{"diagnostics": &diags, tools.OptionPhysicalMemory: memory.MemoryReader(img.mem)},
	}, &diags
}
