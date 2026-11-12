package registryhivescan

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// The fixture follows S63 P1 and P2 with the 26100 sizes of M2.
const (
	fxCMHIVESize   = 0x12d8
	fxPoolSize     = 0x12e0
	fxFileFullPath = 0x720
	fxFileUserName = 0x730
	fxHiveRootPath = 0x740
	fxHiveList     = 0x648
)

type fxMemory struct{ pages map[uint64][]byte }

const fxPage = 0x1000

func newMemory() *fxMemory { return &fxMemory{pages: map[uint64][]byte{}} }

func (m *fxMemory) write(at uint64, b []byte) {
	for i, c := range b {
		a := at + uint64(i)
		p := m.pages[a&^(fxPage-1)]
		if p == nil {
			p = make([]byte, fxPage)
			m.pages[a&^(fxPage-1)] = p
		}
		p[a&(fxPage-1)] = c
	}
}

func (m *fxMemory) u32(at uint64, v uint32) { m.write(at, binary.LittleEndian.AppendUint32(nil, v)) }
func (m *fxMemory) u64(at uint64, v uint64) { m.write(at, binary.LittleEndian.AppendUint64(nil, v)) }

func (m *fxMemory) ReadAt(at, n uint64) ([]byte, error) {
	out := make([]byte, n)
	for i := uint64(0); i < n; i++ {
		p := m.pages[(at+i)&^(fxPage-1)]
		if p == nil {
			return nil, memory.ErrOutOfBounds
		}
		out[i] = p[(at+i)&(fxPage-1)]
	}
	return out, nil
}

func (m *fxMemory) Size() uint64 { return 1 << 63 }

func fxTable() *symbols.Table {
	t := symbols.NewTable("s63", 8)
	f := func(name string, off uint64) symbols.Field { return symbols.Field{Name: name, Offset: off} }
	t.AddStruct(symbols.StructType{Name: "_CMHIVE", Size: fxCMHIVESize, Fields: []symbols.Field{
		f("Hive", 0), f("HiveList", fxHiveList), f("FileFullPath", fxFileFullPath), f("FileUserName", fxFileUserName),
		f("HiveRootPath", fxHiveRootPath)}})
	t.AddStruct(symbols.StructType{Name: "_HHIVE", Size: 0x608, Fields: []symbols.Field{f("Signature", 0)}})
	t.AddStruct(symbols.StructType{Name: "_UNICODE_STRING", Size: 16, Fields: []symbols.Field{
		f("Length", 0), f("MaximumLength", 2), f("Buffer", 8)}})
	t.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 16, Fields: []symbols.Field{f("Flink", 0), f("Blink", 8)}})
	return t
}

func (m *fxMemory) unicode(at, buffer uint64, s string) {
	units := utf16.Encode([]rune(s))
	raw := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], u)
	}
	m.write(at, binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(nil, uint16(len(raw))), uint16(len(raw))))
	m.u64(at+8, buffer)
	m.write(buffer, raw)
}

func (m *fxMemory) hive(at uint64, file, root string) {
	m.u32(at, hiveSignature)
	if file != "" {
		m.unicode(at+fxFileUserName, at+0x2000, file)
	}
	if root != "" {
		m.unicode(at+fxHiveRootPath, at+0x2400, root)
	}
}

func fxContext(m *fxMemory, t *symbols.Table, diags *[]string, strict bool) tools.Context {
	return tools.Context{Memory: m, Symbols: t, Options: map[string]any{"diagnostics": diags, "strict": strict}}
}
