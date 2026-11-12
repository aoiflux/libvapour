package modulelist

import (
	"encoding/binary"
	"fmt"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const page = uint64(0x1000)

type sparse map[uint64][]byte

func (m sparse) Size() uint64 { return ^uint64(0) }

func (m sparse) ReadAt(at, n uint64) ([]byte, error) {
	out := make([]byte, 0, n)
	for i := uint64(0); i < n; i++ {
		p, ok := m[(at+i)&^(page-1)]
		if !ok {
			return nil, fmt.Errorf("sparse: 0x%x not mapped", at+i)
		}
		out = append(out, p[(at+i)&(page-1)])
	}
	return out, nil
}

func (m sparse) write(at uint64, b []byte) {
	for i := range b {
		base := (at + uint64(i)) &^ (page - 1)
		if m[base] == nil {
			m[base] = make([]byte, page)
		}
		m[base][(at+uint64(i))&(page-1)] = b[i]
	}
}

func (m sparse) u64(at, v uint64) { m.write(at, binary.LittleEndian.AppendUint64(nil, v)) }
func (m sparse) u32(at uint64, v uint32) {
	m.write(at, binary.LittleEndian.AppendUint32(nil, v))
}
func (m sparse) u16(at uint64, v uint16) {
	m.write(at, binary.LittleEndian.AppendUint16(nil, v))
}

// The _KLDR_DATA_TABLE_ENTRY offsets of the 26100, 19045 and 14393 kernel
// tables (S55 T1).
const (
	offLinks    = 0x00
	offDllBase  = 0x30
	offSize     = 0x40
	offFullName = 0x48
	offBaseName = 0x58
	entryBytes  = 0xa0

	listHead    = uint64(0xfffff80000001000)
	rangeStart  = uint64(0xfffff80000002000)
	entryArea   = uint64(0xffffa00000100000)
	systemStart = uint64(0xffff800000000000)
)

type fixMod struct {
	base, size uint64
	name, path string
}

func field(name string, off uint64, typ string) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: typ}}
}

func loaderTable(entryType string, withFull bool) *symbols.Table {
	t := symbols.NewTable("s55", 8)
	t.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 16, Fields: []symbols.Field{
		field("Flink", 0, "_LIST_ENTRY"), field("Blink", 8, "_LIST_ENTRY")}})
	t.AddStruct(symbols.StructType{Name: "_UNICODE_STRING", Size: 16, Fields: []symbols.Field{
		field("Length", 0, "unsigned short"), field("MaximumLength", 2, "unsigned short"), field("Buffer", 8, "wchar_t")}})
	fields := []symbols.Field{
		field("InLoadOrderLinks", offLinks, "_LIST_ENTRY"), field("DllBase", offDllBase, "void"),
		field("SizeOfImage", offSize, "unsigned int"), field("BaseDllName", offBaseName, "_UNICODE_STRING"),
	}
	if withFull {
		fields = append(fields, field("FullDllName", offFullName, "_UNICODE_STRING"))
	}
	t.AddStruct(symbols.StructType{Name: entryType, Size: entryBytes, Fields: fields})
	t.AddSymbol(symbols.Symbol{Name: "PsLoadedModuleList", Address: listHead})
	t.AddSymbol(symbols.Symbol{Name: "MmSystemRangeStart", Address: rangeStart})
	return t
}

func entryAt(i int) uint64 { return entryArea + uint64(i)*page }

func (m sparse) text(at, buffer uint64, s string) {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	m.u16(at, uint16(len(b)))
	m.u16(at+2, uint16(len(b)+2))
	m.u64(at+8, buffer)
	m.write(buffer, b)
}

// Each entry sits at the start of its own page, its strings after it.
func loaderList(mods []fixMod) sparse {
	m := sparse{}
	m.u64(rangeStart, systemStart)
	links := []uint64{listHead}
	for i := range mods {
		links = append(links, entryAt(i)+offLinks)
	}
	links = append(links, listHead)
	for i := 1; i < len(links)-1; i++ {
		m.u64(links[i], links[i+1])
		m.u64(links[i]+8, links[i-1])
	}
	m.u64(listHead, links[1])
	m.u64(listHead+8, links[len(links)-2])
	for i, mod := range mods {
		e := entryAt(i)
		m.u64(e+offDllBase, mod.base)
		m.u32(e+offSize, uint32(mod.size))
		m.u32(e+offSize+4, 0xa5a5a5a5)
		m.text(e+offBaseName, e+0x400, mod.name)
		m.text(e+offFullName, e+0x800, mod.path)
	}
	return m
}

var threeMods = []fixMod{
	{0xfffff80001000000, 0x1046000, "ntoskrnl.exe", `\SystemRoot\system32\ntoskrnl.exe`},
	{0xfffff80003000000, 0x6000, "kdcom.dll", `\SystemRoot\system32\kd.dll`},
	{0xfffff80004000000, 0x20000, "acme.sys", `\??\C:\acme.sys`},
}

func windowsContext(m sparse, t *symbols.Table, opts map[string]any) (tools.Context, *[]string) {
	diags := &[]string{}
	o := map[string]any{"diagnostics": diags}
	for k, v := range opts {
		o[k] = v
	}
	return tools.Context{Memory: m, Symbols: t, Profile: profiles.WindowsX64Profile{}, Options: o}, diags
}

func hasDiag(diags []string, want string) bool {
	for _, d := range diags {
		if d == want {
			return true
		}
	}
	return false
}

func mustRun(t *testing.T, ctx tools.Context) []Module {
	t.Helper()
	mods, err := Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return mods
}
