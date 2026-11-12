package handlelist

import (
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/util"
)

// Build 26100 layouts of S30 T1 to T4.
const (
	s30Body       = 0x30
	s30InfoMask   = 0x1a
	s30MaskTable  = 0x100
	s30RootSymbol = 0x300
	s30Strings    = 0x8000
)

func s30Table() *symbols.Table {
	t := symbols.NewTable("s30", 8)
	u := func(n string) symbols.TypeRef { return symbols.TypeRef{Name: n} }
	bits := func(n string, off, length uint8) symbols.TypeRef {
		return symbols.TypeRef{Name: n, BitOffset: off, BitLength: length}
	}
	ptr := symbols.TypeRef{Name: "void", IsPointer: true}
	t.AddStruct(symbols.StructType{Name: "_OBJECT_HEADER", Size: 0x38, Fields: []symbols.Field{
		{Name: "InfoMask", Offset: s30InfoMask, Type: u("unsigned char")},
		{Name: "Body", Offset: s30Body, Type: u("_QUAD")},
	}})
	t.AddStruct(symbols.StructType{Name: "_OBJECT_HEADER_NAME_INFO", Size: 0x20, Fields: []symbols.Field{
		{Name: "Directory", Offset: 0, Type: ptr}, {Name: "Name", Offset: 8, Type: u("_UNICODE_STRING")},
	}})
	t.AddStruct(symbols.StructType{Name: "_UNICODE_STRING", Size: 16, Fields: []symbols.Field{
		{Name: "Length", Offset: 0, Type: u("unsigned short")},
		{Name: "MaximumLength", Offset: 2, Type: u("unsigned short")},
		{Name: "Buffer", Offset: 8, Type: ptr},
	}})
	t.AddStruct(symbols.StructType{Name: "_FILE_OBJECT", Size: 0xd8, Fields: []symbols.Field{
		{Name: "DeviceObject", Offset: 8, Type: ptr}, {Name: "FileName", Offset: 0x58, Type: u("_UNICODE_STRING")},
	}})
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x600, Fields: []symbols.Field{
		{Name: "UniqueProcessId", Offset: 0x440, Type: ptr},
		{Name: "ImageFileName", Offset: 0x5a8, Type: symbols.TypeRef{Name: "unsigned char", ArrayLength: 15, IsArray: true}},
	}})
	t.AddStruct(symbols.StructType{Name: "_ETHREAD", Size: 0x500, Fields: []symbols.Field{
		{Name: "Cid", Offset: 0x478, Type: u("_CLIENT_ID")},
	}})
	t.AddStruct(symbols.StructType{Name: "_CLIENT_ID", Size: 16, Fields: []symbols.Field{
		{Name: "UniqueProcess", Offset: 0, Type: ptr}, {Name: "UniqueThread", Offset: 8, Type: ptr},
	}})
	t.AddStruct(symbols.StructType{Name: "_CM_KEY_BODY", Size: 0x70, Fields: []symbols.Field{
		{Name: "KeyControlBlock", Offset: 8, Type: ptr},
	}})
	t.AddStruct(symbols.StructType{Name: "_CM_KEY_CONTROL_BLOCK", Size: 0x138, Fields: []symbols.Field{
		{Name: "TotalLevels", Offset: 8, Type: bits("unsigned int", 21, 10)},
		{Name: "ParentKcb", Offset: 0x48, Type: ptr},
		{Name: "NameBlock", Offset: 0x50, Type: ptr},
		{Name: "Flags", Offset: 0xb8, Type: bits("unsigned int", 16, 16)},
	}})
	t.AddStruct(symbols.StructType{Name: "_CM_NAME_CONTROL_BLOCK", Size: 0x20, Fields: []symbols.Field{
		{Name: "Compressed", Offset: 0, Type: bits("unsigned int", 0, 1)},
		{Name: "NameLength", Offset: 0x18, Type: u("unsigned short")},
		{Name: "Name", Offset: 0x1a, Type: symbols.TypeRef{Name: "wchar_t", ArrayLength: 1, IsArray: true}},
	}})
	t.AddSymbol(symbols.Symbol{Name: "ObpInfoMaskToOffset", Address: s30MaskTable})
	t.AddSymbol(symbols.Symbol{Name: "ObpRootDirectoryObject", Address: s30RootSymbol})
	return t
}

type s30Memory struct {
	*mockMemory
	next uint64
}

func newS30Memory() *s30Memory {
	m := &s30Memory{mockMemory: &mockMemory{buf: make([]byte, 0x10000)}, next: s30Strings}
	m.buf[s30MaskTable+2] = 0x20
	m.buf[s30MaskTable+3] = 0x40
	return m
}

func (m *s30Memory) text(at uint64, s string) {
	n := writeUTF16(m.buf, m.next, s)
	writeU16(m.buf, at, uint16(n))
	writeU16(m.buf, at+2, uint16(n))
	writeU64(m.buf, at+8, m.next)
	m.next += (n + 15) &^ 15
}

// A named object at header, its name info 0x20 in front.
func (m *s30Memory) named(header uint64, name string, directoryBody uint64) {
	m.buf[header+s30InfoMask] = 0x02
	writeU64(m.buf, header-0x20, directoryBody)
	m.text(header-0x20+8, name)
}

func (m *s30Memory) root(header uint64) { writeU64(m.buf, s30RootSymbol, header+s30Body) }

func s30Context(m *s30Memory, diags *[]string) tools.Context {
	return tools.Context{Memory: m, Symbols: s30Table(), Options: map[string]any{"diagnostics": diags}}
}

func readName(t *testing.T, m *s30Memory, typeName string, header uint64, steps int) (string, bool, []string) {
	t.Helper()
	var diags []string
	ctx := s30Context(m, &diags)
	n := newNameReader(ctx.Symbols, steps)
	name, unreadable := n.read(ctx, typeName, header)
	n.report(ctx)
	return name, unreadable, diags
}

func TestANamespacePathIsBuiltFromTheDirectoryChain(t *testing.T) {
	m := newS30Memory()
	m.root(0x1000)
	m.named(0x1100, "Sessions", 0x1000+s30Body)
	m.named(0x1200, "1", 0x1100+s30Body)
	m.named(0x1300, "BaseNamedObjects", 0x1200+s30Body)
	m.named(0x1400, "Evil\x00Tail", 0x1300+s30Body)
	for _, c := range []struct {
		header uint64
		want   string
	}{
		{0x1400, `\Sessions\1\BaseNamedObjects\Evil` + util.VisibleNUL + "Tail"},
		{0x1100, `\Sessions`},
		{0x1000, `\`},
	} {
		if got, unreadable, _ := readName(t, m, "Event", c.header, 16); got != c.want || unreadable {
			t.Errorf("header %#x: %q %v, want %q", c.header, got, unreadable, c.want)
		}
	}
}

func TestAPathNotAnchoredAtTheRootHasNoLeadingBackslash(t *testing.T) {
	m := newS30Memory()
	m.root(0x1000)
	m.named(0x1200, "KernelObjects", 0x1100+s30Body)
	m.named(0x1300, "LowMemoryCondition", 0x1200+s30Body)
	m.named(0x1400, "Default", 0)
	if got, _, _ := readName(t, m, "Event", 0x1300, 16); got != `KernelObjects\LowMemoryCondition` {
		t.Errorf("under an unnamed directory: %q", got)
	}
	if got, _, _ := readName(t, m, "Desktop", 0x1400, 16); got != "Default" {
		t.Errorf("with no directory: %q", got)
	}
	if got, unreadable, _ := readName(t, m, "Event", 0x1500, 16); got != "" || unreadable {
		t.Errorf("unnamed object: %q %v", got, unreadable)
	}
}

func TestACycleOrALongChainIsNotRead(t *testing.T) {
	m := newS30Memory()
	m.root(0x1000)
	m.named(0x1200, "a", 0x1300+s30Body)
	m.named(0x1300, "b", 0x1200+s30Body)
	if _, unreadable, diags := readName(t, m, "Event", 0x1200, 16); !unreadable || len(diags) != 1 ||
		!strings.Contains(diags[0], "1 namespace handle names did not read") {
		t.Errorf("cycle: unreadable %v, diags %q", unreadable, diags)
	}
	m.named(0x1300, "b", 0x1000+s30Body)
	if _, unreadable, diags := readName(t, m, "Event", 0x1200, 1); !unreadable ||
		!strings.Contains(diags[0], errPathTooLong.Error()) {
		t.Errorf("past MaxPathSteps: unreadable %v, diags %q", unreadable, diags)
	}
}

func TestAFileIsNamedByItsDeviceAndPath(t *testing.T) {
	m := newS30Memory()
	m.root(0x1000)
	m.named(0x1100, "Device", 0x1000+s30Body)
	m.named(0x1200, "HarddiskVolume3", 0x1100+s30Body)
	for _, c := range []struct{ file, want string }{
		{`\Windows\System32\config\SAM`, `\Device\HarddiskVolume3\Windows\System32\config\SAM`},
		{"", `\Device\HarddiskVolume3`},
		{"TxfLog", "TxfLog"},
	} {
		header := uint64(0x2000)
		writeU64(m.buf, header+s30Body+8, 0x1200+s30Body)
		m.text(header+s30Body+0x58, c.file)
		if got, unreadable, _ := readName(t, m, "File", header, 16); got != c.want || unreadable {
			t.Errorf("FileName %q: %q %v, want %q", c.file, got, unreadable, c.want)
		}
	}
}

type kcb struct {
	name       string
	wide, root bool
}

// Blocks are listed outermost first; the key body points at the last.
func (m *s30Memory) key(body uint64, levels uint32, chain []kcb) {
	parent := uint64(0)
	for i, k := range chain {
		block := 0x4000 + uint64(i)*0x200
		names := block + 0x140
		writeU64(m.buf, block+0x48, parent)
		writeU64(m.buf, block+0x50, names)
		writeU32(m.buf, block+8, levels<<21)
		if k.root {
			writeU32(m.buf, block+0xb8, hiveRootFlag<<16)
		}
		raw := []byte(k.name)
		if k.wide {
			raw = nil
			for _, u := range utf16.Encode([]rune(k.name)) {
				raw = append(raw, byte(u), byte(u>>8))
			}
		} else {
			writeU32(m.buf, names, 1)
		}
		writeU16(m.buf, names+0x18, uint16(len(raw)))
		copy(m.buf[names+0x1a:], raw)
		parent = block
	}
	writeU64(m.buf, body+8, parent)
}

func TestAKeyIsNamedOnceAcrossItsHiveMount(t *testing.T) {
	m := newS30Memory()
	header := uint64(0x2000)
	m.key(header+s30Body, 4, []kcb{{name: "REGISTRY", root: true}, {name: "MACHINE"}, {name: "SYSTEM"},
		{name: "SYSTEM", root: true}, {name: "CONTROLSET001", wide: true}})
	if got, unreadable, _ := readName(t, m, "Key", header, 16); got != `\REGISTRY\MACHINE\SYSTEM\CONTROLSET001` || unreadable {
		t.Fatalf("%q %v", got, unreadable)
	}
	m.key(header+s30Body, 5, []kcb{{name: "REGISTRY", root: true}, {name: "MACHINE"}, {name: "SYSTEM"},
		{name: "SYSTEM", root: true}, {name: "CONTROLSET001"}})
	if _, unreadable, diags := readName(t, m, "Key", header, 16); !unreadable ||
		!strings.Contains(diags[0], "4 levels, TotalLevels 5") {
		t.Fatalf("TotalLevels mismatch read: %v %q", unreadable, diags)
	}
	if _, unreadable, _ := readName(t, m, "Key", header, 3); !unreadable {
		t.Fatal("a chain past MaxPathSteps was read")
	}
}

func TestProcessAndThreadHandlesNameWhatTheyOpen(t *testing.T) {
	m := newS30Memory()
	header := uint64(0x2000)
	writeU64(m.buf, header+s30Body+0x440, 4)
	copy(m.buf[header+s30Body+0x5a8:], "System\x00junk")
	if got, _, _ := readName(t, m, "Process", header, 16); got != "System pid 4" {
		t.Errorf("process: %q", got)
	}
	writeU64(m.buf, header+s30Body+0x478, 1300)
	writeU64(m.buf, header+s30Body+0x478+8, 64)
	if got, _, _ := readName(t, m, "Thread", header, 16); got != "tid 64 pid 1300" {
		t.Errorf("thread: %q", got)
	}
}

func FuzzKeyLevel(f *testing.F) {
	f.Add([]byte("CONTROLSET001"), true)
	f.Add([]byte{0x41, 0, 0, 0xd8}, false)
	f.Fuzz(func(t *testing.T, raw []byte, compressed bool) {
		got := decodeKeyLevel(raw, compressed)
		if compressed && len([]rune(got)) != len(raw) {
			t.Fatalf("%d bytes gave %d characters", len(raw), len([]rune(got)))
		}
	})
}
