package linuxobj_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const coreBase = lt.Base + 0x100000

func coreKernel(t *testing.T, mode string, width uint8) (*linuxobj.Kernel, *lt.Memory, *symbols.Table) {
	t.Helper()
	mem := lt.NewMemory()
	tab := symbols.NewTable("s46core", width)
	f := func(name string, off uint64, typ symbols.TypeRef) symbols.Field {
		return symbols.Field{Name: name, Offset: off, Type: typ}
	}
	scalar := func(name string) symbols.TypeRef { return symbols.TypeRef{Name: name} }
	tab.AddStruct(symbols.StructType{Name: "rec", Size: 0x40, Fields: []symbols.Field{
		f("small", 0x00, scalar("short int")),
		f("word", 0x04, scalar("unsigned int")),
		f("count", 0x08, scalar("long int")),
		f("big", 0x10, scalar("long long unsigned int")),
		f("ptr", 0x18, symbols.TypeRef{Name: "rec", IsPointer: true, Element: &symbols.TypeRef{Name: "rec"}}),
		f("name", 0x20, symbols.TypeRef{Name: "char", IsArray: true, ArrayLength: 8, Element: &symbols.TypeRef{Name: "char"}}),
		f("bits", 0x28, symbols.TypeRef{Name: "int", BitOffset: 4, BitLength: 4}),
		f("blob", 0x30, scalar("rec")),
	}})
	tab.AddSymbol(symbols.Symbol{Name: "the_rec", Address: coreBase, Type: "rec"})
	mem.Map(coreBase, 0x1000)
	ctx := tools.Context{Memory: mem, Symbols: tab, Profile: profiles.LinuxX64Profile{},
		Options: map[string]any{tools.OptionPagingMode: mode}}
	return linuxobj.New(ctx), mem, tab
}

func TestAddressFormsFollowThePagingMode(t *testing.T) {
	cases := []struct {
		mode      string
		width     uint8
		mask      uint64
		in, canon uint64
	}{
		{"linux-x64", 8, 1<<48 - 1, 0x0000_8000_0000_1000, 0xffff_8000_0000_1000},
		{"linux-x64", 8, 1<<48 - 1, 0x1234_7fff_ffff_f000, 0x0000_7fff_ffff_f000},
		{"linux-la57", 8, 1<<57 - 1, 0x0100_0000_0000_0000, 0xff00_0000_0000_0000},
		{"", 8, 1<<48 - 1, 0xffff_8880_0000_0000, 0xffff_8880_0000_0000},
		{"linux-x86pae", 4, 1<<32 - 1, 0x1_c000_0000, 0xc000_0000},
	}
	for _, c := range cases {
		k, _, _ := coreKernel(t, c.mode, c.width)
		if k.AddressMask() != c.mask {
			t.Errorf("%q: mask %#x, want %#x", c.mode, k.AddressMask(), c.mask)
		}
		if got := k.Canonical(c.in); got != c.canon {
			t.Errorf("%q: canonical %#x = %#x, want %#x", c.mode, c.in, got, c.canon)
		}
		if got := k.Masked(c.canon); got != c.canon&c.mask {
			t.Errorf("%q: masked %#x = %#x", c.mode, c.canon, got)
		}
	}
}

func TestIntegerMembersReadAtTheirWidthAndSign(t *testing.T) {
	k, mem, _ := coreKernel(t, "linux-x64", 8)
	mem.Write(coreBase, []byte{0xfe, 0xff, 0x77, 0x77})
	mem.U32(coreBase+4, 0xffff_fff0)
	mem.U64(coreBase+8, ^uint64(2))
	mem.U64(coreBase+0x10, 1<<63)
	mem.U32(coreBase+0x28, 0x0000_00f0)
	if v, err := k.Int(mem, coreBase, "rec", "small"); err != nil || v != -2 {
		t.Errorf("short int: %d, %v; want -2 from two bytes", v, err)
	}
	if v, err := k.Int(mem, coreBase, "rec", "word"); err != nil || v != 0xffff_fff0 {
		t.Errorf("unsigned int read by Int: %#x, %v; want no sign extension", v, err)
	}
	if v, err := k.Int(mem, coreBase, "rec", "count"); err != nil || v != -3 {
		t.Errorf("long int: %d, %v; want -3 from eight bytes", v, err)
	}
	if v, err := k.Uint(mem, coreBase, "rec", "big"); err != nil || v != 1<<63 {
		t.Errorf("u64: %#x, %v", v, err)
	}
	if v, err := k.Int(mem, coreBase, "rec", "bits"); err != nil || v != -1 {
		t.Errorf("4-bit signed field of 0xf: %d, %v; want -1", v, err)
	}
	if v, err := k.Uint(mem, coreBase, "rec", "bits"); err != nil || v != 0xf {
		t.Errorf("4-bit field as unsigned: %d, %v", v, err)
	}
	if _, err := k.Uint(mem, coreBase, "rec", "name"); !errors.Is(err, linuxobj.ErrNotInteger) {
		t.Errorf("array as integer: %v, want ErrNotInteger", err)
	}
	if _, err := k.Uint(mem, coreBase, "rec", "missing"); !linuxobj.TableGap(err) {
		t.Errorf("missing member: %v, want a table gap", err)
	}
	if _, err := k.Uint(mem, coreBase+0x2000, "rec", "word"); err == nil || !strings.Contains(err.Error(), "rec.word at 0x") {
		t.Errorf("unreadable member: %v", err)
	}
}

func TestBaseTypeSizesFollowTheKernelDataModel(t *testing.T) {
	k, _, _ := coreKernel(t, "linux-x64", 8)
	for name, want := range map[string]uint64{"char": 1, "unsigned char": 1, "short int": 2, "int": 4,
		"unsigned int": 4, "long int": 8, "long unsigned int": 8, "long long int": 8, "long": 8, "rec": 0x40} {
		if got, err := k.SizeOf(name); err != nil || got != want {
			t.Errorf("SizeOf(%q) = %d, %v; want %d", name, got, err, want)
		}
	}
	if _, err := k.SizeOf("no_such_type"); err == nil {
		t.Error("an unknown type has a size")
	}
	k32, _, _ := coreKernel(t, "linux-x86pae", 4)
	if got, _ := k32.SizeOf("long unsigned int"); got != 4 {
		t.Errorf("32-bit long is %d bytes, want 4", got)
	}
}

func TestPointersAndDereferences(t *testing.T) {
	k, mem, tab := coreKernel(t, "linux-x64", 8)
	other := coreBase + 0x400
	mem.U64(coreBase+0x18, other)
	if v, err := k.Pointer(mem, coreBase, "rec", "ptr"); err != nil || v != other {
		t.Errorf("Pointer: %#x, %v", v, err)
	}
	if v, err := k.PointerAt(mem, coreBase+0x18); err != nil || v != other {
		t.Errorf("PointerAt: %#x, %v", v, err)
	}
	if v, ok, err := k.Deref(mem, coreBase, "rec", "ptr"); err != nil || !ok || v != other {
		t.Errorf("Deref of a readable object: %#x %t %v", v, ok, err)
	}
	mem.U64(coreBase+0x18, coreBase+0xfe0)
	if _, ok, err := k.Deref(mem, coreBase, "rec", "ptr"); err != nil || ok {
		t.Errorf("Deref of an object running off mapped memory: ok %t, %v", ok, err)
	}
	mem.U64(coreBase+0x18, 0)
	if v, ok, err := k.Deref(mem, coreBase, "rec", "ptr"); err != nil || ok || v != 0 {
		t.Errorf("Deref of null: %#x %t %v", v, ok, err)
	}
	f, _ := tab.Field("rec", "ptr")
	if n := k.PointeeSize(f); n != 0x40 {
		t.Errorf("PointeeSize = %d", n)
	}
	if n := k.PointeeSize(symbols.Field{Type: symbols.TypeRef{IsPointer: true, Element: &symbols.TypeRef{Name: "void"}}}); n != 0 {
		t.Errorf("void pointee size %d", n)
	}
}

func TestReadableNeedsEveryByte(t *testing.T) {
	k, _, _ := coreKernel(t, "linux-x64", 8)
	if !k.Readable(coreBase, 0x1000) || !k.Readable(coreBase+0xfff, 0) {
		t.Error("a mapped page does not read")
	}
	if k.Readable(coreBase+0xff0, 0x20) {
		t.Error("a range into an unmapped page reads")
	}
	if k.Readable(^uint64(0)-4, 16) {
		t.Error("a range that wraps reads")
	}
}

func TestStringsStopAtNULAndAtTheCount(t *testing.T) {
	k, mem, _ := coreKernel(t, "linux-x64", 8)
	mem.Write(coreBase+0x20, []byte("comm\x00xyz"))
	if s, err := k.CharArray(mem, coreBase, "rec", "name"); err != nil || s != "comm" {
		t.Errorf("CharArray: %q, %v", s, err)
	}
	mem.Write(coreBase+0x20, []byte("12345678"))
	if s, err := k.CharArray(mem, coreBase, "rec", "name"); err != nil || s != "12345678" {
		t.Errorf("full CharArray: %q, %v", s, err)
	}
	if _, err := k.CharArray(mem, coreBase, "rec", "word"); !errors.Is(err, linuxobj.ErrNotArray) {
		t.Errorf("CharArray of an integer: %v", err)
	}
	end := coreBase + 0x1000 - 3
	mem.Write(end, []byte("ab\x00"))
	if s, err := k.StringAt(end, 4096); err != nil || s != "ab" {
		t.Errorf("string ending before an unmapped page: %q, %v", s, err)
	}
	mem.Write(end, []byte("abc"))
	if _, err := k.StringAt(end, 4096); err == nil {
		t.Error("a string running into an unmapped page read")
	}
	if s, err := k.StringAt(end, 2); err != nil || s != "ab" {
		t.Errorf("string cut at its count: %q, %v", s, err)
	}
}

func TestTableQueries(t *testing.T) {
	k, _, _ := coreKernel(t, "linux-x64", 8)
	if !k.Has("rec", "word") || k.Has("rec", "nope") || !k.HasType("rec") || k.HasType("nope") {
		t.Error("Has or HasType wrong")
	}
	if !k.HasSymbol("the_rec") || k.HasSymbol("nope") {
		t.Error("HasSymbol wrong")
	}
	if s, err := k.Symbol("the_rec"); err != nil || s.Address != coreBase {
		t.Errorf("Symbol: %+v, %v", s, err)
	}
	if _, err := k.Symbol("nope"); err == nil || !strings.HasPrefix(err.Error(), "linuxobj: symbol nope") {
		t.Errorf("missing symbol: %v", err)
	}
	if names := k.SymbolsAt(coreBase); len(names) != 1 || names[0] != "the_rec" {
		t.Errorf("SymbolsAt: %v", names)
	}
	if names, listed := k.SymbolNames(); !listed || len(names) != 1 {
		t.Errorf("SymbolNames: %v %t", names, listed)
	}
	if k.PointerSize() != 8 {
		t.Error("pointer size")
	}
}

func TestModulesAreBuiltOnceFromTheSharedModel(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	mods := lt.AddModuleTypes(k)
	mod := mods.Add("alpha", lt.Base+0x40000, 0x2000, nil, 1)
	mods.List(mod)
	ctx, _ := k.Context(nil)
	kk := linuxobj.New(ctx)
	a, err := kk.Modules()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := kk.Modules()
	if a != b {
		t.Error("the model is built twice")
	}
	m, err := a.Read(mod)
	if err != nil || m.Name != "alpha" {
		t.Errorf("module read through the model: %+v, %v", m, err)
	}
}
