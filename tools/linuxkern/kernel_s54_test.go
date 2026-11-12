package linuxkern_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	lt "github.com/aoiflux/libvapour/symbols/linuxkernel/linuxtest"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

const (
	shift   = 0x1c000000
	sample  = 0xffffffff83100000
	sample2 = sample + 0x1000
	mask48  = 1<<48 - 1
)

func sampleTypes(ptr uint64) *kerntest.Types {
	i := kerntest.NewTypes(ptr)
	i.Enum("packed_kind", 1, "unsigned char", map[string]int64{"KIND_A": 0, "KIND_B": 1})
	i.Struct("inner", 8, map[string]kerntest.F{"val": {Off: 4, Type: kerntest.Base("int")}})
	i.Struct("atomic_t", 4, map[string]kerntest.F{"counter": {Off: 0, Type: kerntest.Base("int")}})
	i.Struct("other", 0x20, map[string]kerntest.F{"x": {Off: 0, Type: kerntest.Base("int")}})
	i.Struct("sample", 0x58, map[string]kerntest.F{
		"i32":    {Off: 0x00, Type: kerntest.Base("int")},
		"u16":    {Off: 0x04, Type: kerntest.Base("short unsigned int")},
		"flag":   {Off: 0x08, Type: kerntest.Bits(3, 4, "unsigned int")},
		"plain":  {Off: 0x08, Type: kerntest.Bits(0, 3, "int")},
		"past":   {Off: 0x08, Type: kerntest.Bits(30, 4, "unsigned int")},
		"sc":     {Off: 0x0c, Type: kerntest.Bits(2, 4, "signed char")},
		"kind":   {Off: 0x0d, Type: kerntest.Enum("packed_kind")},
		"l":      {Off: 0x10, Type: kerntest.Base("long int")},
		"ptr":    {Off: 0x18, Type: kerntest.Ptr(kerntest.Struct("other"))},
		"addr":   {Off: 0x20, Type: kerntest.Base("long unsigned int")},
		"name":   {Off: 0x28, Type: kerntest.Arr(16, kerntest.Base("char"))},
		"wide":   {Off: 0x38, Type: kerntest.Arr(4, kerntest.Base("short unsigned int"))},
		"nest":   {Off: 0x40, Type: kerntest.Struct("inner")},
		"atom":   {Off: 0x48, Type: kerntest.Struct("atomic_t")},
		"vp":     {Off: 0x50, Type: kerntest.Ptr(kerntest.Void())},
		"chars":  {Off: 0x50, Type: kerntest.Arr(0, kerntest.Base("char"))},
		"nested": {Off: 0x18, Type: kerntest.Ptr(kerntest.Struct("inner"))},
	})
	return i
}

func sampleKernel(t *testing.T, opts map[string]any) (*linuxkern.Kernel, *kerntest.Memory) {
	t.Helper()
	mem := kerntest.NewMemory()
	mem.Map(sample, 0x2000)
	ctx, _ := kerntest.Context(mem, sampleTypes(8).Table(t), opts)
	k, err := linuxkern.New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return k, mem
}

func TestTheAddressFormFollowsPointerSizeAndPagingMode(t *testing.T) {
	for _, c := range []struct {
		ptr  uint64
		mode string
		mask uint64
	}{
		{8, "", 1<<48 - 1}, {8, "linux-x64", 1<<48 - 1}, {8, "linux-la57", 1<<57 - 1}, {4, "linux-x86pae", 1<<32 - 1},
	} {
		if got := linuxkern.AddressMask(c.ptr, c.mode); got != c.mask {
			t.Errorf("AddressMask(%d, %q) = %#x, want %#x", c.ptr, c.mode, got, c.mask)
		}
	}
	for _, c := range []struct{ addr, mask, want uint64 }{
		{0x0000ffff81000000, 1<<48 - 1, 0xffffffff81000000},
		{0x00007fff81000000, 1<<48 - 1, 0x00007fff81000000},
		{0x01ffffff81000000, 1<<57 - 1, 0xffffffff81000000},
		{0xffffffffc0001000, 1<<32 - 1, 0xc0001000},
	} {
		if got := linuxkern.CanonicalAddress(c.addr, c.mask); got != c.want {
			t.Errorf("CanonicalAddress(%#x, %#x) = %#x, want %#x", c.addr, c.mask, got, c.want)
		}
	}
	k, _ := sampleKernel(t, map[string]any{"paging_mode": "linux-la57"})
	if k.Mask != 1<<57-1 || k.PtrSize != 8 {
		t.Errorf("la57 kernel: mask %#x, pointer %d", k.Mask, k.PtrSize)
	}
	ctx, _ := kerntest.Context(kerntest.NewMemory(), sampleTypes(4).Table(t), nil)
	k4, err := linuxkern.New(ctx)
	if err != nil || k4.Mask != 1<<32-1 || k4.PtrSize != 4 {
		t.Errorf("4-byte kernel: %+v, %v", k4, err)
	}
}

func TestNewRefusesAProfileThatIsNotLinux(t *testing.T) {
	ctx, _ := kerntest.Context(kerntest.NewMemory(), sampleTypes(8).Table(t), nil)
	ctx.Profile = profiles.WindowsX64Profile{}
	if _, err := linuxkern.New(ctx); err == nil || !strings.Contains(err.Error(), "is not linux") {
		t.Errorf("New on a windows profile: %v", err)
	}
}

func TestSymbolsAreMaskedAndReadsPutThemBackInCanonicalForm(t *testing.T) {
	f := kerntest.NewFixture(shift)
	ctx, _ := f.Context(t, nil)
	k, err := linuxkern.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	at, err := k.Symbol("modules")
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(kerntest.ModulesSym+shift) & mask48; at != want {
		t.Errorf("modules = %#x, want %#x", at, want)
	}
	next, err := k.ReadPointer(at)
	if err != nil || next != at {
		t.Errorf("empty list next = %#x, %v, want the masked head %#x", next, err, at)
	}
	if c := k.Canonical(at); c != kerntest.ModulesSym+shift {
		t.Errorf("Canonical(%#x) = %#x", at, c)
	}
	if _, err := k.Symbol("no_such_symbol"); !errors.Is(err, linuxkern.ErrNoSymbol) {
		t.Errorf("missing symbol: %v", err)
	}
	if k.HasSymbol("no_such_symbol") || !k.HasSymbol("modules") {
		t.Error("HasSymbol")
	}
}

func TestReadIsExactAndReadableNeedsEveryPage(t *testing.T) {
	k, mem := sampleKernel(t, nil)
	mem.Write(sample, []byte{1, 2, 3, 4})
	b, err := k.Read(sample, 4)
	if err != nil || string(b) != "\x01\x02\x03\x04" {
		t.Errorf("Read = %v, %v", b, err)
	}
	if b, err := k.Read(sample, 0); err != nil || len(b) != 0 {
		t.Errorf("zero-byte read = %v, %v", b, err)
	}
	if _, err := k.Read(^uint64(0)-1, 4); err == nil {
		t.Error("a read past the top of the address space succeeded")
	}
	if !k.Valid(sample+0xff0, 0x20) || !k.Readable(sample, 0) {
		t.Error("mapped range not readable")
	}
	if k.Valid(sample+0x1ff0, 0x20) || linuxkern.Readable(mem, ^uint64(0), 2) {
		t.Error("range into an unmapped page, or wrapping, is readable")
	}
	padded := k.ReadPadded(sample+0x1ffe, 4)
	if len(padded) != 4 || padded[2] != 0 || padded[3] != 0 {
		t.Errorf("ReadPadded = %v", padded)
	}
}

func TestReadUintTakesOneToEightBytes(t *testing.T) {
	k, mem := sampleKernel(t, nil)
	mem.Write(sample, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	if v, err := k.ReadUint(sample, 3); err != nil || v != 0x332211 {
		t.Errorf("3-byte read = %#x, %v", v, err)
	}
	for _, w := range []uint64{0, 9} {
		if _, err := k.ReadUint(sample, w); err == nil {
			t.Errorf("%d-byte read succeeded", w)
		}
	}
}

func TestMemberPathsAndTypeSizes(t *testing.T) {
	k, _ := sampleKernel(t, nil)
	m, err := k.Member("sample", "nest.val")
	if err != nil || m.Offset != 0x44 || m.Parent != "inner" || m.Field.Name != "val" {
		t.Errorf("nest.val = %+v, %v", m, err)
	}
	if _, err := k.Member("sample", "nested.val"); err == nil {
		t.Error("a path went through a pointer")
	}
	if _, err := k.Member("sample", "missing"); err == nil || !k.HasMember("sample", "nest.val") || k.HasMember("sample", "nope") {
		t.Errorf("missing member: %v", err)
	}
	if !k.HasType("sample") || !k.HasType("packed_kind") || k.HasType("nothing") {
		t.Error("HasType")
	}
	for name, want := range map[string]uint64{"sample": 0x58, "long int": 8, "packed_kind": 1} {
		if n, err := k.TypeSize(name); err != nil || n != want {
			t.Errorf("TypeSize(%s) = %d, %v, want %d", name, n, err, want)
		}
	}
	if _, err := k.TypeSize("nothing"); err == nil {
		t.Error("TypeSize of an unknown type")
	}
	for _, c := range []struct {
		name string
		ptr  uint64
		want uint64
	}{{"long int", 4, 4}, {"long int", 8, 8}, {"size_t", 8, 8}, {"u16", 8, 2}, {"__s64", 4, 8}, {"_Bool", 8, 1}, {"widget", 8, 0}} {
		if got := linuxkern.CWidth(c.name, c.ptr); got != c.want {
			t.Errorf("CWidth(%q, %d) = %d, want %d", c.name, c.ptr, got, c.want)
		}
	}
	m, _ = k.Member("sample", "ptr")
	if n := k.PointeeSize(m); n != 0x20 {
		t.Errorf("PointeeSize(ptr) = %d", n)
	}
	m, _ = k.Member("sample", "vp")
	if n := k.PointeeSize(m); n != 0 {
		t.Errorf("PointeeSize(void *) = %d", n)
	}
	m, _ = k.Member("sample", "wide")
	if n, err := k.ElementSize(m); err != nil || n != 2 {
		t.Errorf("ElementSize(wide) = %d, %v", n, err)
	}
}

func TestIntegersTakeTheirWidthAndSignFromTheirType(t *testing.T) {
	k, mem := sampleKernel(t, nil)
	mem.U32(sample, 0xfffffffe)
	mem.U16(sample+4, 0xffff)
	mem.U32(sample+8, 0b1010_111|0b1111<<3)
	mem.U8(sample+0x0c, 0b1111<<2)
	mem.Write(sample+0x0d, []byte{0x01, 0x55})
	mem.U64(sample+0x10, ^uint64(0))
	mem.U32(sample+0x48, 0xffffffff)
	for _, c := range []struct {
		member string
		u      uint64
		i      int64
	}{
		{"i32", 0xfffffffe, -2},
		{"u16", 0xffff, 0xffff},
		{"flag", 0b1111, 0b1111},
		{"plain", 0b111, 0b111},
		{"sc", 0b1111, -1},
		{"kind", 1, 1},
		{"l", ^uint64(0), -1},
		{"nest.val", 0, 0},
		{"atom", 0xffffffff, 0xffffffff},
	} {
		u, err := k.Uint(sample, "sample", c.member)
		if err != nil || u != c.u {
			t.Errorf("Uint(%s) = %#x, %v, want %#x", c.member, u, err, c.u)
		}
		i, err := k.Int(sample, "sample", c.member)
		if err != nil || i != c.i {
			t.Errorf("Int(%s) = %d, %v, want %d", c.member, i, err, c.i)
		}
	}
	for _, member := range []string{"past", "name", "wide"} {
		if _, err := k.Uint(sample, "sample", member); !errors.Is(err, linuxkern.ErrNotInteger) {
			t.Errorf("Uint(%s): %v, want ErrNotInteger", member, err)
		}
	}
	if _, err := k.Uint(sample+0x2000, "sample", "i32"); err == nil {
		t.Error("Uint on unmapped memory succeeded")
	}
}

func TestPtrTakesPointersAndAddressWideUnsignedMembers(t *testing.T) {
	k, mem := sampleKernel(t, nil)
	mem.U64(sample+0x18, 0xffffffff83100100)
	mem.U64(sample+0x20, 0xffffffffc0001000)
	if p, err := k.Ptr(sample, "sample", "ptr"); err != nil || p != 0xffffffff83100100&mask48 {
		t.Errorf("Ptr(ptr) = %#x, %v", p, err)
	}
	if p, err := k.Ptr(sample, "sample", "addr"); err != nil || p != 0xffffffffc0001000&mask48 {
		t.Errorf("Ptr(addr) = %#x, %v", p, err)
	}
	for _, member := range []string{"i32", "l", "name"} {
		if _, err := k.Ptr(sample, "sample", member); err == nil {
			t.Errorf("Ptr(%s) read a member that holds no address", member)
		}
	}
}

func TestSymbolsAtGivesNamesInOrder(t *testing.T) {
	f := kerntest.NewFixture(shift)
	f.Types.Symbol("text_alias", kerntest.Text, kerntest.Fn())
	ctx, _ := f.Context(t, nil)
	k, _ := linuxkern.New(ctx)
	names, ok := k.SymbolsAt((kerntest.Text + shift) & mask48)
	if !ok || strings.Join(names, ",") != "_text,text_alias" {
		t.Errorf("SymbolsAt = %v, %v", names, ok)
	}
	ctx.Symbols = unlisted{ctx.Symbols}
	k, _ = linuxkern.New(ctx)
	if _, ok := k.SymbolsAt(kerntest.Text + shift); ok {
		t.Error("a table with no address index answered")
	}
}

func TestTheModuleModelIsBuiltOncePerKernel(t *testing.T) {
	f := kerntest.NewFixture(shift)
	at := uint64(kerntest.ModuleArea + 0x10000)
	f.AddModule(kerntest.ModuleSpec{At: at, Name: "ext4", Base: at + 0x100000, TextSize: 0x1000})
	ctx, _ := f.Context(t, nil)
	k, _ := linuxkern.New(ctx)
	m, err := k.Modules()
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := k.Modules(); again != m {
		t.Error("the model was built twice")
	}
	list, err := m.List()
	if err != nil || len(list.Modules) != 1 || list.Modules[0].Address != at&mask48 || list.Modules[0].Name != "ext4" {
		t.Errorf("list %+v, %v", list.Modules, err)
	}
}

type unlisted struct{ symbols.SymbolTable }

type namesOnly struct {
	symbols.SymbolTable
	names []string
}

func (n namesOnly) SymbolNames() []string { return n.names }

func TestTableSymbolsAreInLinkTimeSpace(t *testing.T) {
	f := kerntest.NewFixture(shift)
	f.Types.Symbol("percpu_counter", 0x2a000, kerntest.Base("int"))
	ctx, _ := f.Context(t, nil)
	k, _ := linuxkern.New(ctx)
	listed, err := k.TableSymbols()
	if err != nil {
		t.Fatal(err)
	}
	link := map[string]uint64{}
	for _, s := range listed {
		link[s.Name] = s.Address
	}
	if link["_text"] != kerntest.Text || link["percpu_counter"] != 0x2a000 {
		t.Errorf("listed %v", link)
	}

	table := ctx.Symbols
	ctx.Symbols = namesOnly{SymbolTable: unlisted{table}, names: []string{"_text", "percpu_counter"}}
	ctx.Options["physical_memory"] = vmcoreinfoMemory(nil)
	k, _ = linuxkern.New(ctx)
	named, err := k.TableSymbols()
	if err != nil {
		t.Fatal(err)
	}
	if len(named) != 2 || named[0].Address != kerntest.Text || named[1].Address != 0x2a000 {
		t.Errorf("from names: %+v", named)
	}

	ctx.Symbols = unlisted{table}
	k, _ = linuxkern.New(ctx)
	if _, err := k.TableSymbols(); !errors.Is(err, linuxkern.ErrNoSymbolList) {
		t.Errorf("unlisted table: %v", err)
	}
}

const (
	damagedNoteAt = 0x100
	goodNoteAt    = 0x800
)

func vmcoreinfoMemory(damaged []int) *lt.Memory {
	buf := lt.Capture(shift, []string{"T_stext", "Tfoo", "B_end"}, []uint32{0, 0x10, 0x100})
	for _, at := range damaged {
		lt.PutNote(buf, at, "OSRELEASE=6.17.0\nGARBAGE\n")
	}
	lt.PutNote(buf, goodNoteAt, "OSRELEASE=6.17.0\n"+lt.LayoutKeys(shift)+lt.KallsymsKeys(shift))
	return &lt.Memory{Buf: buf}
}

func TestTheShiftComesFromTheImageStartSymbol(t *testing.T) {
	f := kerntest.NewFixture(shift)
	ctx, _ := f.Context(t, nil)
	k, _ := linuxkern.New(ctx)
	if s, err := k.Shift(); err != nil || s != shift {
		t.Errorf("Shift = %#x, %v", s, err)
	}
	ctx.Symbols = unlisted{ctx.Symbols}
	k, _ = linuxkern.New(ctx)
	if _, err := k.Shift(); err == nil {
		t.Error("a shift with no listed anchor and no physical memory")
	}
}

func TestTheShiftFallsBackToTheFirstVMCoreInfoNoteThatReads(t *testing.T) {
	for _, strict := range []bool{false, true} {
		f := kerntest.NewFixture(shift)
		opts := map[string]any{"physical_memory": vmcoreinfoMemory([]int{damagedNoteAt})}
		if strict {
			opts["strict"] = true
		}
		ctx, diags := f.Context(t, opts)
		ctx.Symbols = unlisted{ctx.Symbols}
		k, _ := linuxkern.New(ctx)
		got, err := k.Shift()
		if strict {
			var damage *autoload.VMCoreInfoDamageError
			if !errors.As(err, &damage) || len(damage.Damaged) != 1 || damage.Damaged[0].Offset != damagedNoteAt {
				t.Errorf("strict Shift: %v, want the damage at %#x", err, damagedNoteAt)
			}
			continue
		}
		if err != nil || got != shift {
			t.Fatalf("Shift = %#x, %v", got, err)
		}
		if len(*diags) != 1 || !strings.Contains((*diags)[0], "VMCOREINFO note at 0x100: skipped") {
			t.Errorf("diagnostics %q", *diags)
		}
	}
}
