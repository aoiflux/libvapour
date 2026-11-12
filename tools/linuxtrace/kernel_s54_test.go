package linuxtrace_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxtrace"
	ltt "github.com/aoiflux/libvapour/tools/linuxtrace/linuxtracetest"
)

const obj = 0xffff888000200000

func objectKernel(t *testing.T, opts map[string]any) (*linuxtrace.Kernel, *kerntest.Memory) {
	t.Helper()
	i := kerntest.NewTypes(8)
	i.Enum("state", 4, "unsigned int", map[string]int64{"STATE_IDLE": 0, "STATE_BUSY": 1, "STATE_GONE": -1})
	i.Struct("target", 0x10, map[string]kerntest.F{"x": {Off: 0, Type: kerntest.Base("int")}})
	i.Struct("object", 0x60, map[string]kerntest.F{
		"count":  {Off: 0x00, Type: kerntest.Base("int")},
		"bits":   {Off: 0x04, Type: kerntest.Bits(1, 3, "int")},
		"state":  {Off: 0x08, Type: kerntest.Enum("state")},
		"next":   {Off: 0x10, Type: kerntest.Ptr(kerntest.Struct("target"))},
		"opaque": {Off: 0x18, Type: kerntest.Ptr(kerntest.Void())},
		"base":   {Off: 0x20, Type: kerntest.Base("long unsigned int")},
		"id":     {Off: 0x28, Type: kerntest.Arr(16, kerntest.Base("char"))},
		"short":  {Off: 0x38, Type: kerntest.Base("short int")},
	})
	i.Symbol("the_object", obj, kerntest.Struct("object"))
	mem := kerntest.NewMemory()
	mem.Map(obj, 0x1000)
	ctx, _ := kerntest.Context(mem, i.Table(t), opts)
	return linuxtrace.New(ctx), mem
}

func TestAddressesLeaveInCanonicalForm(t *testing.T) {
	k, mem := objectKernel(t, nil)
	s, err := k.Symbol("the_object")
	if err != nil || s.Address != obj {
		t.Errorf("Symbol = %#x, %v", s.Address, err)
	}
	mem.U64(obj+0x10, obj&(1<<48-1)+0x100)
	if p, err := k.Pointer(obj, "object", "next"); err != nil || p != obj+0x100 {
		t.Errorf("Pointer(next) = %#x, %v", p, err)
	}
	if k.Masked(obj) != obj&(1<<48-1) || k.Canonical(obj&(1<<48-1)) != obj {
		t.Error("Masked or Canonical")
	}
	la57, _ := objectKernel(t, map[string]any{"paging_mode": "linux-la57"})
	if got := la57.Canonical(0x01ff888000000000); got != 0xffff888000000000 {
		t.Errorf("la57 Canonical = %#x", got)
	}
	if _, err := k.Symbol("absent"); err == nil {
		t.Error("absent symbol")
	}
}

func TestPointersMustHoldAddresses(t *testing.T) {
	k, mem := objectKernel(t, nil)
	mem.U64(obj+0x20, 0xffffffffc0000000)
	if p, err := k.Pointer(obj, "object", "base"); err != nil || p != 0xffffffffc0000000 {
		t.Errorf("Pointer(base) = %#x, %v", p, err)
	}
	if _, err := k.Pointer(obj, "object", "count"); err == nil {
		t.Error("Pointer read a 4-byte int")
	}
	if _, err := k.PointerAt(obj + 0xffc); err == nil {
		t.Error("PointerAt across into an unmapped page")
	}
}

func TestDerefSaysWhetherThePointeeReads(t *testing.T) {
	k, mem := objectKernel(t, nil)
	mem.U64(obj+0x10, obj+0xff8)
	mem.U64(obj+0x18, obj+0xfff)
	if p, ok, err := k.Deref(obj, "object", "next"); err != nil || ok || p != obj+0xff8 {
		t.Errorf("Deref(next) to a 16-byte target crossing into an unmapped page = %#x, %v, %v", p, ok, err)
	}
	if _, ok, err := k.Deref(obj, "object", "opaque"); err != nil || !ok {
		t.Errorf("Deref(void *) to one mapped byte = %v, %v", ok, err)
	}
	mem.U64(obj+0x10, 0)
	if _, ok, _ := k.Deref(obj, "object", "next"); ok {
		t.Error("a null pointer dereferences")
	}
}

func TestIntegersAndEnumerations(t *testing.T) {
	k, mem := objectKernel(t, nil)
	mem.U32(obj, 0xffffff9c)
	mem.U32(obj+4, 0b1110)
	mem.U32(obj+8, 0xffffffff)
	mem.U16(obj+0x38, 0x8000)
	for _, c := range []struct {
		member string
		u      uint64
		i      int64
	}{{"count", 0xffffff9c, -100}, {"bits", 0b111, 0b111}, {"state", 0xffffffff, -1}, {"short", 0x8000, -0x8000}} {
		if u, err := k.Uint(obj, "object", c.member); err != nil || u != c.u {
			t.Errorf("Uint(%s) = %#x, %v", c.member, u, err)
		}
		if i, err := k.Int(obj, "object", c.member); err != nil || i != c.i {
			t.Errorf("Int(%s) = %d, %v", c.member, i, err)
		}
	}
	v, typ, err := k.EnumField(obj, "object", "state")
	if err != nil || v != -1 || typ != "state" {
		t.Errorf("EnumField = %d, %q, %v", v, typ, err)
	}
	if name, ok, err := k.EnumName(typ, v); err != nil || !ok || name != "STATE_GONE" {
		t.Errorf("EnumName(%d) = %q, %v, %v", v, name, ok, err)
	}
	if _, ok, err := k.EnumName(typ, 7); err != nil || ok {
		t.Errorf("EnumName(7) = %v, %v", ok, err)
	}
	if _, _, err := k.EnumName("object", 0); err == nil {
		t.Error("EnumName of a structure")
	}
	if _, err := k.Uint(obj, "object", "id"); !errors.Is(err, linuxkern.ErrNotInteger) {
		t.Errorf("Uint of an array: %v", err)
	}
	if got := linuxtrace.SignExtend(0xff, 1); got != -1 {
		t.Errorf("SignExtend = %d", got)
	}
}

func TestSizesAndCharArrays(t *testing.T) {
	k, mem := objectKernel(t, nil)
	for name, want := range map[string]uint64{"object": 0x60, "long int": 8, "size_t": 8, "state": 4} {
		if n, err := k.SizeOf(name); err != nil || n != want {
			t.Errorf("SizeOf(%s) = %d, %v, want %d", name, n, err, want)
		}
	}
	if !k.HasType("state") || !k.HasType("object") || k.HasType("nothing") || !k.Has("object", "id") {
		t.Error("HasType or Has")
	}
	mem.Str(obj+0x28, "simple-framebuffer")
	if s, err := k.CharArray(obj, "object", "id"); err != nil || s != "simple-framebuff" {
		t.Errorf("CharArray = %q, %v", s, err)
	}
	if _, err := k.CharArray(obj, "object", "count"); !errors.Is(err, linuxkern.ErrNotByteArray) {
		t.Errorf("CharArray of an int: %v", err)
	}
	mem.Write(obj+0xff0, []byte("0123456789abcdef"))
	if _, err := k.StringAt(obj+0xff0, 0x20); !errors.Is(err, linuxkern.ErrStringUnread) {
		t.Errorf("StringAt into an unmapped page: %v", err)
	}
	if b := k.ReadPadded(obj+0xffe, 4); len(b) != 4 {
		t.Errorf("ReadPadded = %v", b)
	}
	if !linuxtrace.Readable(mem, obj, 0) || linuxtrace.Readable(mem, obj+0xfff, 2) {
		t.Error("Readable")
	}
}

func TestModulesComeFromTheSharedModel(t *testing.T) {
	k := ltt.NewKernel()
	k.Table.Symbol("worker_thread", ltt.Text+0x5000, nil)
	k.Table.Symbol("worker_alias", ltt.Text+0x5000, nil)
	base := uint64(0xffffffffc1000000)
	ext4 := k.AddModule(ltt.Module{Name: "ext4", Base: base, Size: 0x8000, Text: 0x4000,
		Symbols: []ltt.ModuleSymbol{{Name: "ext4_fn", Value: base + 0x100}}})
	ctx, _, err := k.Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	kern := linuxtrace.New(ctx)
	model, err := kern.Modules()
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := kern.Modules(); again != model {
		t.Error("Modules built the model twice")
	}
	vs, err := model.Views()
	if err != nil {
		t.Fatal(err)
	}
	known := vs.Known()
	if len(known) != 1 || known[0].Address != ext4 {
		t.Fatalf("known %+v", known)
	}
	if o := model.Lookup(known, base+0x104, kern.SymbolsAt); !o.Found || o.Module.Name != "ext4" || o.Symbol != "ext4_fn" {
		t.Errorf("module lookup %+v", o)
	}
	if names := kern.SymbolsAt(ltt.Text + 0x5000); strings.Join(names, ",") != "worker_alias,worker_thread" {
		t.Errorf("SymbolsAt = %v", names)
	}
	if _, ok := kern.SymbolLocator(); !ok {
		t.Error("SymbolLocator")
	}
}
