package linuxmodule_test

import (
	"bytes"
	"debug/elf"
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const mask = 1<<48 - 1

const (
	extAt    = ModuleArea + 0x10000
	extBase  = ModuleArea + 0x40000
	vboxAt   = ModuleArea + 0x20000
	vboxBase = ModuleArea + 0x80000
	hideAt   = ModuleArea + 0x30000
	hideBase = ModuleArea + 0xc0000
)

func threeModules() *Fixture {
	f := NewFixture(0)
	f.AddModule(ModuleSpec{At: extAt, Name: "ext4", Base: extBase, TextSize: 0x1000, DataSize: 0x800})
	f.AddModule(ModuleSpec{At: vboxAt, Name: "vboxguest", Base: vboxBase, TextSize: 0x2000, Taints: 1<<12 | 1<<13})
	f.AddModule(ModuleSpec{At: hideAt, Name: "rk", Base: hideBase, TextSize: 0x1000, NotListed: true, NotInKset: true})
	return f
}

func model(t *testing.T, f *Fixture) *linuxmodule.Model {
	t.Helper()
	ctx, _ := f.Context(t, nil)
	k, err := linuxkern.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m, err := k.Modules()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAModuleReadsWithItsRegionsAndChecks(t *testing.T) {
	m := model(t, threeModules())
	mod, err := m.Read(extAt)
	if err != nil {
		t.Fatal(err)
	}
	if mod.Name != "ext4" || mod.State != linuxmodule.Live || !mod.SelfLinked || !mod.Placed {
		t.Errorf("module %+v", mod)
	}
	if mod.Base() != extBase&mask || mod.TextSize() != 0x1000 || mod.CoreSize() != 0x1800 || mod.InitSize() != 0 {
		t.Errorf("base %#x text %#x core %#x init %#x", mod.Base(), mod.TextSize(), mod.CoreSize(), mod.InitSize())
	}
	if !mod.Holds((extBase+0x10)&mask) || mod.Holds((extBase+0x1000)&mask) {
		t.Error("text region bounds")
	}
}

func TestAModuleThatBreaksARuleIsRefused(t *testing.T) {
	for _, c := range []struct {
		name  string
		write func(f *Fixture)
		want  error
	}{
		{"state past the enum", func(f *Fixture) { f.Mem.U32(extAt, 4) }, linuxmodule.ErrState},
		{"name without a NUL", func(f *Fixture) { f.Mem.Write(extAt+ModName, bytes.Repeat([]byte{'a'}, ModNameLen)) }, linuxmodule.ErrName},
		{"empty name", func(f *Fixture) { f.Mem.U8(extAt+ModName, 0) }, linuxmodule.ErrName},
		{"space in the name", func(f *Fixture) { f.Mem.Str(extAt+ModName, "ex t4") }, linuxmodule.ErrName},
		{"unmapped", func(f *Fixture) {}, linuxmodule.ErrUnreadable},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := threeModules()
			c.write(f)
			at := uint64(extAt)
			if c.want == linuxmodule.ErrUnreadable {
				at = ModuleArea + 0xf0000
			}
			if _, err := model(t, f).Read(at); !errors.Is(err, c.want) {
				t.Errorf("err %v, want %v", err, c.want)
			}
		})
	}
}

func TestSelfLinkAndPlacementAreFactsNotErrors(t *testing.T) {
	f := threeModules()
	f.Mem.U64(extAt+ModMkobj+MkobjMod, 0)
	f.Mem.U64(extAt+ModMem+uint64(linuxmodule.Data)*ModMemSize, extBase+0x10000)
	mod, err := model(t, f).Read(extAt)
	if err != nil {
		t.Fatal(err)
	}
	if mod.SelfLinked || mod.Placed {
		t.Errorf("self-linked %v placed %v", mod.SelfLinked, mod.Placed)
	}
}

func layoutFixture(textSize, roSize, roAfter, size uint32) (*Fixture, uint64) {
	f := NewFixture(0)
	ty := f.Types
	ty.Struct("module_layout", 32, map[string]F{
		"base": {Off: 0, Type: Ptr(Void())}, "size": {Off: 8, Type: Base("unsigned int")},
		"text_size": {Off: 12, Type: Base("unsigned int")}, "ro_size": {Off: 16, Type: Base("unsigned int")},
		"ro_after_init_size": {Off: 20, Type: Base("unsigned int")},
	})
	ty.Struct("module", 256, map[string]F{
		"state": {Off: 0, Type: Enum("module_state")}, "list": {Off: 8, Type: Struct("list_head")},
		"name": {Off: 24, Type: Arr(56, Base("char"))}, "mkobj": {Off: 80, Type: Struct("module_kobject")},
		"core_layout": {Off: 176, Type: Struct("module_layout")}, "init_layout": {Off: 208, Type: Struct("module_layout")},
	})
	at := uint64(ModuleArea + 0x1000)
	base := uint64(ModuleArea + 0x10000)
	f.Mem.Map(at, 256)
	f.Mem.Str(at+24, "old")
	f.Mem.U64(at+80+64, at)
	f.Mem.U64(at+176, base)
	f.Mem.U32(at+176+8, size)
	f.Mem.U32(at+176+12, textSize)
	f.Mem.U32(at+176+16, roSize)
	f.Mem.U32(at+176+20, roAfter)
	return f, at
}

func TestOnlyTheRegionsFormHasSeparateRegions(t *testing.T) {
	if !model(t, NewFixture(0)).SeparateRegions() {
		t.Error("module.mem regions are not separate")
	}
	f, _ := layoutFixture(0x1000, 0x1800, 0x2000, 0x3000)
	if model(t, f).SeparateRegions() {
		t.Error("core_layout is one allocation")
	}
}

func TestTheLayoutsFormSplitsEachLayoutByItsEndOffsets(t *testing.T) {
	f, at := layoutFixture(0x1000, 0x1800, 0x2000, 0x3000)
	mod, err := model(t, f).Read(at)
	if err != nil {
		t.Fatal(err)
	}
	base := uint64(ModuleArea+0x10000) & mask
	want := []linuxmodule.Region{
		{Kind: linuxmodule.Text, Base: base, Size: 0x1000},
		{Kind: linuxmodule.ROData, Base: base + 0x1000, Size: 0x800},
		{Kind: linuxmodule.ROAfterInit, Base: base + 0x1800, Size: 0x800},
		{Kind: linuxmodule.Data, Base: base + 0x2000, Size: 0x1000},
	}
	if len(mod.Regions) != len(want) {
		t.Fatalf("regions %+v", mod.Regions)
	}
	for i := range want {
		if mod.Regions[i] != want[i] {
			t.Errorf("region %d %+v, want %+v", i, mod.Regions[i], want[i])
		}
	}
	if mod.LayoutDisordered || mod.Placed {
		t.Errorf("disordered %v placed %v", mod.LayoutDisordered, mod.Placed)
	}
}

func TestADisorderedLayoutBecomesOneTextRegion(t *testing.T) {
	f, at := layoutFixture(0x2000, 0x1000, 0x1000, 0x3000)
	mod, err := model(t, f).Read(at)
	if err != nil {
		t.Fatal(err)
	}
	if !mod.LayoutDisordered || len(mod.Regions) != 1 || mod.Regions[0].Kind != linuxmodule.Text || mod.Regions[0].Size != 0x3000 {
		t.Errorf("module %+v", mod)
	}
}

func addresses(mods []linuxmodule.Module) []uint64 {
	out := make([]uint64, len(mods))
	for i, m := range mods {
		out[i] = m.Address
	}
	return out
}

func equal(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTheThreeViewsAndTheirDifferences(t *testing.T) {
	f := threeModules()
	builtin := uint64(KsetStruct + 0x800)
	f.Mem.Map(builtin, 0x100)
	head := uint64(KsetStruct)
	last := uint64(vboxAt + ModMkobj + KobjEntry)
	f.Mem.U64(last, builtin+KobjEntry)
	f.Mem.U64(builtin+KobjEntry, head)
	f.Mem.U64(builtin+KobjEntry+8, last)
	f.Mem.U64(head+8, builtin+KobjEntry)
	vs, err := model(t, f).Views()
	if err != nil {
		t.Fatal(err)
	}
	listed := []uint64{extAt & mask, vboxAt & mask}
	if got := addresses(vs.List.Modules); !equal(got, listed) {
		t.Errorf("list %#x", got)
	}
	if got := addresses(vs.Sysfs.Modules); !equal(got, listed) || vs.Sysfs.BuiltIn != 1 {
		t.Errorf("sysfs %#x built-in %d", got, vs.Sysfs.BuiltIn)
	}
	all := []uint64{extAt & mask, vboxAt & mask, hideAt & mask}
	if got := addresses(vs.Scan.Modules); !equal(got, all) {
		t.Errorf("scan %#x", got)
	}
	if got := addresses(linuxmodule.Missing(vs.Scan, vs.List)); !equal(got, []uint64{hideAt & mask}) {
		t.Errorf("hidden %#x", got)
	}
	if got := addresses(vs.Known()); !equal(got, all) {
		t.Errorf("known %#x", got)
	}
	if vs.Lossy() {
		t.Error("no view should have lost anything")
	}
}

func TestTheScanNeedsTheModuleToSitInItsOwnData(t *testing.T) {
	f := threeModules()
	f.Mem.U64(hideAt+ModMem+uint64(linuxmodule.Data)*ModMemSize, hideBase+0x10000)
	vs, err := model(t, f).Views()
	if err != nil {
		t.Fatal(err)
	}
	if vs.Scan.Has(hideAt & mask) {
		t.Error("a self-linked module outside its own data was accepted")
	}
}

func TestTheScanRefusesBoundsOutsideTheModuleArea(t *testing.T) {
	f := threeModules()
	f.Mem.U64(ModTree+24, 0xffff888000000000)
	if _, err := model(t, f).Scan(); !errors.Is(err, linuxmodule.ErrModuleArea) {
		t.Errorf("err %v", err)
	}
}

func TestACappedScanIsInAddressOrder(t *testing.T) {
	f := threeModules()
	f.Types.Struct("mod_tree_root", 56, map[string]F{
		"root": {Off: 0, Type: Struct("latch_tree_root")}, "addr_min": {Off: 24, Type: Base("long unsigned int")},
		"addr_max": {Off: 32, Type: Base("long unsigned int")}, "data_addr_min": {Off: 40, Type: Base("long unsigned int")},
		"data_addr_max": {Off: 48, Type: Base("long unsigned int")},
	})
	f.Mem.U64(ModTree+24, hideAt)
	f.Mem.U64(ModTree+32, ModuleArea+0x100000)
	f.Mem.U64(ModTree+40, ModuleArea)
	f.Mem.U64(ModTree+48, hideAt)
	ctx, _ := f.Context(t, nil)
	ctx.Limits = limits.Limits{MaxListEntries: 2}
	k, err := linuxkern.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m, err := k.Modules()
	if err != nil {
		t.Fatal(err)
	}
	v, err := m.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if !v.Capped || len(v.Modules) != 2 || v.Modules[0].Address != extAt&mask || v.Modules[1].Address != hideAt&mask {
		var got []uint64
		for _, mod := range v.Modules {
			got = append(got, mod.Address)
		}
		t.Errorf("capped %v, modules %#x", v.Capped, got)
	}
}

func TestEmptyBoundsScanNothing(t *testing.T) {
	f := threeModules()
	f.Mem.U64(ModTree+24, ^uint64(0))
	f.Mem.U64(ModTree+32, 0)
	v, err := model(t, f).Scan()
	if err != nil || len(v.Modules) != 0 || len(v.Ranges) != 0 {
		t.Errorf("view %+v err %v", v, err)
	}
}

func TestTaintNamesAndLetters(t *testing.T) {
	m := model(t, threeModules())
	ts := m.Taints(1<<9 | 1<<12 | 1<<13 | 1<<40)
	if got := linuxmodule.TaintNames(ts); got != "WARN,OOT_MODULE,UNSIGNED_MODULE,bit 40" {
		t.Errorf("names %q", got)
	}
	if got := linuxmodule.TaintLetters(ts); got != "OE" {
		t.Errorf("letters %q", got)
	}
}

func TestTaintsFallBackToTheSourceTableWhenTheImageEntryIsDamaged(t *testing.T) {
	f := threeModules()
	f.Mem.U8(TaintFlags+12*16, '#')
	ts := model(t, f).Taints(1 << 12)
	if len(ts) != 1 || ts[0].Name != "OOT_MODULE" || ts[0].Letter != 'O' {
		t.Errorf("taints %+v", ts)
	}
}

func TestTaintNamesComeFromDescWhenItReads(t *testing.T) {
	f := threeModules()
	name := uint64(Data + 0x3000)
	f.Mem.Str(name, "OUT_OF_TREE")
	f.Mem.U64(TaintFlags+12*16+8, name)
	ts := model(t, f).Taints(1 << 12)
	if len(ts) != 1 || ts[0].Name != "OUT_OF_TREE" {
		t.Errorf("taints %+v", ts)
	}
}

func TestParametersDecodeByTheirOps(t *testing.T) {
	f := threeModules()
	kp := uint64(extAt + 0x2000)
	vals := uint64(extAt + 0x3000)
	f.Mem.U64(extAt+ModKp, kp)
	f.Mem.U32(extAt+ModNumKp, 7)
	param := func(i int, name string, ops, arg uint64) {
		at := kp + uint64(i)*40
		nameAt := vals + 0x800 + uint64(i)*0x20
		f.Mem.Str(nameAt, name)
		f.Mem.U64(at, nameAt)
		f.Mem.U64(at+16, ops)
		f.Mem.U64(at+32, arg)
	}
	f.Mem.U32(vals, uint32(0xfffffffe))
	param(0, "debug", f.ParamOpsAt("param_ops_int"), vals)
	f.Mem.U8(vals+8, 1)
	param(1, "on", f.ParamOpsAt("param_ops_bool"), vals+8)
	f.Mem.U64(vals+16, 0)
	param(2, "path", f.ParamOpsAt("param_ops_charp"), vals+16)
	f.Mem.Str(vals+0x100, "abc")
	f.Mem.U64(vals+0x40, 8)
	f.Mem.U64(vals+0x48, vals+0x100)
	param(3, "label", f.ParamOpsAt("param_ops_string"), vals+0x40)
	arr := vals + 0x200
	f.Mem.U32(arr, 4)
	f.Mem.U32(arr+4, 4)
	f.Mem.U64(arr+8, vals+0x280)
	f.Mem.U32(vals+0x280, 2)
	f.Mem.U64(arr+16, f.ParamOpsAt("param_ops_uint"))
	f.Mem.U64(arr+24, vals+0x300)
	f.Mem.U32(vals+0x300, 5)
	f.Mem.U32(vals+0x304, 6)
	param(4, "ids", f.ParamOpsAt("param_array_ops"), arr)
	param(5, "mystery", Text+0x500, vals)
	f.Mem.U32(vals+0x380, 0)
	param(6, "mask", f.ParamOpsAt("param_ops_hexint"), vals+0x380)
	m := model(t, f)
	mod, err := m.Read(extAt)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := m.Parameters(mod)
	if err != nil {
		t.Fatal(err)
	}
	want := "debug=-2 on=Y path=(null) label=abc ids=5,6 mystery mask=00000000"
	if got := ps.Text(); got != want {
		t.Errorf("parameters %q, want %q", got, want)
	}
}

func symbolFixture() *Fixture {
	f := threeModules()
	ks := uint64(extAt + KallsymsAt)
	symtab, strtab, typetab := ks+0x100, ks+0x800, ks+0xc00
	f.Mem.U64(extAt+ModKallsyms, ks)
	f.Mem.U64(ks, symtab)
	f.Mem.U32(ks+8, 6)
	f.Mem.U64(ks+16, strtab)
	f.Mem.U64(ks+24, typetab)
	f.Mem.Write(strtab, []byte("\x00ext4_init\x00$x\x00ext4_fill\x00undef\x00\x00"))
	sym := func(i int, name uint32, info byte, shndx uint16, value uint64, typ byte) {
		at := symtab + uint64(i)*24
		f.Mem.U32(at, name)
		f.Mem.U8(at+4, info)
		f.Mem.U16(at+6, shndx)
		f.Mem.U64(at+8, value)
		f.Mem.U64(at+16, 0x10)
		f.Mem.U8(typetab+uint64(i), typ)
	}
	sym(0, 0, 0, 0, 0, 0)
	sym(1, 1, 0x12, 2, extBase+0x10, 't')
	sym(2, 11, 0, 2, extBase+0x30, 't')
	sym(3, 14, 0x02, 2, extBase+0x20, 't')
	sym(4, 24, 0x10, 0, extBase+0x38, 'U')
	sym(5, 30, 0x01, 4, extAt+0x40, 'd')
	return f
}

func TestLookupNamesTheNearestRealSymbolBelowTheAddress(t *testing.T) {
	m := model(t, symbolFixture())
	vs, err := m.Views()
	if err != nil {
		t.Fatal(err)
	}
	o := m.Lookup(vs.Known(), extBase+0x3c, nil)
	if !o.Found || o.Kernel || o.Module.Name != "ext4" || o.Symbol != "ext4_fill" || o.Offset != 0x1c || o.Owners != 1 {
		t.Errorf("owner %+v", o)
	}
	o = m.Lookup(vs.Known(), Text+0x80, func(uint64) []string { return []string{"start_kernel"} })
	if !o.Found || !o.Kernel || o.Symbol != "start_kernel" {
		t.Errorf("kernel owner %+v", o)
	}
	if o := m.Lookup(vs.Known(), 0xffff888000001000, nil); o.Found {
		t.Errorf("owner of an address nothing holds %+v", o)
	}
}

// sections lays out module_sect_attrs in the bin_attribute form (S08 E2 C):
// grp.bin_attrs at 40 points at a null-ended pointer list, entries start at 48
// and are 88 bytes, with attr.name at 0 and private at 24.
func sections(f *Fixture, mod uint64, names []string, addrs []uint64) {
	sa := mod + 0x2000
	list := sa + 0x1000
	f.Mem.U64(mod+ModSectAttrs, sa)
	f.Mem.U64(sa+40, list)
	for i, n := range names {
		entry := sa + 48 + uint64(i)*88
		nameAt := sa + 0x800 + uint64(i)*0x40
		f.Mem.Str(nameAt, n)
		f.Mem.U64(entry, nameAt)
		f.Mem.U64(entry+24, addrs[i])
		f.Mem.U64(list+uint64(i)*8, entry)
	}
	f.Mem.U64(list+uint64(len(names))*8, 0)
}

func TestRebuildWritesAnELFFileThatParses(t *testing.T) {
	f := symbolFixture()
	f.Mem.Write(extBase, bytes.Repeat([]byte{0x90}, 0x1000))
	sections(f, extAt, []string{".text", ".data", ".init.text"}, []uint64{extBase, extAt + 0x400, 0xffff888000002000})
	m := model(t, f)
	mod, err := m.Read(extAt)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := m.RebuildELF(mod, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if rb.Sections != 2 || len(rb.Dropped) != 1 || rb.Dropped[0] != ".init.text" || rb.ZeroPages != 0 {
		t.Errorf("rebuild %+v", rb)
	}
	file, err := elf.NewFile(bytes.NewReader(rb.File))
	if err != nil {
		t.Fatal(err)
	}
	if file.Type != elf.ET_REL || file.Machine != elf.EM_X86_64 {
		t.Errorf("type %v machine %v", file.Type, file.Machine)
	}
	text := file.Section(".text")
	if text == nil || text.Addr != extBase&mask || text.Size != 0x1000 || text.Flags != elf.SHF_ALLOC|elf.SHF_EXECINSTR {
		t.Fatalf("text %+v", text)
	}
	got, err := text.Data()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0x90}, 0x1000)) {
		t.Error("text contents differ from memory")
	}
	if d := file.Section(".data"); d == nil || d.Flags != elf.SHF_ALLOC|elf.SHF_WRITE || d.Size != 0x400 {
		t.Errorf("data %+v", d)
	}
	syms, err := file.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]elf.Symbol{}
	for _, s := range syms {
		byName[s.Name] = s
	}
	if s := byName["ext4_init"]; s.Section != 1 || s.Value != 0x10 || elf.ST_TYPE(s.Info) != elf.STT_FUNC || elf.ST_BIND(s.Info) != elf.STB_GLOBAL {
		t.Errorf("ext4_init %+v", s)
	}
	if _, ok := byName["undef"]; ok {
		t.Error("an undefined symbol was written")
	}
	if s := byName["ext4_fill"]; elf.ST_BIND(s.Info) != elf.STB_LOCAL || s.Value != 0x20 {
		t.Errorf("ext4_fill %+v", s)
	}
	for i, s := range syms {
		if elf.ST_BIND(s.Info) == elf.STB_LOCAL && i > 0 && elf.ST_BIND(syms[i-1].Info) != elf.STB_LOCAL {
			t.Errorf("local %s comes after a global", s.Name)
		}
	}
}

func TestRebuildRefusesAFileOverTheCap(t *testing.T) {
	f := threeModules()
	sections(f, extAt, []string{".text"}, []uint64{extBase})
	m := model(t, f)
	mod, err := m.Read(extAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.RebuildELF(mod, 0x100); !errors.Is(err, linuxmodule.ErrTooLarge) {
		t.Errorf("err %v", err)
	}
}
