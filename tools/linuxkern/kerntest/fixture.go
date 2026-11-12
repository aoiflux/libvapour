package kerntest

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/tools"
)

// Addresses (S80 3.1). Text is __START_KERNEL_map plus the default
// CONFIG_PHYSICAL_START of 16 MiB; ModuleArea is MODULES_VADDR, the end of
// the 1 GiB image mapping (pgtable_64_types.h). The data symbols keep the
// slots that the dependent tests place their own objects around (S80 open point O1).
const (
	Text       = 0xffffffff81000000
	Etext      = 0xffffffff82000000
	Data       = 0xffffffff83000000
	ModulesSym = Data + 0x000
	ModuleKset = Data + 0x100
	ModTree    = Data + 0x200
	TaintFlags = Data + 0x300
	KsetStruct = Data + 0x1000
	ParamOps   = Text + 0x10000
	ModuleArea = 0xffffffffc0000000
)

// struct module and its kobject, v6.17 (S80 K1, K2): the prefix up to mkobj is
// fixed by include/linux/module.h; the rest is placed in declaration order,
// mem on a cache line and clear of the bytes the moduledump test writes at
// module + 0x100.
const (
	ModList      = 8
	ModName      = 24
	ModNameLen   = 56
	ModMkobj     = 80
	ModKp        = 176
	ModNumKp     = 184
	ModMem       = 320
	ModMemSize   = 72
	ModTaints    = 824
	ModKallsyms  = 832
	ModSectAttrs = 840
	ModSize      = 896
	MkobjMod     = 64
	KobjName     = 0
	KobjEntry    = 8
	KobjKref     = 56
)

// enum mod_mem_type, include/linux/module.h v6.4 and v6.17.
var modMemType = map[string]int64{
	"MOD_TEXT": 0, "MOD_DATA": 1, "MOD_RODATA": 2, "MOD_RO_AFTER_INIT": 3,
	"MOD_INIT_TEXT": 4, "MOD_INIT_DATA": 5, "MOD_INIT_RODATA": 6, "MOD_MEM_NUM_TYPES": 7, "MOD_INVALID": -1,
}

const (
	taintFlagSize = 16
	paramOpsStep  = 0x40
	kparamSize    = 40
)

type Fixture struct {
	Types    *Types
	Mem      *Memory
	Shift    uint64
	kobjects []uint64
	modules  []uint64
}

// NewFixture lays out an empty module list and kset, the module area bounds
// and the taint table, every image address moved by shift.
func NewFixture(shift uint64) *Fixture {
	f := &Fixture{Types: NewTypes(8), Mem: NewMemory(), Shift: shift}
	AddModuleTypes(f.Types)
	ty := f.Types
	ty.Symbol("_text", Text, Arr(0, Base("char")))
	ty.Symbol("_etext", Etext, Arr(0, Base("char")))
	ty.Symbol("modules", ModulesSym, Struct("list_head"))
	ty.Symbol("module_kset", ModuleKset, Ptr(Struct("kset")))
	ty.Symbol("mod_tree", ModTree, Struct("mod_tree_root"))
	ty.Symbol("taint_flags", TaintFlags, Arr(uint64(len(KernelTaintFlags)), Struct("taint_flag")))
	for n, name := range ParamOpsNames {
		ty.Symbol(name, ParamOps+uint64(n)*paramOpsStep, Struct("kernel_param_ops"))
	}

	f.Mem.Map(Text+shift, PageSize)
	f.emptyList(ModulesSym + shift)
	kset := KsetStruct + shift
	f.Mem.Map(kset, 96)
	f.emptyList(kset)
	f.Mem.U64(ModuleKset+shift, kset)
	f.Mem.U64(ModTree+shift+24, ModuleArea)
	f.Mem.U64(ModTree+shift+32, ModuleArea+0x100000)
	for n, flag := range KernelTaintFlags {
		f.Mem.Write(TaintFlags+shift+uint64(n)*taintFlagSize, flag[:])
	}
	return f
}

// The kernel_param_ops objects kernel/params.c defines (v6.17), in no
// particular order; a parameter's ops pointer names its type.
var ParamOpsNames = []string{"param_ops_int", "param_array_ops", "param_ops_string", "param_ops_charp",
	"param_ops_bool", "param_ops_invbool", "param_ops_ulong", "param_ops_ullong", "param_ops_long",
	"param_ops_uint", "param_ops_ushort", "param_ops_short", "param_ops_byte", "param_ops_hexint"}

func (f *Fixture) ParamOpsAt(name string) uint64 {
	for n, s := range ParamOpsNames {
		if s == name {
			return ParamOps + uint64(n)*paramOpsStep + f.Shift
		}
	}
	panic("kerntest: no kernel_param_ops named " + name)
}

// taint_flags of kernel/panic.c v6.17: c_true, c_false and whether the flag
// applies to modules, in bit order.
var KernelTaintFlags = [][3]byte{
	{'P', 'G', 1}, {'F', ' ', 1}, {'S', ' ', 0}, {'R', ' ', 0}, {'M', ' ', 0}, {'B', ' ', 0},
	{'U', ' ', 0}, {'D', ' ', 0}, {'A', ' ', 0}, {'W', ' ', 0}, {'C', ' ', 1}, {'I', ' ', 0},
	{'O', ' ', 1}, {'E', ' ', 1}, {'L', ' ', 0}, {'K', ' ', 1}, {'X', ' ', 1}, {'T', ' ', 1},
	{'N', ' ', 1}, {'J', ' ', 1},
}

type ModuleSpec struct {
	At                         uint64
	Name                       string
	Base                       uint64
	TextSize, DataSize, InitSz uint32
	Taints                     uint64
	NotListed, NotInKset       bool
	Refs                       int32
}

// A loaded module's struct module lives in its own core data (S06 F5), so
// the data region starts at the structure.
func (f *Fixture) AddModule(m ModuleSpec) {
	mem := f.Mem
	mem.Map(m.At, ModSize)
	mem.Str(m.At+ModName, m.Name)
	mem.U64(m.At+ModMkobj+MkobjMod, m.At)
	f.region(m.At, "MOD_TEXT", m.Base, m.TextSize)
	f.region(m.At, "MOD_DATA", m.At, max(m.DataSize, ModSize))
	f.region(m.At, "MOD_INIT_TEXT", 0, m.InitSz)
	mem.U64(m.At+ModTaints, m.Taints)
	if !m.NotListed {
		f.link(ModulesSym+f.Shift, m.At+ModList)
		f.modules = append(f.modules, m.At)
	}
	if m.NotInKset {
		return
	}
	kobj := m.At + ModMkobj
	name := m.At + ModSize + 0x10
	mem.Str(name, m.Name)
	mem.U64(kobj+KobjName, name)
	refs := m.Refs
	if refs == 0 {
		refs = 3
	}
	mem.U32(kobj+KobjKref, uint32(refs))
	f.link(KsetStruct+f.Shift, kobj+KobjEntry)
	f.kobjects = append(f.kobjects, kobj)
}

// region writes module.mem[kind]; base 0 leaves the base unset.
func (f *Fixture) region(mod uint64, kind string, base uint64, size uint32) {
	at := mod + ModMem + uint64(modMemType[kind])*ModMemSize
	if base != 0 {
		f.Mem.U64(at, base)
	}
	f.Mem.U32(at+12, size)
}

func (f *Fixture) emptyList(head uint64) {
	f.Mem.U64(head, head)
	f.Mem.U64(head+8, head)
}

// link adds node before head, at the tail, as list_add_tail does
// (include/linux/list.h).
func (f *Fixture) link(head, node uint64) {
	tail := f.read64(head + 8)
	f.Mem.U64(node, head)
	f.Mem.U64(node+8, tail)
	f.Mem.U64(tail, node)
	f.Mem.U64(head+8, node)
}

func (f *Fixture) read64(at uint64) uint64 {
	b, err := f.Mem.ReadAt(at, 8)
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(b)
}

func (f *Fixture) Context(t testing.TB, opts map[string]any) (tools.Context, *[]string) {
	t.Helper()
	table := f.Types.Table(t)
	table.Shift = f.Shift
	return Context(f.Mem, table, opts)
}

func member(off uint64, t T) F { return F{Off: off, Type: t} }

// AddModuleTypes declares the module types of S80 3.2. Offsets cite
// include/linux/module.h, kobject.h, moduleparam.h, sysfs.h, panic.h and
// rbtree_latch.h at v6.17, kernel/module/internal.h and sysfs.c at v6.17,
// and the ELF gABI for the Elf64 records.
func AddModuleTypes(i *Types) {
	ptr := func(n string) T { return Ptr(Struct(n)) }
	charp := Ptr(Base("char"))
	u32 := Base("unsigned int")
	ulong := Base("long unsigned int")
	i.Struct("list_head", 16, map[string]F{"next": member(0, ptr("list_head")), "prev": member(8, ptr("list_head"))})
	i.Struct("atomic_t", 4, map[string]F{"counter": member(0, Base("int"))})
	i.Struct("atomic64_t", 8, map[string]F{"counter": member(0, Base("long long int"))})
	i.Struct("refcount_t", 4, map[string]F{"refs": member(0, Struct("atomic_t"))})
	i.Struct("kref", 4, map[string]F{"refcount": member(0, Struct("refcount_t"))})
	i.Struct("kobject", 64, map[string]F{
		"name": member(KobjName, charp), "entry": member(KobjEntry, Struct("list_head")),
		"parent": member(24, ptr("kobject")), "kset": member(32, ptr("kset")),
		"kref": member(KobjKref, Struct("kref")),
	})
	i.Struct("module_kobject", 96, map[string]F{"kobj": member(0, Struct("kobject")), "mod": member(MkobjMod, ptr("module"))})
	i.Struct("kset", 96, map[string]F{"list": member(0, Struct("list_head")), "kobj": member(24, Struct("kobject"))})
	i.Struct("module_memory", ModMemSize, map[string]F{
		"base": member(0, Ptr(Void())), "is_rox": member(8, Base("_Bool")), "size": member(12, u32),
	})
	i.Enum("mod_mem_type", 4, "int", modMemType)
	i.Enum("module_state", 4, "unsigned int", map[string]int64{
		"MODULE_STATE_LIVE": 0, "MODULE_STATE_COMING": 1, "MODULE_STATE_GOING": 2, "MODULE_STATE_UNFORMED": 3,
	})
	i.Struct("module", ModSize, map[string]F{
		"state":      member(0, Enum("module_state")),
		"list":       member(ModList, Struct("list_head")),
		"name":       member(ModName, Arr(ModNameLen, Base("char"))),
		"mkobj":      member(ModMkobj, Struct("module_kobject")),
		"kp":         member(ModKp, ptr("kernel_param")),
		"num_kp":     member(ModNumKp, u32),
		"mem":        member(ModMem, Arr(uint64(modMemType["MOD_MEM_NUM_TYPES"]), Struct("module_memory"))),
		"taints":     member(ModTaints, ulong),
		"kallsyms":   member(ModKallsyms, ptr("mod_kallsyms")),
		"sect_attrs": member(ModSectAttrs, ptr("module_sect_attrs")),
	})
	i.Struct("mod_kallsyms", 32, map[string]F{
		"symtab": member(0, ptr("Elf64_Sym")), "num_symtab": member(8, u32),
		"strtab": member(16, charp), "typetab": member(24, charp),
	})
	i.Struct("Elf64_Sym", elfSymSize, map[string]F{
		"st_name": member(0, u32), "st_info": member(4, Base("unsigned char")),
		"st_other": member(5, Base("unsigned char")), "st_shndx": member(6, Base("short unsigned int")),
		"st_value": member(8, Base("long long unsigned int")), "st_size": member(16, Base("long long unsigned int")),
	})
	i.Struct("Elf64_Ehdr", 64, map[string]F{"e_ident": member(0, Arr(16, Base("unsigned char")))})
	i.Struct("Elf64_Shdr", 64, map[string]F{"sh_name": member(0, u32)})
	i.Struct("latch_tree_root", 24, map[string]F{"seq": member(0, u32)})
	i.Struct("mod_tree_root", 40, map[string]F{
		"root": member(0, Struct("latch_tree_root")), "addr_min": member(24, ulong), "addr_max": member(32, ulong),
	})
	i.Union("kernel_param_union", 8, map[string]F{
		"arg": member(0, Ptr(Void())), "str": member(0, ptr("kparam_string")), "arr": member(0, ptr("kparam_array")),
	})
	i.Struct("kernel_param", kparamSize, map[string]F{
		"name": member(0, charp), "mod": member(8, ptr("module")), "ops": member(16, ptr("kernel_param_ops")),
		"perm": member(24, Base("short unsigned int")), "level": member(26, Base("signed char")),
		"flags":           member(27, Base("unsigned char")),
		"unnamed_field_0": {Off: 32, Type: Union("kernel_param_union"), Anonymous: true},
	})
	i.Struct("kernel_param_ops", 32, map[string]F{
		"flags": member(0, u32), "set": member(8, Ptr(Fn())), "get": member(16, Ptr(Fn())), "free": member(24, Ptr(Fn())),
	})
	i.Struct("kparam_array", 32, map[string]F{
		"max": member(0, u32), "elemsize": member(4, u32), "num": member(8, Ptr(u32)),
		"ops": member(16, ptr("kernel_param_ops")), "elem": member(24, Ptr(Void())),
	})
	i.Struct("kparam_string", 16, map[string]F{"maxlen": member(0, u32), "string": member(8, charp)})
	i.Struct("taint_flag", taintFlagSize, map[string]F{
		"c_true": member(0, Base("char")), "c_false": member(1, Base("char")),
		"module": member(2, Base("_Bool")), "desc": member(8, charp),
	})
	i.Struct("attribute", 16, map[string]F{"name": member(0, charp), "mode": member(8, Base("short unsigned int"))})
	i.Union("attribute_group_union", 8, map[string]F{
		"bin_attrs":     member(0, Ptr(ptr("bin_attribute"))),
		"bin_attrs_new": member(0, Ptr(ptr("bin_attribute"))),
	})
	i.Struct("attribute_group", attrGroupSize, map[string]F{
		"name": member(0, charp), "is_visible": member(8, Ptr(Fn())), "is_bin_visible": member(16, Ptr(Fn())),
		"bin_size": member(24, Ptr(Fn())), "attrs": member(32, Ptr(ptr("attribute"))),
		"unnamed_field_0": {Off: attrGroupBinAttrs, Type: Union("attribute_group_union"), Anonymous: true},
	})
	i.Struct("bin_attribute", binAttrSize, map[string]F{
		"attr": member(0, Struct("attribute")), "size": member(16, ulong), "private": member(binAttrPrivate, Ptr(Void())),
	})
	i.Struct("module_sect_attrs", attrGroupSize, map[string]F{
		"grp": member(0, Struct("attribute_group")), "attrs": member(attrGroupSize, Arr(0, Struct("bin_attribute"))),
	})
}

// Section attribute and symbol table records: module_sect_attrs is the
// attribute group then the bin_attribute array (kernel/module/sysfs.c v6.14
// and v6.17); Elf64_Sym is 24 bytes (ELF gABI).
const (
	attrGroupSize     = 48
	attrGroupBinAttrs = 40
	binAttrSize       = 88
	binAttrPrivate    = 24
	elfSymSize        = 24
	shnAbs            = 0xfff1
	globalFunc        = 0x12
)

// Placements inside a module's own area (S80 D1, D2); the linuxmodule fuzz
// test reads the section attributes at module + 0x2000.
const (
	sectAttrsAt  = 0x2000
	binAttrsGap  = 0x1000
	sectNamesGap = 0x800
	KallsymsAt   = 0x4000
)

// AddELF gives the module at mod sysfs section attributes, one per name at
// the matching address, int3 bytes at each address, and a three-entry symbol
// table: the null symbol, then init_module and helper as absolute global
// functions.
func (f *Fixture) AddELF(mod uint64, names []string, addrs []uint64) {
	sa := mod + sectAttrsAt
	f.Mem.U64(mod+ModSectAttrs, sa)
	binAttrs := sa + binAttrsGap
	f.Mem.U64(sa+attrGroupBinAttrs, binAttrs)
	for n, name := range names {
		attr := sa + attrGroupSize + uint64(n)*binAttrSize
		nameAt := sa + sectNamesGap + uint64(n)*0x40
		f.Mem.Str(nameAt, name)
		f.Mem.U64(attr, nameAt)
		f.Mem.U64(attr+binAttrPrivate, addrs[n])
		f.Mem.U64(binAttrs+uint64(n)*8, attr)
	}
	f.Mem.U64(binAttrs+uint64(len(names))*8, 0)
	trap := make([]byte, 16)
	for n := range trap {
		trap[n] = 0xcc
	}
	for _, a := range addrs {
		f.Mem.Write(a, trap)
	}

	ks := mod + KallsymsAt
	f.Mem.U64(mod+ModKallsyms, ks)
	symtab, strtab := ks+0x100, ks+0x800
	f.Mem.U64(ks, symtab)
	f.Mem.U32(ks+8, 3)
	f.Mem.U64(ks+16, strtab)
	f.Mem.Write(strtab, []byte("\x00init_module\x00helper\x00\x00"))
	sym := func(n int, name uint32, info byte, value uint64) {
		at := symtab + uint64(n)*elfSymSize
		f.Mem.U32(at, name)
		f.Mem.U8(at+4, info)
		f.Mem.U16(at+6, shnAbs)
		f.Mem.U64(at+8, value)
		f.Mem.U64(at+16, 0x20)
	}
	sym(0, 0, 0, 0)
	sym(1, 1, globalFunc, addrs[0]+0x10)
	sym(2, uint32(len("\x00init_module\x00")), globalFunc, addrs[0]+0x40)
}
