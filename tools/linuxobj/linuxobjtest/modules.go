package linuxobjtest

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/symbols"
)

// struct module (include/linux/module.h v6.4, no CONFIG_MODULES_TREE_LOOKUP):
// fixed to mkobj, the rest placed. syms and num_syms (AddKallsymsLists) take
// 0xb0 and 0xb8; mem holds seven module_memory of up to 72 bytes, the S38
// tree form, so kallsyms comes after the largest form. kobject and
// module_kobject are fixed (include/linux/kobject.h, v4.19 and v6.17).
const (
	ModuleSize     = 0x2c0
	ModuleState    = 0x00
	ModuleList     = 0x08
	ModuleName     = 0x18
	ModuleMkobj    = 0x50
	ModuleKallsyms = 0x2b8
	ModuleMem      = 0xc0
	MkobjMod       = 0x40
	KobjName       = 0x00
	KobjEntry      = 0x08
	KobjKref       = 0x38
)

// Region kinds index module.mem (enum mod_mem_type, v6.4 to v6.17).
const (
	RegionText = 0
	RegionData = 1
)

const (
	moduleNameLen     = 56
	moduleMemorySize  = 0x10
	moduleKobjectSize = 0x60
	kobjectSize       = 0x40
	ksetSize          = 0x60
	modKallsymsSize   = 0x18
	modTreeRootSize   = 0x10
	modTreeAddrMax    = 0x08
	elfSymSize        = 24
)

type Modules struct {
	k        *Kernel
	listHead uint64
	kset     uint64
	modTree  uint64
}

type ModuleSymbol struct {
	Name  string
	Value uint64
}

// AddModuleTypes declares the module types and lays out an empty modules
// list, an empty module_kset and mod_tree.
func AddModuleTypes(k *Kernel) *Modules {
	t := k.Table
	t.AddStruct(symbols.StructType{Name: "module_memory", Size: moduleMemorySize, Fields: []symbols.Field{
		field("base", 0, voidPtr()), field("size", 8, scalar("unsigned int")),
	}})
	t.AddStruct(symbols.StructType{Name: "module", Size: ModuleSize, Fields: []symbols.Field{
		field("state", ModuleState, scalar("unsigned int")),
		field("list", ModuleList, scalar("list_head")),
		field("name", ModuleName, array("char", moduleNameLen)),
		field("mkobj", ModuleMkobj, scalar("module_kobject")),
		field("mem", ModuleMem, array("module_memory", 7)),
		field("kallsyms", ModuleKallsyms, ptr("mod_kallsyms")),
	}})
	t.AddStruct(symbols.StructType{Name: "module_kobject", Size: moduleKobjectSize, Fields: []symbols.Field{
		field("kobj", 0, scalar("kobject")), field("mod", MkobjMod, ptr("module")),
	}})
	t.AddStruct(symbols.StructType{Name: "kobject", Size: kobjectSize, Fields: []symbols.Field{
		field("name", KobjName, ptr("char")), field("entry", KobjEntry, scalar("list_head")), field("kref", KobjKref, scalar("kref")),
	}})
	t.AddStruct(symbols.StructType{Name: "kref", Size: 4, Fields: []symbols.Field{field("refcount", 0, scalar("refcount_t"))}})
	t.AddStruct(symbols.StructType{Name: "refcount_t", Size: 4, Fields: []symbols.Field{field("refs", 0, scalar("atomic_t"))}})
	t.AddStruct(symbols.StructType{Name: "atomic_t", Size: 4, Fields: []symbols.Field{field("counter", 0, scalar("int"))}})
	t.AddStruct(symbols.StructType{Name: "kset", Size: ksetSize, Fields: []symbols.Field{field("list", 0, scalar("list_head"))}})
	t.AddStruct(symbols.StructType{Name: "mod_kallsyms", Size: modKallsymsSize, Fields: []symbols.Field{
		field("symtab", 0, ptr("Elf64_Sym")), field("num_symtab", 8, scalar("unsigned int")), field("strtab", 0x10, ptr("char")),
	}})
	t.AddStruct(symbols.StructType{Name: "mod_tree_root", Size: modTreeRootSize, Fields: []symbols.Field{
		field("addr_min", 0, scalar("long long unsigned int")), field("addr_max", modTreeAddrMax, scalar("long long unsigned int")),
	}})
	var values []symbols.EnumValue
	for n, name := range []string{"MOD_TEXT", "MOD_DATA", "MOD_RODATA", "MOD_RO_AFTER_INIT", "MOD_INIT_TEXT",
		"MOD_INIT_DATA", "MOD_INIT_RODATA"} {
		values = append(values, symbols.EnumValue{Name: name, Value: int64(n)})
	}
	t.AddEnum(symbols.EnumType{Name: "mod_mem_type", Values: values, Size: 4})

	m := &Modules{k: k}
	m.listHead = k.Alloc(16)
	k.Circle(m.listHead)
	t.AddSymbol(symbols.Symbol{Name: "modules", Address: m.listHead, Type: "list_head"})
	m.kset = k.Alloc(ksetSize)
	k.Circle(m.kset)
	ksetPtr := k.Alloc(8)
	k.Mem.U64(ksetPtr, m.kset)
	t.AddSymbol(symbols.Symbol{Name: "module_kset", Address: ksetPtr, Type: "*kset"})
	m.modTree = k.Alloc(modTreeRootSize)
	t.AddSymbol(symbols.Symbol{Name: "mod_tree", Address: m.modTree, Type: "mod_tree_root"})
	return m
}

// Add lays out a live module whose text is [at, at+size) and whose struct
// module sits at the start of its data region, as a loaded module's does
// (S06 F5). Its kallsyms hold the null symbol then syms, each a defined text
// symbol with the type letter in st_info as the v4.19 add_kallsyms leaves
// it. It goes on no list; List and Kset do that.
func (m *Modules) Add(name string, at, size uint64, syms []ModuleSymbol, refs int32) uint64 {
	k := m.k
	k.Mem.Map(at, ModuleSize)
	n := make([]byte, moduleNameLen)
	copy(n, name)
	k.Mem.Write(at+ModuleName, n)
	m.Region(at, RegionText, at, size)
	m.Region(at, RegionData, at, ModuleSize)
	k.Mem.U64(at+ModuleMkobj+MkobjMod, at)
	kobj := at + ModuleMkobj
	k.Mem.U64(kobj+KobjName, k.Str(name))
	k.Mem.U32(kobj+KobjKref, uint32(refs))

	strtab := []byte{0}
	symtab := make([]byte, elfSymSize*(len(syms)+1))
	for i, s := range syms {
		rec := symtab[elfSymSize*(i+1):]
		binary.LittleEndian.PutUint32(rec, uint32(len(strtab)))
		rec[4] = 't'
		binary.LittleEndian.PutUint16(rec[6:], 1)
		binary.LittleEndian.PutUint64(rec[8:], s.Value)
		strtab = append(append(strtab, s.Name...), 0)
	}
	ks := k.Alloc(modKallsymsSize)
	k.Mem.U64(at+ModuleKallsyms, ks)
	st := k.Alloc(uint64(len(symtab)))
	k.Mem.Write(st, symtab)
	str := k.Alloc(uint64(len(strtab)))
	k.Mem.Write(str, strtab)
	k.Mem.U64(ks, st)
	k.Mem.U32(ks+8, uint32(len(syms)+1))
	k.Mem.U64(ks+0x10, str)
	return at
}

// Region sets module.mem[kind] at the element size the table gives
// module_memory, so it follows a form another fixture declares.
func (m *Modules) Region(mod uint64, kind int, base, size uint64) {
	stride := uint64(moduleMemorySize)
	if st, err := m.k.Table.Struct("module_memory"); err == nil && st.Size > 0 {
		stride = st.Size
	}
	at := mod + ModuleMem + uint64(kind)*stride
	m.k.Mem.U64(at, base)
	m.k.Mem.U32(at+8, uint32(size))
}

func (m *Modules) List(mods ...uint64) {
	heads := []uint64{m.listHead}
	for _, mod := range mods {
		heads = append(heads, mod+ModuleList)
	}
	m.k.Circle(heads...)
}

func (m *Modules) Kset(mods ...uint64) {
	heads := []uint64{m.kset}
	for _, mod := range mods {
		heads = append(heads, mod+ModuleMkobj+KobjEntry)
	}
	m.k.Circle(heads...)
}

// Area sets the module address bounds mod_tree records.
func (m *Modules) Area(lo, hi uint64) {
	m.k.Mem.U64(m.modTree, lo)
	m.k.Mem.U64(m.modTree+modTreeAddrMax, hi)
}
