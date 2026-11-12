package linuxobjtest

import (
	"encoding/binary"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
)

// module.syms and num_syms are placed after mkobj (S80 O21). kernel_symbol
// is the PREL32 form of include/linux/export.h v6.1 (three int offsets) or
// the absolute form of v4.19 (value, name). ftrace_mod_map and
// ftrace_mod_func are fixed (kernel/trace/ftrace.c v4.19 and v6.17), as are
// ftrace_ops to list (include/linux/ftrace.h v6.17, CONFIG_DYNAMIC_FTRACE)
// and bpf_ksym (include/linux/bpf.h v6.1 and v6.17, KSYM_NAME_LEN 512).
const (
	ModuleSyms             = 0xb0
	ModuleNumSyms          = 0xb8
	KernelSymbolSize       = 12
	FtraceModMapSize       = 0x50
	FtraceModMapList       = 0x10
	FtraceModMapMod        = 0x20
	FtraceModMapFuncs      = 0x38
	FtraceModFuncSize      = 0x28
	FtraceModFuncName      = 0x10
	FtraceModFuncIP        = 0x18
	FtraceModFuncSz        = 0x20
	FtraceOpsSize          = 0xb0
	FtraceOpsTrampoline    = 0x90
	FtraceOpsTrampolineSz  = 0x98
	FtraceOpsList          = 0xa0
	BPFKsymSize            = 0x258
	BPFKsymStart           = 0x00
	BPFKsymEnd             = 0x08
	BPFKsymName            = 0x10
	BPFKsymLnode           = 0x210
	BPFKsymNameLen         = 512
	kallsymsListKsymtabGap = 0x1000
)

const (
	absoluteSymbolSize = 0x10
	modKallsymsTypes   = 0x20
	modKallsymsTypetab = 0x18
	moduleTextSize     = 0x1000
	liveModuleRefs     = 3
)

type KallsymsLists struct {
	k        *Kernel
	Mods     *Modules
	Absolute bool

	ftraceMaps, trampolines, bpf uint64
}

type ElfSym struct {
	Name        string
	Info        byte
	Value, Size uint64
	Type        byte
}

type Export struct {
	Name  string
	Value uint64
}

type FtraceFunc struct {
	Name     string
	IP, Size uint64
}

// AddKallsymsLists declares the module export and kallsyms types of S38 and
// lays out empty ftrace_mod_maps, ftrace_ops_trampoline_list and
// bpf_kallsyms lists.
func AddKallsymsLists(k *Kernel, mods *Modules, absolute bool) *KallsymsLists {
	t := k.Table
	u64 := scalar("long long unsigned int")
	k.addFields("module", ModuleSize, field("syms", ModuleSyms, ptr("kernel_symbol")),
		field("num_syms", ModuleNumSyms, scalar("unsigned int")))
	t.AddStruct(symbols.StructType{Name: "mod_kallsyms", Size: modKallsymsTypes, Fields: []symbols.Field{
		field("symtab", 0, ptr("Elf64_Sym")), field("num_symtab", 8, scalar("unsigned int")),
		field("strtab", 0x10, ptr("char")), field("typetab", modKallsymsTypetab, ptr("char")),
	}})
	if absolute {
		t.AddStruct(symbols.StructType{Name: "kernel_symbol", Size: absoluteSymbolSize, Fields: []symbols.Field{
			field("value", 0, u64), field("name", 8, ptr("char")),
		}})
	} else {
		t.AddStruct(symbols.StructType{Name: "kernel_symbol", Size: KernelSymbolSize, Fields: []symbols.Field{
			field("value_offset", 0, scalar("int")), field("name_offset", 4, scalar("int")),
			field("namespace_offset", 8, scalar("int")),
		}})
	}
	t.AddStruct(symbols.StructType{Name: "ftrace_mod_map", Size: FtraceModMapSize, Fields: []symbols.Field{
		field("list", FtraceModMapList, scalar("list_head")), field("mod", FtraceModMapMod, ptr("module")),
		field("funcs", FtraceModMapFuncs, scalar("list_head")),
	}})
	t.AddStruct(symbols.StructType{Name: "ftrace_mod_func", Size: FtraceModFuncSize, Fields: []symbols.Field{
		field("list", 0, scalar("list_head")), field("name", FtraceModFuncName, ptr("char")),
		field("ip", FtraceModFuncIP, u64), field("size", FtraceModFuncSz, scalar("unsigned int")),
	}})
	t.AddStruct(symbols.StructType{Name: "ftrace_ops", Size: FtraceOpsSize, Fields: []symbols.Field{
		field("trampoline", FtraceOpsTrampoline, u64), field("trampoline_size", FtraceOpsTrampolineSz, u64),
		field("list", FtraceOpsList, scalar("list_head")),
	}})
	t.AddStruct(symbols.StructType{Name: "bpf_ksym", Size: BPFKsymSize, Fields: []symbols.Field{
		field("start", BPFKsymStart, u64), field("end", BPFKsymEnd, u64),
		field("name", BPFKsymName, array("char", BPFKsymNameLen)), field("lnode", BPFKsymLnode, scalar("list_head")),
	}})
	l := &KallsymsLists{k: k, Mods: mods, Absolute: absolute}
	head := func(name string) uint64 {
		a := k.Alloc(16)
		k.Circle(a)
		t.AddSymbol(symbols.Symbol{Name: name, Address: a, Type: "list_head"})
		return a
	}
	l.ftraceMaps = head("ftrace_mod_maps")
	l.trampolines = head("ftrace_ops_trampoline_list")
	l.bpf = head("bpf_kallsyms")
	return l
}

// Module adds a live module at at with its own symbol table (syms in order,
// with their type letters in typetab) and its exports sorted by name, as
// modpost sorts __ksymtab, in a table a page past at with the names after
// it. A PREL32 entry holds each target's offset from the entry's own field.
func (l *KallsymsLists) Module(name string, at uint64, syms []ElfSym, exports []Export) uint64 {
	k := l.k
	m := l.Mods.Add(name, at, moduleTextSize, nil, liveModuleRefs)
	strtab := []byte{0}
	symtab := make([]byte, elfSymSize*len(syms))
	typetab := make([]byte, len(syms))
	for i, s := range syms {
		rec := symtab[elfSymSize*i:]
		if s.Name != "" {
			binary.LittleEndian.PutUint32(rec, uint32(len(strtab)))
			strtab = append(append(strtab, s.Name...), 0)
		}
		rec[4] = s.Info
		binary.LittleEndian.PutUint64(rec[8:], s.Value)
		binary.LittleEndian.PutUint64(rec[16:], s.Size)
		typetab[i] = s.Type
	}
	ks := k.Alloc(modKallsymsTypes)
	k.Mem.U64(m+ModuleKallsyms, ks)
	st, str, tt := k.Alloc(uint64(len(symtab))+1), k.Alloc(uint64(len(strtab))), k.Alloc(uint64(len(typetab))+1)
	k.Mem.Write(st, symtab)
	k.Mem.Write(str, strtab)
	k.Mem.Write(tt, typetab)
	k.Mem.U64(ks, st)
	k.Mem.U32(ks+8, uint32(len(syms)))
	k.Mem.U64(ks+0x10, str)
	k.Mem.U64(ks+modKallsymsTypetab, tt)

	sorted := slices.Clone(exports)
	slices.SortStableFunc(sorted, func(a, b Export) int { return strings.Compare(a.Name, b.Name) })
	entry := uint64(KernelSymbolSize)
	if l.Absolute {
		entry = absoluteSymbolSize
	}
	ksymtab := at + kallsymsListKsymtabGap
	names := ksymtab + entry*uint64(len(sorted))
	for i, e := range sorted {
		sym := ksymtab + entry*uint64(i)
		if l.Absolute {
			k.Mem.U64(sym, e.Value)
			k.Mem.U64(sym+8, names)
		} else {
			k.Mem.U32(sym, uint32(int32(int64(e.Value-sym))))
			k.Mem.U32(sym+4, uint32(int32(int64(names-(sym+4)))))
			k.Mem.U32(sym+8, 0)
		}
		k.Mem.Write(names, append([]byte(e.Name), 0))
		names += uint64(len(e.Name)) + 1
	}
	if len(sorted) > 0 {
		k.Mem.U64(m+ModuleSyms, ksymtab)
	}
	k.Mem.U32(m+ModuleNumSyms, uint32(len(sorted)))
	return m
}

// FtraceMap adds an ftrace_mod_map for mod holding funcs in order.
func (l *KallsymsLists) FtraceMap(mod uint64, funcs []FtraceFunc) uint64 {
	k := l.k
	m := k.Alloc(FtraceModMapSize)
	k.Mem.U64(m+FtraceModMapMod, mod)
	heads := []uint64{m + FtraceModMapFuncs}
	for _, fn := range funcs {
		f := k.Alloc(FtraceModFuncSize)
		k.Mem.U64(f+FtraceModFuncName, k.Str(fn.Name))
		k.Mem.U64(f+FtraceModFuncIP, fn.IP)
		k.Mem.U32(f+FtraceModFuncSz, uint32(fn.Size))
		heads = append(heads, f)
	}
	k.Circle(heads...)
	l.addTail(l.ftraceMaps, m+FtraceModMapList)
	return m
}

func (l *KallsymsLists) Trampoline(addr, size uint64) uint64 {
	k := l.k
	op := k.Alloc(FtraceOpsSize)
	k.Mem.U64(op+FtraceOpsTrampoline, addr)
	k.Mem.U64(op+FtraceOpsTrampolineSz, size)
	l.addTail(l.trampolines, op+FtraceOpsList)
	return op
}

func (l *KallsymsLists) BPF(name string, start, end uint64) uint64 {
	k := l.k
	s := k.Alloc(BPFKsymSize)
	k.Mem.U64(s+BPFKsymStart, start)
	k.Mem.U64(s+BPFKsymEnd, end)
	k.Mem.Write(s+BPFKsymName, append([]byte(name), 0))
	l.addTail(l.bpf, s+BPFKsymLnode)
	return s
}

// addTail is list_add_tail (include/linux/list.h).
func (l *KallsymsLists) addTail(head, node uint64) {
	m := l.k.Mem
	last := m.read64(head + 8)
	m.U64(last, node)
	m.U64(node, head)
	m.U64(node+8, last)
	m.U64(head+8, node)
}
