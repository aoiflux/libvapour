package linuxtracetest

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
)

// Addresses (S80 3.1). Text is __START_KERNEL_map plus the default 16 MiB
// CONFIG_PHYSICAL_START, Heap a page into the v6.17 direct map
// (__PAGE_OFFSET_BASE_L4) and ModuleArea MODULES_VADDR. The data symbol
// slots stay where the dependent tests place their objects around them.
const (
	Text          = 0xffffffff81000000
	EText         = 0xffffffff81800000
	Data          = 0xffffffff82000000
	Heap          = 0xffff888000100000
	ModuleArea    = 0xffffffffc0000000
	ModuleAreaEnd = 0xffffffffc0100000
)

const (
	ModulesHead = Data + 0x000
	ModuleKset  = Data + 0x100
	ModTree     = Data + 0x200
	KsetObject  = Data + 0x300
	InitTask    = Data + 0x1000
)

// The module form with core and init layouts (include/linux/module.h v6.1,
// no CONFIG_MODULES_TREE_LOOKUP), and the task members of S80 T2. The
// module prefix to mkobj, the kobject, the layout, mod_kallsyms and
// signal_struct.thread_head are fixed by the headers; the rest is placed.
const (
	ModuleSize       = 0x100
	ModuleList       = 0x08
	ModuleName       = 0x18
	ModuleNameLen    = 56
	ModuleMkobj      = 0x50
	ModuleState      = 0x00
	ModuleCoreLayout = 0xb0
	ModuleInitLayout = 0xc8
	ModuleKallsyms   = 0xe0
	MkobjKobj        = 0x00
	MkobjMod         = 0x40
	KobjName         = 0x00
	KobjEntry        = 0x08
	KobjKref         = 0x38
	LayoutBase       = 0x00
	LayoutSize       = 0x08
	LayoutTextSize   = 0x0c
	KallsymsSymtab   = 0x00
	KallsymsNum      = 0x08
	KallsymsStrtab   = 0x10

	TaskSize          = 0x78
	TaskTasks         = 0x08
	TaskPID           = 0x28
	TaskTGID          = 0x2c
	TaskComm          = 0x48
	TaskSignal        = 0x60
	TaskNsproxy       = 0x58
	TaskRealParent    = 0x30
	TaskMM            = 0x18
	TaskActiveMM      = 0x20
	TaskThreadNode    = 0x38
	TaskPerfEventList = 0x68
	TaskFlags         = 0x00
	SignalSize        = 0x20
	SignalThreadHead  = 0x10
	NsproxySize       = 0x48
	MMSize            = 0x08
)

const (
	moduleKobjectSize = 0x60
	kobjectSize       = 0x40
	layoutSize        = 0x18
	modKallsymsSize   = 0x20
	modTreeRootSize   = 0x10
	ksetSize          = 0x60
	ksetKobj          = 0x18
	elfSymSize        = 24
	moduleSlot        = 0x1000
	firstModule       = 0x80000
)

type Kernel struct {
	Mem   *Memory
	Table *Table

	heap       uint64
	moduleSlot uint64
	modules    []uint64
	kset       []uint64
	tasks      []uint64
	nsproxy    uint64
}

type Module struct {
	Name                 string
	Base                 uint64
	Size, Text           uint32
	Hidden               bool
	NotInKset            bool
	NotInLinuxModuleList bool
	Refcount             int32
	Symbols              []ModuleSymbol
	NotSelfMapped        bool
}

type ModuleSymbol struct {
	Name  string
	Value uint64
}

// NewKernel declares the module types and lays out the module kset pointer,
// the module area bounds in mod_tree and the module area itself.
func NewKernel() *Kernel {
	k := &Kernel{Mem: NewMemory(), Table: NewTable(), heap: Heap}
	t := k.Table
	t.ListHead()
	t.Struct("module", ModuleSize,
		M("state", ModuleState, Base("unsigned int")),
		M("list", ModuleList, Struct("list_head")),
		M("name", ModuleName, Array(Base("char"), ModuleNameLen)),
		M("mkobj", ModuleMkobj, Struct("module_kobject")),
		M("core_layout", ModuleCoreLayout, Struct("module_layout")),
		M("init_layout", ModuleInitLayout, Struct("module_layout")),
		M("kallsyms", ModuleKallsyms, Ptr(Struct("mod_kallsyms"))))
	t.Struct("module_kobject", moduleKobjectSize, M("kobj", MkobjKobj, Struct("kobject")), M("mod", MkobjMod, Ptr(Struct("module"))))
	t.Struct("kobject", kobjectSize,
		M("name", KobjName, Ptr(Base("char"))),
		M("entry", KobjEntry, Struct("list_head")),
		M("kref", KobjKref, Struct("kref")))
	t.Struct("kref", 4, M("refcount", 0, Struct("refcount_struct")))
	t.Struct("refcount_struct", 4, M("refs", 0, Struct("atomic_t")))
	t.Struct("atomic_t", 4, M("counter", 0, Base("int")))
	t.Struct("kset", ksetSize, M("list", 0, Struct("list_head")), M("kobj", ksetKobj, Struct("kobject")))
	t.Struct("module_layout", layoutSize,
		M("base", LayoutBase, Ptr(Base("void"))),
		M("size", LayoutSize, Base("unsigned int")),
		M("text_size", LayoutTextSize, Base("unsigned int")))
	t.Struct("mod_kallsyms", modKallsymsSize,
		M("symtab", KallsymsSymtab, Ptr(Struct("elf64_sym"))),
		M("num_symtab", KallsymsNum, Base("unsigned int")),
		M("strtab", KallsymsStrtab, Ptr(Base("char"))))
	t.Struct("mod_tree_root", modTreeRootSize, M("addr_min", 0, Base("long unsigned int")),
		M("addr_max", 8, Base("long unsigned int")))
	t.Symbol("modules", ModulesHead, Struct("list_head"))
	t.Symbol("module_kset", ModuleKset, Ptr(Struct("kset")))
	t.Symbol("mod_tree", ModTree, Struct("mod_tree_root"))
	t.Symbol("_text", Text, Array(Base("char"), 0))
	t.Symbol("_etext", EText, Array(Base("char"), 0))
	k.Mem.Map(Data, pageSize)
	k.Mem.U64(ModuleKset, KsetObject)
	k.Mem.U64(ModTree, ModuleArea)
	k.Mem.U64(ModTree+8, ModuleAreaEnd)
	k.Mem.Map(ModuleArea, ModuleAreaEnd-ModuleArea)
	return k
}

// 16-byte steps keep every allocation aligned for the widest member the
// fixtures declare.
func (k *Kernel) Alloc(size uint64) uint64 {
	addr := k.heap
	k.Mem.Map(addr, size)
	k.heap += (size + 15) &^ 15
	return addr
}

// NextModule is the struct module address the next AddModule uses, so a
// test can lay a module's core layout around it.
func (k *Kernel) NextModule() uint64 { return ModuleArea + firstModule + k.moduleSlot*moduleSlot }

func (k *Kernel) AddModule(m Module) uint64 {
	mod := k.NextModule()
	k.moduleSlot++
	mem := k.Mem
	mem.Write(mod, make([]byte, ModuleSize))
	mem.Str(mod+ModuleName, m.Name)
	if !m.NotSelfMapped {
		mem.U64(mod+ModuleMkobj+MkobjMod, mod)
	}
	core := mod + ModuleCoreLayout
	mem.U64(core+LayoutBase, m.Base)
	mem.U32(core+LayoutSize, m.Size)
	mem.U32(core+LayoutTextSize, m.Text)
	kobj := mod + ModuleMkobj + MkobjKobj
	name := k.Alloc(uint64(len(m.Name)) + 1)
	mem.Str(name, m.Name)
	mem.U64(kobj+KobjName, name)
	refs := m.Refcount
	if refs == 0 {
		refs = 3
	}
	mem.U32(kobj+KobjKref, uint32(refs))
	if len(m.Symbols) > 0 {
		k.moduleSymbols(mod, m.Symbols)
	}
	if !m.Hidden && !m.NotInLinuxModuleList {
		k.modules = append(k.modules, mod+ModuleList)
	}
	if !m.Hidden && !m.NotInKset {
		k.kset = append(k.kset, kobj+KobjEntry)
	}
	return mod
}

// moduleSymbols writes the module's kallsyms: entry 0 is the null symbol
// (ELF gABI), and each symbol carries its type letter in st_info and a
// defined section index, as the v4.19 add_kallsyms leaves them.
func (k *Kernel) moduleSymbols(mod uint64, syms []ModuleSymbol) {
	strtab := []byte{0}
	symtab := make([]byte, elfSymSize*(len(syms)+1))
	for n, s := range syms {
		rec := symtab[elfSymSize*(n+1):]
		binary.LittleEndian.PutUint32(rec, uint32(len(strtab)))
		rec[4] = 't'
		binary.LittleEndian.PutUint16(rec[6:], 1)
		binary.LittleEndian.PutUint64(rec[8:], s.Value)
		strtab = append(append(strtab, s.Name...), 0)
	}
	ks := k.Alloc(modKallsymsSize)
	st := k.Alloc(uint64(len(symtab)))
	k.Mem.Write(st, symtab)
	str := k.Alloc(uint64(len(strtab)))
	k.Mem.Write(str, strtab)
	k.Mem.U64(ks+KallsymsSymtab, st)
	k.Mem.U32(ks+KallsymsNum, uint32(len(syms)+1))
	k.Mem.U64(ks+KallsymsStrtab, str)
	k.Mem.U64(mod+ModuleKallsyms, ks)
}

type Task struct {
	PID, TGID  int32
	Comm       string
	Threads    []Task
	PerfEvents []uint64
	NoSignal   bool
}

// AddTask lays out a thread group leader and its threads, all sharing one
// signal_struct whose thread_head links them; it returns the leader and the
// threads.
func (k *Kernel) AddTask(t Task) (uint64, []uint64) {
	k.declareTasks()
	signal := k.Alloc(SignalSize)
	leader := k.newTask(t, signal)
	k.tasks = append(k.tasks, leader+TaskTasks)
	group := []uint64{signal + SignalThreadHead, leader + TaskThreadNode}
	var threads []uint64
	for _, th := range t.Threads {
		at := k.newTask(th, signal)
		threads = append(threads, at)
		group = append(group, at+TaskThreadNode)
	}
	k.Mem.Link(group...)
	return leader, threads
}

func (k *Kernel) newTask(t Task, signal uint64) uint64 {
	task := k.Alloc(TaskSize)
	mem := k.Mem
	mem.U32(task+TaskPID, uint32(t.PID))
	mem.U32(task+TaskTGID, uint32(t.TGID))
	mem.Str(task+TaskComm, t.Comm)
	if !t.NoSignal {
		mem.U64(task+TaskSignal, signal)
	}
	mem.U64(task+TaskNsproxy, k.nsproxy)
	mem.U64(task+TaskRealParent, InitTask)
	mem.Link(append([]uint64{task + TaskPerfEventList}, t.PerfEvents...)...)
	return task
}

func (k *Kernel) declareTasks() {
	if k.nsproxy != 0 {
		return
	}
	t := k.Table
	t.Struct("task_struct", TaskSize,
		M("tasks", TaskTasks, Struct("list_head")),
		M("pid", TaskPID, Base("int")),
		M("tgid", TaskTGID, Base("int")),
		M("comm", TaskComm, Array(Base("char"), 16)),
		M("signal", TaskSignal, Ptr(Struct("signal_struct"))),
		M("nsproxy", TaskNsproxy, Ptr(Struct("nsproxy"))),
		M("real_parent", TaskRealParent, Ptr(Struct("task_struct"))),
		M("mm", TaskMM, Ptr(Struct("mm_struct"))),
		M("active_mm", TaskActiveMM, Ptr(Struct("mm_struct"))),
		M("thread_node", TaskThreadNode, Struct("list_head")),
		M("perf_event_list", TaskPerfEventList, Struct("list_head")),
		M("flags", TaskFlags, Base("unsigned int")))
	t.Struct("signal_struct", SignalSize, M("thread_head", SignalThreadHead, Struct("list_head")))
	t.Struct("nsproxy", NsproxySize, M("count", 0, Base("int")))
	t.Struct("mm_struct", MMSize, M("pgd", 0, Ptr(Base("void"))))
	t.Symbol("init_task", InitTask, Struct("task_struct"))
	k.nsproxy = k.Alloc(NsproxySize)
	k.Mem.Write(InitTask, make([]byte, TaskSize))
	k.Mem.Str(InitTask+TaskComm, "swapper/0")
}

// Build closes the module list, the kset and, once a task exists, the task
// list through init_task, then builds the table.
func (k *Kernel) Build(options map[string]any) (tools.Context, *[]string, error) {
	k.Mem.Link(append([]uint64{ModulesHead}, k.modules...)...)
	k.Mem.Link(append([]uint64{KsetObject}, k.kset...)...)
	if k.nsproxy != 0 {
		k.Mem.Link(append([]uint64{InitTask + TaskTasks}, k.tasks...)...)
	}
	table, err := k.Table.Build()
	if err != nil {
		return tools.Context{}, nil, fmt.Errorf("linuxtracetest: build the symbol table: %w", err)
	}
	diags := &[]string{}
	return Context(k.Mem, table, diags, options), diags, nil
}

// xarray and xa_node as include/linux/xarray.h lays them out (v4.19 to
// v6.17, XA_CHUNK_SHIFT 6): slots at 0x28, three mark words after them.
const (
	XANodeShift = 0x00
	XANodeSlots = 0x28
	XANodeSize  = XANodeSlots + xaChunk*8 + 3*8
	XAHead      = 0x08
	IDRSize     = 0x18
	xaChunk     = 64
	xaNodeMark  = 2
)

func (k *Kernel) DeclareXArray() {
	t := k.Table
	t.Struct("address_space", 0x18, M("i_pages", 0x08, Struct("xarray")))
	t.Struct("xarray", 0x10, M("xa_flags", 0x04, Base("unsigned int")), M("xa_head", XAHead, Ptr(Base("void"))))
	t.Struct("xa_node", XANodeSize,
		M("shift", XANodeShift, Base("unsigned char")),
		M("slots", XANodeSlots, Array(Ptr(Base("void")), xaChunk)))
	t.Struct("idr", IDRSize, M("idr_rt", 0, Struct("xarray")), M("idr_base", 0x10, Base("unsigned int")))
}

// IDR stores entries at ids 1, 2, ... in a two-level tree: a root node of
// shift 6 whose slots hold leaf nodes, internal entries tagged with 2
// (xa_mk_node, include/linux/xarray.h).
func (k *Kernel) IDR(idr uint64, entries []uint64) {
	root := k.Alloc(XANodeSize)
	k.Mem.Write(root+XANodeShift, []byte{6})
	k.Mem.Map(idr, IDRSize)
	k.Mem.U64(idr+XAHead, root|xaNodeMark)
	for n, e := range entries {
		id := uint64(n) + 1
		slot := root + XANodeSlots + id/xaChunk*8
		b, err := k.Mem.ReadAt(slot, 8)
		if err != nil {
			panic(err)
		}
		leaf := binary.LittleEndian.Uint64(b) &^ 3
		if leaf == 0 {
			leaf = k.Alloc(XANodeSize)
			k.Mem.U64(slot, leaf|xaNodeMark)
		}
		k.Mem.U64(leaf+XANodeSlots+id%xaChunk*8, e)
	}
}
