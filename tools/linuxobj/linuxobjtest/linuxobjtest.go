package linuxobjtest

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// The x86-64 base page (Intel SDM Vol. 3A 4.5).
const pageSize = 0x1000

// Memory is a sparse address space: a page exists once something maps or
// writes it, and a read touching a page that does not exist is unmapped.
type Memory struct {
	pages map[uint64][]byte
}

func NewMemory() *Memory { return &Memory{pages: map[uint64][]byte{}} }

func pageBase(addr uint64) uint64 { return addr &^ (pageSize - 1) }

func (m *Memory) ReadAt(offset, size uint64) ([]byte, error) {
	if offset+size < offset {
		return nil, memory.ErrOutOfBounds
	}
	out := make([]byte, 0, size)
	for size > 0 {
		p, ok := m.pages[pageBase(offset)]
		if !ok {
			return nil, memory.ErrUnmapped
		}
		in := offset - pageBase(offset)
		n := min(pageSize-in, size)
		out = append(out, p[in:in+n]...)
		offset, size = offset+n, size-n
	}
	return out, nil
}

func (m *Memory) Size() uint64 { return ^uint64(0) }

func (m *Memory) Map(addr, size uint64) {
	if size == 0 {
		return
	}
	last := addr + size - 1
	if last < addr {
		last = ^uint64(0)
	}
	for p := pageBase(addr); ; p += pageSize {
		if m.pages[p] == nil {
			m.pages[p] = make([]byte, pageSize)
		}
		if p == pageBase(last) {
			return
		}
	}
}

func (m *Memory) Unmap(addr uint64) { delete(m.pages, pageBase(addr)) }

func (m *Memory) Write(addr uint64, b []byte) {
	m.Map(addr, uint64(len(b)))
	for len(b) > 0 {
		n := copy(m.pages[pageBase(addr)][addr-pageBase(addr):], b)
		b, addr = b[n:], addr+uint64(n)
	}
}

func (m *Memory) U64(addr, v uint64) { m.Write(addr, binary.LittleEndian.AppendUint64(nil, v)) }

func (m *Memory) U32(addr uint64, v uint32) { m.Write(addr, binary.LittleEndian.AppendUint32(nil, v)) }

func (m *Memory) u16(addr uint64, v uint16) { m.Write(addr, binary.LittleEndian.AppendUint16(nil, v)) }

func (m *Memory) read64(addr uint64) uint64 {
	b, err := m.ReadAt(addr, 8)
	if err != nil {
		panic(fmt.Sprintf("linuxobjtest: read at %#x: %v", addr, err))
	}
	return binary.LittleEndian.Uint64(b)
}

// Flat is a physical image: a read past its end is out of bounds.
type Flat struct{ Buf []byte }

func (f *Flat) ReadAt(offset, size uint64) ([]byte, error) {
	if offset > uint64(len(f.Buf)) || size > uint64(len(f.Buf))-offset {
		return nil, memory.ErrOutOfBounds
	}
	return append([]byte(nil), f.Buf[offset:offset+size]...), nil
}

func (f *Flat) Size() uint64 { return uint64(len(f.Buf)) }

// task_struct members in v6.17 declaration order (include/linux/sched.h),
// placed (S80 O1). 0xf0 and 0xf8 hold fs and files once AddFS or
// AddNetTypes declares them; the size covers the members the socketlist and
// processkernelstack tests add at 0x110 and 0x180 to 0x1a8.
const (
	TaskSize        = 0x1a8
	TaskFlags       = 0x00
	TaskPtrace      = 0x04
	TaskSchedClass  = 0x08
	TaskTasks       = 0x10
	TaskMM          = 0x20
	TaskActiveMM    = 0x28
	TaskExitState   = 0x30
	TaskPID         = 0x34
	TaskTGID        = 0x38
	TaskRealParent  = 0x40
	TaskParent      = 0x48
	TaskPtraced     = 0x50
	TaskPtraceEntry = 0x60
	TaskPIDLinks    = 0x70
	TaskThreadNode  = 0xb0
	TaskWorkerPriv  = 0xc0
	TaskStartBoot   = 0xc8
	TaskRealCred    = 0xd0
	TaskCred        = 0xd8
	TaskComm        = 0xe0
	TaskNsproxy     = 0x100
	TaskSignal      = 0x108

	// signal_struct (include/linux/sched/signal.h, v4.19 and v6.17) and
	// struct cred (include/linux/cred.h v6.17) are fixed by their headers
	// up to the members declared.
	SignalSize       = 0x20
	SignalThreadHead = 0x10
	CredSize         = 0x58
	CredUID          = 0x08
	CredGID          = 0x0c
	CredEUID         = 0x18
	CredEGID         = 0x1c
	CredCapInh       = 0x30
	CredCapPerm      = 0x38
	CredCapEff       = 0x40
	CredCapBset      = 0x48
	CredCapAmb       = 0x50

	// tk_core is seq then the timekeeper (kernel/time/timekeeping.c v6.1).
	// offs_real and offs_boot follow wall_to_monotonic in declaration order
	// (include/linux/timekeeper_internal.h v6.17), after the slots the S46
	// fixture declares.
	TkCoreTimekeeper = 0x08
	TimekeeperReal   = 0x40
	TimekeeperBoot   = 0x48
	timekeeperSize   = 0x50
)

const (
	nsproxySize    = 0x48
	pointeeSize    = 0x40
	cacheLine      = 64
	taskCommLength = 16
	pidTypes       = 4
)

// Base is a MiB into the x86-64 direct map, __PAGE_OFFSET_BASE_L4 of
// arch/x86/include/asm/page_64_types.h v6.17.
const Base uint64 = 0xffff888000100000

type Kernel struct {
	Mem      *Memory
	Table    *symbols.Table
	next     uint64
	InitTask uint64
}

func ptr(name string) symbols.TypeRef {
	return symbols.TypeRef{Name: name, IsPointer: true, Element: &symbols.TypeRef{Name: name}}
}

func scalar(name string) symbols.TypeRef { return symbols.TypeRef{Name: name} }

func array(name string, n uint64) symbols.TypeRef {
	return symbols.TypeRef{Name: name, IsArray: true, ArrayLength: n, Element: &symbols.TypeRef{Name: name}}
}

func voidPtr() symbols.TypeRef {
	return symbols.TypeRef{IsPointer: true, Element: &symbols.TypeRef{Name: "void"}}
}

func field(name string, off uint64, typ symbols.TypeRef) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: typ}
}

// addFields gives a declared record more members, replacing any of the same
// name; an undeclared record is declared with size.
func (k *Kernel) addFields(record string, size uint64, fields ...symbols.Field) {
	st, err := k.Table.Struct(record)
	if err != nil {
		st = symbols.StructType{Name: record, Size: size}
	}
	for _, f := range fields {
		kept := st.Fields[:0]
		for _, old := range st.Fields {
			if old.Name != f.Name {
				kept = append(kept, old)
			}
		}
		st.Fields = append(kept, f)
	}
	k.Table.AddStruct(st)
}

// The DWARF base type names, sized by the x86-64 psABI LP64 model (Figure
// 3.1), plus the C spellings the fixtures and their callers use.
var lp64 = []symbols.Scalar{
	{Name: "_Bool", Width: 1, Kind: symbols.ScalarBool},
	{Name: "char", Width: 1, Kind: symbols.ScalarChar, Signed: true},
	{Name: "signed char", Width: 1, Kind: symbols.ScalarChar, Signed: true},
	{Name: "unsigned char", Width: 1, Kind: symbols.ScalarChar},
	{Name: "short int", Width: 2, Kind: symbols.ScalarInteger, Signed: true},
	{Name: "short unsigned int", Width: 2, Kind: symbols.ScalarInteger},
	{Name: "unsigned short", Width: 2, Kind: symbols.ScalarInteger},
	{Name: "int", Width: 4, Kind: symbols.ScalarInteger, Signed: true},
	{Name: "unsigned int", Width: 4, Kind: symbols.ScalarInteger},
	{Name: "long int", Width: 8, Kind: symbols.ScalarInteger, Signed: true},
	{Name: "long unsigned int", Width: 8, Kind: symbols.ScalarInteger},
	{Name: "long long int", Width: 8, Kind: symbols.ScalarInteger, Signed: true},
	{Name: "long long unsigned int", Width: 8, Kind: symbols.ScalarInteger},
	{Name: "pointer", Width: 8, Kind: symbols.ScalarInteger},
	{Name: "void", Width: 0, Kind: symbols.ScalarVoid},
}

func newTable() *symbols.Table {
	t, err := symbols.Build("linuxobjtest", symbols.Declaration{PointerWidth: 8, Scalars: lp64})
	if err != nil {
		panic(fmt.Sprintf("linuxobjtest: build the table: %v", err))
	}
	return t
}

// NewKernel lays out init_task alone on the task list, named swapper/0 as
// init/init_task.c names it, and a tk_core whose clock offsets put boot at
// bootSec.bootNsec of wall time after 5 s of suspend.
func NewKernel(bootSec, bootNsec int64) *Kernel {
	t := newTable()
	t.AddStruct(symbols.StructType{Name: "list_head", Size: 16, Fields: []symbols.Field{
		field("next", 0, ptr("list_head")), field("prev", 8, ptr("list_head")),
	}})
	t.AddStruct(symbols.StructType{Name: "hlist_head", Size: 8, Fields: []symbols.Field{field("first", 0, ptr("hlist_node"))}})
	t.AddStruct(symbols.StructType{Name: "hlist_node", Size: 16, Fields: []symbols.Field{
		field("next", 0, ptr("hlist_node")), field("pprev", 8, ptr("hlist_node")),
	}})
	t.AddStruct(symbols.StructType{Name: "task_struct", Size: TaskSize, Fields: []symbols.Field{
		field("flags", TaskFlags, scalar("unsigned int")),
		field("ptrace", TaskPtrace, scalar("unsigned int")),
		field("sched_class", TaskSchedClass, ptr("sched_class")),
		field("tasks", TaskTasks, scalar("list_head")),
		field("mm", TaskMM, ptr("mm_struct")),
		field("active_mm", TaskActiveMM, ptr("mm_struct")),
		field("exit_state", TaskExitState, scalar("int")),
		field("pid", TaskPID, scalar("int")),
		field("tgid", TaskTGID, scalar("int")),
		field("real_parent", TaskRealParent, ptr("task_struct")),
		field("parent", TaskParent, ptr("task_struct")),
		field("ptraced", TaskPtraced, scalar("list_head")),
		field("ptrace_entry", TaskPtraceEntry, scalar("list_head")),
		field("pid_links", TaskPIDLinks, array("hlist_node", pidTypes)),
		field("thread_node", TaskThreadNode, scalar("list_head")),
		field("worker_private", TaskWorkerPriv, voidPtr()),
		field("start_boottime", TaskStartBoot, scalar("long long unsigned int")),
		field("real_cred", TaskRealCred, ptr("cred")),
		field("cred", TaskCred, ptr("cred")),
		field("comm", TaskComm, array("char", taskCommLength)),
		field("nsproxy", TaskNsproxy, ptr("nsproxy")),
		field("signal", TaskSignal, ptr("signal_struct")),
	}})
	t.AddStruct(symbols.StructType{Name: "signal_struct", Size: SignalSize, Fields: []symbols.Field{
		field("thread_head", SignalThreadHead, scalar("list_head")),
	}})
	t.AddStruct(symbols.StructType{Name: "nsproxy", Size: nsproxySize})
	t.AddStruct(symbols.StructType{Name: "mm_struct", Size: FSMMSize})
	t.AddStruct(symbols.StructType{Name: "sched_class", Size: pointeeSize})
	t.AddStruct(symbols.StructType{Name: "kuid_t", Size: 4, Fields: []symbols.Field{field("val", 0, scalar("unsigned int"))}})
	t.AddStruct(symbols.StructType{Name: "kgid_t", Size: 4, Fields: []symbols.Field{field("val", 0, scalar("unsigned int"))}})
	t.AddStruct(symbols.StructType{Name: "kernel_cap_t", Size: 8, Fields: []symbols.Field{
		field("val", 0, scalar("long long unsigned int")),
	}})
	t.AddStruct(symbols.StructType{Name: "cred", Size: CredSize, Fields: []symbols.Field{
		field("uid", CredUID, scalar("kuid_t")),
		field("gid", CredGID, scalar("kgid_t")),
		field("euid", CredEUID, scalar("kuid_t")),
		field("egid", CredEGID, scalar("kgid_t")),
		field("cap_inheritable", CredCapInh, scalar("kernel_cap_t")),
		field("cap_permitted", CredCapPerm, scalar("kernel_cap_t")),
		field("cap_effective", CredCapEff, scalar("kernel_cap_t")),
		field("cap_bset", CredCapBset, scalar("kernel_cap_t")),
		field("cap_ambient", CredCapAmb, scalar("kernel_cap_t")),
	}})
	t.AddStruct(symbols.StructType{Name: "timekeeper", Size: timekeeperSize, Fields: []symbols.Field{
		field("offs_real", TimekeeperReal, scalar("long long int")),
		field("offs_boot", TimekeeperBoot, scalar("long long int")),
	}})
	t.AddStruct(symbols.StructType{Name: "tk_core_t", Size: TkCoreTimekeeper + timekeeperSize, Fields: []symbols.Field{
		field("timekeeper", TkCoreTimekeeper, scalar("timekeeper")),
	}})

	k := &Kernel{Mem: NewMemory(), Table: t, next: Base}
	k.InitTask = k.Alloc(TaskSize)
	k.Circle(k.InitTask + TaskTasks)
	k.Mem.Write(k.InitTask+TaskComm, []byte("swapper/0\x00"))
	t.AddSymbol(symbols.Symbol{Name: "init_task", Address: k.InitTask, Type: "task_struct"})

	const suspendNs = 5e9
	tk := k.Alloc(TkCoreTimekeeper + timekeeperSize)
	t.AddSymbol(symbols.Symbol{Name: "tk_core", Address: tk, Type: "tk_core_t"})
	k.Mem.U64(tk+TkCoreTimekeeper+TimekeeperReal, uint64(bootSec*1e9+bootNsec+suspendNs))
	k.Mem.U64(tk+TkCoreTimekeeper+TimekeeperBoot, uint64(suspendNs))
	return k
}

// Alloc hands out zeroed kernel memory on cache-line steps.
func (k *Kernel) Alloc(size uint64) uint64 {
	addr := k.next
	k.Mem.Map(addr, size)
	k.next += (size + cacheLine - 1) &^ (cacheLine - 1)
	return addr
}

type Cred struct {
	UID, GID, EUID, EGID uint32
	Caps                 [5]uint64
}

// Caps are inheritable, permitted, effective, bounding and ambient, the
// cred.h order.
func (k *Kernel) AddCred(c Cred) uint64 {
	a := k.Alloc(CredSize)
	k.Mem.U32(a+CredUID, c.UID)
	k.Mem.U32(a+CredGID, c.GID)
	k.Mem.U32(a+CredEUID, c.EUID)
	k.Mem.U32(a+CredEGID, c.EGID)
	for n, off := range []uint64{CredCapInh, CredCapPerm, CredCapEff, CredCapBset, CredCapAmb} {
		k.Mem.U64(a+off, c.Caps[n])
	}
	return a
}

type Task struct {
	PID, TGID int32
	Comm      string
	Flags     uint32
	Parent    uint64
	Cred      uint64
	StartNS   uint64
	MM        uint64
	ExitState int32
	Ptrace    uint32
}

// AddTask lays out a thread group leader alone in its signal_struct, with
// its own nsproxy, one cred for both cred pointers (a fresh empty one when
// spec.Cred is 0) and init_task as parent when spec.Parent is 0. It is not
// put on the task list; LinkTasks does that.
func (k *Kernel) AddTask(spec Task) uint64 {
	a := k.Alloc(TaskSize)
	m := k.Mem
	m.U32(a+TaskPID, uint32(spec.PID))
	m.U32(a+TaskTGID, uint32(spec.TGID))
	m.U32(a+TaskFlags, spec.Flags)
	m.U32(a+TaskPtrace, spec.Ptrace)
	comm := make([]byte, taskCommLength)
	copy(comm, spec.Comm)
	m.Write(a+TaskComm, comm)
	parent := spec.Parent
	if parent == 0 {
		parent = k.InitTask
	}
	m.U64(a+TaskRealParent, parent)
	m.U64(a+TaskParent, parent)
	signal := k.Alloc(SignalSize)
	m.U64(a+TaskSignal, signal)
	k.Circle(signal+SignalThreadHead, a+TaskThreadNode)
	m.U64(a+TaskNsproxy, k.Alloc(nsproxySize))
	if spec.MM != 0 {
		m.Map(spec.MM, FSMMSize)
	}
	m.U64(a+TaskMM, spec.MM)
	m.U64(a+TaskActiveMM, spec.MM)
	cred := spec.Cred
	if cred == 0 {
		cred = k.AddCred(Cred{})
	}
	m.U64(a+TaskCred, cred)
	m.U64(a+TaskRealCred, cred)
	m.U64(a+TaskStartBoot, spec.StartNS)
	m.U32(a+TaskExitState, uint32(spec.ExitState))
	k.Circle(a + TaskPtraced)
	return a
}

// Circle makes the list_heads one circular list in the order given; one head
// alone is an empty list.
func (k *Kernel) Circle(heads ...uint64) {
	for n, h := range heads {
		k.Mem.U64(h, heads[(n+1)%len(heads)])
		k.Mem.U64(h+8, heads[(n+len(heads)-1)%len(heads)])
	}
}

// LinkTasks puts the tasks on the task list after init_task, in order.
func (k *Kernel) LinkTasks(tasks ...uint64) {
	heads := []uint64{k.InitTask + TaskTasks}
	for _, t := range tasks {
		heads = append(heads, t+TaskTasks)
	}
	k.Circle(heads...)
}

// LinkThreads makes the threads share the leader's signal_struct and puts
// them on its thread_head after the leader.
func (k *Kernel) LinkThreads(leader uint64, threads ...uint64) {
	signal := k.Mem.read64(leader + TaskSignal)
	heads := []uint64{signal + SignalThreadHead, leader + TaskThreadNode}
	for _, t := range threads {
		k.Mem.U64(t+TaskSignal, signal)
		heads = append(heads, t+TaskThreadNode)
	}
	k.Circle(heads...)
}

// Context collects diagnostics into the returned slice; options may be nil.
func (k *Kernel) Context(options map[string]any) (tools.Context, *[]string) {
	diags := &[]string{}
	if options == nil {
		options = map[string]any{}
	}
	options["diagnostics"] = diags
	return tools.Context{Memory: k.Mem, Symbols: k.Table, Profile: profiles.LinuxX64Profile{}, Options: options}, diags
}
