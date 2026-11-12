package linuxobjtest

import "github.com/aoiflux/libvapour/symbols"

// struct pid and upid (include/linux/pid.h v6.17), xarray and xa_node
// (include/linux/xarray.h, XA_CHUNK_SHIFT 6, three mark words), idr
// (include/linux/idr.h), pid_namespace (include/linux/pid_namespace.h v6.17,
// idr first) and address_space.i_pages (include/linux/fs.h): all fixed by
// their headers.
const (
	PIDSize       = 0xa0
	PIDTasks      = 0x40
	PIDNumbers    = 0x90
	UpidSize      = 0x10
	PidNsIDR      = 0x00
	XANodeShift   = 0x00
	XANodeSlots   = 0x28
	XANodeSize    = XANodeSlots + xaSlots*8 + 3*8
	XArrayXAHead  = 0x08
	AddrSpacePage = 0x08
)

const (
	xaSlots     = 64
	xaShift     = 6
	xaNodeTag   = 2
	idrSize     = 0x18
	pidNSSize   = idrSize
	xarraySize  = 0x10
	addrSpaceSz = 0x20
)

func AddPIDTypes(k *Kernel) {
	t := k.Table
	slots := voidPtr()
	t.AddStruct(symbols.StructType{Name: "pid", Size: PIDSize, Fields: []symbols.Field{
		field("tasks", PIDTasks, array("hlist_head", pidTypes)),
		field("numbers", PIDNumbers, array("upid", 1)),
	}})
	t.AddStruct(symbols.StructType{Name: "upid", Size: UpidSize, Fields: []symbols.Field{
		field("nr", 0, scalar("int")), field("ns", 8, ptr("pid_namespace")),
	}})
	t.AddStruct(symbols.StructType{Name: "address_space", Size: addrSpaceSz, Fields: []symbols.Field{
		field("i_pages", AddrSpacePage, scalar("xarray")),
	}})
	t.AddStruct(symbols.StructType{Name: "xarray", Size: xarraySize, Fields: []symbols.Field{field("xa_head", XArrayXAHead, voidPtr())}})
	t.AddStruct(symbols.StructType{Name: "xa_node", Size: XANodeSize, Fields: []symbols.Field{
		field("shift", XANodeShift, scalar("unsigned char")),
		field("slots", XANodeSlots, symbols.TypeRef{Name: "void", IsArray: true, ArrayLength: xaSlots, Element: &slots}),
	}})
	t.AddStruct(symbols.StructType{Name: "idr", Size: idrSize, Fields: []symbols.Field{field("idr_rt", 0, scalar("xarray"))}})
	t.AddEnum(symbols.EnumType{Name: "pid_type", Size: 4, Values: []symbols.EnumValue{
		{Name: "PIDTYPE_PID", Value: 0}, {Name: "PIDTYPE_TGID", Value: 1},
		{Name: "PIDTYPE_PGID", Value: 2}, {Name: "PIDTYPE_SID", Value: 3},
	}})
}

// AddPID lays out a struct pid whose PIDTYPE_PID list holds task, or no task
// when task is 0.
func (k *Kernel) AddPID(task uint64) uint64 {
	p := k.Alloc(PIDSize)
	if task != 0 {
		k.Mem.U64(p+PIDTasks, task+TaskPIDLinks)
	}
	return p
}

// XArray stores entries by index under the xarray at root: one node when
// every index is below 64, else a root of shift 6 over leaf nodes. Node
// pointers carry the internal-entry tag 2 (xa_mk_node).
func (k *Kernel) XArray(root uint64, entries map[uint64]uint64) {
	top := k.Alloc(XANodeSize)
	k.Mem.U64(root+XArrayXAHead, top|xaNodeTag)
	wide := false
	for i := range entries {
		wide = wide || i >= xaSlots
	}
	if !wide {
		for i, e := range entries {
			k.Mem.U64(top+XANodeSlots+8*i, e)
		}
		return
	}
	k.Mem.Write(top+XANodeShift, []byte{xaShift})
	leaves := map[uint64]uint64{}
	for i, e := range entries {
		hi := i >> xaShift
		leaf, ok := leaves[hi]
		if !ok {
			leaf = k.Alloc(XANodeSize)
			leaves[hi] = leaf
			k.Mem.U64(top+XANodeSlots+8*hi, leaf|xaNodeTag)
		}
		k.Mem.U64(leaf+XANodeSlots+8*(i%xaSlots), e)
	}
}

// AddPIDNamespace declares init_pid_ns over an IDR mapping each PID to its
// struct pid.
func (k *Kernel) AddPIDNamespace(pids map[uint64]uint64) {
	k.Table.AddStruct(symbols.StructType{Name: "pid_namespace", Size: pidNSSize, Fields: []symbols.Field{
		field("idr", PidNsIDR, scalar("idr")),
	}})
	ns := k.Alloc(pidNSSize)
	k.Table.AddSymbol(symbols.Symbol{Name: "init_pid_ns", Address: ns, Type: "pid_namespace"})
	k.XArray(ns+PidNsIDR, pids)
}
