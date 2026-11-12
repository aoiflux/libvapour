package linuxwalk_test

import (
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const (
	base     uint64 = 0xffff888000100000
	page            = kerntest.PageSize
	initTask uint64 = 0xffffffff82000000
)

// item: value int @0, link list_head @8, hnode hlist_node @24.
const (
	itemLink  = 8
	itemHNode = 24
	itemSize  = 40
)

// task_struct: pid @0, tgid @4, tasks @8, signal @24, thread_node @32,
// thread_group @48, comm @64.
const (
	taskPID         = 0
	taskTGID        = 4
	taskTasks       = 8
	taskSignal      = 24
	taskThreadNode  = 32
	taskThreadGroup = 48
	taskSize        = 80
	signalHead      = 0
	signalSize      = 16
)

type layout uint8

const (
	viaSignal layout = iota
	viaGroup
	noThreads
)

func listTypes(ty *kerntest.Types) {
	vp := kerntest.Ptr(kerntest.Void())
	ty.Struct("list_head", 16, map[string]kerntest.F{"next": {Off: 0, Type: kerntest.Ptr(kerntest.Struct("list_head"))}, "prev": {Off: 8, Type: kerntest.Ptr(kerntest.Struct("list_head"))}})
	ty.Struct("hlist_head", 8, map[string]kerntest.F{"first": {Off: 0, Type: kerntest.Ptr(kerntest.Struct("hlist_node"))}})
	ty.Struct("hlist_node", 16, map[string]kerntest.F{"next": {Off: 0, Type: vp}, "pprev": {Off: 8, Type: vp}})
	ty.Struct("item", itemSize, map[string]kerntest.F{
		"value": {Off: 0, Type: kerntest.Base("int")},
		"link":  {Off: itemLink, Type: kerntest.Struct("list_head")},
		"hnode": {Off: itemHNode, Type: kerntest.Struct("hlist_node")},
	})
}

func taskTypes(ty *kerntest.Types, l layout) {
	f := map[string]kerntest.F{
		"pid":    {Off: taskPID, Type: kerntest.Base("int")},
		"tgid":   {Off: taskTGID, Type: kerntest.Base("int")},
		"tasks":  {Off: taskTasks, Type: kerntest.Struct("list_head")},
		"signal": {Off: taskSignal, Type: kerntest.Ptr(kerntest.Struct("signal_struct"))},
		"comm":   {Off: 64, Type: kerntest.Arr(16, kerntest.Base("char"))},
	}
	sig := map[string]kerntest.F{"nr_threads": {Off: 8, Type: kerntest.Base("int")}}
	switch l {
	case viaSignal:
		f["thread_node"] = kerntest.F{Off: taskThreadNode, Type: kerntest.Struct("list_head")}
		sig["thread_head"] = kerntest.F{Off: signalHead, Type: kerntest.Struct("list_head")}
	case viaGroup:
		f["thread_group"] = kerntest.F{Off: taskThreadGroup, Type: kerntest.Struct("list_head")}
	}
	ty.Struct("task_struct", taskSize, f)
	ty.Struct("signal_struct", signalSize, sig)
	ty.Symbol("init_task", initTask, kerntest.Struct("task_struct"))
}

func reader(t testing.TB, mem *kerntest.Memory, ty *kerntest.Types, lim limits.Limits) linuxwalk.Reader {
	return linuxwalk.Reader{Mem: mem, Sym: ty.Table(t), Limits: lim}
}

// ring links the list_heads at the given addresses into a well-formed ring.
func ring(mem *kerntest.Memory, heads ...uint64) {
	for i, h := range heads {
		mem.U64(h, heads[(i+1)%len(heads)])
		mem.U64(h+8, heads[(i+len(heads)-1)%len(heads)])
	}
}

func items(n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = base + uint64(i)*0x100
	}
	return out
}

func links(entries []uint64, off uint64) []uint64 {
	out := make([]uint64, len(entries))
	for i, e := range entries {
		out[i] = e + off
	}
	return out
}

// hchain links hlist nodes from head through each node in order.
func hchain(mem *kerntest.Memory, head uint64, nodes ...uint64) {
	mem.U64(head, 0)
	holder := head
	for i, n := range nodes {
		if i == 0 {
			mem.U64(head, n)
		}
		next := uint64(0)
		if i+1 < len(nodes) {
			next = nodes[i+1]
		}
		mem.U64(n, next)
		mem.U64(n+8, holder)
		holder = n
	}
}

type task struct {
	addr      uint64
	pid, tgid int32
	signal    uint64
}

func writeTask(mem *kerntest.Memory, tk task) {
	mem.Map(tk.addr, taskSize)
	mem.U32(tk.addr+taskPID, uint32(tk.pid))
	mem.U32(tk.addr+taskTGID, uint32(tk.tgid))
	mem.U64(tk.addr+taskSignal, tk.signal)
}
