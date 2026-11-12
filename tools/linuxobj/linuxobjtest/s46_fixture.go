package linuxobjtest

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/symbols"
)

const (
	S46NsproxyTimeNS   = 0x30
	S46TimeNSCommon    = 0x10
	S46TimeNSOffsets   = 0x28
	S46TimeNSSize      = 0x58
	S46OffsetsBoottime = 0x10
	S46TkSequence      = 0x00
	S46TimekeeperXtime = 0x00
	S46TimekeeperWall  = 0x20
	S46TimekeeperSleep = 0x30
)

func (k *Kernel) s46Field(name string, off uint64, typ symbols.TypeRef) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: typ}
}

func (k *Kernel) addTimespec() {
	if _, err := k.Table.Struct("timespec64"); err == nil {
		return
	}
	k.Table.AddStruct(symbols.StructType{Name: "timespec64", Size: 0x10, Fields: []symbols.Field{
		k.s46Field("tv_sec", 0, scalar("long long int")), k.s46Field("tv_nsec", 8, scalar("long int")),
	}})
}

func (k *Kernel) inumOffset() uint64 {
	if f, err := k.Table.Field("ns_common", "inum"); err == nil {
		return f.Offset
	}
	k.Table.AddStruct(symbols.StructType{Name: "ns_common", Size: 0x18, Fields: []symbols.Field{
		k.s46Field("inum", 0x10, scalar("unsigned int")),
	}})
	return 0x10
}

func (k *Kernel) timespec(at uint64, sec, nsec int64) {
	k.Mem.U64(at, uint64(sec))
	k.Mem.U64(at+8, uint64(nsec))
}

// The timekeeper gains xtime_sec, wall_to_monotonic and monotonic_to_boot,
// written to agree with offs_real and offs_boot unless told otherwise, and the
// container gains its sequence counter.
func (k *Kernel) AddClockChecks(sequence uint32, wallAgrees, sleepAgrees bool) {
	k.addTimespec()
	k.Table.AddStruct(symbols.StructType{Name: "timekeeper", Size: 0x40, Fields: []symbols.Field{
		k.s46Field("xtime_sec", S46TimekeeperXtime, scalar("long long unsigned int")),
		k.s46Field("offs_real", TimekeeperReal, scalar("long long int")),
		k.s46Field("offs_boot", TimekeeperBoot, scalar("long long int")),
		k.s46Field("wall_to_monotonic", S46TimekeeperWall, scalar("timespec64")),
		k.s46Field("monotonic_to_boot", S46TimekeeperSleep, scalar("timespec64")),
	}})
	k.Table.AddStruct(symbols.StructType{Name: "seqcount_t", Size: 4, Fields: []symbols.Field{
		k.s46Field("sequence", 0, scalar("unsigned int")),
	}})
	tk, _ := k.Table.LookupSymbol("tk_core")
	k.Mem.U32(tk.Address+S46TkSequence, sequence)
	at := tk.Address + TkCoreTimekeeper
	real := int64(k.u64(at + TimekeeperReal))
	boot := int64(k.u64(at + TimekeeperBoot))
	k.Mem.U64(at+S46TimekeeperXtime, uint64(real/1e9+600))
	wall := -real
	if !wallAgrees {
		wall++
	}
	k.timespec(at+S46TimekeeperWall, floorDiv(wall, 1e9), wall-floorDiv(wall, 1e9)*1e9)
	if !sleepAgrees {
		boot += 1e9
	}
	k.timespec(at+S46TimekeeperSleep, boot/1e9, boot%1e9)
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

func (k *Kernel) u64(at uint64) uint64 {
	b, err := k.Mem.ReadAt(at, 8)
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

func AddTimeNamespaceTypes(k *Kernel) {
	k.addTimespec()
	k.inumOffset()
	k.Table.AddStruct(symbols.StructType{Name: "timens_offsets", Size: 0x20, Fields: []symbols.Field{
		k.s46Field("monotonic", 0, scalar("timespec64")),
		k.s46Field("boottime", S46OffsetsBoottime, scalar("timespec64")),
	}})
	k.Table.AddStruct(symbols.StructType{Name: "time_namespace", Size: S46TimeNSSize, Fields: []symbols.Field{
		k.s46Field("ns", S46TimeNSCommon, scalar("ns_common")),
		k.s46Field("offsets", S46TimeNSOffsets, scalar("timens_offsets")),
	}})
	nsproxy, err := k.Table.Struct("nsproxy")
	if err != nil {
		nsproxy = symbols.StructType{Name: "nsproxy", Size: 0x40}
	}
	nsproxy.Fields = append(nsproxy.Fields, k.s46Field("time_ns", S46NsproxyTimeNS, ptr("time_namespace")))
	k.Table.AddStruct(nsproxy)
}

func (k *Kernel) AddTimeNamespace(inum uint32, bootSec, bootNsec int64) uint64 {
	ns := k.Alloc(S46TimeNSSize)
	k.Mem.U32(ns+S46TimeNSCommon+k.inumOffset(), inum)
	k.timespec(ns+S46TimeNSOffsets+S46OffsetsBoottime, bootSec, bootNsec)
	return ns
}

func (k *Kernel) SetTaskTimeNS(task, ns uint64) {
	proxy := k.u64(task + TaskNsproxy)
	k.Mem.U64(proxy+S46NsproxyTimeNS, ns)
}
