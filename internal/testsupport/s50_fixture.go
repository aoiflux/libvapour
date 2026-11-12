package testsupport

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/symbols"
)

// Offsets of the S50 thread fixture. The _KTHREAD and _KTRAP_FRAME members sit
// where S50 T3 and T5 measured them; the _ETHREAD members are packed into a
// small body of the fixture's own.
const (
	S50ThreadListHeadOffset = uint64(0x5e0)

	S50KThreadTrapFrame    = uint64(0x90)
	S50KThreadPriority     = uint64(0xc3)
	S50KThreadTeb          = uint64(0xf0)
	S50KThreadState        = uint64(0x184)
	S50KThreadProcess      = uint64(0x220)
	S50KThreadWaitReason   = uint64(0x283)
	S50KThreadSuspendCount = uint64(0x284)

	S50ThreadCreateTime   = uint64(0x400)
	S50ThreadExitTime     = uint64(0x408)
	S50ThreadStartAddress = uint64(0x418)
	S50ThreadCid          = uint64(0x420)
	S50ThreadWin32Start   = uint64(0x438)
	S50ThreadListEntry    = uint64(0x440)
	S50ThreadFlags        = uint64(0x450)
	S50StartInvalidBit    = uint8(3)
	S50ThreadSize         = uint64(0x600)

	S50FrameRip   = uint64(0x168)
	S50FrameSegCs = uint64(0x170)
	S50FrameFlags = uint64(0x178)
	S50FrameRsp   = uint64(0x180)
	S50FrameSegSs = uint64(0x188)
	S50FrameRax   = uint64(0x30)
	S50FrameSize  = uint64(0x190)

	S50ThreadObject = 6

	s50ThreadBaseVA     = uint64(0xfffff80001000000)
	s50FrameBaseVA      = uint64(0xfffff80002000000)
	s50ModuleEntryVA    = uint64(0xfffff80003000000)
	s50ModuleListHeadVA = uint64(0xfffff80003001000)
	s50ModuleNameVA     = uint64(0xfffff80003002000)
	s50ModuleBaseVA     = uint64(0xfffff80004000000)
	s50ModuleSize       = uint64(0x100000)
	s50Stride           = uint64(0x1000)
)

type S50TrapFrame struct {
	Rip, Rsp, Rax uint64
	SegCs, SegSs  uint16
	EFlags        uint32
	Unmapped      bool
}

type S50Thread struct {
	TID          uint64
	Owner        uint64
	OwnerAddress uint64
	CidPID       uint64
	State        byte
	WaitReason   byte
	SuspendCount int8
	Priority     int8
	Teb          uint64
	Start        uint64
	StartInvalid bool
	Win32Start   uint64
	Created      uint64
	Exited       uint64
	TrapFrame    *S50TrapFrame
	Unlisted     bool
	Pooled       bool
	Unmapped     bool
}

type S50Placement struct {
	TID               uint64
	Virtual, Physical uint64
	TrapFrame         uint64
	TrapFramePhysical uint64
}

func S50ModuleBase() uint64 { return s50ModuleBaseVA }

func (f *ProcessFixture) AddS50Threads(threads []S50Thread, modulePath string) []S50Placement {
	pm := f.Memory
	addS50Types(f.Table)
	heads := map[uint64]uint64{}
	headPA := map[uint64]uint64{}
	tails := map[uint64][2]uint64{}
	for pid, place := range f.eprocesses {
		head := place.virtual + S50ThreadListHeadOffset
		heads[pid], headPA[pid] = head, place.physical+S50ThreadListHeadOffset
		pm.WriteU64(headPA[pid], head)
		pm.WriteU64(headPA[pid]+FixtureBlinkOffset, head)
		tails[pid] = [2]uint64{head, headPA[pid]}
	}
	out := make([]S50Placement, len(threads))
	for i, th := range threads {
		va := s50ThreadBaseVA + uint64(i)*s50Stride
		var pa uint64
		if th.Unmapped {
			pa = pm.AllocPage()
		} else {
			pa = f.Kernel.MapPage(va)
		}
		if th.Pooled {
			writeS50PoolHeaders(pm, pa)
		}
		va += fixturePooledBodyOffset
		pa += fixturePooledBodyOffset
		owner := f.eprocesses[th.Owner]
		cid := th.CidPID
		if cid == 0 {
			cid = th.Owner
		}
		pm.WriteAt(pa, []byte{S50ThreadObject})
		ownerVA := owner.virtual
		if th.OwnerAddress != 0 {
			ownerVA = th.OwnerAddress
		}
		pm.WriteU64(pa+S50KThreadProcess, ownerVA)
		pm.WriteU64(pa+S50KThreadTeb, th.Teb)
		pm.WriteAt(pa+S50KThreadState, []byte{th.State})
		pm.WriteAt(pa+S50KThreadWaitReason, []byte{th.WaitReason})
		pm.WriteAt(pa+S50KThreadSuspendCount, []byte{byte(th.SuspendCount)})
		pm.WriteAt(pa+S50KThreadPriority, []byte{byte(th.Priority)})
		pm.WriteU64(pa+S50ThreadCreateTime, th.Created)
		exit := th.Exited
		if exit == 0 {
			exit = va + S50ThreadExitTime
		}
		pm.WriteU64(pa+S50ThreadExitTime, exit)
		pm.WriteU64(pa+S50ThreadStartAddress, th.Start)
		if th.StartInvalid {
			pm.WriteAt(pa+S50ThreadFlags, []byte{1 << S50StartInvalidBit})
		}
		pm.WriteU64(pa+S50ThreadCid, cid)
		pm.WriteU64(pa+S50ThreadCid+8, th.TID)
		pm.WriteU64(pa+S50ThreadWin32Start, th.Win32Start)
		out[i] = S50Placement{TID: th.TID, Virtual: va, Physical: pa}
		if th.TrapFrame != nil {
			frameVA := s50FrameBaseVA + uint64(i)*s50Stride
			pm.WriteU64(pa+S50KThreadTrapFrame, frameVA)
			out[i].TrapFrame = frameVA
			if !th.TrapFrame.Unmapped {
				framePA := f.Kernel.MapPage(frameVA)
				out[i].TrapFramePhysical = framePA
				pm.WriteU64(framePA+S50FrameRip, th.TrapFrame.Rip)
				pm.WriteU64(framePA+S50FrameRsp, th.TrapFrame.Rsp)
				pm.WriteU64(framePA+S50FrameRax, th.TrapFrame.Rax)
				pm.WriteU16(framePA+S50FrameSegCs, th.TrapFrame.SegCs)
				pm.WriteU16(framePA+S50FrameSegSs, th.TrapFrame.SegSs)
				pm.WriteU32(framePA+S50FrameFlags, th.TrapFrame.EFlags)
			}
		}
		if th.Unlisted || th.Unmapped {
			continue
		}
		tail := tails[th.Owner]
		entry := va + S50ThreadListEntry
		pm.WriteU64(tail[1], entry)
		pm.WriteU64(pa+S50ThreadListEntry+FixtureBlinkOffset, tail[0])
		pm.WriteU64(pa+S50ThreadListEntry, heads[th.Owner])
		pm.WriteU64(headPA[th.Owner]+FixtureBlinkOffset, entry)
		tails[th.Owner] = [2]uint64{entry, pa + S50ThreadListEntry}
	}
	if modulePath != "" {
		f.addS50Module(modulePath)
	}
	return out
}

func writeS50PoolHeaders(pm *PagedMemory, pa uint64) {
	headers := make([]byte, fixturePooledBodyOffset)
	WritePoolHeader(headers, 0, scan.ThreadFilter.Tag, BlocksFor(fixturePooledBodyOffset+S50ThreadSize),
		NonPagedPoolType)
	binary.LittleEndian.PutUint64(headers[fixtureObjectHeaderOffset:], 1)
	pm.WriteAt(pa, headers)
}

func (f *ProcessFixture) addS50Module(path string) {
	headPA := f.Kernel.MapPage(s50ModuleListHeadVA)
	entryPA := f.Kernel.MapPage(s50ModuleEntryVA)
	pm := f.Memory
	pm.WriteU64(headPA+FixtureFlinkOffset, s50ModuleEntryVA)
	pm.WriteU64(headPA+FixtureBlinkOffset, s50ModuleEntryVA)
	pm.WriteU64(entryPA+FixtureInLoadLinksOffset, s50ModuleListHeadVA)
	pm.WriteU64(entryPA+FixtureInLoadLinksOffset+FixtureBlinkOffset, s50ModuleListHeadVA)
	pm.WriteU64(entryPA+FixtureDllBaseOffset, s50ModuleBaseVA)
	pm.WriteU32(entryPA+FixtureSizeOfImageOffset, uint32(s50ModuleSize))
	f.writeUnicodeString(f.Kernel, entryPA+FixtureFullDllNameOffset, s50ModuleNameVA, path)
	f.writeUnicodeString(f.Kernel, entryPA+FixtureBaseDllNameOffset, s50ModuleNameVA+0x800, path)
	f.Table.AddSymbol(symbols.Symbol{Name: "PsLoadedModuleList", Address: s50ModuleListHeadVA})
}

func s50Field(name string, offset uint64, typ string) symbols.Field {
	return symbols.Field{Name: name, Offset: offset, Type: symbols.TypeRef{Name: typ}}
}

func s50Pointer(name string, offset uint64) symbols.Field {
	return symbols.Field{Name: name, Offset: offset, Type: symbols.TypeRef{Name: "void", IsPointer: true}}
}

func addS50Types(t *symbols.Table) {
	if _, err := t.Struct("_ETHREAD"); err == nil {
		return
	}
	eprocess, err := t.Struct("_EPROCESS")
	if err != nil {
		panic("testsupport: fixture table lacks _EPROCESS: " + err.Error())
	}
	eprocess.Fields = append(eprocess.Fields, symbols.Field{Name: "ThreadListHead", Offset: S50ThreadListHeadOffset,
		Type: symbols.TypeRef{Name: "_LIST_ENTRY"}})
	t.AddStruct(eprocess)
	t.AddStruct(symbols.StructType{Name: "_ETHREAD", Size: S50ThreadSize, Fields: []symbols.Field{
		s50Field("Tcb", 0, "_KTHREAD"),
		s50Field("CreateTime", S50ThreadCreateTime, "_LARGE_INTEGER"),
		s50Field("ExitTime", S50ThreadExitTime, "_LARGE_INTEGER"),
		s50Pointer("StartAddress", S50ThreadStartAddress),
		s50Field("Cid", S50ThreadCid, "_CLIENT_ID"),
		s50Pointer("Win32StartAddress", S50ThreadWin32Start),
		s50Field("ThreadListEntry", S50ThreadListEntry, "_LIST_ENTRY"),
		{Name: "StartAddressInvalid", Offset: S50ThreadFlags,
			Type: symbols.TypeRef{Name: "unsigned char", BitOffset: S50StartInvalidBit, BitLength: 1}},
	}})
	t.AddStruct(symbols.StructType{Name: "_KTHREAD", Size: 0x300, Fields: []symbols.Field{
		s50Field("Header", 0, "_DISPATCHER_HEADER"),
		{Name: "TrapFrame", Offset: S50KThreadTrapFrame, Type: symbols.TypeRef{Name: "_KTRAP_FRAME", IsPointer: true}},
		s50Field("Priority", S50KThreadPriority, "char"),
		s50Pointer("Teb", S50KThreadTeb),
		s50Field("State", S50KThreadState, "unsigned char"),
		{Name: "Process", Offset: S50KThreadProcess, Type: symbols.TypeRef{Name: "_KPROCESS", IsPointer: true}},
		s50Field("WaitReason", S50KThreadWaitReason, "unsigned char"),
		s50Field("SuspendCount", S50KThreadSuspendCount, "char"),
	}})
	t.AddStruct(symbols.StructType{Name: "_DISPATCHER_HEADER", Size: 0x18, Fields: []symbols.Field{
		s50Field("Type", 0, "unsigned char"),
	}})
	t.AddStruct(symbols.StructType{Name: "_CLIENT_ID", Size: 0x10, Fields: []symbols.Field{
		s50Pointer("UniqueProcess", 0), s50Pointer("UniqueThread", 8),
	}})
	t.AddStruct(symbols.StructType{Name: "_KTRAP_FRAME", Size: S50FrameSize, Fields: []symbols.Field{
		s50Field("Rax", S50FrameRax, "unsigned long long"),
		s50Field("Rip", S50FrameRip, "unsigned long long"),
		s50Field("SegCs", S50FrameSegCs, "unsigned short"),
		s50Field("EFlags", S50FrameFlags, "unsigned int"),
		s50Field("Rsp", S50FrameRsp, "unsigned long long"),
		s50Field("SegSs", S50FrameSegSs, "unsigned short"),
	}})
	t.AddEnum(symbols.EnumType{Name: "_KTHREAD_STATE", Size: 4, Values: []symbols.EnumValue{
		{Name: "Running", Value: 2}, {Name: "Terminated", Value: 4}, {Name: "Waiting", Value: 5},
	}})
	t.AddEnum(symbols.EnumType{Name: "_KWAIT_REASON", Size: 4, Values: []symbols.EnumValue{
		{Name: "Suspended", Value: 5}, {Name: "UserRequest", Value: 6}, {Name: "WrTerminated", Value: 22},
	}})
	if _, err := t.Struct("_POOL_HEADER"); err != nil {
		addPoolTypes(t)
	}
}

// A table with the thread types alone, for tests that read thread bytes
// without a process fixture.
func NewS50Table() *symbols.Table {
	t := buildFixtureSymbolTable(false, false)
	addS50Types(t)
	return t
}
