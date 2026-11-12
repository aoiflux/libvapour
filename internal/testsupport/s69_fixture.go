package testsupport

import (
	"github.com/aoiflux/libvapour/symbols"
)

// The S69 object fixture extends the S64 kernel with the mutant, symbolic
// link and file object types at the offsets the 26100 tables give (S69
// section 3).
const (
	S69MutantSize       = uint64(0x38)
	S69MutantListEntry  = uint64(0x18)
	S69MutantOwner      = uint64(0x28)
	S69MutantAbandoned  = uint64(0x30)
	S69ThreadCid        = uint64(0x508)
	S69ThreadSize       = uint64(0x900)
	S69LinkSize         = uint64(0x28)
	S69LinkCreationTime = uint64(0x00)
	S69LinkTarget       = uint64(0x08)
	S69LinkContext      = uint64(0x10)
	S69LinkFlags        = uint64(0x1c)
	S69FileSize         = uint64(0xd8)
	S69FileDevice       = uint64(0x08)
	S69FileDeletePend   = uint64(0x49)
	S69FileReadAccess   = uint64(0x4a)
	S69FileName         = uint64(0x58)

	s69Header = uint64(0x30)
)

type S69Kernel struct{ *S64Kernel }

func NewS69Kernel() *S69Kernel {
	k := &S69Kernel{NewS64Kernel()}
	add := func(name string, size uint64, fields ...symbols.Field) {
		k.Table.AddStruct(symbols.StructType{Name: name, Size: size, Fields: fields})
	}
	// HandleCount lets the scan refuse an object header placed over the name
	// information, as on a capture.
	add("_OBJECT_HEADER", 0x38, s64Field("PointerCount", 0, "long long"), s64Field("HandleCount", 8, "long long"),
		s64Field("TypeIndex", 0x18, "unsigned char"), s64Field("InfoMask", 0x1a, "unsigned char"),
		s64Field("Body", s69Header, "_QUAD"))
	add("_KMUTANT", S69MutantSize, s64Field("Header", 0, "_DISPATCHER_HEADER"),
		s64Field("MutantListEntry", S69MutantListEntry, "_LIST_ENTRY"),
		s64Ptr("OwnerThread", S69MutantOwner, "_KTHREAD"),
		symbols.Field{Name: "Abandoned", Offset: S69MutantAbandoned, Type: symbols.TypeRef{Name: "unsigned char",
			BitOffset: 0, BitLength: 1}})
	add("_CLIENT_ID", 0x10, s64Ptr("UniqueProcess", 0, "void"), s64Ptr("UniqueThread", 8, "void"))
	add("_ETHREAD", S69ThreadSize, s64Field("Tcb", 0, "_KTHREAD"), s64Field("Cid", S69ThreadCid, "_CLIENT_ID"))
	add("_OBJECT_SYMBOLIC_LINK", S69LinkSize, s64Field("CreationTime", S69LinkCreationTime, "_LARGE_INTEGER"),
		s64Field("LinkTarget", S69LinkTarget, "_UNICODE_STRING"), s64Ptr("Callback", S69LinkTarget, "void"),
		s64Ptr("CallbackContext", S69LinkContext, "void"),
		s64Field("DosDeviceDriveIndex", 0x18, "unsigned int"), s64Field("Flags", S69LinkFlags, "unsigned int"))
	file := []symbols.Field{s64Field("Type", 0, "short"), s64Field("Size", 2, "short"),
		s64Ptr("DeviceObject", S69FileDevice, "_DEVICE_OBJECT"),
		s64Field("DeletePending", S69FileDeletePend, "unsigned char")}
	for i, name := range []string{"ReadAccess", "WriteAccess", "DeleteAccess", "SharedRead", "SharedWrite", "SharedDelete"} {
		file = append(file, s64Field(name, S69FileReadAccess+uint64(i), "unsigned char"))
	}
	file = append(file, s64Field("FileName", S69FileName, "_UNICODE_STRING"))
	add("_FILE_OBJECT", S69FileSize, file...)
	return k
}

// Object lays out pool header, name information, object header and body
// like PoolObject, with the pool type the caller gives.
func (k *S69Kernel) Object(tag string, body uint64, name string, poolType byte) uint64 {
	va := k.Alloc(S64PoolBodyOffset + body)
	pool := s64PoolHeader
	if name == "" {
		pool = s69Header - PoolHeaderSize
	}
	header := make([]byte, PoolHeaderSize)
	WritePoolHeader(header, 0, tag, BlocksFor(S64PoolBodyOffset-pool+body), poolType)
	k.Write(va+pool, header)
	k.U64(va+s69Header, 1)
	if name != "" {
		k.Write(va+s69Header+0x1a, []byte{s64InfoMaskValue})
		k.String(va+s64NameInfo+8, name)
	}
	return va + S64PoolBodyOffset
}

func (k *S69Kernel) AddThread(pid, tid uint64) uint64 {
	t := k.Alloc(S69ThreadSize)
	k.Write(t, []byte{6})
	k.U64(t+S69ThreadCid, pid)
	k.U64(t+S69ThreadCid+8, tid)
	return t
}

// An owned mutant has SignalState 0 and an unowned one 1, as a wait leaves
// them.
func (k *S69Kernel) AddMutant(name string, owner uint64) uint64 {
	m := k.Object("Muta", S69MutantSize, name, NonPagedPoolType)
	k.Write(m, []byte{2})
	if owner == 0 {
		k.U32(m+S64HeaderSignal, 1)
	} else {
		k.U32(m+S64HeaderSignal, 0)
		k.U64(m+S69MutantOwner, owner)
	}
	k.U64(m+S69MutantListEntry, m+S69MutantListEntry)
	k.U64(m+S69MutantListEntry+8, m+S69MutantListEntry)
	return m
}

func (k *S69Kernel) AddLink(name, target string, created uint64) uint64 {
	l := k.Object("Symb", S69LinkSize, name, PagedPoolType)
	k.U64(l+S69LinkCreationTime, created)
	k.String(l+S69LinkTarget, target)
	return l
}

func (k *S69Kernel) AddCallbackLink(name string, routine, context, created uint64) uint64 {
	l := k.Object("Symb", S69LinkSize, name, PagedPoolType)
	k.U64(l+S69LinkCreationTime, created)
	k.U64(l+S69LinkTarget, routine)
	k.U64(l+S69LinkContext, context)
	k.U32(l+S69LinkFlags, 0x10)
	return l
}

// Access lists the FILE_OBJECT booleans from ReadAccess on, in member order.
func (k *S69Kernel) AddFile(name string, device uint64, access ...bool) uint64 {
	f := k.Object("File", S69FileSize, "", NonPagedPoolType)
	k.U16(f, 5)
	k.U16(f+2, uint16(S69FileSize))
	k.U64(f+S69FileDevice, device)
	for i, a := range access {
		if a {
			k.Write(f+S69FileReadAccess+uint64(i), []byte{1})
		}
	}
	if name != "" {
		k.String(f+S69FileName, name)
	}
	return f
}

// The S69 process fixture adds jobs, session spaces and image paths to the
// process fixture; its _EPROCESS members sit at their 19045 offsets, the
// build the process fixture lays out, so no member overlaps another.
const (
	S69ProcessJob      = uint64(0x510)
	S69ProcessJobLinks = uint64(0x5c8)
	S69ProcessAudit    = uint64(0x5c0)
	S69ProcessSession  = uint64(0x558)
	S69ProcessCreate   = uint64(0x468)
	S69JobListHead     = uint64(0x28)
	S69JobTotal        = uint64(0xd4)
	S69JobActive       = uint64(0xd8)
	S69JobTerminated   = uint64(0xdc)
	S69JobSession      = uint64(0x240)
	S69JobSize         = uint64(0x728)
	S69SessionID       = uint64(0x08)
	S69CreateTime      = uint64(133500000000000000)

	s69JobVA     = uint64(0xfffff80000c00000)
	s69SessionVA = uint64(0xfffff80000d00000)
	s69NameVA    = uint64(0xfffff80000e00000)
)

type S69Processes struct {
	*ProcessFixture
	jobs, sessions, names uint64
}

func NewS69Processes(procs []FixtureProcess) *S69Processes {
	f := &S69Processes{ProcessFixture: BuildProcessFixture(procs), jobs: s69JobVA, sessions: s69SessionVA, names: s69NameVA}
	st, _ := f.Table.Struct("_EPROCESS")
	st.Fields = append(append([]symbols.Field(nil), st.Fields...),
		s64Ptr("Job", S69ProcessJob, "_EJOB"), s64Field("JobLinks", S69ProcessJobLinks, "_LIST_ENTRY"),
		s64Field("SeAuditProcessCreationInfo", S69ProcessAudit, "_SE_AUDIT_PROCESS_CREATION_INFO"),
		s64Ptr("Session", S69ProcessSession, "_MM_SESSION_SPACE"),
		s64Field("CreateTime", S69ProcessCreate, "_LARGE_INTEGER"))
	f.Table.AddStruct(st)
	f.Table.AddStruct(symbols.StructType{Name: "_EJOB", Size: S69JobSize, Fields: []symbols.Field{
		s64Field("ProcessListHead", S69JobListHead, "_LIST_ENTRY"),
		s64Field("TotalProcesses", S69JobTotal, "unsigned int"),
		s64Field("ActiveProcesses", S69JobActive, "unsigned int"),
		s64Field("TotalTerminatedProcesses", S69JobTerminated, "unsigned int"),
		s64Field("SessionId", S69JobSession, "unsigned int")}})
	f.Table.AddStruct(symbols.StructType{Name: "_SE_AUDIT_PROCESS_CREATION_INFO", Size: 8, Fields: []symbols.Field{
		s64Ptr("ImageFileName", 0, "_OBJECT_NAME_INFORMATION")}})
	f.Table.AddStruct(symbols.StructType{Name: "_OBJECT_NAME_INFORMATION", Size: 0x10, Fields: []symbols.Field{
		s64Field("Name", 0, "_UNICODE_STRING")}})
	f.Table.AddStruct(symbols.StructType{Name: "_MM_SESSION_SPACE", Size: 0x1000, Fields: []symbols.Field{
		s64Field("SessionId", S69SessionID, "unsigned int")}})
	for _, p := range procs {
		f.SetCreateTime(p.PID, S69CreateTime)
	}
	return f
}

func (f *S69Processes) pa(va uint64) uint64 {
	table := f.Kernel.DTB & pteAddrMask
	for _, shift := range []uint64{39, 30, 21, 12} {
		entry := f.Memory.readU64(table + (va>>shift)&0x1ff*8)
		if entry&ptePresent == 0 {
			return f.Kernel.MapPage(va&^0xFFF) + va&0xFFF
		}
		table = entry & pteAddrMask
	}
	return table + va&0xFFF
}

func (f *S69Processes) u64(va, v uint64)        { f.Memory.WriteU64(f.pa(va), v) }
func (f *S69Processes) u32(va uint64, v uint32) { f.Memory.WriteU32(f.pa(va), v) }

// AddJob links the processes with the given ids onto a new job's list, in
// the order given, and points each one's Job at it.
func (f *S69Processes) AddJob(total, active, terminated, session uint32, pids ...uint64) uint64 {
	job := f.jobs
	f.jobs += 0x1000
	f.Kernel.MapPage(job)
	f.u32(job+S69JobTotal, total)
	f.u32(job+S69JobActive, active)
	f.u32(job+S69JobTerminated, terminated)
	f.u32(job+S69JobSession, session)
	head := job + S69JobListHead
	prev := head
	for _, pid := range pids {
		ep, _ := f.EPROCESS(pid)
		f.u64(ep+S69ProcessJob, job)
		link := ep + S69ProcessJobLinks
		f.u64(prev, link)
		f.u64(link+8, prev)
		prev = link
	}
	f.u64(prev, head)
	f.u64(head+8, prev)
	return job
}

func (f *S69Processes) SetImagePath(pid uint64, path string) {
	ep, _ := f.EPROCESS(pid)
	at := f.names
	f.names += 0x1000
	f.Kernel.MapPage(at)
	b := S64UTF16(path)
	f.Memory.WriteAt(f.pa(at+0x10), b)
	f.Memory.WriteU16(f.pa(at), uint16(len(b)))
	f.Memory.WriteU16(f.pa(at+2), uint16(len(b)))
	f.u64(at+8, at+0x10)
	f.u64(ep+S69ProcessAudit, at)
}

func (f *S69Processes) SetSession(pid uint64, id uint32) {
	ep, _ := f.EPROCESS(pid)
	space := f.sessions + uint64(id)*0x1000
	f.Kernel.MapPage(space)
	f.u32(space+S69SessionID, id)
	f.u64(ep+S69ProcessSession, space)
}

func (f *S69Processes) SetCreateTime(pid, filetime uint64) {
	ep, _ := f.EPROCESS(pid)
	f.u64(ep+S69ProcessCreate, filetime)
}
