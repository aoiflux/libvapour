package testsupport

import (
	"fmt"
	"slices"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// Kernel and loader members follow the 26100 tables measured in S56 T1 to T5;
// the 32-bit loader offsets are S56 L1.
const (
	S56EprocessSize     = 0x840
	S56PID              = 0x1d0
	S56ActiveLinks      = 0x1d8
	S56CreateTime       = 0x1f8
	S56ParentPID        = 0x2d0
	S56Peb              = 0x2e0
	S56Wow64Process     = 0x310
	S56ImageFileName    = 0x338
	S56AuditInfo        = 0x350
	S56ExitTime         = 0x5c0
	S56DirectoryTable   = 0x28
	S56PebLdr           = 0x18
	S56PebParameters    = 0x20
	S56ImagePathName    = 0x60
	S56CommandLine      = 0x70
	S56LdrHeads         = 0x10
	S56RecordDllBase    = 0x30
	S56RecordSize       = 0x40
	S56RecordFullName   = 0x48
	S56RecordBaseName   = 0x58
	S56RecordDdagNode   = 0x98
	S56RecordLoadTime   = 0x100
	S56DdagLoadCount    = 0x18
	S56Peb32Ldr         = 0x0c
	s56RecordBytes      = 0x138
	s56ListHeadVA       = uint64(0xfffff80000001000)
	s56SystemProcessVA  = uint64(0xfffff80000002000)
	s56KernelHeap       = uint64(0xfffff80000100000)
	s56DTBBase          = uint64(0x1aa000)
	S56PebVA            = uint64(0x7ff600010000)
	S56LdrVA            = uint64(0x7ff600020000)
	S56ParametersVA     = uint64(0x7ff600030000)
	S56RecordVA         = uint64(0x7ff600100000)
	S56Peb32VA          = uint64(0x00300000)
	S56Ldr32VA          = uint64(0x00310000)
	S56Record32VA       = uint64(0x00400000)
	S56RecordStride     = uint64(0x1000)
	s56StringInRecord   = uint64(0x400)
	s56Record32Bytes    = 0x34
	s56EwowInEprocess   = uint64(0x800)
	s56AuditInEprocess  = uint64(0x700)
	s56DdagNodeInRecord = uint64(0x300)
)

type S56Library struct {
	Base      uint64
	Size      uint32
	Name      string
	FullPath  string
	LoadCount uint32
	NoDdag    bool
	LoadTime  uint64
	// Lists that leave the record out; the default is all three.
	NotInLoad, NotInMemory, NotInInit bool
	// Places the record here instead of at its slot in S56RecordVA.
	RecordAt uint64
}

type S56Process struct {
	PID, PPID    uint64
	Name         string
	CreateTime   uint64
	ExitTime     uint64
	NoPeb        bool
	LdrZero      bool
	Libraries    []S56Library
	Wow64        []S56Library
	AuditName    string
	ImagePath    string
	CommandLine  string
	NoParameters bool
}

type S56Placement struct {
	PID, EPROCESS, DirectoryTableBase uint64
	Records, Records32                []uint64
}

type S56Image struct {
	Table       *symbols.Table
	Kernel      *S43Memory
	User        map[uint64]*S43Memory
	Procs       []S56Placement
	Diagnostics []string
	Options     map[string]any
}

func s56Field(name string, off uint64, typ string) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: typ}}
}

func S56Table() *symbols.Table { return S56TableWithout() }

// Each omitted member is named "<type>.<member>"; a bare type name drops the
// whole type.
func S56TableWithout(omit ...string) *symbols.Table {
	t := symbols.NewTable("s56-fixture", 8)
	add := func(name string, size uint64, fields ...symbols.Field) {
		if slices.Contains(omit, name) {
			return
		}
		kept := fields[:0:0]
		for _, f := range fields {
			if !slices.Contains(omit, name+"."+f.Name) {
				kept = append(kept, f)
			}
		}
		t.AddStruct(symbols.StructType{Name: name, Size: size, Fields: kept})
	}
	add("_LIST_ENTRY", 16, s19Pointer("Flink", 0, "_LIST_ENTRY"), s19Pointer("Blink", 8, "_LIST_ENTRY"))
	add("LIST_ENTRY32", 8, s56Field("Flink", 0, "unsigned int"), s56Field("Blink", 4, "unsigned int"))
	add("_UNICODE_STRING", 16, s56Field("Length", 0, "unsigned short"), s56Field("MaximumLength", 2, "unsigned short"),
		s19Pointer("Buffer", 8, "wchar_t"))
	add("_STRING32", 8, s56Field("Length", 0, "unsigned short"), s56Field("MaximumLength", 2, "unsigned short"),
		s56Field("Buffer", 4, "unsigned int"))
	add("_LARGE_INTEGER", 8, s56Field("QuadPart", 0, "long long"))
	add("_KPROCESS", 0x438, s56Field("DirectoryTableBase", S56DirectoryTable, "unsigned long long"))
	add("_EPROCESS", S56EprocessSize, s56Field("Pcb", 0, "_KPROCESS"), s19Pointer("UniqueProcessId", S56PID, "void"),
		s56Field("ActiveProcessLinks", S56ActiveLinks, "_LIST_ENTRY"), s56Field("CreateTime", S56CreateTime, "_LARGE_INTEGER"),
		s19Pointer("InheritedFromUniqueProcessId", S56ParentPID, "void"), s19Pointer("Peb", S56Peb, "_PEB"),
		s19Pointer("WoW64Process", S56Wow64Process, "_EWOW64PROCESS"),
		symbols.Field{Name: "ImageFileName", Offset: S56ImageFileName, Type: symbols.TypeRef{Name: "unsigned char", IsArray: true, ArrayLength: 15}},
		s56Field("SeAuditProcessCreationInfo", S56AuditInfo, "_SE_AUDIT_PROCESS_CREATION_INFO"),
		s56Field("ExitTime", S56ExitTime, "_LARGE_INTEGER"))
	add("_SE_AUDIT_PROCESS_CREATION_INFO", 8, s19Pointer("ImageFileName", 0, "_OBJECT_NAME_INFORMATION"))
	add("_OBJECT_NAME_INFORMATION", 16, s56Field("Name", 0, "_UNICODE_STRING"))
	add("_EWOW64PROCESS", 16, s19Pointer("Peb", 0, "void"))
	add("_PEB", 0x7d0, s19Pointer("Ldr", S56PebLdr, "_PEB_LDR_DATA"), s19Pointer("ProcessParameters", S56PebParameters, "_RTL_USER_PROCESS_PARAMETERS"))
	add("_PEB32", 0x488, s56Field("Ldr", S56Peb32Ldr, "unsigned int"))
	add("_PEB_LDR_DATA", 0x58, s56Field("InLoadOrderModuleList", S56LdrHeads, "_LIST_ENTRY"),
		s56Field("InMemoryOrderModuleList", S56LdrHeads+0x10, "_LIST_ENTRY"),
		s56Field("InInitializationOrderModuleList", S56LdrHeads+0x20, "_LIST_ENTRY"))
	add("_LDR_DATA_TABLE_ENTRY", s56RecordBytes, s56Field("InLoadOrderLinks", 0, "_LIST_ENTRY"),
		s56Field("InMemoryOrderLinks", 0x10, "_LIST_ENTRY"), s56Field("InInitializationOrderLinks", 0x20, "_LIST_ENTRY"),
		s19Pointer("DllBase", S56RecordDllBase, "void"), s56Field("SizeOfImage", S56RecordSize, "unsigned int"),
		s56Field("FullDllName", S56RecordFullName, "_UNICODE_STRING"), s56Field("BaseDllName", S56RecordBaseName, "_UNICODE_STRING"),
		s19Pointer("DdagNode", S56RecordDdagNode, "_LDR_DDAG_NODE"), s56Field("LoadTime", S56RecordLoadTime, "_LARGE_INTEGER"))
	add("_LDR_DDAG_NODE", 0x50, s56Field("LoadCount", S56DdagLoadCount, "unsigned int"))
	add("_RTL_USER_PROCESS_PARAMETERS", 0x448, s56Field("ImagePathName", S56ImagePathName, "_UNICODE_STRING"),
		s56Field("CommandLine", S56CommandLine, "_UNICODE_STRING"))
	t.AddSymbol(symbols.Symbol{Name: "PsActiveProcessHead", Address: s56ListHeadVA})
	t.AddSymbol(symbols.Symbol{Name: "PsInitialSystemProcess", Address: s56SystemProcessVA})
	return t
}

func s56String(m *S43Memory, at, buf uint64, s string, width uint64) {
	raw := utf16LE(s)
	m.Write(buf, raw)
	m.WriteU16(at, uint16(len(raw)))
	m.WriteU16(at+2, uint16(len(raw)+2))
	if width == 4 {
		m.WriteU32(at+4, uint32(buf))
	} else {
		m.WriteU64(at+8, buf)
	}
}

type s56Shape struct {
	width                    uint64
	heads, links             [3]uint64
	base, size, full, name   uint64
	recordVA, ldrVA, recSize uint64
}

var (
	s56Native = s56Shape{width: 8, heads: [3]uint64{0x10, 0x20, 0x30}, links: [3]uint64{0, 0x10, 0x20},
		base: S56RecordDllBase, size: S56RecordSize, full: S56RecordFullName, name: S56RecordBaseName,
		recordVA: S56RecordVA, ldrVA: S56LdrVA, recSize: s56RecordBytes}
	s56Wow = s56Shape{width: 4, heads: [3]uint64{0x0c, 0x14, 0x1c}, links: [3]uint64{0, 0x08, 0x10},
		base: 0x18, size: 0x20, full: 0x24, name: 0x2c, recordVA: S56Record32VA, ldrVA: S56Ldr32VA, recSize: s56Record32Bytes}
)

func (s s56Shape) ptr(m *S43Memory, at, v uint64) {
	if s.width == 4 {
		m.WriteU32(at, uint32(v))
		return
	}
	m.WriteU64(at, v)
}

func (s s56Shape) place(user *S43Memory, libs []S56Library) []uint64 {
	records := make([]uint64, len(libs))
	for j, lib := range libs {
		r := s.recordVA + uint64(j)*S56RecordStride
		if lib.RecordAt != 0 {
			r = lib.RecordAt
		}
		records[j] = r
		s.ptr(user, r+s.base, lib.Base)
		user.WriteU32(r+s.size, lib.Size)
		s56String(user, r+s.name, r+s56StringInRecord, lib.Name, s.width)
		s56String(user, r+s.full, r+s56StringInRecord+0x200, lib.FullPath, s.width)
		if s.width == 8 {
			if !lib.NoDdag {
				node := r + s56DdagNodeInRecord
				user.WriteU64(r+S56RecordDdagNode, node)
				user.WriteU32(node+S56DdagLoadCount, lib.LoadCount)
			}
			user.WriteU64(r+S56RecordLoadTime, lib.LoadTime)
		}
	}
	for list := range 3 {
		head := s.ldrVA + s.heads[list]
		prev := head
		for j, lib := range libs {
			if (list == 0 && lib.NotInLoad) || (list == 1 && lib.NotInMemory) || (list == 2 && lib.NotInInit) {
				continue
			}
			link := records[j] + s.links[list]
			s.ptr(user, prev, link)
			s.ptr(user, link+s.width, prev)
			prev = link
		}
		s.ptr(user, prev, head)
		s.ptr(user, head+s.width, prev)
	}
	return records
}

func BuildS56Image(procs []S56Process) *S56Image {
	img := &S56Image{Table: S56Table(), Kernel: NewS43Memory(), User: map[uint64]*S43Memory{}, Options: map[string]any{}}
	k := img.Kernel
	prev := s56ListHeadVA
	for i, p := range procs {
		ep := s56KernelHeap + uint64(i)*0x1000
		dtb := s56DTBBase + uint64(i)*0x1000
		user := NewS43Memory()
		img.User[dtb] = user
		k.WriteU64(ep+S56DirectoryTable, dtb)
		k.WriteU64(ep+S56PID, p.PID)
		k.WriteU64(ep+S56ParentPID, p.PPID)
		k.WriteU64(ep+S56CreateTime, p.CreateTime)
		k.WriteU64(ep+S56ExitTime, p.ExitTime)
		k.Write(ep+S56ImageFileName, append([]byte(p.Name), 0))
		k.WriteU64(prev, ep+S56ActiveLinks)
		k.WriteU64(ep+S56ActiveLinks+8, prev)
		prev = ep + S56ActiveLinks
		if p.PID == 4 {
			k.WriteU64(s56SystemProcessVA, ep)
		}
		if p.AuditName != "" {
			info := ep + s56AuditInEprocess
			k.WriteU64(ep+S56AuditInfo, info)
			s56String(k, info, info+0x20, p.AuditName, 8)
		}
		placed := S56Placement{PID: p.PID, EPROCESS: ep, DirectoryTableBase: dtb}
		if !p.NoPeb {
			k.WriteU64(ep+S56Peb, S56PebVA)
			if !p.LdrZero {
				user.WriteU64(S56PebVA+S56PebLdr, S56LdrVA)
			}
			if !p.NoParameters {
				user.WriteU64(S56PebVA+S56PebParameters, S56ParametersVA)
				s56String(user, S56ParametersVA+S56ImagePathName, S56ParametersVA+0x200, p.ImagePath, 8)
				s56String(user, S56ParametersVA+S56CommandLine, S56ParametersVA+0x600, p.CommandLine, 8)
			}
			placed.Records = s56Native.place(user, p.Libraries)
		}
		if p.Wow64 != nil {
			ew := ep + s56EwowInEprocess
			k.WriteU64(ep+S56Wow64Process, ew)
			k.WriteU64(ew, S56Peb32VA)
			user.WriteU32(S56Peb32VA+S56Peb32Ldr, uint32(S56Ldr32VA))
			placed.Records32 = s56Wow.place(user, p.Wow64)
		}
		img.Procs = append(img.Procs, placed)
	}
	k.WriteU64(prev, s56ListHeadVA)
	k.WriteU64(s56ListHeadVA+8, prev)
	return img
}

func (img *S56Image) Context() tools.Context {
	img.Diagnostics = nil
	options := map[string]any{"diagnostics": &img.Diagnostics}
	for k, v := range img.Options {
		options[k] = v
	}
	return tools.Context{
		Memory:  img.Kernel,
		Symbols: img.Table,
		Profile: profiles.WindowsX64Profile{},
		Options: options,
		ProcessMemory: func(dtb uint64) (memory.MemoryReader, error) {
			if u, ok := img.User[dtb]; ok {
				return u, nil
			}
			return nil, fmt.Errorf("s56: dtb 0x%x: %w", dtb, memory.ErrOutOfBounds)
		},
	}
}

func (img *S56Image) Process(pid uint64) S56Placement {
	i := slices.IndexFunc(img.Procs, func(p S56Placement) bool { return p.PID == pid })
	if i < 0 {
		return S56Placement{}
	}
	return img.Procs[i]
}

func (img *S56Image) UserOf(pid uint64) *S43Memory {
	return img.User[img.Process(pid).DirectoryTableBase]
}
