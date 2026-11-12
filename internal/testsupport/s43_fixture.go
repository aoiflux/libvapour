package testsupport

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// Kernel members follow the 26100 kernel table measured in S24, S19 and S43;
// the list members are fixture-only offsets.
const (
	S43EprocessSize        = 0x840
	S43DirectoryTableBase  = 0x28
	S43SecureState         = 0x170
	S43UniqueProcessID     = 0x1d0
	S43ActiveProcessLinks  = 0x1d8
	S43SectionObject       = 0x2a8
	S43SectionBaseAddress  = 0x2b0
	S43Peb                 = 0x2e0
	S43ImageFilePointer    = 0x330
	S43ImageFileName       = 0x338
	S43AuditInfo           = 0x350
	S43VadRoot             = 0x558
	S43VadCount            = 0x568
	S43PebImageBaseAddress = 0x10
	S43FileDeletePending   = 0x49
	S43SectionControlArea  = 0x28
	S43ImageVadType        = 2

	s43VadFlags       = 0x30
	s43VadTypeBit     = 4
	s43ProtectionBit  = 7
	s43PrivateBit     = 21
	s43DeleteOnClose  = 18
	s43FileNull       = 19
	s43ProtectVA      = uint64(0xfffff80000002000)
	s43HighestVA      = uint64(0xfffff80000003000)
	s43ListHeadVA     = uint64(0xfffff80000001000)
	s43KernelHeap     = uint64(0xfffff80000100000)
	s43PhysicalFrames = uint64(0x200000)
	s43DTBBase        = uint64(0x1aa000)
)

type S43Memory struct {
	pages map[uint64][]byte
}

func NewS43Memory() *S43Memory { return &S43Memory{pages: map[uint64][]byte{}} }

func (m *S43Memory) page(at uint64, create bool) []byte {
	p, ok := m.pages[at&^0xfff]
	if !ok && create {
		p = make([]byte, 0x1000)
		m.pages[at&^0xfff] = p
	}
	return p
}

func (m *S43Memory) ReadAt(at, size uint64) ([]byte, error) {
	out := make([]byte, 0, size)
	for size > 0 {
		p := m.page(at, false)
		if p == nil {
			return nil, fmt.Errorf("s43: 0x%x: %w", at, memory.ErrOutOfBounds)
		}
		n := min(size, 0x1000-at&0xfff)
		out = append(out, p[at&0xfff:at&0xfff+n]...)
		at, size = at+n, size-n
	}
	return out, nil
}

func (m *S43Memory) Size() uint64 { return 1 << 63 }

func (m *S43Memory) Write(at uint64, b []byte) {
	for len(b) > 0 {
		p := m.page(at, true)
		n := copy(p[at&0xfff:], b)
		at, b = at+uint64(n), b[n:]
	}
}

func (m *S43Memory) WriteU16(at uint64, v uint16) {
	m.Write(at, binary.LittleEndian.AppendUint16(nil, v))
}
func (m *S43Memory) WriteU32(at uint64, v uint32) {
	m.Write(at, binary.LittleEndian.AppendUint32(nil, v))
}
func (m *S43Memory) WriteU64(at uint64, v uint64) {
	m.Write(at, binary.LittleEndian.AppendUint64(nil, v))
}

// Unmap drops the page holding at, so a read of it fails.
func (m *S43Memory) Unmap(at uint64) { delete(m.pages, at&^0xfff) }

type S43File struct {
	Name          string
	DeletePending bool
	DeleteOnClose bool
	NoFilePointer bool
	NotImage      bool
	Header        []byte
}

type S43View struct {
	Start, End uint64
	Private    bool
	VadType    uint32
	Protection uint32
	File       *S43File
}

type S43Process struct {
	PID                uint64
	Name               string
	NoPeb              bool
	ImageBaseAddress   uint64
	SectionBaseAddress uint64
	Views              []S43View
	// Index into Views of the view whose stream ImageFilePointer opens; -1
	// with FilePointer nil gives no ImageFilePointer. FilePointer replaces its
	// name and DeletePending, FilePointerImageSection its image section.
	FilePointerView         int
	FilePointer             *S43File
	FilePointerImageSection uint64
	AuditName               string
	SectionObjectCA         uint64
	Secure                  uint64
	VadCount                uint64
	UserMemory              map[uint64][]byte
}

type S43Placement struct {
	PID, EPROCESS, DirectoryTableBase uint64
	Name                              string
}

type S43Placed struct {
	ControlArea uint64
	FileObject  uint64
	VAD         uint64
}

type S43Image struct {
	Table    *symbols.Table
	Kernel   *S43Memory
	Physical *S43Memory
	User     map[uint64]*S43Memory
	Procs    []S43Placement
	Placed   map[uint64][]S43Placed
	// ImageFilePointer file object of each process, 0 when none.
	FilePointer map[uint64]uint64
	Diagnostics []string

	heap  uint64
	frame uint64
}

func (img *S43Image) alloc(size uint64) uint64 {
	at := img.heap + 0x10
	img.heap = (at + size + 0xff) &^ 0xff
	return at
}

func s43Field(name string, off uint64, typ string) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: typ}}
}

func s43Bits(name string, bit, length uint8) symbols.Field {
	return symbols.Field{Name: name, Type: symbols.TypeRef{Name: "unsigned int", BitOffset: bit, BitLength: length}}
}

func S43Table() *symbols.Table {
	t := S19Table()
	add := func(name string, size uint64, fields ...symbols.Field) {
		t.AddStruct(symbols.StructType{Name: name, Size: size, Fields: fields})
	}
	add("_LIST_ENTRY", 16, s19Pointer("Flink", 0, "_LIST_ENTRY"), s19Pointer("Blink", 8, "_LIST_ENTRY"))
	add("_KPROCESS", 0x438, s43Field("DirectoryTableBase", S43DirectoryTableBase, "unsigned long long"),
		s43Field("SecureState", S43SecureState, "<unnamed-tag>"))
	add("_EPROCESS", S43EprocessSize, s43Field("Pcb", 0, "_KPROCESS"),
		s19Pointer("UniqueProcessId", S43UniqueProcessID, "void"), s43Field("ActiveProcessLinks", S43ActiveProcessLinks, "_LIST_ENTRY"),
		s19Pointer("SectionObject", S43SectionObject, "void"), s19Pointer("SectionBaseAddress", S43SectionBaseAddress, "void"),
		s19Pointer("Peb", S43Peb, "_PEB"), s19Pointer("ImageFilePointer", S43ImageFilePointer, "_FILE_OBJECT"),
		symbols.Field{Name: "ImageFileName", Offset: S43ImageFileName,
			Type: symbols.TypeRef{Name: "unsigned char", IsArray: true, ArrayLength: 15}},
		s43Field("SeAuditProcessCreationInfo", S43AuditInfo, "_SE_AUDIT_PROCESS_CREATION_INFO"),
		s43Field("VadRoot", S43VadRoot, "_RTL_AVL_TREE"), s43Field("VadCount", S43VadCount, "unsigned long long"))
	add("_PEB", 0x7d0, s19Pointer("ImageBaseAddress", S43PebImageBaseAddress, "void"))
	add("_SE_AUDIT_PROCESS_CREATION_INFO", 8, s19Pointer("ImageFileName", 0, "_OBJECT_NAME_INFORMATION"))
	add("_OBJECT_NAME_INFORMATION", 16, s43Field("Name", 0, "_UNICODE_STRING"))
	add("_SECTION", 0x40, s43Field("u1", S43SectionControlArea, "<unnamed-tag>"))
	add("_FILE_OBJECT", S19FileObjectSize, s43Field("Type", 0, "short"), s43Field("Size", 2, "short"),
		s19Pointer("DeviceObject", 8, "_DEVICE_OBJECT"), s19Pointer("SectionObjectPointer", 0x28, "_SECTION_OBJECT_POINTERS"),
		s43Field("DeletePending", S43FileDeletePending, "unsigned char"), s43Field("Flags", 0x50, "unsigned int"),
		s43Field("FileName", 0x58, "_UNICODE_STRING"))
	add("_MMSECTION_FLAGS", 4, s43Bits("BeingDeleted", 0, 1), s43Bits("Image", 5, 1), s43Bits("File", 7, 1),
		s43Bits("DeleteOnClose", s43DeleteOnClose, 1), s43Bits("FilePointerNull", s43FileNull, 1))
	add("_RTL_AVL_TREE", 8, s19Pointer("Root", 0, "_RTL_BALANCED_NODE"))
	add("_RTL_BALANCED_NODE", 24, s19Pointer("Left", 0, "_RTL_BALANCED_NODE"), s19Pointer("Right", 8, "_RTL_BALANCED_NODE"),
		s43Field("ParentValue", 0x10, "unsigned long long"))
	add("_MMVAD_SHORT", 0x40, s43Field("VadNode", 0, "_RTL_BALANCED_NODE"),
		s43Field("StartingVpn", 0x18, "unsigned int"), s43Field("EndingVpn", 0x1c, "unsigned int"),
		s43Field("StartingVpnHigh", 0x20, "unsigned char"), s43Field("EndingVpnHigh", 0x21, "unsigned char"),
		s43Field("u", s43VadFlags, "<unnamed-tag>"))
	add("_MMVAD", 0x88, s19Pointer("Subsection", S19VadSubsection, "_SUBSECTION"),
		s19Pointer("FirstPrototypePte", S19VadFirstProto, "_MMPTE"))
	add("_MMVAD_FLAGS", 4, s43Bits("VadType", s43VadTypeBit, 3), s43Bits("Protection", s43ProtectionBit, 5),
		s43Bits("PrivateMemory", s43PrivateBit, 1))
	add("_POOL_HEADER", 16, s43Field("PoolTag", 4, "unsigned int"))
	t.AddSymbol(symbols.Symbol{Name: "MmProtectToValue", Address: s43ProtectVA})
	t.AddSymbol(symbols.Symbol{Name: "MmHighestUserAddress", Address: s43HighestVA})
	t.AddSymbol(symbols.Symbol{Name: "PsActiveProcessHead", Address: s43ListHeadVA})
	return t
}

func BuildS43Image(procs []S43Process) *S43Image {
	img := &S43Image{Table: S43Table(), Kernel: NewS43Memory(), Physical: NewS43Memory(), User: map[uint64]*S43Memory{},
		Placed: map[uint64][]S43Placed{}, FilePointer: map[uint64]uint64{}, heap: s43KernelHeap, frame: s43PhysicalFrames}
	k := img.Kernel
	k.WriteU64(s43HighestVA, 0x7FFF_FFFE_FFFF)
	base := []uint32{0x01, 0x02, 0x10, 0x20, 0x04, 0x08, 0x40, 0x80}
	for i := range 32 {
		v := base[i&7] | []uint32{0, 0x200, 0x100, 0x400}[i>>3]
		if i&7 == 0 {
			v = 0x01
		}
		k.WriteU32(s43ProtectVA+uint64(4*i), v)
	}
	prev := s43ListHeadVA
	for i, p := range procs {
		ep := img.alloc(S43EprocessSize)
		dtb := s43DTBBase + uint64(i)*0x1000
		user := NewS43Memory()
		img.User[dtb] = user
		k.WriteU64(ep+S43DirectoryTableBase, dtb)
		k.WriteU64(ep+S43UniqueProcessID, p.PID)
		k.Write(ep+S43ImageFileName, append([]byte(p.Name), 0))
		k.WriteU64(prev, ep+S43ActiveProcessLinks)
		k.WriteU64(ep+S43ActiveProcessLinks+8, prev)
		prev = ep + S43ActiveProcessLinks
		k.WriteU64(ep+S43SectionBaseAddress, p.SectionBaseAddress)
		k.WriteU64(ep+S43SecureState, p.Secure)
		count := p.VadCount
		if count == 0 {
			count = uint64(len(p.Views))
		}
		k.WriteU64(ep+S43VadCount, count)
		if !p.NoPeb {
			peb := uint64(0x7ff6_0001_0000) + uint64(i)<<20
			k.WriteU64(ep+S43Peb, peb)
			user.WriteU64(peb+S43PebImageBaseAddress, p.ImageBaseAddress)
		}
		for at, b := range p.UserMemory {
			user.Write(at, b)
		}
		placed := img.placeViews(ep, p.Views)
		img.Placed[p.PID] = placed
		var fpCA uint64
		if p.FilePointerView >= 0 && p.FilePointerView < len(placed) {
			fpCA = placed[p.FilePointerView].ControlArea
		}
		if p.FilePointerImageSection != 0 {
			fpCA = p.FilePointerImageSection
		}
		var fo uint64
		switch {
		case p.FilePointer != nil:
			fo = img.fileObject(p.FilePointer.Name, p.FilePointer.DeletePending, img.sectionPointers(fpCA))
		case p.FilePointerView >= 0 && p.FilePointerView < len(placed):
			fo = img.fileObject(p.Views[p.FilePointerView].File.Name, false, img.sectionPointers(fpCA))
		}
		k.WriteU64(ep+S43ImageFilePointer, fo)
		img.FilePointer[p.PID] = fo
		if p.AuditName != "" {
			info := img.alloc(16)
			img.unicode(info, p.AuditName)
			k.WriteU64(ep+S43AuditInfo, info)
		}
		section := img.alloc(0x40)
		held := p.SectionObjectCA
		for j, v := range p.Views {
			if held == 0 && v.Start == p.SectionBaseAddress {
				held = placed[j].ControlArea
			}
		}
		k.WriteU64(section+S43SectionControlArea, held)
		k.WriteU64(ep+S43SectionObject, section)
		img.Procs = append(img.Procs, S43Placement{PID: p.PID, Name: p.Name, EPROCESS: ep, DirectoryTableBase: dtb})
	}
	k.WriteU64(prev, s43ListHeadVA)
	k.WriteU64(s43ListHeadVA+8, prev)
	return img
}

func (img *S43Image) unicode(at uint64, s string) {
	raw := utf16LE(s)
	buf := img.alloc(uint64(len(raw)) + 2)
	img.Kernel.Write(buf, raw)
	img.Kernel.WriteU16(at, uint16(len(raw)))
	img.Kernel.WriteU16(at+2, uint16(len(raw)))
	img.Kernel.WriteU64(at+8, buf)
}

func (img *S43Image) sectionPointers(ca uint64) uint64 {
	sop := img.alloc(24)
	img.Kernel.WriteU64(sop+0x10, ca)
	return sop
}

func (img *S43Image) fileObject(name string, deletePending bool, sop uint64) uint64 {
	fo := img.alloc(S19FileObjectSize)
	img.Kernel.WriteU16(fo, 5)
	img.Kernel.WriteU16(fo+2, S19FileObjectSize)
	img.Kernel.WriteU64(fo+0x28, sop)
	if deletePending {
		img.Kernel.Write(fo+S43FileDeletePending, []byte{1})
	}
	if name != "" {
		img.unicode(fo+0x58, name)
	}
	return fo
}

func (img *S43Image) placeViews(ep uint64, views []S43View) []S43Placed {
	k := img.Kernel
	fixture := make([]FixtureVAD, len(views))
	for i, v := range views {
		fixture[i] = FixtureVAD{Start: v.Start, End: v.End}
	}
	links := S24VadLinks(fixture)
	nodes := make([]uint64, len(views))
	out := make([]S43Placed, len(views))
	for i := range views {
		nodes[i] = img.alloc(0x88 + 16)
		nodes[i] += 16
	}
	for i, v := range views {
		at := nodes[i]
		tag := "VadS"
		if !v.Private {
			tag = "Vad "
		}
		k.Write(at-12, []byte(tag))
		sv, ev := v.Start>>12, v.End>>12
		k.WriteU32(at+0x18, uint32(sv))
		k.WriteU32(at+0x1c, uint32(ev))
		k.Write(at+0x20, []byte{byte(sv >> 32), byte(ev >> 32)})
		flags := v.Protection<<s43ProtectionBit | v.VadType<<s43VadTypeBit
		if v.Private {
			flags |= 1 << s43PrivateBit
		}
		k.WriteU32(at+s43VadFlags, flags)
		if l := links.Left[i]; l >= 0 {
			k.WriteU64(at, nodes[l])
		}
		if r := links.Right[i]; r >= 0 {
			k.WriteU64(at+8, nodes[r])
		}
		out[i].VAD = at
		if v.File != nil {
			out[i].ControlArea, out[i].FileObject = img.imageFile(at, v.File)
		}
	}
	if len(views) > 0 {
		k.WriteU64(ep+S43VadRoot, nodes[links.Root])
	}
	return out
}

// The control area is followed by its one subsection (S19 M2), whose single
// prototype PTE maps the section's header page.
func (img *S43Image) imageFile(vad uint64, f *S43File) (ca, fo uint64) {
	k := img.Kernel
	ca = img.alloc(S19ControlAreaSize + S19SubsectionSize)
	sub := ca + S19ControlAreaSize
	segment := img.alloc(72)
	sop := img.sectionPointers(ca)
	if !f.NoFilePointer {
		fo = img.fileObject(f.Name, f.DeletePending, sop)
	}
	WriteS19ControlArea(k, S19ControlArea{Address: ca, Segment: segment, FilePointer: fo | 0x3, TotalPtes: 1,
		Image: !f.NotImage, File: true})
	if f.DeleteOnClose || f.NoFilePointer {
		flags, _ := k.ReadAt(ca+s19FlagsAt, 4)
		v := binary.LittleEndian.Uint32(flags)
		if f.DeleteOnClose {
			v |= 1 << s43DeleteOnClose
		}
		if f.NoFilePointer {
			v |= 1 << s43FileNull
		}
		k.WriteU32(ca+s19FlagsAt, v)
	}
	ptes := img.alloc(8)
	WriteS19Subsection(k, S19Subsection{Address: sub, ControlArea: ca, Base: ptes, Ptes: 1, FullSectors: 2})
	if f.Header != nil {
		frame := img.frame
		img.frame += 0x1000
		img.Physical.Write(frame, f.Header)
		k.WriteU64(ptes, S19ValidPTE(frame))
	}
	k.WriteU64(vad+S19VadSubsection, sub)
	k.WriteU64(vad+S19VadFirstProto, ptes)
	return ca, fo
}

func (img *S43Image) Context() tools.Context {
	img.Diagnostics = nil
	return tools.Context{
		Memory:  img.Kernel,
		Symbols: img.Table,
		Profile: profiles.WindowsX64Profile{},
		Options: map[string]any{"diagnostics": &img.Diagnostics, tools.OptionPhysicalMemory: memory.MemoryReader(img.Physical)},
		ProcessMemory: func(dtb uint64) (memory.MemoryReader, error) {
			if u, ok := img.User[dtb]; ok {
				return u, nil
			}
			return nil, fmt.Errorf("s43: dtb 0x%x: %w", dtb, memory.ErrOutOfBounds)
		},
	}
}

func (img *S43Image) Process(pid uint64) S43Placement {
	i := slices.IndexFunc(img.Procs, func(p S43Placement) bool { return p.PID == pid })
	if i < 0 {
		return S43Placement{}
	}
	return img.Procs[i]
}
