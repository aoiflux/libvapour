package testsupport

import "github.com/aoiflux/libvapour/symbols"

// Layouts are the 26100 ones from the kernel table measured in S19; the VAD
// members are fixture-only offsets.
const (
	S19FileObjectSize   = 216
	S19ControlAreaSize  = 128
	S19SubsectionSize   = 56
	S19CacheMapSize     = 616
	S19VacbSize         = 40
	S19VacbHeaderSize   = 16
	S19ObjectHeaderBody = 0x30

	s19DeviceType = 0x48
	s19FlagsAt    = 0x38
	s19SubFlags   = 0x20
)

const (
	S19VadSubsection   = 0x48
	S19VadFirstProto   = 0x50
	S19VadLastContig   = 0x58
	S19VadStartVpn     = 0x18
	S19VadEndVpn       = 0x1c
	S19VadStartVpnHigh = 0x20
	S19VadEndVpnHigh   = 0x21
)

func s19Field(name string, off uint64, typ string) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: typ}}
}

func s19Pointer(name string, off uint64, target string) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: target, IsPointer: true}}
}

func s19Bits(name string, typ string, offset, length uint8) symbols.Field {
	return symbols.Field{Name: name, Type: symbols.TypeRef{Name: typ, BitOffset: offset, BitLength: length}}
}

func S19Table() *symbols.Table {
	t := symbols.NewTable("s19-fixture", 8)
	add := func(name string, size uint64, fields ...symbols.Field) {
		t.AddStruct(symbols.StructType{Name: name, Size: size, Fields: fields})
	}
	add("_LARGE_INTEGER", 8, s19Field("QuadPart", 0, "long long"))
	add("_UNICODE_STRING", 16, s19Field("Length", 0, "unsigned short"), s19Field("MaximumLength", 2, "unsigned short"),
		s19Pointer("Buffer", 8, "wchar"))
	add("_EX_FAST_REF", 8, s19Pointer("Object", 0, "void"), s19Bits("RefCnt", "unsigned long long", 0, 4),
		s19Field("Value", 0, "unsigned long long"))
	add("_FILE_OBJECT", S19FileObjectSize, s19Field("Type", 0, "short"), s19Field("Size", 2, "short"),
		s19Pointer("DeviceObject", 8, "_DEVICE_OBJECT"), s19Pointer("FsContext", 0x18, "void"),
		s19Pointer("SectionObjectPointer", 0x28, "_SECTION_OBJECT_POINTERS"), s19Field("Flags", 0x50, "unsigned int"),
		s19Field("FileName", 0x58, "_UNICODE_STRING"))
	add("_DEVICE_OBJECT", 336, s19Field("DeviceType", s19DeviceType, "unsigned int"))
	add("_OBJECT_HEADER", 56, s19Field("Body", S19ObjectHeaderBody, "_QUAD"))
	add("_FSRTL_ADVANCED_FCB_HEADER", 104, s19Field("FileSize", 0x20, "_LARGE_INTEGER"))
	add("_SECTION_OBJECT_POINTERS", 24, s19Pointer("DataSectionObject", 0, "void"),
		s19Pointer("SharedCacheMap", 8, "void"), s19Pointer("ImageSectionObject", 0x10, "void"))
	add("_CONTROL_AREA", S19ControlAreaSize, s19Pointer("Segment", 0, "_SEGMENT"),
		s19Field("u", s19FlagsAt, "<anonymous-tag>"), s19Field("FilePointer", 0x40, "_EX_FAST_REF"))
	add("_MMSECTION_FLAGS", 4, s19Bits("BeingDeleted", "unsigned int", 0, 1), s19Bits("Image", "unsigned int", 5, 1),
		s19Bits("File", "unsigned int", 7, 1))
	add("_SEGMENT", 72, s19Pointer("ControlArea", 0, "_CONTROL_AREA"), s19Field("TotalNumberOfPtes", 8, "unsigned int"),
		s19Field("SizeOfSegment", 0x18, "unsigned long long"))
	add("_SUBSECTION", S19SubsectionSize, s19Pointer("ControlArea", 0, "_CONTROL_AREA"),
		s19Pointer("SubsectionBase", 8, "_MMPTE"), s19Pointer("NextSubsection", 0x10, "_SUBSECTION"),
		s19Field("SubsectionFlags", s19SubFlags, "_MMSUBSECTION_FLAGS"), s19Field("StartingSector", 0x24, "unsigned int"),
		s19Field("NumberOfFullSectors", 0x28, "unsigned int"), s19Field("PtesInSubsection", 0x2c, "unsigned int"))
	add("_MMSUBSECTION_FLAGS", 4, s19Bits("StartingSector4132", "unsigned int", 6, 10),
		s19Bits("SectorEndOffset", "unsigned int", 20, 12))
	add("_MMPTE", 8, s19Field("u", 0, "<anonymous-tag>"))
	add("_MMPTE_HARDWARE", 8, s19Bits("Valid", "unsigned long long", 0, 1),
		s19Bits("PageFrameNumber", "unsigned long long", 12, 40))
	add("_MMPTE_TRANSITION", 8, s19Bits("Valid", "unsigned long long", 0, 1),
		s19Bits("Prototype", "unsigned long long", 10, 1), s19Bits("Transition", "unsigned long long", 11, 1),
		s19Bits("PageFrameNumber", "unsigned long long", 12, 40))
	add("_MMVAD", 0x88, s19Pointer("Subsection", S19VadSubsection, "_SUBSECTION"),
		s19Pointer("FirstPrototypePte", S19VadFirstProto, "_MMPTE"), s19Pointer("LastContiguousPte", S19VadLastContig, "_MMPTE"))
	add("_MMVAD_SHORT", 0x40, s19Field("StartingVpn", S19VadStartVpn, "unsigned int"),
		s19Field("EndingVpn", S19VadEndVpn, "unsigned int"), s19Field("StartingVpnHigh", S19VadStartVpnHigh, "unsigned char"),
		s19Field("EndingVpnHigh", S19VadEndVpnHigh, "unsigned char"))
	add("_SHARED_CACHE_MAP", S19CacheMapSize, s19Field("NodeTypeCode", 0, "short"), s19Field("NodeByteSize", 2, "short"),
		s19Field("FileSize", 8, "_LARGE_INTEGER"), s19Field("SectionSize", 0x20, "_LARGE_INTEGER"),
		s19Field("ValidDataLength", 0x28, "_LARGE_INTEGER"), s19Pointer("Vacbs", 0x58, "_VACB"),
		s19Field("FileObjectFastRef", 0x60, "_EX_FAST_REF"))
	add("_VACB", S19VacbSize, s19Pointer("BaseAddress", 0, "void"), s19Pointer("SharedCacheMap", 8, "_SHARED_CACHE_MAP"),
		s19Field("Overlay", 0x10, "<anonymous-tag>"), s19Pointer("ArrayHead", 0x20, "_VACB_ARRAY_HEADER"))
	add("_VACB_ARRAY_HEADER", S19VacbHeaderSize, s19Field("VacbArrayIndex", 0, "unsigned int"),
		s19Field("MappingCount", 4, "unsigned int"), s19Field("HighestMappedIndex", 8, "unsigned int"),
		s19Field("Reserved", 12, "unsigned int"))
	return t
}

func S19AddVacbSymbols(t *symbols.Table, arrays, highest uint64) {
	t.AddSymbol(symbols.Symbol{Name: "CcVacbArrays", Address: arrays})
	t.AddSymbol(symbols.Symbol{Name: "CcVacbArraysHighestUsedIndex", Address: highest})
}

type S19Writer interface {
	WriteU16(offset uint64, v uint16)
	WriteU32(offset uint64, v uint32)
	WriteU64(offset uint64, v uint64)
}

type S19FileObject struct {
	Address, Device, SOP, FsContext uint64
	Type, Size                      uint16
	Name                            uint64
	NameBytes                       uint16
}

func WriteS19FileObject(w S19Writer, fo S19FileObject) {
	w.WriteU16(fo.Address, fo.Type)
	w.WriteU16(fo.Address+2, fo.Size)
	w.WriteU64(fo.Address+8, fo.Device)
	w.WriteU64(fo.Address+0x18, fo.FsContext)
	w.WriteU64(fo.Address+0x28, fo.SOP)
	w.WriteU16(fo.Address+0x58, fo.NameBytes)
	w.WriteU16(fo.Address+0x5a, fo.NameBytes)
	w.WriteU64(fo.Address+0x60, fo.Name)
}

func WriteS19Device(w S19Writer, device uint64, deviceType uint32) {
	w.WriteU32(device+s19DeviceType, deviceType)
}

func WriteS19FileSize(w S19Writer, header, size uint64) {
	w.WriteU64(header+0x20, size)
}

func WriteS19SectionPointers(w S19Writer, at, data, cacheMap, image uint64) {
	w.WriteU64(at, data)
	w.WriteU64(at+8, cacheMap)
	w.WriteU64(at+0x10, image)
}

type S19ControlArea struct {
	Address, Segment, FilePointer uint64
	TotalPtes                     uint32
	SizeOfSegment                 uint64
	Image, File, Deleting         bool
	SegmentOwner                  uint64
}

func WriteS19ControlArea(w S19Writer, ca S19ControlArea) {
	w.WriteU64(ca.Address, ca.Segment)
	var flags uint32
	if ca.Deleting {
		flags |= 1
	}
	if ca.Image {
		flags |= 1 << 5
	}
	if ca.File {
		flags |= 1 << 7
	}
	w.WriteU32(ca.Address+s19FlagsAt, flags)
	w.WriteU64(ca.Address+0x40, ca.FilePointer)
	if ca.Segment != 0 {
		owner := ca.SegmentOwner
		if owner == 0 {
			owner = ca.Address
		}
		w.WriteU64(ca.Segment, owner)
		w.WriteU32(ca.Segment+8, ca.TotalPtes)
		w.WriteU64(ca.Segment+0x18, ca.SizeOfSegment)
	}
}

type S19Subsection struct {
	Address, ControlArea, Base, Next uint64
	Ptes, Sector, FullSectors        uint32
	SectorHigh, EndOffset            uint32
}

func WriteS19Subsection(w S19Writer, s S19Subsection) {
	w.WriteU64(s.Address, s.ControlArea)
	w.WriteU64(s.Address+8, s.Base)
	w.WriteU64(s.Address+0x10, s.Next)
	w.WriteU32(s.Address+s19SubFlags, s.SectorHigh<<6|s.EndOffset<<20)
	w.WriteU32(s.Address+0x24, s.Sector)
	w.WriteU32(s.Address+0x28, s.FullSectors)
	w.WriteU32(s.Address+0x2c, s.Ptes)
}

func S19ValidPTE(frame uint64) uint64 { return frame&0x000FFFFFFFFFF000 | 1 }

func S19TransitionPTE(frame uint64) uint64 { return frame&0x000FFFFFFFFFF000 | 1<<11 }

func S19SubsectionPTE() uint64 { return 1 << 10 }

type S19CacheMap struct {
	Address               uint64
	Node, ByteSize        uint16
	FileSize, SectionSize uint64
	FileRef               uint64
}

func WriteS19CacheMap(w S19Writer, m S19CacheMap) {
	w.WriteU16(m.Address, m.Node)
	w.WriteU16(m.Address+2, m.ByteSize)
	w.WriteU64(m.Address+8, m.FileSize)
	w.WriteU64(m.Address+0x20, m.SectionSize)
	w.WriteU64(m.Address+0x60, m.FileRef)
}

type S19Vacb struct {
	Base, CacheMap, Overlay uint64
}

// The array header is followed by its VACBs; one past the last, ArrayHead is
// left zero so a walk stops there.
func WriteS19VacbArray(w S19Writer, header uint64, index uint32, vacbs []S19Vacb) {
	w.WriteU32(header, index)
	for i, v := range vacbs {
		at := header + S19VacbHeaderSize + uint64(i)*S19VacbSize
		w.WriteU64(at, v.Base)
		w.WriteU64(at+8, v.CacheMap)
		w.WriteU64(at+0x10, v.Overlay)
		w.WriteU64(at+0x20, header)
	}
}
