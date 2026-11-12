package testsupport

import "encoding/binary"

// Header field positions are those of the PE format (S79 D1 to D4).
const (
	dosLfanewAt        = 0x3c
	coffHeaderSize     = 20
	sectionHeaderSize  = 40
	dataDirectoryCount = 16
	exportDirectoryAt  = 112

	machineAMD64           = uint16(0x8664)
	fileExecutableImage    = uint16(0x0002)
	fileLargeAddressAware  = uint16(0x0020)
	fileDLL                = uint16(0x2000)
	optionalMagicPE32Plus  = uint16(0x020b)
	subsystemWindowsCUI    = uint16(3)
	scnCodeExecuteRead     = uint32(0x00000020 | 0x20000000 | 0x40000000)
	fixtureFileAlignment   = uint32(0x200)
	fixtureSubsystemMajor  = uint16(6)
	fixtureImageHeaderSize = uint32(0x400)
)

const (
	MappedPESize               = uint32(0x4000)
	MappedPESectionAlignment   = uint32(0x1000)
	MappedPELfanew             = uint32(0x80)
	MappedPEOptionalHeaderSize = uint16(112 + 8*dataDirectoryCount)
	MappedPEMachine            = machineAMD64
	MappedPETimeDateStamp      = uint32(0x5F000000)
	MappedPEMajorOSVersion     = uint16(10)
	MappedPEMinorOSVersion     = uint16(0)
	MappedPECheckSum           = uint32(0x000ABCDE)
)

type MappedPESection struct {
	Name            string
	VirtualAddress  uint32
	VirtualSize     uint32
	StaleRawPointer uint32
	Fill            byte
}

// The raw pointers describe the file the image was loaded from; once mapped,
// nothing sits at them, which is what a rebuilder has to cope with.
var MappedPESections = []MappedPESection{
	{Name: ".text", VirtualAddress: 0x1000, VirtualSize: 0x800, StaleRawPointer: 0x400, Fill: 0xCC},
	{Name: ".data", VirtualAddress: 0x2000, VirtualSize: 0x400, StaleRawPointer: 0xC00, Fill: 0xDD},
}

type peSection struct {
	name               string
	rva, size          uint32
	rawPointer, rawLen uint32
}

type peImage struct {
	img      []byte
	optional uint32
}

func newPEImage(size uint32, imageBase uint64, characteristics uint16, sections []peSection) peImage {
	p := peImage{img: make([]byte, size), optional: MappedPELfanew + 4 + coffHeaderSize}
	le := binary.LittleEndian
	copy(p.img, "MZ")
	le.PutUint32(p.img[dosLfanewAt:], MappedPELfanew)
	copy(p.img[MappedPELfanew:], "PE\x00\x00")

	coff := p.img[MappedPELfanew+4:]
	le.PutUint16(coff[0:], MappedPEMachine)
	le.PutUint16(coff[2:], uint16(len(sections)))
	le.PutUint32(coff[4:], MappedPETimeDateStamp)
	le.PutUint16(coff[16:], MappedPEOptionalHeaderSize)
	le.PutUint16(coff[18:], characteristics)

	opt := p.img[p.optional:]
	le.PutUint16(opt[0:], optionalMagicPE32Plus)
	le.PutUint32(opt[16:], sections[0].rva)
	le.PutUint32(opt[20:], sections[0].rva)
	le.PutUint64(opt[24:], imageBase)
	le.PutUint32(opt[32:], MappedPESectionAlignment)
	le.PutUint32(opt[36:], fixtureFileAlignment)
	le.PutUint16(opt[40:], MappedPEMajorOSVersion)
	le.PutUint16(opt[42:], MappedPEMinorOSVersion)
	le.PutUint16(opt[48:], fixtureSubsystemMajor)
	le.PutUint32(opt[56:], size)
	le.PutUint32(opt[60:], fixtureImageHeaderSize)
	le.PutUint32(opt[64:], MappedPECheckSum)
	le.PutUint16(opt[68:], subsystemWindowsCUI)
	le.PutUint32(opt[108:], dataDirectoryCount)

	table := p.optional + uint32(MappedPEOptionalHeaderSize)
	for i, s := range sections {
		h := p.img[table+uint32(i)*sectionHeaderSize:]
		copy(h[0:8], s.name)
		le.PutUint32(h[8:], s.size)
		le.PutUint32(h[12:], s.rva)
		le.PutUint32(h[16:], s.rawLen)
		le.PutUint32(h[20:], s.rawPointer)
		le.PutUint32(h[36:], scnCodeExecuteRead)
	}
	return p
}

func (p peImage) setExportDirectory(rva, size uint32) {
	binary.LittleEndian.PutUint32(p.img[p.optional+exportDirectoryAt:], rva)
	binary.LittleEndian.PutUint32(p.img[p.optional+exportDirectoryAt+4:], size)
}

func BuildMappedPE(imageBase uint64) []byte {
	sections := make([]peSection, len(MappedPESections))
	for i, s := range MappedPESections {
		sections[i] = peSection{name: s.Name, rva: s.VirtualAddress, size: s.VirtualSize,
			rawPointer: s.StaleRawPointer, rawLen: s.VirtualSize}
	}
	p := newPEImage(MappedPESize, imageBase, fileExecutableImage|fileLargeAddressAware, sections)
	for _, s := range MappedPESections {
		body := p.img[s.VirtualAddress : s.VirtualAddress+s.VirtualSize]
		for i := range body {
			body[i] = s.Fill
		}
	}
	return p.img
}
