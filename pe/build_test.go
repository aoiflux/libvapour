package pe

import (
	"encoding/binary"
	"fmt"
)

const (
	fxLfanew        = uint32(0x80)
	fxSectAlignment = uint32(0x1000)
	fxFileAlignment = uint32(0x200)
	fxSizeOfImage   = uint32(0x4000)
	fxSizeOfHeaders = uint32(0x400)
	fxDirectories   = uint32(16)

	fxOptSize32 = uint16(96 + 16*8)
	fxOptSize64 = uint16(112 + 16*8)
)

type fxSection struct {
	name        string
	va          uint32
	virtualSize uint32
	rawPointer  uint32
	rawSize     uint32
}

// The file layout differs from the memory layout on purpose, as it does in
// most captured images.
var fxSections = []fxSection{
	{".text", 0x1000, 0xE40, 0x400, 0x1000},
	{".data", 0x2000, 0x310, 0x1400, 0x400},
	{".rdata", 0x3000, 0xA00, 0x1800, 0xA00},
}

func buildImage(plus bool, imageBase uint64) []byte {
	img := make([]byte, fxSizeOfImage)
	binary.LittleEndian.PutUint16(img, DOSMagic)
	binary.LittleEndian.PutUint32(img[offDOSLfanew:], fxLfanew)
	binary.LittleEndian.PutUint32(img[fxLfanew:], NTSignature)

	file := uint64(fxLfanew) + 4
	machine, optSize, magic := uint16(0x014C), fxOptSize32, OptionalMagicPE32
	if plus {
		machine, optSize, magic = 0x8664, fxOptSize64, OptionalMagicPE32Plus
	}
	binary.LittleEndian.PutUint16(img[file+offFileMachine:], machine)
	binary.LittleEndian.PutUint16(img[file+offFileNumberOfSections:], uint16(len(fxSections)))
	binary.LittleEndian.PutUint32(img[file+offFileTimeDateStamp:], 0x5F000000)
	binary.LittleEndian.PutUint16(img[file+offFileSizeOfOptionalHeader:], optSize)
	binary.LittleEndian.PutUint16(img[file+offFileCharacteristics:], 0x0022)

	opt := file + FileHeaderSize
	binary.LittleEndian.PutUint16(img[opt:], magic)
	binary.LittleEndian.PutUint32(img[opt+offOptAddressOfEntryPoint:], 0x1010)
	if plus {
		binary.LittleEndian.PutUint64(img[opt+offOptImageBase64:], imageBase)
		binary.LittleEndian.PutUint32(img[opt+offOptNumberOfRvaAndSizes64:], fxDirectories)
	} else {
		binary.LittleEndian.PutUint32(img[opt+offOptImageBase32:], uint32(imageBase))
		binary.LittleEndian.PutUint32(img[opt+offOptNumberOfRvaAndSizes32:], fxDirectories)
	}
	binary.LittleEndian.PutUint32(img[opt+offOptSectionAlignment:], fxSectAlignment)
	binary.LittleEndian.PutUint32(img[opt+offOptFileAlignment:], fxFileAlignment)
	binary.LittleEndian.PutUint16(img[opt+offOptMajorOSVersion:], 10)
	binary.LittleEndian.PutUint32(img[opt+offOptSizeOfImage:], fxSizeOfImage)
	binary.LittleEndian.PutUint32(img[opt+offOptSizeOfHeaders:], fxSizeOfHeaders)
	binary.LittleEndian.PutUint32(img[opt+offOptCheckSum:], 0x1234)

	table := opt + uint64(optSize)
	for i, s := range fxSections {
		at := table + uint64(i)*SectionHeaderSize
		copy(img[at:at+sectionNameSize], s.name)
		binary.LittleEndian.PutUint32(img[at+offSectVirtualSize:], s.virtualSize)
		binary.LittleEndian.PutUint32(img[at+offSectVirtualAddress:], s.va)
		binary.LittleEndian.PutUint32(img[at+offSectSizeOfRawData:], s.rawSize)
		binary.LittleEndian.PutUint32(img[at+offSectPointerToRawData:], s.rawPointer)
		binary.LittleEndian.PutUint32(img[at+offSectCharacteristics:], 0x40000040)
		for j := s.va; j < s.va+s.virtualSize; j++ {
			img[j] = byte(j*7 + uint32(i))
		}
	}
	return img
}

type sliceReader []byte

func (s sliceReader) ReadAt(offset, size uint64) ([]byte, error) {
	if offset > uint64(len(s)) || size > uint64(len(s))-offset {
		return nil, fmt.Errorf("sliceReader: 0x%x+%d past %d bytes", offset, size, len(s))
	}
	return s[offset : offset+size], nil
}

// holes makes the listed pages fail to read, as pages absent from a capture do.
type holes struct {
	b     []byte
	pages map[uint64]bool
}

func (h holes) ReadAt(offset, size uint64) ([]byte, error) {
	for p := offset &^ (pageSize - 1); p < offset+size; p += pageSize {
		if h.pages[p] {
			return nil, fmt.Errorf("holes: page 0x%x not present", p)
		}
	}
	return sliceReader(h.b).ReadAt(offset, size)
}

func flat(b []byte) ReadRVA { return MappedReader(sliceReader(b), 0, uint32(len(b))) }

func withHoles(b []byte, pages ...uint64) ReadRVA {
	m := map[uint64]bool{}
	for _, p := range pages {
		m[p] = true
	}
	return MappedReader(holes{b, m}, 0, uint32(len(b)))
}

func put16(b []byte, at uint64, v uint16) { binary.LittleEndian.PutUint16(b[at:], v) }
func put32(b []byte, at uint64, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
func put64(b []byte, at uint64, v uint64) { binary.LittleEndian.PutUint64(b[at:], v) }
