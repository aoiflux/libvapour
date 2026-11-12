package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	DOSMagic    = uint16(0x5A4D)
	NTSignature = uint32(0x00004550)

	OptionalMagicPE32     = uint16(0x010B)
	OptionalMagicPE32Plus = uint16(0x020B)

	DOSHeaderSize     = uint64(64)
	FileHeaderSize    = uint64(20)
	SectionHeaderSize = uint64(40)
)

const (
	offDOSLfanew = uint64(0x3C)

	offFileMachine              = uint64(0)
	offFileNumberOfSections     = uint64(2)
	offFileTimeDateStamp        = uint64(4)
	offFileSizeOfOptionalHeader = uint64(16)
	offFileCharacteristics      = uint64(18)

	offOptAddressOfEntryPoint   = uint64(16)
	offOptImageBase32           = uint64(28)
	offOptImageBase64           = uint64(24)
	offOptSectionAlignment      = uint64(32)
	offOptFileAlignment         = uint64(36)
	offOptMajorOSVersion        = uint64(40)
	offOptMinorOSVersion        = uint64(42)
	offOptSizeOfImage           = uint64(56)
	offOptSizeOfHeaders         = uint64(60)
	offOptCheckSum              = uint64(64)
	offOptNumberOfRvaAndSizes32 = uint64(92)
	offOptNumberOfRvaAndSizes64 = uint64(108)
	offOptDataDirectory32       = uint64(96)
	offOptDataDirectory64       = uint64(112)

	offSectVirtualSize      = uint64(8)
	offSectVirtualAddress   = uint64(12)
	offSectSizeOfRawData    = uint64(16)
	offSectPointerToRawData = uint64(20)
	offSectCharacteristics  = uint64(36)

	dataDirectoryEntrySize = uint64(8)
	sectionNameSize        = 8
)

var (
	ErrNotPE                    = errors.New("pe: no MZ signature at offset 0")
	ErrNoNTSignature            = errors.New("pe: no PE signature at e_lfanew")
	ErrUnsupportedOptionalMagic = errors.New("pe: optional header magic is neither PE32 nor PE32+")
	ErrShortOptionalHeader      = errors.New("pe: SizeOfOptionalHeader is shorter than the fixed fields")
	ErrImageTooLarge            = errors.New("pe: SizeOfImage too large")
	ErrSectionOutOfRange        = errors.New("pe: section past SizeOfImage")
	ErrBadAlignment             = errors.New("pe: SectionAlignment is not a power of two")
	ErrNoDataDirectory          = errors.New("pe: data directory index past NumberOfRvaAndSizes")
)

type TruncatedError struct {
	Have uint64
	Need uint64
	What string
}

func (e *TruncatedError) Error() string {
	return fmt.Sprintf("pe: %s needs %d bytes, buffer has %d", e.What, e.Need, e.Have)
}

func truncated(have, need uint64, what string) error {
	return &TruncatedError{Have: have, Need: need, What: what}
}

type DOSHeader struct {
	Magic  uint16
	Lfanew uint32
}

type FileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type OptionalHeader struct {
	Magic                       uint16
	PE32Plus                    bool
	AddressOfEntryPoint         uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32

	ImageBaseOffset uint64
	ImageBaseSize   uint64
}

type SectionHeader struct {
	// Raw header bytes up to the first NUL: not safe in a file name as is.
	Name             string
	VirtualSize      uint32
	VirtualAddress   uint32
	SizeOfRawData    uint32
	PointerToRawData uint32
	Characteristics  uint32
	HeaderOffset     uint64
}

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type Headers struct {
	DOS      DOSHeader
	File     FileHeader
	Optional OptionalHeader
	Sections []SectionHeader

	NTOffset           uint64
	OptionalOffset     uint64
	SectionTableOffset uint64
}

// Each stage needs the one before it to know how many bytes it takes, so a
// short buffer reports the length the next stage needs and the caller can
// read that much and try again.
func ParseHeaders(image []byte) (*Headers, error) {
	have := uint64(len(image))
	if have >= 2 && binary.LittleEndian.Uint16(image) != DOSMagic {
		return nil, ErrNotPE
	}
	if have < DOSHeaderSize {
		return nil, truncated(have, DOSHeaderSize, "DOS header")
	}
	h := &Headers{DOS: DOSHeader{Magic: DOSMagic, Lfanew: binary.LittleEndian.Uint32(image[offDOSLfanew:])}}

	h.NTOffset = uint64(h.DOS.Lfanew)
	fileAt := h.NTOffset + 4
	if need := fileAt + FileHeaderSize; have < need {
		return nil, truncated(have, need, "PE signature and file header")
	}
	if binary.LittleEndian.Uint32(image[h.NTOffset:]) != NTSignature {
		return nil, ErrNoNTSignature
	}
	f := image[fileAt:]
	h.File = FileHeader{
		Machine:              binary.LittleEndian.Uint16(f[offFileMachine:]),
		NumberOfSections:     binary.LittleEndian.Uint16(f[offFileNumberOfSections:]),
		TimeDateStamp:        binary.LittleEndian.Uint32(f[offFileTimeDateStamp:]),
		SizeOfOptionalHeader: binary.LittleEndian.Uint16(f[offFileSizeOfOptionalHeader:]),
		Characteristics:      binary.LittleEndian.Uint16(f[offFileCharacteristics:]),
	}

	h.OptionalOffset = fileAt + FileHeaderSize
	if need := h.OptionalOffset + 2; have < need {
		return nil, truncated(have, need, "optional header magic")
	}
	if err := h.decodeOptional(image); err != nil {
		return nil, err
	}

	h.SectionTableOffset = h.OptionalOffset + uint64(h.File.SizeOfOptionalHeader)
	if need := h.HeaderSpan(); have < need {
		return nil, truncated(have, need, "section table")
	}
	h.Sections = make([]SectionHeader, h.File.NumberOfSections)
	for i := range h.Sections {
		at := h.SectionTableOffset + uint64(i)*SectionHeaderSize
		s := image[at : at+SectionHeaderSize]
		name := s[:sectionNameSize]
		if n := indexNUL(name); n >= 0 {
			name = name[:n]
		}
		h.Sections[i] = SectionHeader{
			Name:             string(name),
			VirtualSize:      binary.LittleEndian.Uint32(s[offSectVirtualSize:]),
			VirtualAddress:   binary.LittleEndian.Uint32(s[offSectVirtualAddress:]),
			SizeOfRawData:    binary.LittleEndian.Uint32(s[offSectSizeOfRawData:]),
			PointerToRawData: binary.LittleEndian.Uint32(s[offSectPointerToRawData:]),
			Characteristics:  binary.LittleEndian.Uint32(s[offSectCharacteristics:]),
			HeaderOffset:     at,
		}
	}
	return h, nil
}

func (h *Headers) decodeOptional(image []byte) error {
	o := &h.Optional
	o.Magic = binary.LittleEndian.Uint16(image[h.OptionalOffset:])
	fixed := offOptDataDirectory32
	switch o.Magic {
	case OptionalMagicPE32:
		o.ImageBaseOffset, o.ImageBaseSize = h.OptionalOffset+offOptImageBase32, 4
	case OptionalMagicPE32Plus:
		o.PE32Plus = true
		fixed = offOptDataDirectory64
		o.ImageBaseOffset, o.ImageBaseSize = h.OptionalOffset+offOptImageBase64, 8
	default:
		return fmt.Errorf("%w: 0x%04x", ErrUnsupportedOptionalMagic, o.Magic)
	}
	if uint64(h.File.SizeOfOptionalHeader) < fixed {
		return fmt.Errorf("%w: %d bytes, need %d", ErrShortOptionalHeader, h.File.SizeOfOptionalHeader, fixed)
	}
	if need := h.OptionalOffset + fixed; uint64(len(image)) < need {
		return truncated(uint64(len(image)), need, "optional header")
	}
	opt := image[h.OptionalOffset:]
	o.AddressOfEntryPoint = binary.LittleEndian.Uint32(opt[offOptAddressOfEntryPoint:])
	if o.PE32Plus {
		o.ImageBase = binary.LittleEndian.Uint64(opt[offOptImageBase64:])
	} else {
		o.ImageBase = uint64(binary.LittleEndian.Uint32(opt[offOptImageBase32:]))
	}
	o.SectionAlignment = binary.LittleEndian.Uint32(opt[offOptSectionAlignment:])
	o.FileAlignment = binary.LittleEndian.Uint32(opt[offOptFileAlignment:])
	o.MajorOperatingSystemVersion = binary.LittleEndian.Uint16(opt[offOptMajorOSVersion:])
	o.MinorOperatingSystemVersion = binary.LittleEndian.Uint16(opt[offOptMinorOSVersion:])
	o.SizeOfImage = binary.LittleEndian.Uint32(opt[offOptSizeOfImage:])
	o.SizeOfHeaders = binary.LittleEndian.Uint32(opt[offOptSizeOfHeaders:])
	o.CheckSum = binary.LittleEndian.Uint32(opt[offOptCheckSum:])
	return nil
}

func (h *Headers) HeaderSpan() uint64 {
	return h.SectionTableOffset + uint64(h.File.NumberOfSections)*SectionHeaderSize
}

func (h *Headers) directoryLayout() (countAt, arrayAt uint64) {
	if h.Optional.PE32Plus {
		return h.OptionalOffset + offOptNumberOfRvaAndSizes64, h.OptionalOffset + offOptDataDirectory64
	}
	return h.OptionalOffset + offOptNumberOfRvaAndSizes32, h.OptionalOffset + offOptDataDirectory32
}

// An entry counts only when NumberOfRvaAndSizes declares it and it lies
// inside the optional header; past either, the bytes belong to something else.
func (h *Headers) directoryEntryAt(count uint32, index int) (uint64, error) {
	if index < 0 || uint64(index) >= uint64(count) {
		return 0, fmt.Errorf("%w: index %d, NumberOfRvaAndSizes %d", ErrNoDataDirectory, index, count)
	}
	_, arrayAt := h.directoryLayout()
	at := arrayAt + uint64(index)*dataDirectoryEntrySize
	if at+dataDirectoryEntrySize > h.OptionalOffset+uint64(h.File.SizeOfOptionalHeader) {
		return 0, fmt.Errorf("%w: index %d lies past SizeOfOptionalHeader %d", ErrNoDataDirectory, index, h.File.SizeOfOptionalHeader)
	}
	return at, nil
}

func (h *Headers) DataDirectory(image []byte, index int) (DataDirectory, error) {
	countAt, _ := h.directoryLayout()
	if have := uint64(len(image)); have < countAt+4 {
		return DataDirectory{}, truncated(have, countAt+4, "NumberOfRvaAndSizes")
	}
	at, err := h.directoryEntryAt(binary.LittleEndian.Uint32(image[countAt:]), index)
	if err != nil {
		return DataDirectory{}, err
	}
	if have := uint64(len(image)); have < at+dataDirectoryEntrySize {
		return DataDirectory{}, truncated(have, at+dataDirectoryEntrySize, "data directory")
	}
	return DataDirectory{
		VirtualAddress: binary.LittleEndian.Uint32(image[at:]),
		Size:           binary.LittleEndian.Uint32(image[at+4:]),
	}, nil
}

// The headers are mapped at RVA 0, so a header offset is also its RVA.
func (h *Headers) ReadDataDirectory(read ReadRVA, index int) (DataDirectory, error) {
	countAt, _ := h.directoryLayout()
	b, err := read(uint32(countAt), 4)
	if err != nil {
		return DataDirectory{}, err
	}
	at, err := h.directoryEntryAt(binary.LittleEndian.Uint32(b), index)
	if err != nil {
		return DataDirectory{}, err
	}
	b, err = read(uint32(at), int(dataDirectoryEntrySize))
	if err != nil {
		return DataDirectory{}, err
	}
	return DataDirectory{VirtualAddress: binary.LittleEndian.Uint32(b), Size: binary.LittleEndian.Uint32(b[4:])}, nil
}

func indexNUL(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}
