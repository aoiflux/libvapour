package pe

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
)

const (
	DirectoryEntryCertificate = 4

	offFilePointerToSymbolTable = uint64(8)
	offFileNumberOfSymbols      = uint64(12)
	debugEntryFileOffset        = 24
)

var (
	ErrRebuildTooLarge = errors.New("pe: image is larger than the artifact cap")
	ErrRebuildSize     = errors.New("pe: buffer length is not SizeOfImage")
	ErrRebuildHeaders  = errors.New("pe: optional header does not hold its data directories")
)

type Rebuilt struct {
	File []byte

	Sections []string
	Empty    []string
	Clipped  []string

	ImageBaseSet      bool
	OriginalImageBase uint64

	FileAlignmentSet   bool
	SizeOfHeadersSet   bool
	SizeOfImageAligned bool

	CertificateCleared bool
	DebugRepointed     int
	DebugUnmapped      int
	SymbolTableCleared bool
	CheckSumCleared    bool
}

// The file keeps the memory layout: every section's raw data starts at its
// RVA, so each RVA in the image is also its file offset and no byte moves.
func Rebuild(image []byte, base uint64, l limits.Limits) (Rebuilt, error) {
	l = l.Effective()
	if int64(len(image)) > l.MaxArtifactBytes {
		return Rebuilt{}, fmt.Errorf("%w: %d bytes, cap %d", ErrRebuildTooLarge, len(image), l.MaxArtifactBytes)
	}
	h, err := ParseHeaders(image)
	if err != nil {
		return Rebuilt{}, err
	}
	if uint64(h.Optional.SizeOfImage) != uint64(len(image)) {
		return Rebuilt{}, fmt.Errorf("%w: %d bytes, SizeOfImage %d", ErrRebuildSize, len(image), h.Optional.SizeOfImage)
	}
	if err := h.directoriesFit(image); err != nil {
		return Rebuilt{}, err
	}
	align := uint64(h.Optional.SectionAlignment)
	if !powerOfTwo(align) {
		return Rebuilt{}, fmt.Errorf("%w: 0x%x", ErrBadAlignment, align)
	}

	out := Rebuilt{File: append([]byte(nil), image...), OriginalImageBase: h.Optional.ImageBase}
	file := out.File
	size := uint64(len(file))
	out.SizeOfImageAligned = size%align == 0

	lowest := size
	for _, s := range h.Sections {
		start := uint64(s.VirtualAddress)
		span := uint64(s.VirtualSize)
		if span == 0 {
			span = uint64(s.SizeOfRawData)
		}
		span = roundUp64(span, align)
		raw, pointer := uint64(0), uint64(0)
		switch {
		case start >= size || span == 0:
			out.Empty = append(out.Empty, s.Name)
		case span > size-start:
			raw, pointer = size-start, start
			out.Clipped = append(out.Clipped, s.Name)
		default:
			raw, pointer = span, start
		}
		if raw != 0 {
			out.Sections = append(out.Sections, s.Name)
			lowest = min(lowest, start)
		}
		binary.LittleEndian.PutUint32(file[s.HeaderOffset+offSectPointerToRawData:], uint32(pointer))
		binary.LittleEndian.PutUint32(file[s.HeaderOffset+offSectSizeOfRawData:], uint32(raw))
	}

	if fa := uint64(h.Optional.FileAlignment); !powerOfTwo(fa) || fa > align {
		binary.LittleEndian.PutUint32(file[h.OptionalOffset+offOptFileAlignment:], uint32(align))
		out.FileAlignmentSet = true
	}
	if uint64(h.Optional.SizeOfHeaders) > lowest {
		binary.LittleEndian.PutUint32(file[h.OptionalOffset+offOptSizeOfHeaders:], uint32(lowest))
		out.SizeOfHeadersSet = true
	}

	switch {
	case h.Optional.ImageBaseSize == 8:
		binary.LittleEndian.PutUint64(file[h.Optional.ImageBaseOffset:], base)
		out.ImageBaseSet = true
	case base <= 0xFFFFFFFF:
		binary.LittleEndian.PutUint32(file[h.Optional.ImageBaseOffset:], uint32(base))
		out.ImageBaseSet = true
	}

	symbols := h.NTOffset + 4 + offFilePointerToSymbolTable
	if binary.LittleEndian.Uint32(file[symbols:]) != 0 || binary.LittleEndian.Uint32(file[symbols+4:]) != 0 {
		binary.LittleEndian.PutUint64(file[symbols:], 0)
		out.SymbolTableCleared = true
	}

	if at, ok := h.directoryEntryOffset(file, DirectoryEntryCertificate); ok {
		if binary.LittleEndian.Uint64(file[at:]) != 0 {
			binary.LittleEndian.PutUint64(file[at:], 0)
			out.CertificateCleared = true
		}
	}
	out.DebugRepointed, out.DebugUnmapped = h.repointDebug(file, l)

	// The linker's checksum covers the file on disk; kept, it would vouch for
	// bytes this file does not hold. Zero means not checked.
	if sum := h.OptionalOffset + offOptCheckSum; binary.LittleEndian.Uint32(file[sum:]) != 0 {
		binary.LittleEndian.PutUint32(file[sum:], 0)
		out.CheckSumCleared = true
	}
	return out, nil
}

// The section table starts where SizeOfOptionalHeader says; a header too short
// for its own directories would put rewritten section fields over them.
func (h *Headers) directoriesFit(image []byte) error {
	countOff, arrayOff := offOptNumberOfRvaAndSizes32, offOptDataDirectory32
	if h.Optional.PE32Plus {
		countOff, arrayOff = offOptNumberOfRvaAndSizes64, offOptDataDirectory64
	}
	at := h.OptionalOffset + countOff
	if uint64(len(image)) < at+4 {
		return truncated(uint64(len(image)), at+4, "NumberOfRvaAndSizes")
	}
	need := arrayOff + uint64(binary.LittleEndian.Uint32(image[at:]))*dataDirectoryEntrySize
	if need > uint64(h.File.SizeOfOptionalHeader) {
		return fmt.Errorf("%w: need %d bytes, SizeOfOptionalHeader %d", ErrRebuildHeaders, need, h.File.SizeOfOptionalHeader)
	}
	return nil
}

func (h *Headers) directoryEntryOffset(image []byte, index int) (uint64, bool) {
	if _, err := h.DataDirectory(image, index); err != nil {
		return 0, false
	}
	arrayOff := offOptDataDirectory32
	if h.Optional.PE32Plus {
		arrayOff = offOptDataDirectory64
	}
	return h.OptionalOffset + arrayOff + uint64(index)*dataDirectoryEntrySize, true
}

// A debug entry names its data twice: by RVA and by file offset. Only the RVA
// still holds in memory, so the file offset is made to agree with it.
func (h *Headers) repointDebug(file []byte, l limits.Limits) (repointed, unmapped int) {
	dir, err := h.DataDirectory(file, DirectoryEntryDebug)
	if err != nil || dir.VirtualAddress == 0 || dir.Size == 0 {
		return 0, 0
	}
	start, size := uint64(dir.VirtualAddress), uint64(len(file))
	if start < h.HeaderSpan() || start >= size {
		return 0, 0
	}
	count := min(uint64(dir.Size), size-start) / debugDirectoryEntrySize
	count = min(count, uint64(l.MaxTableEntries))
	for i := range count {
		entry := file[start+i*debugDirectoryEntrySize:]
		rva := uint64(binary.LittleEndian.Uint32(entry[debugEntryRVAOffset:]))
		length := uint64(binary.LittleEndian.Uint32(entry[debugEntrySizeOffset:]))
		pointer := binary.LittleEndian.Uint32(entry[debugEntryFileOffset:])
		want := uint32(rva)
		if rva == 0 || rva > size || length > size-rva {
			want = 0
		}
		if pointer == want {
			continue
		}
		binary.LittleEndian.PutUint32(entry[debugEntryFileOffset:], want)
		if want == 0 {
			unmapped++
		} else {
			repointed++
		}
	}
	return repointed, unmapped
}

func powerOfTwo(v uint64) bool { return v != 0 && v&(v-1) == 0 }

func roundUp64(v, align uint64) uint64 {
	if rem := v % align; rem != 0 {
		if v > ^uint64(0)-(align-rem) {
			return ^uint64(0) &^ (align - 1)
		}
		return v + align - rem
	}
	return v
}
