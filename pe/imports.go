package pe

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
)

const (
	DirectoryEntryImport = 1
	ImportDescriptorSize = 20
)

const (
	offImportLookupTable  = 0
	offImportTimeDate     = 4
	offImportForwarder    = 8
	offImportName         = 12
	offImportAddressTable = 16
	hintBytes             = 2
)

var (
	ErrNoImportDirectory = errors.New("pe: no import directory")
	// The loader overwrites the import address table with resolved
	// addresses; a descriptor with no lookup table leaves only those to read.
	ErrReservedThunkBits = errors.New("pe: import lookup entry sets reserved bits")
	ErrImportLimit       = errors.New("pe: import directory exceeds a limit")
)

type Import struct {
	ByOrdinal bool
	Ordinal   uint16
	Hint      uint16
	Name      string
	NameErr   error
	SlotRVA   uint32
}

func (i Import) SlotAddress(base uint64) uint64 { return base + uint64(i.SlotRVA) }

type ImportDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	NameRVA            uint32
	FirstThunk         uint32

	Library    string
	LibraryErr error

	Imports []Import
}

type ImportTable struct {
	Descriptors []ImportDescriptor
	Problems    []error
}

type thunkFormat struct {
	width        uint64
	ordinalFlag  uint64
	ordinalSpare uint64
	nameSpare    uint64
}

// Bits 15-0 hold the ordinal, so the bits that must be zero in an ordinal
// entry start at 16.
var (
	thunks32 = thunkFormat{width: 4, ordinalFlag: 1 << 31, ordinalSpare: 0x7FFF0000, nameSpare: 0}
	thunks64 = thunkFormat{width: 8, ordinalFlag: 1 << 63, ordinalSpare: 0x7FFFFFFFFFFF0000, nameSpare: 0x7FFFFFFF80000000}
)

// A part that does not read or breaks a rule ends that part only and is
// listed in Problems; the error return is kept for a directory with no
// first descriptor to read. The walk ends at the all-zero descriptor or at
// the directory's Size: past Size, a directory whose terminator was lost
// would be read on into unrelated bytes. MaxTableEntries bounds descriptors
// and lookup entries together.
func ParseImports(read ReadRVA, pe32Plus bool, dir DataDirectory, l limits.Limits) (*ImportTable, error) {
	if dir.VirtualAddress == 0 {
		return nil, ErrNoImportDirectory
	}
	if dir.Size < ImportDescriptorSize {
		return nil, fmt.Errorf("%w: Size %d holds no descriptor", ErrNoImportDirectory, dir.Size)
	}
	descriptors := uint64(dir.Size) / ImportDescriptorSize
	l = l.Effective()
	format := thunks32
	if pe32Plus {
		format = thunks64
	}
	table := &ImportTable{}
	pages := pageReader{read: read}
	budget := l.MaxTableEntries
	for i := uint64(0); ; i++ {
		at := uint64(dir.VirtualAddress) + i*ImportDescriptorSize
		if i == descriptors {
			table.Problems = append(table.Problems, fmt.Errorf("%w: no all-zero descriptor within Size %d", ErrImportLimit, dir.Size))
			break
		}
		if budget == 0 {
			table.Problems = append(table.Problems, fmt.Errorf("%w: more than %d descriptors and lookup entries", ErrImportLimit, l.MaxTableEntries))
			break
		}
		budget--
		b, err := pages.bytes(at, ImportDescriptorSize)
		if err != nil {
			if i == 0 {
				return nil, fmt.Errorf("pe: import descriptor at rva 0x%x: %w", at, err)
			}
			table.Problems = append(table.Problems, fmt.Errorf("pe: import descriptor %d at rva 0x%x: %w", i, at, err))
			break
		}
		d := ImportDescriptor{
			OriginalFirstThunk: binary.LittleEndian.Uint32(b[offImportLookupTable:]),
			TimeDateStamp:      binary.LittleEndian.Uint32(b[offImportTimeDate:]),
			ForwarderChain:     binary.LittleEndian.Uint32(b[offImportForwarder:]),
			NameRVA:            binary.LittleEndian.Uint32(b[offImportName:]),
			FirstThunk:         binary.LittleEndian.Uint32(b[offImportAddressTable:]),
		}
		if allZero(b) {
			break
		}
		d.Library, d.LibraryErr = readString(read, uint64(d.NameRVA), l.MaxNameBytes)
		if d.LibraryErr != nil {
			d.LibraryErr = fmt.Errorf("pe: import descriptor %d library name at rva 0x%x: %w", i, d.NameRVA, d.LibraryErr)
		}
		problem := d.readThunks(read, format, l, &budget)
		if problem != nil {
			table.Problems = append(table.Problems, fmt.Errorf("pe: import descriptor %d (%q): %w", i, d.Library, problem))
		}
		table.Descriptors = append(table.Descriptors, d)
		if errors.Is(problem, ErrImportLimit) {
			break
		}
	}
	return table, nil
}

// The lookup table is read when present: until the image is bound it
// matches the address table, which the loader has since overwritten.
func (d *ImportDescriptor) readThunks(read ReadRVA, f thunkFormat, l limits.Limits, budget *int) error {
	lookup := d.OriginalFirstThunk
	if lookup == 0 {
		lookup = d.FirstThunk
	}
	if lookup == 0 {
		return nil
	}
	pages := pageReader{read: read}
	for i := uint64(0); ; i++ {
		at := uint64(lookup) + i*f.width
		b, err := pages.bytes(at, f.width)
		if err != nil {
			return fmt.Errorf("lookup entry %d at rva 0x%x: %w", i, at, err)
		}
		v := uint64(binary.LittleEndian.Uint32(b))
		if f.width == 8 {
			v = binary.LittleEndian.Uint64(b)
		}
		if v == 0 {
			return nil
		}
		if *budget == 0 {
			return fmt.Errorf("%w: more than %d descriptors and lookup entries", ErrImportLimit, l.MaxTableEntries)
		}
		*budget--
		imp := Import{SlotRVA: uint32(uint64(d.FirstThunk) + i*f.width)}
		switch {
		case v&f.ordinalFlag != 0 && v&f.ordinalSpare != 0, v&f.ordinalFlag == 0 && v&f.nameSpare != 0:
			return fmt.Errorf("%w: entry %d at rva 0x%x is 0x%x", ErrReservedThunkBits, i, at, v)
		case v&f.ordinalFlag != 0:
			imp.ByOrdinal, imp.Ordinal = true, uint16(v)
		default:
			imp.Hint, imp.Name, imp.NameErr = readHintName(read, uint32(v), l.MaxNameBytes)
		}
		d.Imports = append(d.Imports, imp)
	}
}

func readHintName(read ReadRVA, rva uint32, limit int64) (uint16, string, error) {
	h, err := readAt(read, uint64(rva), hintBytes)
	if err != nil {
		return 0, "", fmt.Errorf("pe: hint/name entry at rva 0x%x: %w", rva, err)
	}
	name, err := readString(read, uint64(rva)+hintBytes, limit)
	if err != nil {
		return binary.LittleEndian.Uint16(h), "", fmt.Errorf("pe: hint/name entry at rva 0x%x: %w", rva, err)
	}
	return binary.LittleEndian.Uint16(h), name, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// Array entries are read a page at a time; an entry that crosses a page
// boundary, or a page that does not read whole, falls back to its own read.
type pageReader struct {
	read  ReadRVA
	start uint64
	buf   []byte
}

func (p *pageReader) bytes(rva, n uint64) ([]byte, error) {
	if rva >= p.start && rva+n <= p.start+uint64(len(p.buf)) {
		return p.buf[rva-p.start : rva-p.start+n], nil
	}
	end := (rva + n + pageSize - 1) &^ (pageSize - 1)
	b, err := readAt(p.read, rva, end-rva)
	if err != nil {
		b, err = readAt(p.read, rva, n)
		if err != nil {
			return nil, err
		}
	}
	p.start, p.buf = rva, b
	return b[:n], nil
}
