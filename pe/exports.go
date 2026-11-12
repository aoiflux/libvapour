package pe

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
)

const (
	DirectoryEntryExport = 0
	ExportDirectorySize  = uint64(40)
)

const (
	offExportOrdinalBase    = 16
	offExportAddressEntries = 20
	offExportNamePointers   = 24
	offExportAddressTable   = 28
	offExportNamePointerRVA = 32
	offExportOrdinalTable   = 36
)

var (
	ErrNoExportDirectory   = errors.New("pe: no export directory")
	ErrExportCountTooLarge = errors.New("pe: export directory exceeds a limit")
)

type Export struct {
	Name           string
	NameUnreadable bool
	Ordinal        uint32
	RVA            uint32
	// Set when RVA lies inside the export directory: it names a string, not code.
	Forwarder           string
	ForwarderUnreadable bool
}

func (e Export) Address(base uint64) uint64 { return base + uint64(e.RVA) }

func (e Export) forwarded() bool { return e.Forwarder != "" || e.ForwarderUnreadable }

// A forwarder has no code in this image, so it gives no address.
func LookupExport(exports []Export, name string, base uint64) (uint64, bool) {
	for _, e := range exports {
		if e.Name == name && !e.NameUnreadable && !e.forwarded() {
			return e.Address(base), true
		}
	}
	return 0, false
}

type exportDirectory struct {
	ordinalBase         uint32
	addressEntries      uint32
	namePointers        uint32
	addressTable        uint32
	namePointerTable    uint32
	ordinalTable        uint32
	start, end          uint64
	nameLimit           int64
	addresses, nameRVAs []byte
	nameOrdinals        []byte
}

// One record per address-table slot in ordinal order, and one per name for
// a slot that has several. A slot with RVA 0 and no name exports nothing and
// is left out. The three arrays are the directory's skeleton: if one does
// not read, the result would hide which exports are missing, so the parse
// fails instead.
func ParseExports(read ReadRVA, dir DataDirectory, l limits.Limits) ([]Export, error) {
	if dir.VirtualAddress == 0 {
		return nil, ErrNoExportDirectory
	}
	l = l.Effective()
	d, err := readExportDirectory(read, dir, l)
	if err != nil {
		return nil, err
	}

	names := make([][]int, d.addressEntries)
	for i := range d.namePointers {
		slot := binary.LittleEndian.Uint16(d.nameOrdinals[2*i:])
		if uint32(slot) < d.addressEntries {
			names[slot] = append(names[slot], int(i))
		}
	}

	var out []Export
	for slot := range d.addressEntries {
		e := Export{Ordinal: d.ordinalBase + slot, RVA: binary.LittleEndian.Uint32(d.addresses[4*slot:])}
		if e.RVA == 0 && len(names[slot]) == 0 {
			continue
		}
		if rva := uint64(e.RVA); rva >= d.start && rva < d.end {
			limit := min(d.nameLimit, int64(d.end-rva)-1)
			fwd, err := readString(read, rva, limit)
			e.Forwarder, e.ForwarderUnreadable = fwd, err != nil || fwd == ""
		}
		if len(names[slot]) == 0 {
			out = append(out, e)
			continue
		}
		for _, i := range names[slot] {
			named := e
			name, err := readString(read, uint64(binary.LittleEndian.Uint32(d.nameRVAs[4*i:])), d.nameLimit)
			named.Name, named.NameUnreadable = name, err != nil
			out = append(out, named)
		}
	}
	return out, nil
}

func readExportDirectory(read ReadRVA, dir DataDirectory, l limits.Limits) (*exportDirectory, error) {
	b, err := readAt(read, uint64(dir.VirtualAddress), ExportDirectorySize)
	if err != nil {
		return nil, err
	}
	d := &exportDirectory{
		ordinalBase:      binary.LittleEndian.Uint32(b[offExportOrdinalBase:]),
		addressEntries:   binary.LittleEndian.Uint32(b[offExportAddressEntries:]),
		namePointers:     binary.LittleEndian.Uint32(b[offExportNamePointers:]),
		addressTable:     binary.LittleEndian.Uint32(b[offExportAddressTable:]),
		namePointerTable: binary.LittleEndian.Uint32(b[offExportNamePointerRVA:]),
		ordinalTable:     binary.LittleEndian.Uint32(b[offExportOrdinalTable:]),
		start:            uint64(dir.VirtualAddress),
		end:              uint64(dir.VirtualAddress) + uint64(dir.Size),
		nameLimit:        l.MaxNameBytes,
	}
	maxEntries := uint64(l.MaxTableEntries)
	if uint64(d.addressEntries) > maxEntries || uint64(d.namePointers) > maxEntries {
		return nil, fmt.Errorf("%w: %d addresses, %d names, limit %d", ErrExportCountTooLarge, d.addressEntries, d.namePointers, maxEntries)
	}
	if d.addressEntries > 0 && uint64(d.ordinalBase)+uint64(d.addressEntries)-1 > 0xFFFFFFFF {
		return nil, fmt.Errorf("%w: ordinal base %d with %d addresses passes 32 bits", ErrExportCountTooLarge, d.ordinalBase, d.addressEntries)
	}
	if d.addresses, err = readTable(read, "address", d.addressTable, uint64(d.addressEntries)*4, l); err != nil {
		return nil, err
	}
	if d.nameRVAs, err = readTable(read, "name pointer", d.namePointerTable, uint64(d.namePointers)*4, l); err != nil {
		return nil, err
	}
	if d.nameOrdinals, err = readTable(read, "ordinal", d.ordinalTable, uint64(d.namePointers)*2, l); err != nil {
		return nil, err
	}
	return d, nil
}

func readTable(read ReadRVA, which string, rva uint32, size uint64, l limits.Limits) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	if int64(size) > l.MaxBufferBytes {
		return nil, fmt.Errorf("%w: export %s table is %d bytes, limit %d", ErrExportCountTooLarge, which, size, l.MaxBufferBytes)
	}
	b, err := readAt(read, uint64(rva), size)
	if err != nil {
		return nil, fmt.Errorf("pe: export %s table at rva 0x%x: %w", which, rva, err)
	}
	return b, nil
}
