package testsupport

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/memory"
)

// Four-level x64 paging (S79 D7): 4 KB pages, 512 eight-byte entries per
// table, the frame in bits 51:12 of an entry.
const (
	pageSize       = uint64(0x1000)
	ptePresent     = uint64(1)
	pteAddrMask    = uint64(0x000ffffffffff000)
	tableEntries   = uint64(512)
	pageTableLevel = 4

	PTEDirty = uint64(1) << 6
)

type PagedMemory struct {
	buf      []byte
	nextFree uint64
}

// Frame 0 is never handed out, so a zero pointer or entry in a fixture never
// names a page the fixture wrote.
func NewPagedMemory(sizeBytes int) *PagedMemory {
	size := max(uint64(max(sizeBytes, 0)), 4*pageSize)
	return &PagedMemory{buf: make([]byte, size), nextFree: pageSize}
}

func (p *PagedMemory) Size() uint64 { return uint64(len(p.buf)) }

func (p *PagedMemory) ReadAt(offset uint64, size uint64) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil
	}
	if !p.holds(offset, size) {
		return nil, memory.ErrOutOfBounds
	}
	return append([]byte(nil), p.buf[offset:offset+size]...), nil
}

func (p *PagedMemory) holds(offset, size uint64) bool {
	return offset <= p.Size() && size <= p.Size()-offset
}

func (p *PagedMemory) span(offset, size uint64) []byte {
	if !p.holds(offset, size) {
		panic("testsupport: physical write out of range")
	}
	return p.buf[offset : offset+size]
}

func (p *PagedMemory) WriteAt(offset uint64, data []byte) {
	copy(p.span(offset, uint64(len(data))), data)
}

func (p *PagedMemory) WriteU64(offset uint64, v uint64) {
	binary.LittleEndian.PutUint64(p.span(offset, 8), v)
}

func (p *PagedMemory) WriteU32(offset uint64, v uint32) {
	binary.LittleEndian.PutUint32(p.span(offset, 4), v)
}

func (p *PagedMemory) WriteU16(offset uint64, v uint16) {
	binary.LittleEndian.PutUint16(p.span(offset, 2), v)
}

func (p *PagedMemory) readU64(offset uint64) uint64 {
	return binary.LittleEndian.Uint64(p.span(offset, 8))
}

func (p *PagedMemory) AllocPage() uint64 {
	frame := p.nextFree
	if !p.holds(frame, pageSize) {
		panic("testsupport: no free physical page; give NewPagedMemory more space")
	}
	p.nextFree += pageSize
	return frame
}

type AddressSpace struct {
	pm  *PagedMemory
	DTB uint64
}

func (p *PagedMemory) NewAddressSpace() *AddressSpace {
	return &AddressSpace{pm: p, DTB: p.AllocPage()}
}

func tableIndex(va uint64, level int) uint64 {
	return va >> (12 + 9*uint(level)) & (tableEntries - 1)
}

// The tables above a page carry only the present bit, so the flags a test
// gives the page are the only ones a reader sees.
func (as *AddressSpace) leafEntry(va uint64) uint64 {
	table := as.DTB & pteAddrMask
	for level := pageTableLevel - 1; level > 0; level-- {
		at := table + tableIndex(va, level)*8
		entry := as.pm.readU64(at)
		if entry&ptePresent == 0 {
			entry = as.pm.AllocPage() | ptePresent
			as.pm.WriteU64(at, entry)
		}
		table = entry & pteAddrMask
	}
	return table + tableIndex(va, 0)*8
}

func (as *AddressSpace) MapFlags(va uint64, pa uint64, extraFlags uint64) {
	as.pm.WriteU64(as.leafEntry(va), pa&pteAddrMask|ptePresent|extraFlags)
}

func (as *AddressSpace) Map(va uint64, pa uint64) { as.MapFlags(va, pa, 0) }

// For a not-present entry, such as a Windows prototype entry, whose bits a
// test sets whole.
func (as *AddressSpace) SetEntry(va, entry uint64) { as.pm.WriteU64(as.leafEntry(va), entry) }

// Each call takes a fresh zeroed frame; mapping a page twice drops what was
// written through the first mapping.
func (as *AddressSpace) MapPageFlags(va uint64, extraFlags uint64) uint64 {
	pa := as.pm.AllocPage()
	as.MapFlags(va, pa, extraFlags)
	return pa
}

func (as *AddressSpace) MapPage(va uint64) uint64 { return as.MapPageFlags(va, 0) }

func (as *AddressSpace) MapData(va uint64, data []byte) uint64 {
	if uint64(len(data)) > pageSize {
		panic("testsupport: MapData takes at most one page")
	}
	pa := as.MapPage(va)
	as.pm.WriteAt(pa, data)
	return pa
}

func (as *AddressSpace) MapImage(va uint64, data []byte) int {
	pages := 0
	for at := uint64(0); at < uint64(len(data)); at += pageSize {
		as.MapData(va+at, data[at:min(at+pageSize, uint64(len(data)))])
		pages++
	}
	return pages
}
