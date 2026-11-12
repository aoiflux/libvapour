package layers

import (
	"encoding/binary"
	"errors"

	"github.com/aoiflux/libvapour/memory"
)

const (
	fP   = uint64(1) << 0
	fRW  = uint64(1) << 1
	fD   = uint64(1) << 6
	fPS  = uint64(1) << 7
	fNX  = uint64(1) << 63
	fPro = uint64(1) << 10
	fTr  = uint64(1) << 11
)

type physImage struct {
	buf       []byte
	holes     map[uint64]bool
	segments  []memory.Segment
	reads     int
	immutable bool
}

func newPhys(size uint64) *physImage {
	return &physImage{buf: make([]byte, size), holes: map[uint64]bool{}}
}

func (p *physImage) ReadAt(off, size uint64) ([]byte, error) {
	p.reads++
	if off > uint64(len(p.buf)) || size > uint64(len(p.buf))-off {
		return nil, memory.ErrOutOfBounds
	}
	for page := off &^ 0xfff; page < off+size; page += 0x1000 {
		if p.holes[page] {
			return nil, errors.New("hole")
		}
	}
	return p.buf[off : off+size], nil
}

func (p *physImage) Size() uint64 { return uint64(len(p.buf)) }

func (p *physImage) Segments() []memory.Segment {
	if p.segments == nil {
		return []memory.Segment{{PhysicalBase: 0, Length: uint64(len(p.buf))}}
	}
	return append([]memory.Segment(nil), p.segments...)
}

func (p *physImage) ImmutableSnapshot() bool { return p.immutable }

func (p *physImage) put8(at, v uint64) { binary.LittleEndian.PutUint64(p.buf[at:], v) }

func (p *physImage) put4(at uint64, v uint32) { binary.LittleEndian.PutUint32(p.buf[at:], v) }

func (p *physImage) fill(at uint64, b byte) {
	for i := range uint64(0x1000) {
		p.buf[at+i] = b
	}
}

// pageTables builds 4-level or 5-level tables, allocating tables upwards from
// next.
type pageTables struct {
	img    *physImage
	mode   PagingMode
	root   uint64
	next   uint64
	tables map[[2]uint64]uint64
}

func newTables(img *physImage, mode PagingMode, root, next uint64) *pageTables {
	return &pageTables{img: img, mode: mode, root: root, next: next, tables: map[[2]uint64]uint64{}}
}

func (t *pageTables) table(level int, va uint64) uint64 {
	if level == 0 {
		return t.root
	}
	key := [2]uint64{uint64(level), va >> t.mode.shift(level-1)}
	if at, ok := t.tables[key]; ok {
		return at
	}
	parent := t.table(level-1, va)
	at := t.next
	t.next += 0x1000
	t.tables[key] = at
	t.img.put8(parent+8*t.mode.index(va, level-1), at|fP|fRW)
	return at
}

func (t *pageTables) set(level int, va, entry uint64) {
	t.img.put8(t.table(level, va)+8*t.mode.index(va, level), entry)
}

func (t *pageTables) page(va, pa uint64) { t.set(t.mode.leaf(), va, pa|fP|fRW) }

func (t *pageTables) translator() *IntelTranslator {
	return &IntelTranslator{Physical: t.img, CR3: t.root, Mode: t.mode}
}

func missOf(err error) (UnmappedPageError, bool) {
	var miss UnmappedPageError
	ok := errors.As(err, &miss)
	return miss, ok
}
