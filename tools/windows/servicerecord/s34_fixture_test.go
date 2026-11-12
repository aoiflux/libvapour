package servicerecord

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/memory"
)

type sparse struct{ pages map[uint64][]byte }

func newSparse() *sparse { return &sparse{pages: map[uint64][]byte{}} }

func (s *sparse) ReadAt(at, n uint64) ([]byte, error) {
	out := make([]byte, 0, n)
	for n > 0 {
		p, ok := s.pages[at&^(pageSize-1)]
		if !ok {
			return nil, memory.ErrOutOfBounds
		}
		off := at % pageSize
		take := min(n, pageSize-off)
		out = append(out, p[off:off+take]...)
		at, n = at+take, n-take
	}
	return out, nil
}

func (s *sparse) Size() uint64 { return ^uint64(0) }

func (s *sparse) put(at uint64, b []byte) {
	for len(b) > 0 {
		base := at &^ (pageSize - 1)
		p, ok := s.pages[base]
		if !ok {
			p = make([]byte, pageSize)
			s.pages[base] = p
		}
		n := copy(p[at-base:], b)
		at, b = at+uint64(n), b[n:]
	}
}

func (s *sparse) u32(at uint64, v uint32) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	s.put(at, b)
}

func (s *sparse) u64(at, v uint64) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	s.put(at, b)
}

func (s *sparse) text(at uint64, v string) {
	units := append(utf16.Encode([]rune(v)), 0)
	b := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}
	s.put(at, b)
}

func (s *sparse) drop(page uint64) { delete(s.pages, page&^(pageSize-1)) }

const (
	fixtureImageStart = 0x7ff700000000
	fixtureImageEnd   = 0x7ff700100000
	fixtureVTable     = fixtureImageStart + 0x9000
	fixtureHeap       = 0x2000000000
	fixtureStrings    = 0x3000000000
	fixtureImages     = 0x3800000000
)

var fixtureImage = addressRange{start: fixtureImageStart, end: fixtureImageEnd}

func layoutNamed(name string) layout {
	for _, l := range layouts {
		if l.name == name {
			return l
		}
	}
	panic("no layout " + name)
}

type fixtureRecord struct {
	at              uint64
	previous, next  uint64
	name, display   string
	sequence        uint32
	serviceType     uint32
	state           uint32
	startType       uint32
	errorControl    uint32
	processOrDriver uint64
}

type world struct {
	mem     *sparse
	layout  layout
	strings uint64
	images  uint64
}

func newWorld(l layout) *world {
	return &world{mem: newSparse(), layout: l, strings: fixtureStrings, images: fixtureImages}
}

func (w *world) str(v string) uint64 {
	at := w.strings
	w.mem.text(at, v)
	w.strings += uint64(2*len(utf16.Encode([]rune(v)))+2+15) &^ 15
	return at
}

func (w *world) record(r fixtureRecord) {
	l := w.layout
	w.mem.put(r.at, make([]byte, l.span()))
	if l.imagePointer {
		w.mem.u64(r.at, fixtureVTable)
	}
	w.mem.u32(r.at+l.tagAt, l.tag)
	w.mem.u64(r.at+l.previous, r.previous)
	w.mem.u64(r.at+l.next, r.next)
	if r.name != "" {
		w.mem.u64(r.at+l.serviceName, w.str(r.name))
	}
	if r.display != "" {
		w.mem.u64(r.at+l.displayName, w.str(r.display))
	}
	w.mem.u32(r.at+l.sequence, r.sequence)
	w.mem.u32(r.at+l.status, r.serviceType)
	w.mem.u32(r.at+l.status+4, r.state)
	w.mem.u32(r.at+l.startType, r.startType)
	w.mem.u32(r.at+l.errorControl, r.errorControl)
	w.mem.u64(r.at+l.processOrDriver, r.processOrDriver)
}

func (w *world) imageRecord(pid uint32, commandLine string) uint64 {
	at := w.images
	w.images += 0x100
	w.mem.put(at, make([]byte, 0x40))
	w.mem.u32(at, tagImage)
	w.mem.u64(at+imageCommandLine, w.str(commandLine))
	w.mem.u32(at+w.layout.imageProcessID, pid)
	return at
}

func running(at uint64, name string, seq uint32) fixtureRecord {
	return fixtureRecord{at: at, name: name, display: name + " display", sequence: seq,
		serviceType: 0x20, state: 4, startType: 2, errorControl: 1}
}

func driver(at uint64, name string, seq uint32) fixtureRecord {
	return fixtureRecord{at: at, name: name, sequence: seq, serviceType: 0x1, state: 1, startType: 3, errorControl: 1}
}

// A list of n records 0x200 apart from fixtureHeap, linked under the
// layout's head form; the head is returned.
func (w *world) list(names ...string) head {
	l := w.layout
	h := head{form: l.head}
	h.address = fixtureImageStart + 0x20000
	w.mem.put(h.address, make([]byte, 0x100))
	w.mem.u32(h.address, l.headTag())
	addr := func(i int) uint64 { return fixtureHeap + uint64(i)*0x200 }
	for i, n := range names {
		r := running(addr(i), n, uint32(i+1))
		if i > 0 {
			r.previous = addr(i - 1)
		} else if l.head == headSentinel {
			r.previous = h.address
		}
		if i+1 < len(names) {
			r.next = addr(i + 1)
		}
		w.record(r)
	}
	if l.head == headDatabase {
		w.mem.u64(h.address+databaseFirst, addr(0))
		w.mem.u64(h.address+databaseLast, addr(len(names)-1))
		w.mem.u32(h.address+databaseCounter, uint32(len(names)))
		w.mem.u32(h.address+databaseCount, uint32(len(names)))
	} else {
		w.mem.u64(h.address+l.next, addr(0))
	}
	return h
}
