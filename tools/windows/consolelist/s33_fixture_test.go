package consolelist

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/memory"
)

// Page-granular memory: a read touching a page never written fails, as a
// page that is not present does.
type sparse struct{ pages map[uint64][]byte }

func newSparse() *sparse { return &sparse{pages: map[uint64][]byte{}} }

func (m *sparse) ReadAt(at, n uint64) ([]byte, error) {
	out := make([]byte, 0, n)
	for n > 0 {
		page := at &^ (pageBytes - 1)
		p, ok := m.pages[page]
		if !ok {
			return nil, fmt.Errorf("sparse: 0x%x: %w", at, memory.ErrOutOfBounds)
		}
		off := at - page
		take := min(n, pageBytes-off)
		out = append(out, p[off:off+take]...)
		at, n = at+take, n-take
	}
	return out, nil
}

func (m *sparse) Size() uint64 { return 1 << 48 }

func (m *sparse) write(at uint64, b []byte) {
	for len(b) > 0 {
		page := at &^ (pageBytes - 1)
		p, ok := m.pages[page]
		if !ok {
			p = make([]byte, pageBytes)
			m.pages[page] = p
		}
		n := copy(p[at-page:], b)
		at, b = at+uint64(n), b[n:]
	}
}

func (m *sparse) u16(at uint64, v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	m.write(at, b[:])
}

func (m *sparse) u32(at uint64, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	m.write(at, b[:])
}

func (m *sparse) u64(at uint64, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	m.write(at, b[:])
}

func (m *sparse) put(at uint64, p prim, v int64) {
	switch p.size {
	case 2:
		m.u16(at, uint16(v))
	case 4:
		m.u32(at, uint32(v))
	default:
		m.u64(at, uint64(v))
	}
}

const (
	fixtureHeap      = uint64(0x20000000)
	fixtureHeapBytes = uint64(0x200000)
	fixtureImage     = uint64(0x7ff600000000)
	fixtureImageSize = uint64(0x10000)
	fixtureConsole   = fixtureImage + 0x2e68
)

type fixture struct {
	l    *Layout
	m    *sparse
	next uint64
}

func newFixture(l *Layout) *fixture {
	f := &fixture{l: l, m: newSparse(), next: fixtureHeap}
	f.m.write(fixtureImage, make([]byte, fixtureImageSize))
	return f
}

func (f *fixture) space() Space {
	return NewSpace(f.m, []Region{
		{Start: fixtureHeap, End: fixtureHeap + fixtureHeapBytes},
		{Start: fixtureImage, End: fixtureImage + fixtureImageSize},
	})
}

func (f *fixture) alloc(n uint64) uint64 {
	at := f.next
	f.next += (n + 15) &^ 15
	f.m.write(at, make([]byte, n))
	return at
}

func (f *fixture) wide(at uint64, text string) {
	units := utf16.Encode([]rune(text))
	b := make([]byte, 0, 2*len(units)+2)
	for _, u := range units {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	b = append(b, 0, 0)
	n := uint64(len(units))
	capacity := max(n, f.l.inlineChars())
	where := uint64(int64(at) + f.l.text.chars)
	if capacity > f.l.inlineChars() {
		where = f.alloc((capacity + 1) * wideBytes)
		f.m.u64(uint64(int64(at)+f.l.text.pointer), where)
	}
	f.m.write(where, b)
	f.m.put(uint64(int64(at)+f.l.text.length.off), f.l.text.length, int64(n))
	f.m.put(uint64(int64(at)+f.l.text.capacity.off), f.l.text.capacity, int64(capacity))
}

// A ring of n nodes of nodeBytes each through a fresh head, with its head
// pointer and size written at headAt and sizeAt.
func (f *fixture) ring(headAt, sizeAt uint64, n int, nodeBytes uint64) []uint64 {
	head := f.alloc(nodeBytes)
	nodes := make([]uint64, n)
	for i := range nodes {
		nodes[i] = f.alloc(nodeBytes)
	}
	all := append([]uint64{head}, nodes...)
	for i, node := range all {
		f.m.u64(uint64(int64(node)+f.l.node.next), all[(i+1)%len(all)])
		f.m.u64(uint64(int64(node)+f.l.node.next+pointerBytes), all[(i+len(all)-1)%len(all)])
	}
	f.m.u64(headAt, head)
	f.m.u64(sizeAt, uint64(n))
	return nodes
}

func (f *fixture) record(pid uint32) uint64 {
	r := f.alloc(64)
	f.m.put(uint64(int64(r)+f.l.process.pid.off), f.l.process.pid, int64(pid))
	return r
}

type historySpec struct {
	app      string
	commands []string
	size     int64
	recall   int64
	owner    uint64
}

func (f *fixture) fillHistory(node uint64, h historySpec) {
	l := f.l
	if h.size == 0 {
		h.size = DefaultHistoryBufferSize
	}
	f.m.put(uint64(int64(node)+l.history.capacity.off), l.history.capacity, h.size)
	f.wide(uint64(int64(node)+l.history.application), h.app)
	f.m.u64(uint64(int64(node)+l.history.process), h.owner)
	f.m.put(uint64(int64(node)+l.history.lastDisplayed.off), l.history.lastDisplayed, h.recall)
	vec := uint64(int64(node) + l.history.commands)
	if len(h.commands) == 0 {
		return
	}
	begin := f.alloc(uint64(len(h.commands)) * l.text.size)
	for i, c := range h.commands {
		f.wide(begin+uint64(i)*l.text.size, c)
	}
	end := begin + uint64(len(h.commands))*l.text.size
	f.m.u64(uint64(int64(vec)+l.vector.begin), begin)
	f.m.u64(uint64(int64(vec)+l.vector.end), end)
	f.m.u64(uint64(int64(vec)+l.vector.capacityEnd), end)
}

// A history alone on a ring of its own, as the search finds one.
func (f *fixture) loneHistory(h historySpec) uint64 {
	holder := f.alloc(16)
	nodes := f.ring(holder, holder+8, 1, uint64(f.l.history.size))
	f.fillHistory(nodes[0], h)
	return nodes[0]
}

type aliasSpec struct {
	exe            string
	source, target []string
}

type screenSpec struct {
	rows  []string
	width int
	first int
}

type consoleSpec struct {
	title, original string
	cols, rows      int
	historySize     uint32
	buffers         uint32
	pids            []uint32
	histories       []historySpec
	historyOwner    []int
	aliases         []aliasSpec
	screens         []screenSpec
	active          int
}

func defaultConsole() consoleSpec {
	return consoleSpec{
		title: "Command Prompt", original: `C:\Windows\system32\cmd.exe`,
		cols: 120, rows: 9001, historySize: 50, buffers: 4,
		pids:         []uint32{4242},
		histories:    []historySpec{{app: "cmd.exe", commands: []string{"whoami", "net user /domain"}, recall: 1}},
		historyOwner: []int{0},
		aliases:      []aliasSpec{{exe: "cmd.exe", source: []string{"ll"}, target: []string{"dir /a $*"}}},
		screens:      []screenSpec{{rows: []string{"Microsoft Windows", "", `C:\>whoami`}, width: 120}},
	}
}

func (f *fixture) console(at uint64, spec consoleSpec) {
	l, c := f.l, f.l.console
	m := func(off int64) uint64 { return uint64(int64(at) + off) }
	f.m.put(m(c.screenWidth.off), c.screenWidth, int64(spec.cols))
	f.m.put(m(c.screenHeight.off), c.screenHeight, int64(spec.rows))
	f.m.put(m(c.historySize.off), c.historySize, int64(spec.historySize))
	f.m.put(m(c.historyMax.off), c.historyMax, int64(spec.buffers))
	f.wide(m(c.title), spec.title)
	f.wide(m(c.originalTitle), spec.original)

	procNodes := f.ring(m(c.processList), m(c.processCount.off), len(spec.pids), l.node.size+pointerBytes)
	records := make([]uint64, len(spec.pids))
	for i, n := range procNodes {
		records[i] = f.record(spec.pids[i])
		f.m.u64(uint64(int64(n)+c.processNode.process), records[i])
	}

	histNodes := f.ring(m(c.historyList), m(c.historyCount.off), len(spec.histories), l.history.size)
	for i, n := range histNodes {
		h := spec.histories[i]
		if i < len(spec.historyOwner) && spec.historyOwner[i] >= 0 {
			h.owner = records[spec.historyOwner[i]]
		}
		f.fillHistory(n, h)
	}

	entryBytes := uint64(c.aliasEntry.aliases) + 2*pointerBytes
	exeNodes := f.ring(m(c.aliases), m(c.aliases+pointerBytes), len(spec.aliases), entryBytes)
	for i, e := range exeNodes {
		a := spec.aliases[i]
		f.wide(uint64(int64(e)+c.aliasEntry.name), a.exe)
		inner := f.ring(uint64(int64(e)+c.aliasEntry.aliases), uint64(int64(e)+c.aliasEntry.aliases+pointerBytes),
			len(a.source), uint64(c.alias.target)+l.text.size)
		for j, n := range inner {
			f.wide(uint64(int64(n)+c.alias.source), a.source[j])
			f.wide(uint64(int64(n)+c.alias.target), a.target[j])
		}
	}

	var prev uint64
	for i, sc := range spec.screens {
		at := f.screen(sc)
		if i == 0 {
			f.m.u64(m(c.screenList), at)
		} else {
			f.m.u64(uint64(int64(prev)+c.screen.next), at)
		}
		if i == spec.active {
			f.m.u64(m(c.activeScreen), at)
		}
		prev = at
	}
}

// Rows are stored from first on, wrapping, so row 0 of the screen is stored
// at index first.
func (f *fixture) screen(sc screenSpec) uint64 {
	c := f.l.console
	scr := f.alloc(uint64(c.screen.next) + pointerBytes)
	tb := f.alloc(uint64(c.textBuffer.firstRow.off) + 8)
	f.m.u64(uint64(int64(scr)+c.screen.textBuffer), tb)
	n := len(sc.rows)
	rowMap := f.alloc(uint64(n) * pointerBytes)
	f.m.u64(uint64(int64(tb)+c.textBuffer.rows), rowMap)
	f.m.put(uint64(int64(tb)+c.textBuffer.rowCount.off), c.textBuffer.rowCount, int64(n))
	f.m.put(uint64(int64(tb)+c.textBuffer.firstRow.off), c.textBuffer.firstRow, int64(sc.first))
	for j, text := range sc.rows {
		row := f.alloc(uint64(c.row.width.off) + 8)
		cells := f.alloc(uint64(sc.width) * cellBytes)
		units := utf16.Encode([]rune(text))
		for k := 0; k < sc.width; k++ {
			u := uint16(' ')
			if k < len(units) {
				u = units[k]
			}
			f.m.u16(cells+uint64(k)*cellBytes, u)
		}
		f.m.u64(uint64(int64(row)+c.row.cells), cells)
		f.m.put(uint64(int64(row)+c.row.width.off), c.row.width, int64(sc.width))
		stored := (sc.first + j) % n
		f.m.u64(rowMap+uint64(stored)*pointerBytes, row)
	}
	return scr
}
