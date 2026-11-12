package layers

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/aoiflux/libvapour/memory"
)

type MappedRun struct {
	Virtual  uint64
	Physical uint64
	Size     uint64
}

type MappingStats struct {
	Tables           int
	UnreadableTables int
	RepeatedTables   int
	UncapturedPages  int
}

type heldRanges []memory.Range

func (h heldRanges) holds(pa, size uint64) bool {
	i := sort.Search(len(h), func(i int) bool { return h[i].End > pa })
	return i < len(h) && h[i].Start <= pa && size <= h[i].End-pa
}

func (h heldRanges) touches(pa, size uint64) bool {
	i := sort.Search(len(h), func(i int) bool { return h[i].End > pa })
	return i < len(h) && (h[i].Start <= pa || h[i].Start-pa < size)
}

func oneValue(raw []byte, width uint64) bool {
	return uint64(len(raw)) > width && bytes.Equal(raw[width:], raw[:uint64(len(raw))-width])
}

func readTable(r memory.MemoryReader, at, size uint64) ([]byte, bool) {
	raw, err := r.ReadAt(at, size)
	return raw, err == nil && uint64(len(raw)) == size
}

type tableState uint8

const (
	tableUnread tableState = iota + 1
	tableEmpty
	tableOneValue
)

// Runs come in virtual-address order, each as long as both spaces stay
// contiguous, and only where the image holds every byte. A table that is one
// value repeated is left out with all it maps: Windows fills thousands of
// tables with one entry for one frame (S53 M6), and listing them would list
// that frame millions of times.
func (t *IntelTranslator) Mapping(fn func(MappedRun) error) (MappingStats, error) {
	m := t.Mode.effective()
	if t.Physical == nil {
		return MappingStats{}, fmt.Errorf("layers: address-space listing: no physical layer")
	}
	l := &lister{mode: m, physical: t.Physical, held: memory.MappedRanges(t.Physical), emit: fn,
		states: map[uint64]tableState{}}
	if bits := m.addressBits(); bits > 32 && bits < 64 {
		l.upperStart = uint64(1) << (bits - 1)
	}
	root := m.root(t.CR3)
	raw, ok := readTable(t.Physical, root, m.tableSize(0))
	if !ok {
		return l.stats, fmt.Errorf("layers: page-table root at 0x%x: %w", root, ErrPageNotCaptured)
	}
	if oneValue(raw, m.entryBytes) {
		return l.stats, fmt.Errorf("layers: page-table root at 0x%x: every entry is one value", root)
	}
	l.stats.Tables++
	if err := l.table(0, raw, 0); err != nil {
		return l.stats, err
	}
	return l.stats, l.flush()
}

type lister struct {
	mode       PagingMode
	physical   memory.MemoryReader
	held       heldRanges
	emit       func(MappedRun) error
	states     map[uint64]tableState
	upperStart uint64
	pending    MappedRun
	stats      MappingStats
}

func (l *lister) table(level int, raw []byte, va uint64) error {
	m := l.mode
	shift := m.shift(level)
	for i := range uint64(len(raw)) / m.entryBytes {
		at := va | i<<shift
		s := m.step(level, m.entryAt(raw, i))
		var err error
		switch s.kind {
		case stepPage:
			err = l.page(at, s.addr, s.size)
		case stepTable:
			err = l.child(level+1, s.addr, at)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (l *lister) child(level int, at, va uint64) error {
	if _, bad := l.states[at]; bad {
		return nil
	}
	size := l.mode.tableSize(level)
	raw, ok := readTable(l.physical, at, size)
	switch {
	case !ok:
		l.states[at] = tableUnread
		l.stats.UnreadableTables++
		return nil
	case !oneValue(raw, l.mode.entryBytes):
		l.stats.Tables++
		return l.table(level, raw, va)
	case l.mode.entryAt(raw, 0) == 0:
		l.states[at] = tableEmpty
	default:
		l.states[at] = tableOneValue
		l.stats.RepeatedTables++
	}
	return nil
}

func (l *lister) page(va, pa, size uint64) error {
	if !l.held.holds(pa, size) {
		l.stats.UncapturedPages++
		return nil
	}
	p := &l.pending
	if p.Size > 0 && p.Virtual+p.Size == va && p.Physical+p.Size == pa && va != l.upperStart {
		p.Size += size
		return nil
	}
	if err := l.flush(); err != nil {
		return err
	}
	l.pending = MappedRun{Virtual: va, Physical: pa, Size: size}
	return nil
}

func (l *lister) flush() error {
	if l.pending.Size == 0 {
		return nil
	}
	r := l.pending
	l.pending = MappedRun{}
	r.Virtual = l.mode.canonical(r.Virtual)
	return l.emit(r)
}
