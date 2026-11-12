package layers

import (
	"fmt"
	"sort"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
)

// A frame's page keys are the values of virtual-address bits 15:12 at which
// some leaf maps it. Bits 11:8 are the physical address's own, so the keys
// give every value of bits 15:8, the second byte of the address, that a
// mapping of the frame can have. Object headers are decoded with that byte,
// which a physical scan otherwise does not know.
type FrameMap struct {
	held       heldRanges
	spans      []frameSpan
	keys       []uint16
	paths      map[uint64]uint64
	large      map[largePage]largeReach
	sizes      []uint64
	leafTables []leafTable
	physical   memory.MemoryReader
	mode       PagingMode
	frames     int

	Tables            int
	UnreadableTables  int
	RecursiveEntries  int
	RepeatedTables    int
	PartialLargePages int
}

type frameSpan struct {
	first, count uint64
	at           int
}

type largePage struct{ base, size uint64 }

type largeReach struct{ paths, lowest uint64 }

type leafTable struct{ base, lowest uint64 }

type tableVisit struct{ base, paths, lowest uint64 }

func spansOf(held heldRanges, limit uint64) ([]frameSpan, int, error) {
	var spans []frameSpan
	total := uint64(0)
	for _, r := range held {
		if r.End <= r.Start {
			continue
		}
		first, last := r.Start>>pageShift, (r.End-1)>>pageShift
		if n := len(spans); n > 0 && first <= spans[n-1].first+spans[n-1].count {
			prev := &spans[n-1]
			if end := last + 1; end > prev.first+prev.count {
				total += end - (prev.first + prev.count)
				prev.count = end - prev.first
			}
		} else {
			spans = append(spans, frameSpan{first: first, count: last - first + 1, at: int(total)})
			total += last - first + 1
		}
		if total > limit {
			return nil, 0, fmt.Errorf("layers: frame map: the image holds more than %d frames, the MaxImageBytes limit", limit)
		}
	}
	for i := range spans {
		if i > 0 {
			spans[i].at = spans[i-1].at + int(spans[i-1].count)
		}
	}
	return spans, int(total), nil
}

func (f *FrameMap) slot(frame uint64) (int, bool) {
	i := sort.Search(len(f.spans), func(i int) bool { return f.spans[i].first+f.spans[i].count > frame })
	if i == len(f.spans) || frame < f.spans[i].first {
		return 0, false
	}
	return f.spans[i].at + int(frame-f.spans[i].first), true
}

// The walk follows what IntelTranslator.Translate follows, level by level, so
// it ends after as many levels as the mode has, however entries point. A table
// reached by several entries is walked once per level, carrying how many
// paths reach it and the lowest address prefix among them. Windows points a
// root entry at the root itself (S53 M3); through that self-map each table is
// walked again a level lower, and its entries map the tables as data, which
// is what a scan of the virtual space reads there.
func MapFrames(physical memory.MemoryReader, cr3 uint64, mode PagingMode, l limits.Limits) (*FrameMap, error) {
	if physical == nil {
		return nil, fmt.Errorf("layers: frame map: no physical layer")
	}
	m := mode.effective()
	held := heldRanges(memory.MappedRanges(physical))
	spans, total, err := spansOf(held, uint64(l.Effective().MaxImageBytes)>>pageShift)
	if err != nil {
		return nil, err
	}
	f := &FrameMap{held: held, spans: spans, keys: make([]uint16, total), paths: map[uint64]uint64{},
		large: map[largePage]largeReach{}, physical: physical, mode: m}
	for level, lv := range m.levels {
		if lv.mapsPage {
			f.sizes = append(f.sizes, m.span(level))
		}
	}

	partial := map[largePage]bool{}
	walked := make([]map[uint64]bool, len(m.levels))
	seenAbove := func(base uint64, upTo int) bool {
		for i := 0; i <= upTo; i++ {
			if walked[i][base] {
				return true
			}
		}
		return false
	}
	current := []tableVisit{{base: m.root(cr3), paths: 1}}
	for level := range m.levels {
		walked[level] = make(map[uint64]bool, len(current))
		for _, v := range current {
			walked[level][v.base] = true
		}
		shift := m.shift(level)
		var next []tableVisit
		place := map[uint64]int{}
		for _, v := range current {
			first := level == 0 || !seenAbove(v.base, level-1)
			raw, ok := readTable(physical, v.base, m.tableSize(level))
			if !ok {
				if level == 0 {
					return nil, fmt.Errorf("layers: page-table root at 0x%x: %w", v.base, ErrPageNotCaptured)
				}
				if first {
					f.UnreadableTables++
				}
				continue
			}
			if oneValue(raw, m.entryBytes) {
				if level == 0 {
					return nil, fmt.Errorf("layers: page-table root at 0x%x: every entry is one value", v.base)
				}
				if first && m.entryAt(raw, 0) != 0 {
					f.RepeatedTables++
				}
				continue
			}
			if first {
				f.Tables++
			}
			if level == m.leaf() {
				f.leafTables = append(f.leafTables, leafTable{base: v.base, lowest: v.lowest})
			}
			for i := range uint64(len(raw)) / m.entryBytes {
				s := m.step(level, m.entryAt(raw, i))
				va := v.lowest | i<<shift
				switch {
				case s.kind == stepPage && s.size == pageBytes:
					f.leaf(s.addr, uint16(1)<<(i&0xf), v.paths)
				case s.kind == stepPage:
					p := largePage{s.addr, s.size}
					if !held.holds(p.base, p.size) {
						if held.touches(p.base, p.size) && !partial[p] {
							partial[p] = true
							f.PartialLargePages++
						}
						continue
					}
					r, known := f.large[p]
					if !known || va < r.lowest {
						r.lowest = va
					}
					r.paths += v.paths
					f.large[p] = r
				case s.kind == stepTable:
					if first && seenAbove(s.addr, level) {
						f.RecursiveEntries++
					}
					j, known := place[s.addr]
					if !known {
						j = len(next)
						place[s.addr] = j
						next = append(next, tableVisit{base: s.addr, lowest: va})
					}
					next[j].paths += v.paths
					next[j].lowest = min(next[j].lowest, va)
				}
			}
		}
		current = next
	}
	f.frames = f.countFrames()
	return f, nil
}

func (f *FrameMap) leaf(frameBase uint64, key uint16, paths uint64) {
	frame := frameBase >> pageShift
	i, ok := f.slot(frame)
	if !ok || !f.held.holds(frameBase, pageBytes) {
		return
	}
	had := uint64(0)
	if n, ok := f.paths[frame]; ok {
		had = n
	} else if f.keys[i] != 0 {
		had = 1
	}
	if had+paths > 1 {
		f.paths[frame] = had + paths
	}
	f.keys[i] |= key
}

func (f *FrameMap) countFrames() int {
	n := 0
	for _, k := range f.keys {
		if k != 0 {
			n++
		}
	}
	type interval struct{ first, end uint64 }
	pages := make([]interval, 0, len(f.large))
	for p := range f.large {
		pages = append(pages, interval{p.base >> pageShift, (p.base + p.size) >> pageShift})
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].first < pages[j].first })
	covered := uint64(0)
	for i, p := range pages {
		if i > 0 && p.first < covered {
			p.first = covered
		}
		for frame := p.first; frame < p.end; frame++ {
			if s, ok := f.slot(frame); ok && f.keys[s] == 0 {
				n++
			}
		}
		covered = max(covered, p.end)
	}
	return n
}

func (f *FrameMap) largePaths(pa uint64) uint64 {
	n := uint64(0)
	for _, size := range f.sizes {
		n += f.large[largePage{pa &^ (size - 1), size}].paths
	}
	return n
}

func (f *FrameMap) Contains(physicalAddress uint64) bool {
	if f == nil {
		return false
	}
	i, ok := f.slot(physicalAddress >> pageShift)
	return ok && (f.keys[i] != 0 || f.largePaths(physicalAddress) > 0)
}

func (f *FrameMap) Len() int {
	if f == nil {
		return 0
	}
	return f.frames
}

func (f *FrameMap) Mappings(physicalAddress uint64) uint64 {
	if !f.Contains(physicalAddress) {
		return 0
	}
	frame := physicalAddress >> pageShift
	n := f.largePaths(physicalAddress)
	if k, ok := f.paths[frame]; ok {
		return n + k
	}
	if i, _ := f.slot(frame); f.keys[i] != 0 {
		n++
	}
	return n
}

func (f *FrameMap) SecondAddressBytes(physicalAddress uint64) []byte {
	if !f.Contains(physicalAddress) {
		return nil
	}
	frame := physicalAddress >> pageShift
	i, _ := f.slot(frame)
	keys := f.keys[i]
	if f.largePaths(physicalAddress) > 0 {
		keys |= 1 << (frame & 0xf)
	}
	low := byte(physicalAddress>>8) & 0xf
	var out []byte
	for k := range 16 {
		if keys&(1<<k) != 0 {
			out = append(out, byte(k)<<4|low)
		}
	}
	return out
}

const AnyPageKey = uint16(0xffff)

type AddressQuery struct {
	Physical uint64
	Keys     uint16
}

type LowestAddress struct {
	Virtual uint64
	Mapped  bool
}

// A large page is aligned to its size in both spaces, so a frame inside one
// has the key its own bits 15:12 give.
func (f *FrameMap) LowestAddresses(queries []AddressQuery) ([]LowestAddress, error) {
	out := make([]LowestAddress, len(queries))
	if f == nil || len(queries) == 0 {
		return out, nil
	}
	offer := func(q int, va uint64) {
		if !out[q].Mapped || va < out[q].Virtual {
			out[q] = LowestAddress{Virtual: va, Mapped: true}
		}
	}
	asked := map[uint64][]int{}
	for q, query := range queries {
		frame := query.Physical >> pageShift
		if _, ok := f.slot(frame); !ok || !f.held.holds(frame<<pageShift, pageBytes) {
			continue
		}
		asked[frame] = append(asked[frame], q)
		if query.Keys&(1<<(frame&0xf)) == 0 {
			continue
		}
		for _, size := range f.sizes {
			base := query.Physical &^ (size - 1)
			if r, ok := f.large[largePage{base, size}]; ok {
				offer(q, r.lowest+query.Physical-base)
			}
		}
	}
	if len(asked) > 0 {
		leaf := f.mode.leaf()
		for _, t := range f.leafTables {
			raw, ok := readTable(f.physical, t.base, f.mode.tableSize(leaf))
			if !ok {
				return nil, fmt.Errorf("layers: page table at 0x%x: %w", t.base, ErrPageNotCaptured)
			}
			for i := range uint64(len(raw)) / f.mode.entryBytes {
				s := f.mode.step(leaf, f.mode.entryAt(raw, i))
				if s.kind != stepPage {
					continue
				}
				for _, q := range asked[s.addr>>pageShift] {
					if queries[q].Keys&(1<<(i&0xf)) != 0 {
						offer(q, t.lowest|i<<pageShift|queries[q].Physical&(pageBytes-1))
					}
				}
			}
		}
	}
	for q := range out {
		if out[q].Mapped {
			out[q].Virtual = f.mode.canonical(out[q].Virtual)
		}
	}
	return out, nil
}
