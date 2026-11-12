package consolelist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/aoiflux/libvapour/memory"
)

// LayoutFor admits 64-bit conhost.exe only.
const pointerBytes = 8

const pageBytes = 0x1000

var (
	ErrUnread  = errors.New("consolelist: memory does not read")
	ErrOutside = errors.New("consolelist: pointer lands outside the process's address ranges")
)

// End is exclusive.
type Region struct {
	Start, End uint64
}

// A process's memory as conhost.exe sees it: every pointer it follows must
// land inside one of its VADs (S33 5, rule P1).
type Space struct {
	mem     memory.MemoryReader
	regions []Region
	search  []Region
}

func NewSpace(mem memory.MemoryReader, regions []Region) Space {
	rs := make([]Region, 0, len(regions))
	for _, r := range regions {
		if r.End > r.Start {
			rs = append(rs, r)
		}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].Start < rs[j].Start })
	return Space{mem: mem, regions: rs, search: rs}
}

// The search reads only these runs, clipped to the regions: the page tables
// name the pages that are present, and most of a process's reserved space is
// not (S33 4.2).
func (s Space) WithSearch(runs []Region) Space {
	var out []Region
	for _, r := range runs {
		i := sort.Search(len(s.regions), func(i int) bool { return s.regions[i].End > r.Start })
		for ; i < len(s.regions) && s.regions[i].Start < r.End; i++ {
			c := Region{Start: max(r.Start, s.regions[i].Start), End: min(r.End, s.regions[i].End)}
			if c.End > c.Start {
				out = append(out, c)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	s.search = out
	return s
}

func (s Space) SearchRuns() []Region { return append([]Region(nil), s.search...) }

func (s Space) Regions() []Region { return append([]Region(nil), s.regions...) }

func (s Space) Memory() memory.MemoryReader { return s.mem }

func (s Space) Holds(at, n uint64) bool {
	if at+n < at {
		return false
	}
	i := sort.Search(len(s.regions), func(i int) bool { return s.regions[i].End > at })
	return i < len(s.regions) && s.regions[i].Start <= at && at+n <= s.regions[i].End
}

func (s Space) read(at, n uint64) ([]byte, error) {
	if !s.Holds(at, n) {
		return nil, fmt.Errorf("0x%x+%d: %w", at, n, ErrOutside)
	}
	b, err := s.mem.ReadAt(at, n)
	if err != nil {
		return nil, fmt.Errorf("0x%x+%d: %w: %w", at, n, ErrUnread, err)
	}
	if uint64(len(b)) < n {
		return nil, fmt.Errorf("0x%x+%d: %w: %d bytes", at, n, ErrUnread, len(b))
	}
	return b, nil
}

func (s Space) uint(at, n uint64) (uint64, error) {
	b, err := s.read(at, n)
	if err != nil {
		return 0, err
	}
	switch n {
	case 1:
		return uint64(b[0]), nil
	case 2:
		return uint64(binary.LittleEndian.Uint16(b)), nil
	case 4:
		return uint64(binary.LittleEndian.Uint32(b)), nil
	case 8:
		return binary.LittleEndian.Uint64(b), nil
	}
	return 0, fmt.Errorf("0x%x: %w: width %d", at, ErrUnread, n)
}

func (s Space) pointer(at uint64) (uint64, error) { return s.uint(at, pointerBytes) }

func (s Space) member(base uint64, off int64) uint64 { return uint64(int64(base) + off) }

func (s Space) value(base uint64, p prim) (int64, error) {
	v, err := s.uint(s.member(base, p.off), p.size)
	if err != nil {
		return 0, err
	}
	if p.signed && p.size < 8 {
		shift := 64 - 8*p.size
		return int64(v<<shift) >> shift, nil
	}
	return int64(v), nil
}
