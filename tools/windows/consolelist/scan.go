package consolelist

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/aoiflux/libvapour/limits"
)

var (
	ErrScanBudget  = errors.New("consolelist: process memory past MaxRegionScanBytes is not searched")
	ErrMatchBudget = errors.New("consolelist: matches past MaxMatchesPerChunk are not checked")
)

type ScanStats struct {
	PagesRead, PagesUnread int
}

// Little-endian bytes of v in width bytes; false when v does not fit.
func Pattern(v uint64, width uint64) ([]byte, bool) {
	if width == 0 || width > 8 || width < 8 && v>>(8*width) != 0 {
		return nil, false
	}
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b[:width], true
}

// Every address in the space, at a multiple of align, where one of the
// patterns starts. A history's buffer size is aligned to its own width and
// the console's settings pair was measured 8-aligned (S33 4.2, 4.3). Pages
// that do not read are counted and skipped.
func (s Space) FindAligned(patterns [][]byte, align uint64, b limits.Limits) ([]uint64, ScanStats, error) {
	var stats ScanStats
	if len(patterns) == 0 || align == 0 {
		return nil, stats, nil
	}
	width := uint64(len(patterns[0]))
	for _, p := range patterns {
		if uint64(len(p)) != width {
			return nil, stats, fmt.Errorf("consolelist: patterns of different widths")
		}
	}
	var hits []uint64
	var budget uint64
	for _, r := range s.search {
		for page := r.Start &^ (pageBytes - 1); page < r.End; page += pageBytes {
			if b.MaxRegionScanBytes > 0 && budget >= uint64(b.MaxRegionScanBytes) {
				return hits, stats, fmt.Errorf("%w (%d)", ErrScanBudget, b.MaxRegionScanBytes)
			}
			budget += pageBytes
			buf, err := s.mem.ReadAt(page, pageBytes)
			if err != nil || len(buf) < pageBytes {
				stats.PagesUnread++
				continue
			}
			stats.PagesRead++
			for off := uint64(0); off+width <= pageBytes; off += align {
				at := page + off
				if at < r.Start || at+width > r.End {
					continue
				}
				if !matchAny(buf[off:off+width], patterns) {
					continue
				}
				if b.MaxMatchesPerChunk > 0 && len(hits) >= b.MaxMatchesPerChunk {
					return hits, stats, fmt.Errorf("%w (%d)", ErrMatchBudget, b.MaxMatchesPerChunk)
				}
				hits = append(hits, at)
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i] < hits[j] })
	return hits, stats, nil
}

func matchAny(b []byte, patterns [][]byte) bool {
	for _, p := range patterns {
		if bytes.Equal(b, p) {
			return true
		}
	}
	return false
}

// Console candidates: the settings pair at its offset, searched for every
// pair of sizes (S33 4.2).
func (l *Layout) FindConsoles(s Space, historySizes, bufferCounts []uint64, b limits.Limits) (Candidates, error) {
	out := Candidates{RejectedBy: map[string]int{}}
	pair, ok := l.SettingsPair()
	if !ok {
		return out, fmt.Errorf("%w: %s", ErrUnsupportedVersion, l.noConsole)
	}
	var patterns [][]byte
	for _, h := range historySizes {
		for _, n := range bufferCounts {
			if p, ok := Pattern(n<<32|h, pair.size); ok && h>>32 == 0 {
				patterns = append(patterns, p)
			}
		}
	}
	hits, _, err := s.FindAligned(patterns, pair.size, b)
	for _, hit := range hits {
		at := uint64(int64(hit) - pair.off)
		v := l.InspectConsole(s, at, b)
		if v.Accepted() {
			out.Accepted = append(out.Accepted, at)
		} else {
			out.RejectedBy[v.Rule]++
			out.Rejections = append(out.Rejections, v)
		}
	}
	return out, err
}

// History candidates: the buffer size at its offset (S33 4.3).
func (l *Layout) FindHistories(s Space, historySizes []uint64, b limits.Limits) (Candidates, error) {
	out := Candidates{RejectedBy: map[string]int{}}
	width := l.history.capacity.size
	var patterns [][]byte
	for _, h := range historySizes {
		if p, ok := Pattern(h, width); ok {
			patterns = append(patterns, p)
		}
	}
	hits, _, err := s.FindAligned(patterns, width, b)
	for _, hit := range hits {
		node := uint64(int64(hit) - l.history.capacity.off)
		want, _ := s.uint(hit, width)
		v := l.InspectHistory(s, node, want, b)
		if v.Accepted() {
			out.Accepted = append(out.Accepted, node)
		} else {
			out.RejectedBy[v.Rule]++
			out.Rejections = append(out.Rejections, v)
		}
	}
	return out, err
}
