package memorycode

import (
	"errors"
	"strconv"
	"strings"

	"github.com/aoiflux/libvapour/layers"
)

// x86 page-table entry bits as Linux uses them (S47 L4, L5).
const (
	linuxPresent    = uint64(1) << 0
	linuxDirty      = uint64(1) << 6
	linuxSavedDirty = uint64(1) << 58
	linuxNoExec     = uint64(1) << 63
)

// The kernel releases whose leaf entries were checked for the SavedDirty bit
// (S47 L5): set at 6.14 and 6.17, not yet at 6.4.
var (
	savedDirtyFrom  = [2]int{6, 14}
	savedDirtyUntil = [2]int{6, 4}
)

type writtenBits uint64

func writtenBitsFor(release string) (writtenBits, bool) {
	v, ok := majorMinor(release)
	switch {
	case !ok:
		return writtenBits(linuxDirty), false
	case !before(v, savedDirtyFrom):
		return writtenBits(linuxDirty | linuxSavedDirty), true
	case !before(savedDirtyUntil, v):
		return writtenBits(linuxDirty), true
	}
	return writtenBits(linuxDirty), false
}

func before(a, b [2]int) bool { return a[0] < b[0] || a[0] == b[0] && a[1] < b[1] }

func majorMinor(release string) ([2]int, bool) {
	major, rest, ok := strings.Cut(release, ".")
	if !ok {
		return [2]int{}, false
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	a, err1 := strconv.Atoi(major)
	b, err2 := strconv.Atoi(rest[:end])
	if err1 != nil || err2 != nil {
		return [2]int{}, false
	}
	return [2]int{a, b}, true
}

const bannerPrefix = "Linux version "

// The release is the token linux_banner puts after "Linux version " (S47 B1).
func bannerRelease(text string) (string, bool) {
	rest, ok := strings.CutPrefix(text, bannerPrefix)
	if !ok {
		return "", false
	}
	if i := strings.IndexAny(rest, " \n"); i >= 0 {
		rest = rest[:i]
	}
	return rest, rest != ""
}

type linuxPage struct {
	resident, executable, written bool
}

// A not-present entry is the kernel's (swap, migration, NUMA hint): the
// processor ignores it, so it holds no right the page has now.
func decodeLinuxEntry(entry uint64, written writtenBits) linuxPage {
	if entry&linuxPresent == 0 {
		return linuxPage{}
	}
	return linuxPage{resident: true, executable: entry&linuxNoExec == 0, written: entry&uint64(written) != 0}
}

type areaPages struct {
	pages, resident, executable, written, noExecSet uint64
	executableAt, writtenAt                         []uint64
	cut                                             bool
}

func walkArea(le leafEntries, start, end uint64, written writtenBits, budget uint64) areaPages {
	var a areaPages
	if end < start {
		return a
	}
	a.pages = (end-start)/pageSize + 1
	visited := uint64(0)
	for page := start &^ (pageSize - 1); ; {
		step := pageSize
		entry, err := le.LeafEntry(page)
		var miss layers.UnmappedPageError
		switch {
		case err == nil:
			visited++
			if visited > budget {
				a.cut = true
				return a
			}
			p := decodeLinuxEntry(entry, written)
			if p.resident {
				a.resident++
				if !p.executable {
					a.noExecSet++
				}
			}
			if p.executable {
				a.executable++
				a.executableAt = append(a.executableAt, page)
			}
			if p.written {
				a.written++
				a.writtenAt = append(a.writtenAt, page)
			}
		case errors.As(err, &miss) && miss.Span > pageSize:
			step = miss.Span - page&(miss.Span-1)
		}
		if end-page < step {
			return a
		}
		page += step
	}
}
