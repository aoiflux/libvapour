package shellhistory

import (
	"encoding/binary"
	"sort"
	"strconv"
	"time"
)

const pageSize = 4096

type space struct {
	pages map[uint64][]byte
	width uint64
	order []uint64
}

func newSpace(width uint64) *space {
	return &space{pages: map[uint64][]byte{}, width: width}
}

func (sp *space) add(page uint64, b []byte) {
	if _, dup := sp.pages[page]; dup || uint64(len(b)) < pageSize {
		return
	}
	sp.pages[page] = b[:pageSize]
	sp.order = nil
}

func (sp *space) word(at uint64) (uint64, bool) {
	page := at &^ (pageSize - 1)
	off := at - page
	b, ok := sp.pages[page]
	if !ok || off+sp.width > pageSize {
		return 0, false
	}
	if sp.width == 4 {
		return uint64(binary.LittleEndian.Uint32(b[off:])), true
	}
	return binary.LittleEndian.Uint64(b[off:]), true
}

// S15c 4.3: history lines are typed input, so only tab, newline and
// non-control bytes may appear in them.
func textByte(c byte) bool {
	return c == '\t' || c == '\n' || c >= 0x20 && c != 0x7f
}

func (sp *space) text(at, limit uint64, empty bool) (string, bool) {
	var out []byte
	for {
		page := at &^ (pageSize - 1)
		b, ok := sp.pages[page]
		if !ok {
			return "", false
		}
		for _, c := range b[at-page:] {
			if c == 0 {
				return string(out), empty || len(out) > 0
			}
			if !textByte(c) || uint64(len(out)) >= limit {
				return "", false
			}
			out = append(out, c)
		}
		if page+pageSize < page {
			return "", false
		}
		at = page + pageSize
	}
}

type entry struct {
	at     uint64
	line   string
	stamp  string
	digits string
}

type search struct {
	sp      *space
	textMax uint64
	memo    map[uint64]*entry
}

func (s *search) entry(at uint64) *entry {
	if e, done := s.memo[at]; done {
		return e
	}
	e := s.decode(at)
	s.memo[at] = e
	return e
}

func (s *search) decode(at uint64) *entry {
	w := s.sp.width
	if at%w != 0 || at+3*w < at {
		return nil
	}
	line, ok1 := s.sp.word(at)
	stamp, ok2 := s.sp.word(at + w)
	_, ok3 := s.sp.word(at + 2*w)
	if !ok1 || !ok2 || !ok3 {
		return nil
	}
	if stamp == 0 || stamp == line {
		return nil
	}
	e := &entry{at: at}
	var ok bool
	if e.line, ok = s.sp.text(line, s.textMax, false); !ok {
		return nil
	}
	if e.stamp, e.digits, ok = s.sp.stamp(stamp); !ok {
		return nil
	}
	return e
}

// S15c 4.3 step 3: the library writes the comment character and the time in
// decimal (H5). Bash's comment character is '#' and the library's own is NUL
// (H6); other characters are what histchars sets, rare enough that accepting
// every byte there found only false lists on the captures (M3). A NUL comment
// character leaves the digits as the text shown.
func (sp *space) stamp(at uint64) (shown, digits string, ok bool) {
	if at+1 < at {
		return "", "", false
	}
	page := at &^ (pageSize - 1)
	b, found := sp.pages[page]
	if !found {
		return "", "", false
	}
	c := b[at-page]
	if c != 0 && c != '#' {
		return "", "", false
	}
	digits, ok = sp.text(at+1, maxStampDigits, false)
	if !ok {
		return "", "", false
	}
	for i := 0; i < len(digits); i++ {
		if !isDigit(digits[i]) {
			return "", "", false
		}
	}
	if c == 0 {
		return digits, digits, true
	}
	return string(c) + digits, digits, true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

type array struct {
	at      uint64
	entries []*entry
}

// findList gives the longest null-ended array of entry pointers (S15c 4.4)
// and how many other arrays there were.
func findList(sp *space, textMax uint64) (array, int) {
	s := &search{sp: sp, textMax: textMax, memo: map[uint64]*entry{}}
	if sp.order == nil {
		for p := range sp.pages {
			sp.order = append(sp.order, p)
		}
		sort.Slice(sp.order, func(i, j int) bool { return sp.order[i] < sp.order[j] })
	}
	var best array
	found := 0
	var run array
	running := false
	next := uint64(0)
	for _, page := range sp.order {
		if running && page != next {
			running = false
		}
		for at := page; at < page+pageSize; at += sp.width {
			v, _ := sp.word(at)
			if e := s.entry(v); e != nil {
				if !running {
					run, running = array{at: at}, true
				}
				run.entries = append(run.entries, e)
				continue
			}
			if running && v == 0 {
				found++
				if len(run.entries) > len(best.entries) {
					best = run
				}
			}
			running = false
		}
		next = page + pageSize
	}
	if found == 0 {
		return array{}, 0
	}
	return best, found - 1
}

// H5: the library prints an unsigned long, up to 20 digits, and reads it
// back with strtol, which gives no time past the signed range.
const maxStampDigits = 20

func parseStamp(digits string) (time.Time, bool) {
	if digits == "" || len(digits) > maxStampDigits {
		return time.Time{}, false
	}
	for i := 0; i < len(digits); i++ {
		if !isDigit(digits[i]) {
			return time.Time{}, false
		}
	}
	v, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(v, 0).UTC(), true
}
