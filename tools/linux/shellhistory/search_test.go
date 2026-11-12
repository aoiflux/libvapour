package shellhistory

import (
	"encoding/binary"
	"testing"
	"time"
)

const heapStart = 0x5000000

// image lays out user memory the way S15c H1 to H4 describe it: entries of
// three pointers, their strings, and null-ended arrays of entry pointers.
type image struct {
	buf  []byte
	base uint64
	next uint64
}

func newImage(pages int) *image {
	return &image{buf: make([]byte, pages*pageSize), base: heapStart, next: heapStart + 0x10}
}

func (m *image) alloc(n uint64) uint64 {
	at := m.next
	m.next = (m.next + n + 15) &^ 15
	return at
}

func (m *image) str(s string) uint64 {
	at := m.alloc(uint64(len(s)) + 1)
	copy(m.buf[at-m.base:], s)
	return at
}

func (m *image) word(at, v uint64) { binary.LittleEndian.PutUint64(m.buf[at-m.base:], v) }

func (m *image) entry(line, stamp string) uint64 {
	l := m.str(line)
	var s uint64
	if stamp != "" {
		s = m.str(stamp)
	}
	at := m.alloc(24)
	m.word(at, l)
	m.word(at+8, s)
	return at
}

func (m *image) list(entries ...uint64) uint64 {
	at := m.alloc(uint64(len(entries)+1) * 8)
	for i, e := range entries {
		m.word(at+uint64(i)*8, e)
	}
	return at
}

func (m *image) space() *space {
	sp := newSpace(8)
	for off := 0; off < len(m.buf); off += pageSize {
		sp.add(m.base+uint64(off), m.buf[off:off+pageSize])
	}
	return sp
}

const textMax = 1 << 20

func TestTheLongestNullEndedArrayIsTheHistoryList(t *testing.T) {
	m := newImage(3)
	a := m.entry("ls -la /tmp", "#1700000000")
	b := m.entry("cat <<EOF\nline\nEOF", "#1700000060")
	c := m.entry("history -c", "#1700000120")
	decoy := m.list(m.entry("decoy", "#5"))
	list := m.list(a, b, c)
	sp := m.space()
	got, others := findList(sp, textMax)
	if got.at != list || others != 1 || decoy == 0 {
		t.Fatalf("list at %#x with %d others, want %#x and 1", got.at, others, list)
	}
	want := []entry{{a, "ls -la /tmp", "#1700000000", "1700000000"},
		{b, "cat <<EOF\nline\nEOF", "#1700000060", "1700000060"}, {c, "history -c", "#1700000120", "1700000120"}}
	if len(got.entries) != len(want) {
		t.Fatalf("entries %+v", got.entries)
	}
	for i := range want {
		if *got.entries[i] != want[i] {
			t.Errorf("entry %d %+v, want %+v", i, *got.entries[i], want[i])
		}
	}
}

func TestAnArrayWithoutANullEndOrWithABadEntryIsNotAList(t *testing.T) {
	m := newImage(2)
	good := m.entry("echo ok", "#1")
	bad := m.alloc(24)
	m.word(bad, m.str("bell\x07"))
	m.word(bad+8, m.str("#1"))
	outside := m.alloc(24)
	m.word(outside, m.str("ok"))
	m.word(outside+8, 0x7fff0000)
	open := m.alloc(16 * 8)
	for i := range uint64(15) {
		m.word(open+i*8, good)
	}
	m.word(open+15*8, 0x1234)
	m.list(good, bad)
	m.list(outside)
	if got, others := findList(m.space(), textMax); len(got.entries) != 0 || others != 0 {
		t.Fatalf("list %+v, %d others", got, others)
	}
	m.list(good)
	got, others := findList(m.space(), textMax)
	if len(got.entries) != 1 || got.entries[0].at != good || others != 0 {
		t.Fatalf("list %+v, %d others", got, others)
	}
}

func TestEqualArraysAreDecidedByAddress(t *testing.T) {
	m := newImage(2)
	first := m.list(m.entry("one", "#1"))
	m.list(m.entry("two", "#2"))
	got, others := findList(m.space(), textMax)
	if got.at != first || others != 1 {
		t.Errorf("list at %#x, %d others, want %#x", got.at, others, first)
	}
}

func TestAStampIsTheCommentCharacterThenDigits(t *testing.T) {
	m := newImage(2)
	shell := m.entry("ls", "#1700000000")
	custom := m.entry("pwd", "#1700000060")
	library := m.entry("print(1)", "\x001700000120")
	m.list(shell, custom, library)
	for _, bad := range []string{"", ";1700000000", "e1", "1700000000", "#", "##1", "#12a", "\x00later", "Tue Nov 12", "#123456789012345678901"} {
		m.list(m.entry("x", bad))
	}
	same := m.alloc(24)
	text := m.str("#1700000000")
	m.word(same, text)
	m.word(same+8, text)
	m.list(same)
	got, others := findList(m.space(), textMax)
	if others != 0 || len(got.entries) != 3 {
		t.Fatalf("entries %+v, %d others", got.entries, others)
	}
	want := []entry{{shell, "ls", "#1700000000", "1700000000"}, {custom, "pwd", "#1700000060", "1700000060"},
		{library, "print(1)", "1700000120", "1700000120"}}
	for i := range want {
		if *got.entries[i] != want[i] {
			t.Errorf("entry %d %+v, want %+v", i, *got.entries[i], want[i])
		}
	}
}

func TestACommandAboveTheTextCapIsNotAnEntry(t *testing.T) {
	m := newImage(2)
	m.list(m.entry("0123456789", "#1"))
	if got, _ := findList(m.space(), 9); len(got.entries) != 0 {
		t.Errorf("list %+v under a 9-byte cap", got)
	}
	if got, _ := findList(m.space(), 10); len(got.entries) != 1 {
		t.Errorf("list %+v under a 10-byte cap", got)
	}
}

func TestStampsAreSecondsSinceTheEpoch(t *testing.T) {
	for _, c := range []struct {
		in   string
		want time.Time
		ok   bool
	}{
		{"1700000000", time.Unix(1700000000, 0).UTC(), true},
		{"0", time.Unix(0, 0).UTC(), true},
		{"9223372036854775807", time.Unix(9223372036854775807, 0).UTC(), true},
		{"9223372036854775808", time.Time{}, false},
		{"12345678901234567890", time.Time{}, false},
		{"", time.Time{}, false},
		{"12a", time.Time{}, false},
	} {
		got, ok := parseStamp(c.in)
		if ok != c.ok || !got.Equal(c.want) || ok && got.Location() != time.UTC {
			t.Errorf("parseStamp(%q) = %v %t, want %v %t", c.in, got, ok, c.want, c.ok)
		}
	}
}
