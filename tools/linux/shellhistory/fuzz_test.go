package shellhistory

import (
	"testing"
	"time"
)

// Process memory is untrusted: whatever two pages hold, the search ends and
// every entry it reports satisfies the S15c 4.3 rules.
func FuzzHistorySearch(f *testing.F) {
	seed := history()
	f.Add(seed.buf)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		m := newImage(2)
		copy(m.buf, data)
		list, others := findList(m.space(), 64)
		if others < 0 {
			t.Fatalf("%d other arrays", others)
		}
		for _, e := range list.entries {
			if e.at%8 != 0 || e.line == "" || len(e.line) > 64 || e.digits == "" || len(e.digits) > maxStampDigits {
				t.Fatalf("entry %+v breaks the rules", *e)
			}
			for i := 0; i < len(e.line); i++ {
				if !textByte(e.line[i]) {
					t.Fatalf("entry %+v has byte %#x", *e, e.line[i])
				}
			}
		}
	})
}

func FuzzStampParser(f *testing.F) {
	for _, s := range []string{"1700000000", "0", "-1", "99999999999999999999", "9223372036854775808"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, ok := parseStamp(s)
		if !ok {
			if !got.IsZero() {
				t.Fatalf("parseStamp(%q) = %v without ok", s, got)
			}
			return
		}
		if got.Location() != time.UTC || got.Unix() < 0 {
			t.Fatalf("parseStamp(%q) = %v", s, got)
		}
	})
}
