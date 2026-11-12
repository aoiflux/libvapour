package timeline

import (
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func FuzzBodyLine(f *testing.F) {
	f.Add(int64(1769761586), int64(5), "created", "any.process.list", "CreateTime", "process a|b pid 1\n", uint64(0x10))
	f.Add(int64(-5), int64(0), "exited", "t", "F", "\xff\x00", uint64(0))
	f.Add(int64(0), int64(999999999), "other", "", "", "", uint64(1))
	f.Fuzz(func(t *testing.T, secs, nanos int64, ev, tool, field, subject string, address uint64) {
		e := Entry{Time: time.Unix(secs, nanos).UTC(), Event: Event(ev), Tool: tool, Field: field, Subject: subject, Address: address}
		line, ok := BodyLine(e)
		_, known := columnOf[e.Event]
		if ok != (known && !BeforeEpoch(e.Time) && e.Time.Unix() != 0) {
			t.Fatalf("line %v for %+v", ok, e)
		}
		if !ok {
			return
		}
		if strings.ContainsAny(line, "\n\r") || !utf8.ValidString(line) {
			t.Fatalf("line breaks or invalid UTF-8 in %q", line)
		}
		fields := strings.Split(line, "|")
		if len(fields) != 11 {
			t.Fatalf("%d fields in %q", len(fields), line)
		}
		set := 0
		for _, v := range fields[7:] {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 || (v == "0") == (n != 0) {
				t.Fatalf("time column %q", v)
			}
			if v != "0" {
				set++
				if n != e.Time.Unix() {
					t.Fatalf("seconds %d, want %d", n, e.Time.Unix())
				}
			}
		}
		if set != 1 {
			t.Fatalf("%d time columns set in %q", set, line)
		}
	})
}
