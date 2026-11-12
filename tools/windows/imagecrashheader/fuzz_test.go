package imagecrashheader

import (
	"testing"
	"time"
	"unicode/utf8"
)

func FuzzHeaderFields(f *testing.F) {
	f.Add(uint64(36_000_000_000), []byte("manual dump"))
	f.Add(uint64(1<<63), []byte{0xff, 0})
	f.Fuzz(func(t *testing.T, ticks uint64, comment []byte) {
		d, ok := UpTime(ticks)
		if ok && (d < 0 || uint64(d/(100*time.Nanosecond)) != ticks) {
			t.Fatalf("%d ticks gave %v", ticks, d)
		}
		if c := commentText(comment); !utf8.ValidString(c) {
			t.Fatalf("comment %q is not UTF-8", c)
		}
	})
}
