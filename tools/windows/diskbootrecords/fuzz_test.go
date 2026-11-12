package diskbootrecords

import (
	"strings"
	"testing"
)

func FuzzRecord(f *testing.F) {
	f.Add(mbr(1, 0x90, ntfs))
	f.Add(mbr(0, 0, part{0, 0xEE, 1, 0xFFFFFFFF}))
	f.Add(mbr(2, 0x33, part{0x80, 0x07, 2048, 10}, part{0x80, 0x07, 4096, 10}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < recordSize {
			b = append(b, make([]byte, recordSize-len(b))...)
		}
		b[markerOffset], b[markerOffset+1] = 0x55, 0xAA
		rec, ok := parseRecord(b)
		if !ok {
			t.Fatal("marker set but record refused")
		}
		if rec.tableProblem() != "" {
			return
		}
		active, used := 0, 0
		for _, e := range rec.entries {
			if !e.inUse() {
				continue
			}
			used++
			if e.indicator == indicatorActive {
				active++
			}
			if e.total == 0 || e.relative == 0 || e.end() > lbaRange || e.startSector == 0 || e.endSector == 0 {
				t.Fatalf("accepted entry %+v", e)
			}
		}
		if used == 0 || active > 1 {
			t.Fatalf("accepted %d in use, %d active", used, active)
		}
		listing, whole := listBootCode(rec.bootCode(), 1<<20)
		if !whole || strings.Count(listing, "\n") >= bootCodeSize {
			t.Fatalf("listing of %d lines", strings.Count(listing, "\n")+1)
		}
	})
}
