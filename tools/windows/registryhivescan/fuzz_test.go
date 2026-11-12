package registryhivescan

import (
	"testing"

	"github.com/aoiflux/libvapour/tools/windows/poolbig"
)

func FuzzScan(f *testing.F) {
	m := newMemory()
	m.hive(0x10000, "x", "y")
	seed, _ := m.ReadAt(0x10000, 0x800)
	f.Add(seed, uint64(fxPoolSize))
	f.Add([]byte{}, uint64(0))
	f.Fuzz(func(t *testing.T, data []byte, size uint64) {
		m := newMemory()
		m.write(0x10000, data)
		tbl := fxTable()
		l, err := loadLayout(tbl)
		if err != nil {
			t.Fatal(err)
		}
		var diags []string
		rows := scan(fxContext(m, tbl, &diags, false), l, []poolbig.Allocation{allocation(0x10000, size, hiveTag, false)}, nil)
		if len(rows) > 1 {
			t.Fatalf("%d rows from one allocation", len(rows))
		}
		for _, r := range rows {
			if r.Verified && size < fxCMHIVESize {
				t.Fatalf("an allocation of %d bytes verified", size)
			}
		}
	})
}
