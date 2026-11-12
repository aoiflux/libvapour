package librarycompare

import (
	"testing"

	"github.com/aoiflux/libvapour/tools/windows/librarylist"
)

// Each record is 3 bytes: process, base and list bits, bit 4 marking a DllBase
// that did not read. The index must hold, per process and base, the union of
// the lists of every record there whose DllBase read.
func FuzzIndexRecords(f *testing.F) {
	f.Add([]byte{1, 2, 0x0f, 1, 2, 0x10, 2, 2, 0x01, 3, 0, 0x11})
	f.Fuzz(func(t *testing.T, raw []byte) {
		var dlls []librarylist.DLL
		for i := 0; i+3 <= len(raw); i += 3 {
			bits := raw[i+2]
			dlls = append(dlls, librarylist.DLL{EPROCESS: uint64(raw[i] & 3), Base: uint64(raw[i+1] & 7),
				InLoadOrder: bits&1 != 0, InMemoryOrder: bits&2 != 0, InInitializationOrder: bits&4 != 0, Wow64: bits&8 != 0, BaseUnreadable: bits&0x10 != 0})
		}
		idx := indexRecords(dlls)
		want := map[[2]uint64]membership{}
		wow := map[uint64]int{}
		for _, d := range dlls {
			if d.BaseUnreadable {
				continue
			}
			k := [2]uint64{d.EPROCESS, d.Base}
			m := want[k]
			m.load, m.mem, m.init, m.wow = m.load || d.InLoadOrder, m.mem || d.InMemoryOrder,
				m.init || d.InInitializationOrder, m.wow || d.Wow64
			want[k] = m
			if d.Wow64 {
				wow[d.EPROCESS]++
			}
		}
		n := 0
		for ep, r := range idx {
			if r.wow != wow[ep] {
				t.Fatalf("process %d: %d 32-bit records, want %d", ep, r.wow, wow[ep])
			}
			for base, m := range r.bases {
				n++
				if want[[2]uint64{ep, base}] != m {
					t.Fatalf("process %d base %d: %+v, want %+v", ep, base, m, want[[2]uint64{ep, base}])
				}
			}
		}
		if n != len(want) {
			t.Fatalf("%d bases indexed, want %d", n, len(want))
		}
	})
}
