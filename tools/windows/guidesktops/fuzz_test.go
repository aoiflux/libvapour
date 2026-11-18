package guidesktops

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/gui"
	"github.com/aoiflux/libvapour/tools/gui/guitest"
)

const fuzzListEntries = 16

// Each patch stays on one object's page (station, desktop, desktop
// information or thread information), so it reaches that object's headers,
// members and links while the kernel globals every walk needs stay intact.
func FuzzListDesktopsOfAPatchedWorld(f *testing.F) {
	f.Add(uint8(0), uint8(0), uint16(0x148), []byte{0xff})
	f.Add(uint8(1), uint8(1), uint16(0x160), make([]byte, 8))
	f.Add(uint8(2), uint8(3), uint16(0), bytes.Repeat([]byte{0xff}, 8))
	f.Add(uint8(3), uint8(1), uint16(0x170), binary.LittleEndian.AppendUint64(nil, 0xffffa00000100010))
	f.Fuzz(func(t *testing.T, layout, object uint8, at uint16, patch []byte) {
		layouts := gui.Layouts()
		w := guitest.Build(guitest.Typical(layouts[int(layout)%len(layouts)]))
		objects := w.Objects()
		w.PatchPage(objects[int(object)%len(objects)], at, patch)
		w.Ctx.Limits = limits.Limits{MaxListEntries: fuzzListEntries}
		env, err := gui.OpenLayout(w.Ctx, Name, w.Layout)
		if err != nil {
			t.Fatal(err)
		}
		groups, err := byStation(env)
		if err != nil {
			t.Fatalf("a lenient walk failed: %v", err)
		}
		for _, g := range groups {
			if len(g.Desktops) > fuzzListEntries {
				t.Fatalf("station 0x%x: %d desktops", g.Station, len(g.Desktops))
			}
			order := map[uint64]int{}
			for i, d := range g.Desktops {
				if _, twice := order[d]; twice {
					t.Fatalf("station 0x%x: desktop 0x%x twice", g.Station, d)
				}
				order[d] = i
			}
			last := 0
			for _, r := range g.Rows {
				i, listed := order[r.Address]
				if !listed || i < last {
					t.Fatalf("station 0x%x: row %+v out of the list order", g.Station, r)
				}
				last = i
				checkOwner(t, r)
			}
		}
	})
}

func checkOwner(t *testing.T, r Desktop) {
	t.Helper()
	switch {
	case r.Threadless && (r.TID != 0 || r.PID != 0 || r.Process != "" || r.ProcessUnreadable):
		t.Fatalf("a threadless row carries a thread: %+v", r)
	case r.ProcessUnreadable && (r.PID != 0 || r.Process != ""):
		t.Fatalf("an unread owner carries a process: %+v", r)
	}
}
