package guidesktopscan

import (
	"bytes"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/gui"
	"github.com/aoiflux/libvapour/tools/gui/guitest"
)

func FuzzScanDesktopsOfAPatchedWorld(f *testing.F) {
	f.Add(uint8(0), uint8(1), uint16(0x100), []byte("Desk"))
	f.Add(uint8(1), uint8(1), uint16(0x148), []byte{0xff})
	f.Add(uint8(2), uint8(0), uint16(0x160), bytes.Repeat([]byte{0xff}, 4))
	f.Fuzz(func(t *testing.T, layout, object uint8, at uint16, patch []byte) {
		layouts := gui.Layouts()
		w := guitest.Build(guitest.Typical(layouts[int(layout)%len(layouts)]))
		objects := w.Objects()
		w.PatchPage(objects[int(object)%len(objects)], at, patch)
		w.Ctx.Limits = limits.Limits{MaxListEntries: 16}
		env, err := gui.OpenLayout(w.Ctx, Name, w.Layout)
		if err != nil {
			t.Fatal(err)
		}
		got, err := rows(env)
		if err != nil {
			t.Fatalf("a lenient scan failed: %v", err)
		}
		for _, r := range got {
			switch {
			case r.NameUnreadable || !gui.ValidObjectName(r.Name):
				t.Fatalf("a desktop without a valid name kept: %+v", r)
			case r.Threadless && (r.TID != 0 || r.PID != 0 || r.Process != "" || r.ProcessUnreadable):
				t.Fatalf("a threadless row carries a thread: %+v", r)
			case r.ProcessUnreadable && (r.PID != 0 || r.Process != ""):
				t.Fatalf("an unread owner carries a process: %+v", r)
			}
		}
	})
}
