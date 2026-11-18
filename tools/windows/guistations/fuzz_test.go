package guistations

import (
	"bytes"
	"testing"

	"github.com/aoiflux/libvapour/tools/gui"
	"github.com/aoiflux/libvapour/tools/gui/guitest"
)

func FuzzScanStationsOfAPatchedWorld(f *testing.F) {
	f.Add(uint8(0), uint8(0), uint16(0x100), []byte("Wind"))
	f.Add(uint8(1), uint8(0), uint16(0x148), []byte{0xff})
	f.Add(uint8(2), uint8(0), uint16(0x160), bytes.Repeat([]byte{0xff}, 8))
	f.Fuzz(func(t *testing.T, layout, object uint8, at uint16, patch []byte) {
		layouts := gui.Layouts()
		w := guitest.Build(guitest.Typical(layouts[int(layout)%len(layouts)]))
		objects := w.Objects()
		w.PatchPage(objects[int(object)%len(objects)], at, patch)
		env, err := gui.OpenLayout(w.Ctx, Name, w.Layout)
		if err != nil {
			t.Fatal(err)
		}
		got, err := rows(env)
		if err != nil {
			t.Fatalf("a scan failed: %v", err)
		}
		for _, s := range got {
			if !gui.ValidObjectName(s.Name) {
				t.Fatalf("a station without a valid name kept: %+v", s)
			}
		}
	})
}
