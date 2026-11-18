package pedump

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

// Bytes patched anywhere into explorer.exe's mapped image: a row is written
// exactly when its file exists with the row's size, a skipped row leaves no
// file, and no row reads more than it writes.
func FuzzDumpAPatchedImage(f *testing.F) {
	f.Add(uint32(0x3c), binary.LittleEndian.AppendUint32(nil, 0x7fffffff))
	f.Add(uint32(0x50), make([]byte, 4))
	f.Add(uint32(0x86), []byte{0xff, 0xff})
	f.Add(uint32(0x1000), []byte("not code"))
	f.Fuzz(func(t *testing.T, at uint32, patch []byte) {
		procs := explorer()
		img := append([]byte(nil), procs[1].Modules[0].Image...)
		copy(img[int(at%uint32(len(img))):], patch)
		procs[1].Modules[0].Image = img
		w := build(t, procs, nil, nil)
		arts, dir, err := w.run(t, map[string]any{"pid": []uint64{testsupport.S55ExplorerPID}})
		if err != nil {
			return
		}
		for _, a := range arts {
			info, statErr := os.Stat(filepath.Join(dir, a.FileName))
			switch {
			case a.Written() && (statErr != nil || info.Size() != int64(a.Size)):
				t.Fatalf("%s written as %d bytes, file: %v", a.FileName, a.Size, statErr)
			case !a.Written() && a.FileName != "" && statErr == nil:
				t.Fatalf("%s skipped (%s) but its file stays", a.FileName, a.Skipped)
			case a.Captured > uint64(a.Size):
				t.Fatalf("%s captured %d of %d bytes", a.FileName, a.Captured, a.Size)
			}
		}
	})
}
