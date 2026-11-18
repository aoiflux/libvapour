package peimports

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

// The patch lands anywhere in a well-formed image, so the descriptors, the
// name strings, the lookup and address tables and the headers all get hit.
func FuzzImportsOfAPatchedImage(f *testing.F) {
	base := mainImage(
		library{name: "KERNEL32.dll", imports: []wantedImport{{name: "CreateFileW"}, {ordinal: 7}}},
		library{name: "USER32.dll", stamp: 0xFFFFFFFF, imports: []wantedImport{{name: "MessageBoxW"}}},
	)
	f.Add(uint32(descRVA), binary.LittleEndian.AppendUint32(nil, 0x7fffffff))
	f.Add(uint32(iltRVA), binary.LittleEndian.AppendUint64(nil, 0x8000000000000001))
	f.Add(uint32(stringsRVA), []byte("no terminator here"))
	f.Add(uint32(importSlot), binary.LittleEndian.AppendUint64(nil, 0xffffffff00000000))
	f.Fuzz(func(t *testing.T, at uint32, patch []byte) {
		img := append([]byte(nil), base...)
		copy(img[int(at%uint32(len(img))):], patch)
		fx := build([]testsupport.FixtureProcess{process(100, "app.exe", img)}, map[uint64][]byte{100: img})
		rows, err := Run(fx.Context())
		if err != nil {
			return
		}
		for _, r := range rows {
			if r.PID != 100 || r.ImageBase != mainBase {
				t.Fatalf("row of another process or image: %+v", r)
			}
			switch {
			case r.FunctionFrom != "" && r.FunctionFrom != "exports" && r.FunctionFrom != "table":
				t.Fatalf("name source %q is not exports or table: %+v", r.FunctionFrom, r)
			case !r.ByOrdinal && r.FunctionFrom != "":
				t.Fatalf("an import by name has an ordinal name source: %+v", r)
			}
		}
	})
}
