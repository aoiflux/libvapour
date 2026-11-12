//go:build realimage

package memory

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// The variable names one or more crash dumps, separated by ';' or ',', each
// a path or name=path.
func crashDumpPaths(t *testing.T) map[string]string {
	t.Helper()
	spec := strings.TrimSpace(os.Getenv("LIBVAPOUR_TEST_CRASHDUMP"))
	if spec == "" {
		t.Skip("LIBVAPOUR_TEST_CRASHDUMP not set")
	}
	out := map[string]string{}
	for _, field := range strings.FieldsFunc(spec, func(r rune) bool { return r == ';' || r == ',' }) {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		name, path, ok := strings.Cut(field, "=")
		if !ok {
			name, path = field, field
		}
		out[strings.TrimSpace(name)] = strings.TrimSpace(path)
	}
	return out
}

func TestCrashDumpsOnCapturesKeepTheirInvariants(t *testing.T) {
	for name, path := range crashDumpPaths(t) {
		t.Run(name, func(t *testing.T) {
			file, err := NewFileMemoryReader(path)
			if err != nil {
				t.Skipf("%s: %v", path, err)
			}
			defer file.Close()
			r, format, err := DetectFormat(file)
			if err != nil || format != "crashdump" {
				t.Fatalf("format %s: %v", format, err)
			}
			c := r.(*CrashDumpReader)
			h := c.CrashHeader()
			var pages uint64
			for _, s := range c.Segments() {
				pages += s.Length / crashPageBytes
			}
			if pages != h.NumberOfPages || file.Size() != crashHeaderBytes+h.NumberOfPages*crashPageBytes {
				t.Errorf("runs hold 0x%x pages, header 0x%x, file 0x%x", pages, h.NumberOfPages, file.Size())
			}
			root, err := c.ReadAt(h.DirectoryTableBase&^(crashPageBytes-1), crashPageBytes)
			if err != nil {
				t.Fatalf("page-table root 0x%x: %v", h.DirectoryTableBase, err)
			}
			present := 0
			for i := 0; i < len(root); i += 8 {
				if binary.LittleEndian.Uint64(root[i:])&1 != 0 {
					present++
				}
			}
			if present == 0 {
				t.Errorf("page-table root 0x%x has no present entry", h.DirectoryTableBase)
			}
		})
	}
}
