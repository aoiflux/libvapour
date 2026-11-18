package linuxtrace_test

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// PointerAt assembles its own bytes, so a pointer that reads equals the
// little-endian word in canonical form, and canonical form is a fixed point.
func FuzzPointerAtLeavesACanonicalWord(f *testing.F) {
	f.Add(uint16(0x10), binary.LittleEndian.AppendUint64(nil, 0xffff888000200100), false)
	f.Add(uint16(0xffc), bytes.Repeat([]byte{0xff}, 4), false)
	f.Add(uint16(0), []byte{}, true)
	f.Fuzz(func(t *testing.T, at uint16, data []byte, la57 bool) {
		var opts map[string]any
		if la57 {
			opts = map[string]any{"paging_mode": "linux-la57"}
		}
		k, mem := objectKernel(t, opts)
		off := uint64(at) % 0x1000
		n := min(uint64(len(data)), 0x1000-off)
		mem.Write(obj+off, data[:n])
		p, err := k.PointerAt(obj + off)
		if off+8 > 0x1000 {
			if err == nil {
				t.Fatalf("a pointer across into an unmapped page read as %#x", p)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		raw, err := mem.ReadAt(obj+off, 8)
		if err != nil {
			t.Fatal(err)
		}
		if want := k.Canonical(binary.LittleEndian.Uint64(raw)); p != want || k.Canonical(p) != p {
			t.Fatalf("pointer %#x, want %#x", p, want)
		}
	})
}
