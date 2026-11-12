package memoryranges

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

const fuzzNodes = 8

// Each node takes 16 bytes: start VPN (5), end VPN (5), left and right link
// selectors, flags (4). A selector below fuzzNodes names that node, 0xff is
// no link, anything else a raw address near the nodes.
func fuzzImage(data []byte) *tImage {
	img := newImage(nil)
	n := min(len(data)/16, fuzzNodes)
	for i := range n {
		rec := data[16*i:]
		vpn := func(b []byte) uint64 {
			return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32
		}
		img.putVAD(i, tVAD{start: vpn(rec[0:5]) << 12, end: vpn(rec[5:10]) << 12, private: rec[12]&1 == 1})
		img.mem.u32(nodeAt(i)+tFlagsWord, binary.LittleEndian.Uint32(rec[12:16]))
	}
	link := func(sel byte) uint64 {
		switch {
		case sel == 0xff:
			return 0
		case int(sel) < n:
			return nodeAt(int(sel))
		}
		return tNodeBase + uint64(sel)*0x40
	}
	for i := range n {
		rec := data[16*i:]
		img.mem.u64(nodeAt(i), link(rec[10]))
		img.mem.u64(nodeAt(i)+8, link(rec[11]))
	}
	if n > 0 {
		img.root(0)
	} else {
		img.root(-1)
	}
	return img
}

func FuzzVADTree(f *testing.F) {
	seed := make([]byte, 0, 48)
	for _, r := range [][]byte{
		{0x20, 0, 0, 0, 0, 0x2f, 0, 0, 0, 0, 1, 2, 0x81, 0x03, 0x20, 0},
		{0x10, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0xff, 0xff, 0x81, 0x00, 0x20, 0},
		{0x00, 0, 0x60, 0xff, 7, 0x03, 0, 0x60, 0xff, 7, 0xff, 0, 0x90, 0x03, 0, 0},
	} {
		seed = append(seed, r...)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		img := fuzzImage(data)
		ctx := img.ctx(nil)
		ctx.Limits = limits.Limits{MaxListEntries: 6}
		vads, err := ProcessVADs(ctx, tProcess)
		if err != nil {
			return
		}
		if len(vads) > 6 {
			t.Fatalf("%d VADs past a budget of 6", len(vads))
		}
		seen := map[uint64]bool{}
		for i, v := range vads {
			if seen[v.Base] {
				t.Fatalf("VAD 0x%x listed twice", v.Base)
			}
			seen[v.Base] = true
			if v.End < v.Start || v.End > 0x7FFF_FFFE_FFFF || v.Start&pageOffsetMask != 0 || v.End&pageOffsetMask != pageOffsetMask {
				t.Fatalf("VAD %+v", v)
			}
			if i > 0 && v.Start <= vads[i-1].End {
				t.Fatalf("VAD %+v overlaps or precedes %+v", v, vads[i-1])
			}
		}
		d, err := NewDecoder(ctx)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := d.Mappings(ctx, tProcess)
		if err != nil || len(rows) != len(vads) {
			t.Fatalf("%d rows, %v; want %d", len(rows), err, len(vads))
		}
		for _, m := range rows {
			if _, ok := Win32Protection(m.Protection); !ok && m.Protection != ProtectionUnknown {
				t.Fatalf("protection %q does not parse", m.Protection)
			}
			if m.NoFile && (m.PathUnreadable || m.Path != "") || m.PathUnreadable && m.Path != "" {
				t.Fatalf("file states: %+v", m)
			}
		}
	})
}

func FuzzProtectionName(f *testing.F) {
	for _, v := range []uint32{0, 1, 0x204, 0x40000020, 0xffffffff} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v uint32) {
		name := ProtectionName(v)
		back, ok := Win32Protection(name)
		if !ok || back != v {
			t.Fatalf("ProtectionName(0x%x) = %q parses to 0x%x, %v", v, name, back, ok)
		}
	})
}
