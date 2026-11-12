package gui

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

const fuzzBase = uint64(0xffff900000000000)

type flat struct {
	base uint64
	data []byte
}

func (f flat) ReadAt(off, n uint64) ([]byte, error) {
	if off < f.base || off-f.base > uint64(len(f.data)) || n > uint64(len(f.data))-(off-f.base) {
		return nil, memory.ErrOutOfBounds
	}
	return f.data[off-f.base : off-f.base+n], nil
}

func (f flat) Size() uint64 { return uint64(len(f.data)) }

func fuzzEnv(l Layout, lim limits.Limits) *Env {
	return &Env{ctx: tools.Context{Limits: lim, Options: map[string]any{}}, tool: "fuzz", Layout: l,
		system: 0xffff800000000000, noted: map[uint32]bool{}, procs: map[processKey]Owner{}}
}

func FuzzStationAndDesktopMembers(f *testing.F) {
	f.Add(uint8(0), make([]byte, 0x100))
	seed := make([]byte, 0x100)
	binary.LittleEndian.PutUint64(seed[0x8:], fuzzBase)
	f.Add(uint8(1), seed)
	f.Fuzz(func(t *testing.T, which uint8, data []byte) {
		l := measured[int(which)%len(measured)]
		e := fuzzEnv(l, limits.Limits{})
		r := flat{base: fuzzBase, data: data}
		if s, err := e.stationAt(r, fuzzBase); err == nil {
			if !e.objectPointer(s.Next) || !e.objectPointer(s.Desktops) {
				t.Fatalf("station %+v accepted", s)
			}
			if uint64(len(data)) < l.stationExtent() {
				t.Fatal("short station accepted")
			}
		}
		if d, err := e.desktopAt(r, fuzzBase); err == nil {
			if !e.objectPointer(d.Info) || !e.objectPointer(d.Next) || !e.objectPointer(d.Station) || d.Address != fuzzBase {
				t.Fatalf("desktop %+v accepted", d)
			}
		}
	})
}

func FuzzWindowText(f *testing.F) {
	f.Add(uint32(4), uint32(6), uint64(0x10), uint32(0x100), []byte("a\x00b\x00\x00\x00"))
	f.Add(uint32(0), uint32(0), uint64(0), uint32(0), []byte{})
	f.Add(uint32(5), uint32(6), uint64(0x10), uint32(0x100), []byte("a\x00b\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, length, maximum uint32, offset uint64, heapSize uint32, data []byte) {
		e := fuzzEnv(measured[1], limits.Limits{MaxTextBytes: 64, MaxNameBytes: 64})
		d := Desktop{HeapBase: fuzzBase, HeapSize: heapSize}
		buffer := fuzzBase + offset%0x1000
		r := flat{base: buffer, data: data}
		text, err := e.readText(r, d, length, maximum&textMaximumMask, buffer)
		if err != nil {
			if text != "" {
				t.Fatal("text with an error")
			}
			return
		}
		if length == 0 {
			if text != "" {
				t.Fatal("text from an empty descriptor")
			}
			return
		}
		if length%2 != 0 || length >= maximum&textMaximumMask || !inHeap(d, buffer, uint64(maximum&textMaximumMask)) ||
			length > 64 {
			t.Fatalf("descriptor %d/%d at 0x%x accepted", length, maximum, buffer)
		}
		if n := len(utf16.Encode([]rune(text))); n > int(length/2) {
			t.Fatalf("%d units from %d bytes", n, length)
		}
	})
}

func FuzzWindowWalk(f *testing.F) {
	l := measured[0]
	seed := make([]byte, 0x2000)
	win := func(at, self uint64) {
		binary.LittleEndian.PutUint64(seed[at+l.Window.Self:], fuzzBase+self)
		binary.LittleEndian.PutUint64(seed[at+l.Window.Desktop:], fuzzBase+0x1f00)
	}
	binary.LittleEndian.PutUint64(seed[l.DesktopInfoWindow:], fuzzBase+0x100)
	win(0x100, 0x100)
	win(0x400, 0x400)
	binary.LittleEndian.PutUint64(seed[0x100+l.Window.Child:], fuzzBase+0x400)
	binary.LittleEndian.PutUint64(seed[0x400+l.Window.Parent:], fuzzBase+0x100)
	f.Add(uint8(0), seed)
	f.Fuzz(func(t *testing.T, which uint8, data []byte) {
		l := measured[int(which)%len(measured)]
		lim := limits.Limits{MaxListEntries: 64, MaxRecursionDepth: 8, MaxTextBytes: 256, MaxNameBytes: 256}
		e := fuzzEnv(l, lim)
		e.spaces = map[uint32]memory.MemoryReader{0: flat{base: fuzzBase, data: data}}
		d := Desktop{Address: fuzzBase + 0x1f00, Info: fuzzBase, HeapBase: fuzzBase, HeapSize: uint32(len(data))}
		walk, err := e.Windows(d)
		if err != nil {
			t.Fatal(err)
		}
		if len(walk.Windows) > lim.MaxListEntries {
			t.Fatalf("%d windows", len(walk.Windows))
		}
		seen := map[uint64]bool{}
		for i, w := range walk.Windows {
			if seen[w.Address] {
				t.Fatalf("window 0x%x twice", w.Address)
			}
			seen[w.Address] = true
			if w.Depth > lim.MaxRecursionDepth || (i == 0) != (w.Depth == 0) {
				t.Fatalf("window %d depth %d", i, w.Depth)
			}
			if i > 0 && !seen[w.Parent] {
				t.Fatalf("window 0x%x before its parent 0x%x", w.Address, w.Parent)
			}
			if !w.TextReadable && w.Text != "" {
				t.Fatal("unreadable text kept")
			}
		}
	})
}
