package linuxobj_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

type image struct {
	class   int
	base    uint64
	vaddr   uint64
	dynamic uint64
	debug   uint64
}

func (im image) word() uint64 { return uint64(im.class / 8) }

func (im image) put(m *lt.Memory, at, v uint64) {
	if im.class == 64 {
		m.U64(at, v)
		return
	}
	m.U32(at, uint32(v))
}

func (im image) write(m *lt.Memory) {
	le := binary.LittleEndian
	var h []byte
	if im.class == 64 {
		h = make([]byte, 64+2*56)
		h[4] = 2
		le.PutUint16(h[16:], 3)
		le.PutUint16(h[18:], 62)
		le.PutUint64(h[32:], 64)
		le.PutUint16(h[54:], 56)
		le.PutUint16(h[56:], 2)
		p := h[64:]
		le.PutUint32(p, 1)
		le.PutUint64(p[16:], im.vaddr)
		le.PutUint64(p[40:], 0x3000)
		p = h[64+56:]
		le.PutUint32(p, 2)
		le.PutUint64(p[16:], im.vaddr+im.dynamic)
		le.PutUint64(p[40:], 0x40)
	} else {
		h = make([]byte, 52+2*32)
		h[4] = 1
		le.PutUint16(h[16:], 2)
		le.PutUint16(h[18:], 3)
		le.PutUint32(h[28:], 52)
		le.PutUint16(h[42:], 32)
		le.PutUint16(h[44:], 2)
		p := h[52:]
		le.PutUint32(p, 1)
		le.PutUint32(p[8:], uint32(im.vaddr))
		le.PutUint32(p[20:], 0x3000)
		le.PutUint32(p[24:], 5)
		p = h[52+32:]
		le.PutUint32(p, 2)
		le.PutUint32(p[8:], uint32(im.vaddr+im.dynamic))
		le.PutUint32(p[20:], 0x40)
	}
	copy(h, "\x7fELF")
	h[5], h[6] = 1, 1
	m.Write(im.base, h)
	w := im.word()
	dyn := im.base + im.dynamic
	im.put(m, dyn, 3)
	im.put(m, dyn+w, 0x1234)
	im.put(m, dyn+2*w, 21)
	im.put(m, dyn+3*w, im.debug)
	im.put(m, dyn+4*w, 0)
	m.Map(dyn+5*w, 0x40)
}

func (im image) entry(m *lt.Memory, at, bias, name, next uint64, path string) {
	w := im.word()
	im.put(m, at, bias)
	im.put(m, at+w, name)
	im.put(m, at+2*w, bias+0x2000)
	im.put(m, at+3*w, next)
	if path != "" {
		m.Write(name, append([]byte(path), 0))
	}
}

func TestELF64ImageGivesItsSegmentsAndLibraryList(t *testing.T) {
	m := lt.NewMemory()
	im := image{class: 64, base: 0x555555554000, dynamic: 0x2000, debug: 0x555555560000}
	im.write(m)
	m.U32(im.debug, 1)
	m.U64(im.debug+8, 0x555555570000)
	im.entry(m, 0x555555570000, 0, 0x555555580000, 0x555555570100, "")
	im.entry(m, 0x555555570100, 0x7f0000000000, 0x555555580100, 0x555555570200, "/usr/lib/libc.so.6")
	im.entry(m, 0x555555570200, 0x7f0000100000, 0x555555580200, 0x555555570100, "/usr/lib/ld-linux-x86-64.so.2")

	e, ok, err := linuxobj.ParseELF(m, im.base)
	if err != nil || !ok || e.Class != 64 || e.Type != 3 || e.Machine != 62 || e.PhNum != 2 {
		t.Fatalf("ParseELF: %+v %v %v", e, ok, err)
	}
	segs, err := e.LoadSegments()
	if err != nil || len(segs) != 1 || segs[0].Vaddr != 0 || segs[0].Memsz != 0x3000 {
		t.Errorf("LoadSegments: %+v %v", segs, err)
	}
	headers, _ := e.ProgramHeaders(16)
	if bias, ok := e.LoadBias(headers); !ok || bias != im.base {
		t.Errorf("LoadBias %#x %v", bias, ok)
	}
	got, err := e.LinkMap(16)
	if err != nil {
		t.Fatal(err)
	}
	var biases []uint64
	for _, g := range got {
		biases = append(biases, g.LoadBias)
	}
	if !slices.Equal(biases, []uint64{0, 0x7f0000000000, 0x7f0000100000}) || got[1].Dynamic != 0x7f0000002000 {
		t.Errorf("entries %+v, want three, stopping at the revisited one", got)
	}
	if name, ok := e.NameAt(got[2].Name, 4096); !ok || name != "/usr/lib/ld-linux-x86-64.so.2" {
		t.Errorf("name %q %v", name, ok)
	}
	if got, _ := e.LinkMap(2); len(got) != 2 {
		t.Errorf("cap of 2: %d entries", len(got))
	}
}

func TestELF32ExecutableHasNoBias(t *testing.T) {
	m := lt.NewMemory()
	im := image{class: 32, base: 0x08048000, vaddr: 0x08048000, dynamic: 0x2000, debug: 0x08060000}
	im.write(m)
	m.U32(im.debug, 1)
	m.U32(im.debug+4, 0x08070000)
	im.entry(m, 0x08070000, 0xf7f00000, 0x08080000, 0, "/lib/libc.so.6")
	e, ok, err := linuxobj.ParseELF(m, im.base)
	if err != nil || !ok || e.Class != 32 || e.Type != 2 {
		t.Fatalf("ParseELF: %+v %v %v", e, ok, err)
	}
	headers, err := e.ProgramHeaders(16)
	if err != nil || len(headers) != 2 || headers[0].Flags != 5 || headers[0].Vaddr != 0x08048000 {
		t.Errorf("headers %+v %v", headers, err)
	}
	if bias, ok := e.LoadBias(headers); !ok || bias != 0 {
		t.Errorf("LoadBias %#x %v", bias, ok)
	}
	got, err := e.LinkMap(16)
	if err != nil || len(got) != 1 || got[0].LoadBias != 0xf7f00000 {
		t.Errorf("entries %+v %v", got, err)
	}
}

func TestELFIdentificationsThatAreRefused(t *testing.T) {
	m := lt.NewMemory()
	m.Write(0x1000, []byte("not an elf at all"))
	if _, ok, err := linuxobj.ParseELF(m, 0x1000); ok || err != nil {
		t.Errorf("no magic: %v %v", ok, err)
	}
	if _, ok, err := linuxobj.ParseELF(m, 0x9000); ok || err != nil {
		t.Errorf("unmapped: %v %v", ok, err)
	}
	for _, id := range []string{"\x7fELF\x09\x01", "\x7fELF\x02\x02"} {
		m.Write(0x2000, append([]byte(id), make([]byte, 64)...))
		if _, ok, err := linuxobj.ParseELF(m, 0x2000); ok || !errors.Is(err, linuxobj.ErrELFClass) {
			t.Errorf("%q: %v %v", id, ok, err)
		}
	}
	m.Write(0x3ff0, []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	if _, ok, err := linuxobj.ParseELF(m, 0x3ff0); ok || !errors.Is(err, linuxobj.ErrELFRead) {
		t.Errorf("header across an unmapped page: %v %v", ok, err)
	}
}

func TestELFTablesThatDoNotRead(t *testing.T) {
	m := lt.NewMemory()
	im := image{class: 64, base: 0x400000, dynamic: 0x2000, debug: 0x500000}
	im.write(m)
	m.U32(im.debug, 1)
	m.U64(im.debug+8, 0x600000)
	im.entry(m, 0x600000, 0x7f0000000000, 0x700000, 0x900000, "/lib/a.so")
	e, _, _ := linuxobj.ParseELF(m, im.base)
	got, err := e.LinkMap(16)
	if len(got) != 1 || !errors.Is(err, linuxobj.ErrELFRead) {
		t.Errorf("entry that does not read: %+v %v", got, err)
	}
	m.Write(0x700000, bytes.Repeat([]byte{'x'}, 32))
	if _, ok := e.NameAt(0x700000, 16); ok {
		t.Errorf("name with no NUL in 16 bytes read")
	}
	m.Write(im.base+54, []byte{8, 0})
	e, _, _ = linuxobj.ParseELF(m, im.base)
	if _, err := e.ProgramHeaders(16); !errors.Is(err, linuxobj.ErrELFRead) {
		t.Errorf("short program header entries: %v", err)
	}
}

func FuzzELF(f *testing.F) {
	m := lt.NewMemory()
	image{class: 64, base: 0x400000, dynamic: 0x2000, debug: 0x500000}.write(m)
	seed, _ := m.ReadAt(0x400000, 64+2*56)
	f.Add(seed)
	f.Add([]byte("\x7fELF\x01\x01\x01"))
	f.Fuzz(func(t *testing.T, data []byte) {
		m := lt.NewMemory()
		m.Write(0x400000, data)
		m.Write(0x402000, data)
		m.Write(0x500000, data)
		e, ok, err := linuxobj.ParseELF(m, 0x400000)
		if err != nil || !ok {
			return
		}
		headers, _ := e.ProgramHeaders(64)
		_, _ = e.LoadBias(headers)
		_, _ = e.LoadSegments()
		maps, _ := e.LinkMap(64)
		for _, lm := range maps {
			_, _ = e.NameAt(lm.Name, 256)
		}
	})
}
