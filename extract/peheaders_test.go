package extract

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/aoiflux/libvapour/pe"
)

type mapped struct {
	base    uint64
	data    []byte
	missing map[uint64]bool
}

func (m mapped) ReadAt(addr, size uint64) ([]byte, error) {
	if addr < m.base || addr-m.base > uint64(len(m.data)) || size > uint64(len(m.data))-(addr-m.base) {
		return nil, fmt.Errorf("0x%x outside the image", addr)
	}
	for a := addr &^ (pageSize - 1); a < addr+size; a += pageSize {
		if m.missing[a] {
			return nil, fmt.Errorf("page 0x%x not mapped", a)
		}
	}
	return m.data[addr-m.base : addr-m.base+size], nil
}

func (m mapped) Size() uint64 { return m.base + uint64(len(m.data)) }

// A PE32+ header per the PE format: MZ with e_lfanew at 0x3C, the PE
// signature, a 20-byte file header and a 240-byte optional header.
func peImage(size int, lfanew uint32, sections uint16) []byte {
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b, 0x5A4D)
	binary.LittleEndian.PutUint32(b[0x3C:], lfanew)
	nt := int(lfanew)
	if nt+4+20+240 > size {
		return b
	}
	binary.LittleEndian.PutUint32(b[nt:], 0x00004550)
	binary.LittleEndian.PutUint16(b[nt+4:], 0x8664)
	binary.LittleEndian.PutUint16(b[nt+6:], sections)
	binary.LittleEndian.PutUint16(b[nt+20:], 240)
	binary.LittleEndian.PutUint16(b[nt+24:], 0x20B)
	binary.LittleEndian.PutUint32(b[nt+24+56:], 0x10000)
	for i := range int(sections) {
		s := nt + 24 + 240 + 40*i
		if s+40 <= size {
			copy(b[s:], fmt.Sprintf(".s%d", i))
		}
	}
	return b
}

const imageBase = uint64(0x7FF600000000)

func TestHeadersInTheFirstPage(t *testing.T) {
	h, err := ReadHeaders(mapped{base: imageBase, data: peImage(0x2000, 0x80, 3), missing: map[uint64]bool{imageBase + 0x1000: true}}, imageBase)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Sections) != 3 || h.Optional.SizeOfImage != 0x10000 || h.Sections[2].Name != ".s2" {
		t.Errorf("headers %+v", h)
	}
}

func TestHeadersPastTheFirstPageGetASecondRead(t *testing.T) {
	img := mapped{base: imageBase, data: peImage(0x3000, 0xF00, 4)}
	h, err := ReadHeaders(img, imageBase)
	if err != nil {
		t.Fatal(err)
	}
	if h.HeaderSpan() <= HeaderProbeSize || len(h.Sections) != 4 {
		t.Errorf("span 0x%x, %d sections", h.HeaderSpan(), len(h.Sections))
	}
	img.missing = map[uint64]bool{imageBase + 0x1000: true}
	if _, err := ReadHeaders(img, imageBase); !errors.Is(err, ErrHeadersUnreadable) {
		t.Errorf("second page unmapped: %v", err)
	}
}

func TestUnreadFirstPage(t *testing.T) {
	img := mapped{base: imageBase, data: peImage(0x1000, 0x80, 1), missing: map[uint64]bool{imageBase: true}}
	if _, err := ReadHeaders(img, imageBase); !errors.Is(err, ErrHeadersUnreadable) {
		t.Errorf("%v", err)
	}
}

func TestUnalignedBaseStopsAtTheGap(t *testing.T) {
	data := append(make([]byte, 0x800), peImage(0x1800, 0x80, 1)...)
	img := mapped{base: imageBase, data: data, missing: map[uint64]bool{imageBase + 0x1000: true}}
	if _, err := ReadHeaders(img, imageBase+0x800); err != nil {
		t.Errorf("headers inside the readable half page: %v", err)
	}
	data = append(make([]byte, 0x800), peImage(0x1800, 0x700, 2)...)
	img.data = data
	if _, err := ReadHeaders(img, imageBase+0x800); !errors.Is(err, ErrHeadersUnreadable) {
		t.Errorf("headers crossing into the unread page: %v", err)
	}
}

func TestHeaderSpanCap(t *testing.T) {
	_, err := ReadHeaders(mapped{base: imageBase, data: peImage(0x1000, 0x20000, 1)}, imageBase)
	var short *pe.TruncatedError
	if err == nil || errors.Is(err, ErrHeadersUnreadable) || !errors.As(err, &short) {
		t.Errorf("e_lfanew past the cap: %v", err)
	}
}

func TestNotAnImage(t *testing.T) {
	if _, err := ReadHeaders(mapped{base: imageBase, data: make([]byte, 0x1000)}, imageBase); !errors.Is(err, pe.ErrNotPE) {
		t.Errorf("%v", err)
	}
}

func FuzzReadHeaders(f *testing.F) {
	f.Add(peImage(0x2000, 0x80, 2), uint8(0))
	f.Add(peImage(0x3000, 0xF00, 4), uint8(2))
	f.Add([]byte("MZ"), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, holes uint8) {
		missing := map[uint64]bool{}
		for i := range 8 {
			if holes&(1<<i) != 0 {
				missing[imageBase+uint64(i)*pageSize] = true
			}
		}
		h, err := ReadHeaders(mapped{base: imageBase, data: data, missing: missing}, imageBase)
		if err != nil {
			return
		}
		span := h.HeaderSpan()
		if span > MaxHeaderSpan || span > uint64(len(data)) {
			t.Fatalf("span 0x%x from %d bytes", span, len(data))
		}
		for a := uint64(0); a < span; a += pageSize {
			if missing[imageBase+a] {
				t.Fatalf("headers decoded across unread page 0x%x", a)
			}
		}
	})
}
