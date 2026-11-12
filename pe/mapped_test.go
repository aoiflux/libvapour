package pe

import (
	"errors"
	"strings"
	"testing"
)

func TestMappedReaderKeepsReadsInsideTheImage(t *testing.T) {
	img := make([]byte, 0x3000)
	copy(img[0x10:], "abcd")
	read := MappedReader(sliceReader(append(make([]byte, 0x500), img...)), 0x500, 0x3000)
	if b, err := read(0x10, 4); err != nil || string(b) != "abcd" {
		t.Fatalf("%q %v", b, err)
	}
	if b, err := read(0x2FFF, 0); err != nil || len(b) != 0 {
		t.Errorf("empty read: %v %v", b, err)
	}
	for _, tc := range []struct {
		rva uint32
		n   int
	}{{0x2FFF, 2}, {0x3000, 1}, {0, -1}, {0xFFFFFFFF, 2}} {
		if _, err := read(tc.rva, tc.n); !errors.Is(err, ErrOutsideImage) {
			t.Errorf("rva 0x%x+%d: %v", tc.rva, tc.n, err)
		}
	}
	short := MappedReader(shortReader{}, 0, 0x1000)
	if _, err := short(0, 8); !errors.Is(err, ErrUnreadable) {
		t.Errorf("short read: %v", err)
	}
	failing := withHoles(img, 0x1000)
	_, err := failing(0xFF0, 0x20)
	if !errors.Is(err, ErrUnreadable) || !strings.Contains(err.Error(), "holes:") {
		t.Errorf("failed read keeps neither sentinel nor cause: %v", err)
	}
}

type shortReader struct{}

func (shortReader) ReadAt(offset, size uint64) ([]byte, error) { return make([]byte, size/2), nil }

func TestAStringReadsUpToAnUnreadPageOrTheImageEnd(t *testing.T) {
	img := make([]byte, 0x3000)
	copy(img[0xFF0:], "ends-before-the-hole\x00")
	copy(img[0x1FF8:], "crosses-into-the-hole")
	copy(img[0x2FF8:], "lastone\x00")
	copy(img[0x500:], "across-pages")
	read := withHoles(img, 0x2000)
	if s, err := readString(read, 0xFF0, 4096); err != nil || s != "ends-before-the-hole" {
		t.Errorf("%q %v", s, err)
	}
	if _, err := readString(read, 0x1FF8, 4096); !errors.Is(err, ErrUnreadable) {
		t.Errorf("into the hole: %v", err)
	}
	if s, err := readString(flat(img), 0x2FF8, 4096); err != nil || s != "lastone" {
		t.Errorf("image end: %q %v", s, err)
	}
	copy(img[0xFF8:], "abcdefgh")
	copy(img[0x1000:], "ijkl\x00")
	if s, err := readString(flat(img), 0xFF8, 4096); err != nil || s != "abcdefghijkl" {
		t.Errorf("page boundary: %q %v", s, err)
	}
	if s, err := readString(flat(img), 0xFF8, 12); err != nil || s != "abcdefghijkl" {
		t.Errorf("at the limit: %q %v", s, err)
	}
	if _, err := readString(flat(img), 0xFF8, 11); !errors.Is(err, ErrUnterminatedString) {
		t.Errorf("past the limit: %v", err)
	}
	if _, err := readString(flat(img[:0x504]), 0x500, 4096); !errors.Is(err, ErrOutsideImage) {
		t.Errorf("no NUL before the image end: %v", err)
	}
}
