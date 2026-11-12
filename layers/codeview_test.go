package layers

import (
	"encoding/binary"
	"strings"
	"testing"
)

// writeImage lays out headers, a debug directory and an RSDS record in three
// pages from at, as an image loaded at at would hold them.
func writeImage(buf []byte, at uint64, pdb string, magic uint16) {
	hdr := buf[at : at+0x1000]
	copy(hdr, "MZ")
	binary.LittleEndian.PutUint32(hdr[0x3c:], 0x80)
	copy(hdr[0x80:], "PE\x00\x00")
	optional := uint64(0x80 + 4 + 20)
	dirs := uint64(peDirectories64)
	size := uint16(0xf0)
	if magic == peMagic32 {
		dirs, size = peDirectories32, 0xe0
	}
	binary.LittleEndian.PutUint16(hdr[0x80+4+16:], size)
	binary.LittleEndian.PutUint16(hdr[optional:], magic)
	binary.LittleEndian.PutUint32(hdr[optional+dirs-4:], 16)
	binary.LittleEndian.PutUint32(hdr[optional+dirs+6*8:], 0x1000)
	binary.LittleEndian.PutUint32(hdr[optional+dirs+6*8+4:], 2*28)
	dir := buf[at+0x1000:]
	binary.LittleEndian.PutUint32(dir[12:], 4)
	binary.LittleEndian.PutUint32(dir[28+12:], 2)
	binary.LittleEndian.PutUint32(dir[28+16:], uint32(24+len(pdb)+1))
	binary.LittleEndian.PutUint32(dir[28+20:], 0x2000)
	rec := buf[at+0x2000:]
	copy(rec, "RSDS")
	for i := range 16 {
		rec[4+i] = byte(0x10 + i)
	}
	binary.LittleEndian.PutUint32(rec[20:], 3)
	copy(rec[24:], pdb+"\x00")
}

func TestImageCodeViewsReadsTheRSDSRecord(t *testing.T) {
	for _, magic := range []uint16{peMagic64, peMagic32} {
		img := newPhys(0x10000)
		writeImage(img.buf, 0x4000, `d:\build\ntkrnlmp.pdb`, magic)
		recs, err := ImageCodeViews(img, 0x4000)
		if err != nil || len(recs) != 1 {
			t.Fatalf("magic 0x%x: %+v, %v", magic, recs, err)
		}
		r := recs[0]
		if r.PDBPath != `d:\build\ntkrnlmp.pdb` || r.Age != 3 || r.GUID[0] != 0x10 || r.GUID[15] != 0x1f {
			t.Fatalf("record %+v", r)
		}
	}
}

func TestImageCodeViewsRefusesWhatIsNotAnImage(t *testing.T) {
	cases := map[string]func(b []byte){
		"no MZ":                  func(b []byte) { b[0] = 'X' },
		"no PE signature":        func(b []byte) { b[0x81] = 'X' },
		"PE past the first page": func(b []byte) { binary.LittleEndian.PutUint32(b[0x3c:], 0xff0) },
		"unknown magic":          func(b []byte) { binary.LittleEndian.PutUint16(b[0x98:], 0x107) },
		"short optional header":  func(b []byte) { binary.LittleEndian.PutUint16(b[0x94:], 0x90) },
		"empty debug directory":  func(b []byte) { binary.LittleEndian.PutUint32(b[0x98+112+48:], 0) },
		"six directories":        func(b []byte) { binary.LittleEndian.PutUint32(b[0x98+108:], 6) },
		"no directories":         func(b []byte) { binary.LittleEndian.PutUint32(b[0x98+108:], 0) },
		"no CodeView entry":      func(b []byte) { binary.LittleEndian.PutUint32(b[0x98+112+48:], 0x9000) },
	}
	for name, spoil := range cases {
		img := newPhys(0x10000)
		writeImage(img.buf, 0x4000, "ntkrnlmp.pdb", peMagic64)
		spoil(img.buf[0x4000:])
		if recs, err := ImageCodeViews(img, 0x4000); err == nil && len(recs) > 0 {
			t.Errorf("%s: %+v", name, recs)
		}
	}
}

func TestSevenDirectoriesAreEnoughForTheDebugEntry(t *testing.T) {
	img := newPhys(0x10000)
	writeImage(img.buf, 0x4000, "ntkrnlmp.pdb", peMagic64)
	binary.LittleEndian.PutUint32(img.buf[0x4000+0x98+108:], 7)
	if recs, err := ImageCodeViews(img, 0x4000); err != nil || len(recs) != 1 {
		t.Fatalf("%+v, %v", recs, err)
	}
}

func TestARecordWithoutItsNULIsSkipped(t *testing.T) {
	img := newPhys(0x10000)
	writeImage(img.buf, 0x4000, "ntkrnlmp.pdb", peMagic64)
	copy(img.buf[0x6000+24:], strings.Repeat("a", 0x40))
	binary.LittleEndian.PutUint32(img.buf[0x5000+28+16:], 24+0x20)
	if recs, err := ImageCodeViews(img, 0x4000); err != nil || len(recs) != 0 {
		t.Fatalf("%+v, %v", recs, err)
	}
}
