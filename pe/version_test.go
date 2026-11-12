package pe

import (
	"encoding/binary"
	"errors"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/limits"
)

const rsDir = uint32(0x1000)

type rsWriter struct {
	img  []byte
	next uint32
}

type rsEntry struct {
	id     uint32
	name   string
	target uint32
}

// table writes a directory table and returns its offset from the resource
// directory; named entries come first, as the specification orders them.
func (w *rsWriter) table(entries []rsEntry) uint32 {
	at := w.next
	named := 0
	for _, e := range entries {
		if e.name != "" {
			named++
		}
	}
	put16(w.img, uint64(rsDir+at)+offResourceNameEntries, uint16(named))
	put16(w.img, uint64(rsDir+at)+offResourceIDEntries, uint16(len(entries)-named))
	w.next += resourceTableSize + uint32(len(entries))*resourceEntrySize
	for i, e := range entries {
		id := e.id
		if e.name != "" {
			id = w.str(e.name) | resourceSubdirectory
		}
		put32(w.img, uint64(rsDir+at+resourceTableSize)+uint64(i)*resourceEntrySize, id)
		put32(w.img, uint64(rsDir+at+resourceTableSize)+uint64(i)*resourceEntrySize+4, e.target)
	}
	return at
}

func (w *rsWriter) str(s string) uint32 {
	at := w.next
	units := utf16.Encode([]rune(s))
	put16(w.img, uint64(rsDir+at), uint16(len(units)))
	for i, u := range units {
		put16(w.img, uint64(rsDir+at)+2+2*uint64(i), u)
	}
	w.next += 2 + 2*uint32(len(units))
	w.next += w.next % 4
	return at
}

func (w *rsWriter) leaf(rva, size, codePage uint32) uint32 {
	at := w.next
	put32(w.img, uint64(rsDir+at), rva)
	put32(w.img, uint64(rsDir+at)+4, size)
	put32(w.img, uint64(rsDir+at)+8, codePage)
	w.next += resourceDataEntrySize
	return at
}

func sub(off uint32) uint32 { return off | resourceSubdirectory }

func buildResources() ([]byte, map[string]uint32) {
	w := &rsWriter{img: make([]byte, 0x6000), next: 0x800}
	at := map[string]uint32{}
	custom := w.table([]rsEntry{{id: 0, target: w.leaf(0x3000, 0x100, 1200)}})
	german := w.leaf(0x3200, 0x200, 1252)
	english := w.leaf(0x3400, 0x300, 1200)
	at["languages"] = w.table([]rsEntry{{id: 0x407, target: german}, {id: 0x409, target: english}})
	at["names"] = w.table([]rsEntry{{name: "CUSTOM", target: sub(custom)}, {id: 1, target: sub(at["languages"])}})
	icons := w.table([]rsEntry{{id: 1, target: sub(custom)}})
	mui := w.table([]rsEntry{{id: 1, target: sub(custom)}})
	root := w.next
	w.next = 0
	w.table([]rsEntry{{name: "MUI", target: sub(mui)}, {id: 3, target: sub(icons)}, {id: RTVersion, target: sub(at["names"])}})
	w.next = root
	return w.img, at
}

func TestVersionLeavesComeInTreeOrder(t *testing.T) {
	img, _ := buildResources()
	got, err := FindResources(flat(img), DataDirectory{rsDir, 0x1000}, RTVersion, limits.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	if !got[0].NameIsString || got[0].Language != 0 || got[0].RVA != 0x3000 || got[0].Name&resourceSubdirectory != 0 {
		t.Errorf("named leaf: %+v", got[0])
	}
	if got[1] != (ResourceData{Name: 1, Language: 0x407, RVA: 0x3200, Size: 0x200, CodePage: 1252}) ||
		got[2] != (ResourceData{Name: 1, Language: 0x409, RVA: 0x3400, Size: 0x300, CodePage: 1200}) {
		t.Errorf("ID leaves: %+v %+v", got[1], got[2])
	}
	if _, err := FindResources(flat(img), DataDirectory{rsDir, 0x1000}, 24, limits.Limits{}); !errors.Is(err, ErrNoResource) {
		t.Errorf("absent type: %v", err)
	}
	if _, err := FindResources(flat(img), DataDirectory{}, RTVersion, limits.Limits{}); !errors.Is(err, ErrNoResourceDirectory) {
		t.Errorf("no directory: %v", err)
	}
	if _, err := FindResources(flat(img), DataDirectory{rsDir, 0x1000}, RTVersion, limits.Limits{MaxTableEntries: 4}); !errors.Is(err, ErrResourceLimit) {
		t.Errorf("limit: %v", err)
	}
}

func TestAnUnreadSubtreeIsPassedOver(t *testing.T) {
	img, at := buildResources()
	moved := uint32(0x2000)
	copy(img[rsDir+moved:], img[rsDir+at["languages"]:rsDir+at["languages"]+32])
	put32(img, uint64(rsDir+at["names"]+resourceTableSize+resourceEntrySize+4), sub(moved))
	got, err := FindResources(withHoles(img, 0x3000), DataDirectory{rsDir, 0x3000}, RTVersion, limits.Limits{})
	if err != nil || len(got) != 1 || !got[0].NameIsString {
		t.Fatalf("%+v %v", got, err)
	}
	put32(img, uint64(rsDir+at["names"]+resourceTableSize+4), sub(moved))
	if _, err := FindResources(withHoles(img, 0x3000), DataDirectory{rsDir, 0x3000}, RTVersion, limits.Limits{}); !errors.Is(err, ErrUnreadable) {
		t.Errorf("every subtree unread: %v", err)
	}
}

func versionInfo(rva uint32, fixed FixedFileInfo) []byte {
	b := make([]byte, 0x200)
	value := valueOffset(rva)
	put16(b, 0, uint16(value+FixedFileInfoSize+0x40))
	put16(b, 2, FixedFileInfoSize)
	copy(b[versionHeaderBytes:], versionKeyBytes)
	for i, v := range []uint32{fixed.Signature, fixed.StrucVersion, fixed.FileVersionMS, fixed.FileVersionLS,
		fixed.ProductVersionMS, fixed.ProductVersionLS, fixed.FileFlagsMask, fixed.FileFlags, fixed.FileOS,
		fixed.FileType, fixed.FileSubtype, fixed.FileDateMS, fixed.FileDateLS} {
		binary.LittleEndian.PutUint32(b[value+4*i:], v)
	}
	return b
}

var vsFixed = FixedFileInfo{Signature: FixedFileInfoSignature, StrucVersion: 0x10000,
	FileVersionMS: 10 << 16, FileVersionLS: 26100<<16 | 2454, ProductVersionMS: 10 << 16, ProductVersionLS: 26100<<16 | 1,
	FileFlagsMask: 0x3F, FileOS: 0x40004, FileType: 2}

func TestTheFixedInfoFollowsTheKeyAlignedToFourBytes(t *testing.T) {
	for _, rva := range []uint32{0x3000, 0x3002, 0x3001} {
		info, err := ParseVersionInfo(versionInfo(rva, vsFixed), rva)
		if err != nil || info != vsFixed {
			t.Fatalf("rva 0x%x: %+v %v", rva, info, err)
		}
	}
	if valueOffset(0x3000) != 40 || valueOffset(0x3002) != 38 {
		t.Error("padding")
	}
	if v := vsFixed.FileVersion(); v != [4]uint16{10, 0, 26100, 2454} {
		t.Errorf("FileVersion %v", v)
	}
	if v := vsFixed.ProductVersion(); v != [4]uint16{10, 0, 26100, 1} {
		t.Errorf("ProductVersion %v", v)
	}
}

func TestVersionInfoFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
		want error
	}{
		{"short", func(b []byte) []byte { return b[:4] }, ErrBadVersionInfo},
		{"wLength inside the key", func(b []byte) []byte { put16(b, 0, 20); return b }, ErrBadVersionInfo},
		{"other key", func(b []byte) []byte { b[versionHeaderBytes] = 'X'; return b }, ErrBadVersionInfo},
		{"no value", func(b []byte) []byte { put16(b, 2, 0); return b }, ErrNoFixedFileInfo},
		{"short value", func(b []byte) []byte { put16(b, 2, 40); return b }, ErrBadVersionInfo},
		{"value past wLength", func(b []byte) []byte { put16(b, 0, 60); return b }, ErrBadVersionInfo},
		{"value past the buffer", func(b []byte) []byte { return b[:80] }, ErrBadVersionInfo},
		{"signature", func(b []byte) []byte { b[40] ^= 1; return b }, ErrBadFixedFileInfoSignature},
	} {
		if _, err := ParseVersionInfo(tc.edit(versionInfo(0x3000, vsFixed)), 0x3000); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestReadVersionNeedsOnlyTheBytesUpToTheFixedInfo(t *testing.T) {
	img, _ := buildResources()
	copy(img[0x3000:], []byte("not a version resource"))
	copy(img[0x3400:], versionInfo(0x3400, vsFixed)[:0x200])
	dir := DataDirectory{rsDir, 0x1000}
	info, err := ReadVersion(withHoles(img, 0x4000), dir, limits.Limits{})
	if err != nil || info != vsFixed {
		t.Fatalf("%+v %v", info, err)
	}
	if _, err := ReadVersion(withHoles(img, 0x3000), dir, limits.Limits{}); !errors.Is(err, ErrUnreadable) {
		t.Errorf("every leaf unread: %v", err)
	}
}
