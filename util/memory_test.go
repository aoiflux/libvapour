package util

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/memory"
)

var errHole = errors.New("hole")

// Pages listed in holes cannot be read; reads stop short at the end of data.
type pagedReader struct {
	data  []byte
	base  uint64
	holes map[uint64]bool
	reads []uint64
}

func (p *pagedReader) ReadAt(off, n uint64) ([]byte, error) {
	p.reads = append(p.reads, off)
	if off < p.base {
		return nil, errHole
	}
	for page := off &^ 0xFFF; page < off+n; page += 0x1000 {
		if p.holes[page] {
			return nil, errHole
		}
	}
	start := off - p.base
	if start >= uint64(len(p.data)) {
		return nil, errHole
	}
	return p.data[start:min(start+n, uint64(len(p.data)))], nil
}

func (p *pagedReader) Size() uint64 { return p.base + uint64(len(p.data)) }

var _ memory.MemoryReader = (*pagedReader)(nil)

func TestRegionHashesMatchTheStandardDigests(t *testing.T) {
	data := []byte(strings.Repeat("vapour", 400000))
	r := &pagedReader{data: data}
	m, s1, s256 := md5.Sum(data[10:]), sha1.Sum(data[10:]), sha256.Sum256(data[10:])
	size := uint64(len(data) - 10)
	h, err := HashRegion(r, 10, size)
	if err != nil {
		t.Fatal(err)
	}
	want := RegionHashes{hex.EncodeToString(m[:]), hex.EncodeToString(s1[:]), hex.EncodeToString(s256[:])}
	if h != want {
		t.Errorf("HashRegion %+v, want %+v", h, want)
	}
	if len(r.reads) != 3 {
		t.Errorf("%d reads for %d bytes, want 3 of at most 1 MiB", len(r.reads), size)
	}
	for name, f := range map[string]func(memory.MemoryReader, uint64, uint64) (string, error){
		want.MD5: MD5Region, want.SHA1: SHA1Region, want.SHA256: SHA256Region,
	} {
		if got, err := f(r, 10, size); err != nil || got != name {
			t.Errorf("single digest %s %v, want %s", got, err, name)
		}
	}
	empty := sha256.Sum256(nil)
	if got, err := SHA256Region(r, 0, 0); err != nil || got != hex.EncodeToString(empty[:]) {
		t.Errorf("empty region: %s %v", got, err)
	}
}

func TestRegionHashesFailOnUnreadableOrShortRegions(t *testing.T) {
	r := &pagedReader{data: make([]byte, 0x3000), holes: map[uint64]bool{0x2000: true}}
	if _, err := HashRegion(r, 0, 0x3000); !errors.Is(err, errHole) {
		t.Errorf("hole: %v", err)
	}
	short := &pagedReader{data: make([]byte, 0x100)}
	if _, err := MD5Region(short, 0, 0x200); err == nil || !strings.HasPrefix(err.Error(), "util: ") {
		t.Errorf("short read: %v", err)
	}
}

func TestReadCStringEndsAtNULCountOrUnreadableMemory(t *testing.T) {
	data := make([]byte, 0x3000)
	copy(data[0xFF0:], "crossing-a-page\x00tail")
	copy(data[0x2000:], "abc")
	r := &pagedReader{data: data, base: 0x10000}
	for _, c := range []struct {
		name         string
		addr, count  uint64
		limit        uint64
		want         string
		err          error
		wantReadsMax int
	}{
		{"spans a page", 0x10FF0, 64, 64, "crossing-a-page", nil, 2},
		{"count cuts it", 0x10FF0, 5, 64, "cross", nil, 1},
		{"NUL first", 0x12FFD, 16, 64, "", nil, 1},
		{"limit exceeded", 0x10FF0, 64, 4, "", ErrStringPastLimit, 2},
		{"limit met exactly", 0x10FF0, 64, 15, "crossing-a-page", nil, 2},
	} {
		r.reads = nil
		got, err := ReadCString(r, c.addr, c.count, c.limit)
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("%s: %q %v, want %q %v", c.name, got, err, c.want, c.err)
		}
		if len(r.reads) > c.wantReadsMax {
			t.Errorf("%s: %d reads, want at most %d", c.name, len(r.reads), c.wantReadsMax)
		}
	}
	open := make([]byte, 0x1004)
	copy(open[0xFFC:], "wxyz")
	cut := &pagedReader{data: open, holes: map[uint64]bool{0x1000: true}}
	if got, err := ReadCString(cut, 0xFFC, 64, 64); err != nil || got != "wxyz" {
		t.Errorf("text before an unreadable page: %q %v", got, err)
	}
	if _, err := ReadCString(cut, 0x1000, 8, 64); !errors.Is(err, errHole) {
		t.Errorf("unreadable start: %v", err)
	}
	if _, err := ReadCString(cut, 0, 0, 64); err == nil {
		t.Error("count 0 gives no error")
	}
	bad := &pagedReader{data: []byte{0xE2, 0x82, 'a', 0}}
	if got, _ := ReadCString(bad, 0, 4, 64); got != rc+"a" {
		t.Errorf("ill-formed bytes: %q", got)
	}
}

func putUnicodeString(b []byte, at uint64, l UnicodeStringLayout, length, maximum uint16, buffer uint64) {
	binary.LittleEndian.PutUint16(b[at+l.LengthOffset:], length)
	binary.LittleEndian.PutUint16(b[at+l.MaximumLengthOffset:], maximum)
	if l.Size-l.BufferOffset == 4 {
		binary.LittleEndian.PutUint32(b[at+l.BufferOffset:], uint32(buffer))
	} else {
		binary.LittleEndian.PutUint64(b[at+l.BufferOffset:], buffer)
	}
}

func TestReadUnicodeStringForBothPointerWidths(t *testing.T) {
	text := utf16le('l', 's', 'a', 's', 's', 0)
	for _, l := range []UnicodeStringLayout{abiUnicodeStringLayout(8), abiUnicodeStringLayout(4)} {
		data := make([]byte, 0x200)
		copy(data[0x100:], text)
		putUnicodeString(data, 0x20, l, 10, 12, 0x100)
		s, err := ReadUnicodeString(&pagedReader{data: data}, 0x20, l, 0)
		if err != nil {
			t.Fatalf("layout %+v: %v", l, err)
		}
		if s.Length != 10 || s.MaximumLength != 12 || s.Buffer != 0x100 || s.Value != "lsass" || s.Chars() != 5 || s.MaxChars() != 5 {
			t.Errorf("layout %+v: %+v chars %d max %d", l, s, s.Chars(), s.MaxChars())
		}
	}
}

func TestReadUnicodeStringReadsOnlyTheMembers(t *testing.T) {
	l := abiUnicodeStringLayout(8)
	data := make([]byte, 0x1000)
	putUnicodeString(data, 0xFF0, l, 0, 0, 0)
	s, err := ReadUnicodeString(&pagedReader{data: data}, 0xFF0, l, 0)
	if err != nil || s.Value != "" {
		t.Errorf("structure at a page end: %+v %v", s, err)
	}
}

func TestReadUnicodeStringEdgeCases(t *testing.T) {
	l := abiUnicodeStringLayout(8)
	data := make([]byte, 0x20000)
	r := &pagedReader{data: data, holes: map[uint64]bool{0x8000: true}}

	putUnicodeString(data, 0, l, 4, 4, 0)
	if _, err := ReadUnicodeString(r, 0, l, 0); err == nil || !strings.Contains(err.Error(), "null buffer") {
		t.Errorf("null buffer: %v", err)
	}

	putUnicodeString(data, 0x10, l, 4, 4, 0x8000)
	s, err := ReadUnicodeString(r, 0x10, l, 0)
	if !errors.Is(err, errHole) || s.Length != 4 || s.Buffer != 0x8000 {
		t.Errorf("unreadable buffer: %+v %v", s, err)
	}

	for i := range 0x8000 {
		binary.LittleEndian.PutUint16(data[0x10000+2*i:], 'A')
	}
	putUnicodeString(data, 0x20, l, 0xFFFF, 0xFFFF, 0x10000)
	s, err = ReadUnicodeString(r, 0x20, l, 0)
	if err != nil || len(s.Value) != 0x7FFF+len(rc) || !strings.HasSuffix(s.Value, rc) {
		t.Errorf("Length 0xFFFF: %d bytes, %v", len(s.Value), err)
	}
	s, _ = ReadUnicodeString(r, 0x20, l, 8)
	if s.Value != "AAAA" {
		t.Errorf("cap of 8 bytes: %q", s.Value)
	}

	if _, err := ReadUnicodeString(nil, 0, l, 0); err == nil {
		t.Error("nil reader")
	}
	if _, err := ReadUnicodeString(&pagedReader{data: make([]byte, 8)}, 0, l, 0); err == nil {
		t.Error("structure cut short gives no error")
	}
	if got := (UnicodeString{MaximumLength: 1}).MaxChars(); got != 0 {
		t.Errorf("MaxChars of 1 byte: %d", got)
	}
}

func TestTextKeepsInnerNULsVisible(t *testing.T) {
	s := UnicodeString{Value: "a.exe\x00-k\x00"}
	if s.Text() != "a.exe"+VisibleNUL+"-k" {
		t.Errorf("%q", s.Text())
	}
}

func TestResolveUnicodeStringLayoutWithoutATable(t *testing.T) {
	if got := ResolveUnicodeStringLayout(nil); got != (UnicodeStringLayout{0, 2, 8, 16}) {
		t.Errorf("%+v", got)
	}
}
