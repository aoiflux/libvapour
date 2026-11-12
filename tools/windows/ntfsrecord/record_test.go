package ntfsrecord

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestRestoredRecordParses(t *testing.T) {
	b := sampleRecord().restored()
	r, err := parseRecord(0x5000, b)
	if err != nil {
		t.Fatal(err)
	}
	if r.fixup != FixupRestored || r.physical != 0x5000 || r.sequence != 3 || r.flags != flagInUse ||
		!r.segmentKnown || r.segment != 116130 || r.base.segment != 0 {
		t.Fatalf("header = %+v", r)
	}
	codes := []uint32{codeStandardInformation, codeFileName, codeFileName, codeData, codeData, codeData}
	if len(r.attributes) != len(codes) {
		t.Fatalf("got %d attributes, want %d", len(r.attributes), len(codes))
	}
	for i, a := range r.attributes {
		if a.typeCode != codes[i] {
			t.Errorf("attribute %d type 0x%x, want 0x%x", i, a.typeCode, codes[i])
		}
	}
	if r.attributes[0].offset != fixtureFirst {
		t.Errorf("first attribute at 0x%x", r.attributes[0].offset)
	}
	if a := r.attributes[4]; a.name != "Zone.Identifier" || !a.resident || string(a.value) != "[ZoneTransfer]\r\nZoneId=3\r\n" {
		t.Errorf("named data = %+v", a)
	}
	if a := r.attributes[5]; a.resident || a.name != "big" || a.value != nil {
		t.Errorf("nonresident data = %+v", a)
	}
}

func TestProtectedRecordIsRestoredFromTheArray(t *testing.T) {
	f := sampleRecord()
	want := f.restored()
	got := f.protected()
	r, err := parseRecord(0, got)
	if err != nil {
		t.Fatal(err)
	}
	if r.fixup != FixupProtected {
		t.Fatalf("fixup %s, want %s", r.fixup, FixupProtected)
	}
	if !bytes.Equal(r.attributes[0].value, want[r.attributes[0].offset+0x18:r.attributes[0].offset+0x18+0x48]) {
		t.Error("standard information changed by the restore")
	}
	if got[510] != byte(fixtureUSN) {
		t.Error("parse wrote into the caller's bytes")
	}
}

func TestFixupFormFromStrides(t *testing.T) {
	cases := []struct {
		name  string
		tails []strideTail
		used  int
		want  FixupForm
	}{
		{"no stride held the number", []strideTail{{510, false}, {1022, false}}, 900, FixupRestored},
		{"every read stride held it", []strideTail{{510, true}, {1022, true}}, 1024, FixupProtected},
		{"the stride past the end lost it", []strideTail{{510, true}, {1022, false}}, 600, FixupProtected},
		{"a read stride lost it", []strideTail{{510, true}, {1022, false}}, 1024, FixupTorn},
		{"only a stride past the end held it", []strideTail{{510, false}, {1022, true}}, 600, FixupRestored},
		{"tails equal to both say nothing", nil, 1024, FixupRestored},
	}
	for _, c := range cases {
		if got := fixupForm(c.tails, c.used); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func fullRecord() fixtureRecord {
	f := sampleRecord()
	f.attrs = []fixtureAttr{
		resident(codeStandardInformation, "", standardValue([4]time.Time{fixtureT1, fixtureT1, fixtureT1, fixtureT1}, 0, 0x48)),
		resident(codeData, "", bytes.Repeat([]byte{0xab}, 840)),
	}
	return f
}

func TestTornRecordIsKeptAndMarked(t *testing.T) {
	b := fullRecord().protected()
	binary.LittleEndian.PutUint16(b[1022:], 0x1111)
	r, err := parseRecord(0, b)
	if err != nil {
		t.Fatal(err)
	}
	if r.fixup != FixupTorn {
		t.Fatalf("fixup %s, want %s", r.fixup, FixupTorn)
	}
}

func TestRecordRejections(t *testing.T) {
	put16 := func(at int, v uint16) func([]byte) {
		return func(b []byte) { binary.LittleEndian.PutUint16(b[at:], v) }
	}
	put32 := func(at int, v uint32) func([]byte) {
		return func(b []byte) { binary.LittleEndian.PutUint32(b[at:], v) }
	}
	attr := fixtureFirst
	cases := []struct {
		name  string
		edit  func([]byte)
		trim  int
		want  error
		setup func() fixtureRecord
	}{
		{name: "signature", edit: func(b []byte) { copy(b, "BAAD") }, want: errSignature},
		{name: "array before the header end", edit: put16(4, 0x28), want: errArray},
		{name: "array odd", edit: put16(4, 0x31), want: errArray},
		{name: "array past the first sector", edit: put16(4, 0x1fc), want: errArray},
		{name: "one stride", edit: put16(6, 2), want: errSize},
		{name: "more than a page", edit: put16(6, 10), want: errSize},
		{name: "truncated", trim: 1, want: errTruncated},
		{name: "first attribute misaligned", edit: put16(0x14, fixtureFirst+4), want: errFirstAttribute},
		{name: "first attribute inside the array", edit: put16(0x14, 0x30), want: errFirstAttribute},
		{name: "first attribute past the record", edit: put16(0x14, 0x400), want: errFirstAttribute},
		{name: "length not a quadword multiple", edit: put32(attr+4, 0x5c), want: errAttributeSize},
		{name: "length below the resident header", edit: put32(attr+4, 0x10), want: errAttributeSize},
		{name: "length past the record", edit: put32(attr+4, 0x800), want: errAttributeSize},
		{name: "form code", edit: func(b []byte) { b[attr+8] = 2 }, want: errForm},
		{name: "name past the attribute", edit: func(b []byte) { b[attr+9] = 40 }, want: errAttributeName},
		{name: "value inside the header", edit: put16(attr+0x14, 0x10), want: errValue},
		{name: "value past the attribute", edit: put32(attr+0x10, 0x60), want: errValue},
		{name: "no end marker", edit: func(b []byte) {
			end := int(le32(b, 0x18)) - 8
			binary.LittleEndian.PutUint32(b[end:], 0x100)
			binary.LittleEndian.PutUint32(b[end+4:], uint32(len(b)-end))
			binary.LittleEndian.PutUint16(b[end+0x14:], residentHeader)
		}, want: errNoEnd},
		{name: "type codes decrease", setup: func() fixtureRecord {
			f := sampleRecord()
			f.attrs[0], f.attrs[1] = f.attrs[1], f.attrs[0]
			return f
		}, want: errTypeOrder},
		{name: "nonresident shorter than its form", setup: func() fixtureRecord {
			f := sampleRecord()
			f.attrs = []fixtureAttr{{code: codeData, length: 0x40}}
			return f
		}, want: errAttributeSize},
	}
	for _, c := range cases {
		f := sampleRecord()
		if c.setup != nil {
			f = c.setup()
		}
		b := f.restored()
		if c.edit != nil {
			c.edit(b)
		}
		b = b[:len(b)-c.trim]
		if _, err := parseRecord(0, b); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

func TestStandardInformationTimesAndAttributes(t *testing.T) {
	ts := [4]time.Time{fixtureT1, fixtureT2, fixtureT3, {}}
	si, err := resident(codeStandardInformation, "", standardValue(ts, 0x40020, 0x30)).parsed().standardInformation()
	if err != nil {
		t.Fatal(err)
	}
	if !si.creation.Equal(fixtureT1) || !si.lastWrite.Equal(fixtureT2) || !si.change.Equal(fixtureT3) ||
		!si.lastAccess.IsZero() || si.fileAttributes != 0x40020 {
		t.Fatalf("got %+v", si)
	}
	if si.creation.Location() != time.UTC {
		t.Error("time not in UTC")
	}
	if _, err := resident(codeStandardInformation, "", standardValue(ts, 0, 0x2f)).parsed().standardInformation(); !errors.Is(err, errStandardShort) {
		t.Errorf("short: %v", err)
	}
	if _, err := (attribute{typeCode: codeStandardInformation}).standardInformation(); !errors.Is(err, errStandardForm) {
		t.Errorf("nonresident: %v", err)
	}
}

func (a fixtureAttr) parsed() attribute {
	b := a.bytes()
	got, _, err := readAttribute(b, a.code)
	if err != nil {
		panic(err)
	}
	return got
}

func TestFileNameFields(t *testing.T) {
	ts := [4]time.Time{fixtureT1, fixtureT2, fixtureT3, fixtureT4}
	for flags, want := range map[uint8]Namespace{0: NamespaceNeither, 1: NamespaceNTFS, 2: NamespaceDOS, 3: NamespaceNTFSAndDOS} {
		fn, err := resident(codeFileName, "", nameValue(0x0000_1234_5678, 9, ts, flags, "a.txt")).parsed().fileName()
		if err != nil {
			t.Fatal(err)
		}
		if fn.namespace != want || fn.name != "a.txt" || fn.parent.segment != 0x1234_5678 || fn.parent.sequence != 9 ||
			!fn.creation.Equal(fixtureT1) || !fn.lastAccess.Equal(fixtureT4) {
			t.Errorf("flags %d: %+v", flags, fn)
		}
	}
	bad := nameValue(5, 5, ts, 4, "x")
	if _, err := resident(codeFileName, "", bad).parsed().fileName(); !errors.Is(err, errNameFlags) {
		t.Errorf("flags 4: %v", err)
	}
	long := nameValue(5, 5, ts, 1, "abc")
	long[0x40] = 4
	if _, err := resident(codeFileName, "", long).parsed().fileName(); !errors.Is(err, errNameLength) {
		t.Errorf("long name: %v", err)
	}
	if _, err := resident(codeFileName, "", make([]byte, 0x41)).parsed().fileName(); !errors.Is(err, errNameShort) {
		t.Errorf("short: %v", err)
	}
	if _, err := (attribute{typeCode: codeFileName}).fileName(); !errors.Is(err, errNameForm) {
		t.Errorf("nonresident: %v", err)
	}
}

func TestPreferredName(t *testing.T) {
	n := func(ns Namespace, s string) fileName { return fileName{namespace: ns, name: s} }
	cases := []struct {
		names []fileName
		want  string
		known bool
	}{
		{nil, "", false},
		{[]fileName{n(NamespaceDOS, "A~1.TXT"), n(NamespaceNTFS, "a long.txt")}, "a long.txt", true},
		{[]fileName{n(NamespaceDOS, "A~1.TXT"), n(NamespaceNeither, "link")}, "link", true},
		{[]fileName{n(NamespaceNeither, "one"), n(NamespaceNeither, "two")}, "one", true},
		{[]fileName{n(NamespaceNTFSAndDOS, "short.txt")}, "short.txt", true},
		{[]fileName{n(NamespaceDOS, "ONLY~1")}, "ONLY~1", true},
	}
	for _, c := range cases {
		got, known := preferredName(c.names)
		if got != c.want || known != c.known {
			t.Errorf("%v: %q %v, want %q %v", c.names, got, known, c.want, c.known)
		}
	}
}

func TestFiletime(t *testing.T) {
	var b [8]byte
	if !filetime(b[:]).IsZero() {
		t.Error("zero is not absent")
	}
	binary.LittleEndian.PutUint64(b[:], 116444736000000000)
	if got := filetime(b[:]); !got.Equal(time.Unix(0, 0)) {
		t.Errorf("unix epoch: %v", got)
	}
	binary.LittleEndian.PutUint64(b[:], ticksOf(fixtureT1))
	if got := filetime(b[:]); !got.Equal(fixtureT1) {
		t.Errorf("got %v, want %v", got, fixtureT1)
	}
}

func TestSegmentNumberNeedsTheArrayAtThirtyHex(t *testing.T) {
	b := sampleRecord().restored()
	words := le16(b, 6)
	moved := make([]byte, len(b))
	copy(moved, b)
	copy(moved[headerSize:], b[fixtureArray:fixtureArray+2*int(words)])
	binary.LittleEndian.PutUint16(moved[4:], headerSize)
	r, err := parseRecord(0, moved)
	if err != nil {
		t.Fatal(err)
	}
	if r.segmentKnown {
		t.Error("segment number read from an array at 0x2a")
	}
}
