package ntfsrecord

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/profiles"
)

const (
	atRestored  = 0x1000
	atProtected = 0x2400
	atUnaligned = 0x3004
	atGarbage   = 0x5000
	atBoundary  = scanWindow - 0x200
	atSecond    = scanWindow + 0x800
)

func fixtureImage() flat {
	img := make(flat, 2*scanWindow)
	copy(img[atRestored:], sampleRecord().restored())
	copy(img[atProtected:], sampleRecord().protected())
	copy(img[atUnaligned:], sampleRecord().restored())
	copy(img[atGarbage:], "FILE\xff\xff")
	copy(img[atBoundary:], sampleRecord().restored())
	other := sampleRecord()
	other.flags = 0
	other.segment = 42
	other.attrs = other.attrs[:1]
	copy(img[atSecond:], other.restored())
	copy(img[len(img)-0x200:], sampleRecord().restored())
	return img
}

func TestScanFindsEveryAlignedRecord(t *testing.T) {
	res := scanMemory(fixtureImage(), 0)
	var got []uint64
	for _, r := range res.records {
		got = append(got, r.physical)
	}
	want := []uint64{atRestored, atProtected, atBoundary, atSecond}
	if len(got) != len(want) {
		t.Fatalf("records at %#x, want %#x", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("records at %#x, want %#x", got, want)
		}
	}
	if res.candidates != 6 {
		t.Errorf("%d candidates, want 6 (the unaligned copy is not one)", res.candidates)
	}
	if res.rejected.count[errArray] != 1 || res.rejected.first[errArray] != atGarbage {
		t.Errorf("array rejections %v", res.rejected.count)
	}
	if res.rejected.count[errTruncated] != 1 {
		t.Errorf("truncated rejections %v", res.rejected.count)
	}
	if res.records[1].fixup != FixupProtected || res.records[0].fixup != FixupRestored {
		t.Errorf("fixups %s %s", res.records[0].fixup, res.records[1].fixup)
	}
}

func TestScanCapsSignaturesPerWindow(t *testing.T) {
	res := scanMemory(fixtureImage(), 2)
	if res.crowded.count[errCrowded] != 1 || res.crowded.first[errCrowded] != atGarbage {
		t.Fatalf("crowded %v first %v", res.crowded.count, res.crowded.first)
	}
	if len(res.records) != 3 {
		t.Errorf("%d records, want 3", len(res.records))
	}
}

func TestRunRows(t *testing.T) {
	var diags []string
	rows, err := Run(fixtureContext(fixtureImage(), &diags))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3*3+1 {
		t.Fatalf("%d rows, want 10", len(rows))
	}
	si, dos, long := rows[0], rows[1], rows[2]
	used := binary.LittleEndian.Uint32(sampleRecord().restored()[0x18:])
	h := RecordHeader{RecordPhysical: atRestored, SegmentNumber: 116130, SegmentNumberKnown: true, SequenceNumber: 3,
		LinkCount: 1, BytesInUse: used, BytesAllocated: 1024, Flags: flagInUse, InUse: true, Fixup: FixupRestored}
	if si.RecordHeader != h {
		t.Errorf("header %+v, want %+v", si.RecordHeader, h)
	}
	if si.AttributeType != "$STANDARD_INFORMATION" || si.AttributeOffset != fixtureFirst || si.Name != "mem7_server2025.mem" ||
		!si.NameKnown || si.FileAttributes != 0x20 || !si.CreationTime.Equal(fixtureT1) || !si.LastWriteTime.Equal(fixtureT2) ||
		!si.ChangeTime.Equal(fixtureT3) || !si.LastAccessTime.Equal(fixtureT4) || si.Namespace != "" {
		t.Errorf("standard information row %+v", si)
	}
	if dos.AttributeType != "$FILE_NAME" || dos.Name != "MEM7_S~1.MEM" || dos.Namespace != NamespaceDOS ||
		dos.ParentSegmentNumber != 0x1234 || dos.ParentSequenceNumber != 5 || !dos.LastAccessTime.Equal(fixtureT1) {
		t.Errorf("short name row %+v", dos)
	}
	if long.Namespace != NamespaceNTFS || long.AttributeOffset <= dos.AttributeOffset {
		t.Errorf("long name row %+v", long)
	}
	if rows[3].RecordPhysical != atProtected || rows[3].Fixup != FixupProtected {
		t.Errorf("second record row %+v", rows[3].RecordHeader)
	}
	last := rows[9]
	if last.RecordPhysical != atSecond || last.NameKnown || last.Name != "" || last.InUse {
		t.Errorf("unnamed record row %+v", last)
	}
	joined := strings.Join(diags, "\n")
	for _, want := range []string{
		"windows.ntfs.scan_records: 6 FILE signatures at 8-byte multiples, 4 parsed as file record segments",
		"windows.ntfs.scan_records: 1 candidate records rejected, first at 0x5000: " + errArray.Error(),
		"windows.ntfs.scan_records: 1 candidate records rejected, first at 0x1ffe00: " + errTruncated.Error(),
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("diagnostics lack %q:\n%s", want, joined)
		}
	}
}

func TestRunStreamsAndResidentData(t *testing.T) {
	var diags []string
	ctx := fixtureContext(fixtureImage(), &diags)
	streams, err := RunStreams(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(streams) != 3 {
		t.Fatalf("%d stream rows, want 3", len(streams))
	}
	s := streams[0]
	if s.StreamName != "Zone.Identifier" || s.Name != "mem7_server2025.mem" || !s.NameKnown ||
		string(s.Value) != "[ZoneTransfer]\r\nZoneId=3\r\n" || s.RecordPhysical != atRestored {
		t.Errorf("stream row %+v", s)
	}
	data, err := RunResidentData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 3 || string(data[0].Value) != "resident body" || data[0].Name != "mem7_server2025.mem" {
		t.Errorf("data rows %+v", data)
	}
}

func TestAttributeRejectionsAreCounted(t *testing.T) {
	f := sampleRecord()
	f.attrs[0] = resident(codeStandardInformation, "", standardValue([4]time.Time{}, 0, 0x20))
	img := make(flat, 0x2000)
	copy(img[0x800:], f.restored())
	var diags []string
	rows, err := Run(fixtureContext(img, &diags))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].AttributeType != "$FILE_NAME" {
		t.Fatalf("rows %+v", rows)
	}
	want := "windows.ntfs.scan_records: 1 attributes not read, first in the record at 0x800: " + errStandardShort.Error()
	if !strings.Contains(strings.Join(diags, "\n"), want) {
		t.Errorf("diagnostics lack %q: %v", want, diags)
	}
}

func TestRunRefusals(t *testing.T) {
	var diags []string
	if _, err := Run(fixtureContext(nil, &diags)); !errors.Is(err, ErrNoPhysicalMemory) {
		t.Errorf("no physical memory: %v", err)
	}
	ctx := fixtureContext(fixtureImage(), &diags)
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); !errors.Is(err, ErrNotWindows) {
		t.Errorf("linux profile: %v", err)
	}
}

func TestUnreadableMemory(t *testing.T) {
	img := holed{flat: fixtureImage(), from: scanWindow + 0x1100, to: scanWindow + 0x1110}
	var diags []string
	ctx := fixtureContext(img, &diags)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatalf("lenient run: %v", err)
	}
	if len(rows) != 9 {
		t.Errorf("%d rows, want 9 (the second window is lost)", len(rows))
	}
	if !strings.Contains(strings.Join(diags, "\n"), "windows.ntfs.scan_records: physical memory not fully scanned: ") {
		t.Errorf("no coverage diagnostic: %v", diags)
	}
	ctx.Options["strict"] = true
	rows, err = Run(ctx)
	if !errors.Is(err, errHole) || len(rows) != 9 {
		t.Errorf("strict run: %d rows, %v", len(rows), err)
	}
}

func TestLimitsCapApplies(t *testing.T) {
	var diags []string
	ctx := fixtureContext(fixtureImage(), &diags)
	ctx.Limits = limits.Limits{MaxMatchesPerChunk: 2}
	if _, err := Run(ctx); err != nil {
		t.Fatal(err)
	}
	want := "windows.ntfs.scan_records: 1 windows over MaxMatchesPerChunk (2), first signature dropped at 0x5000"
	if !strings.Contains(strings.Join(diags, "\n"), want) {
		t.Errorf("diagnostics lack %q: %v", want, diags)
	}
}
