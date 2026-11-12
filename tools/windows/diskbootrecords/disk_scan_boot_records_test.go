package diskbootrecords

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

type sparse struct {
	size  uint64
	data  map[uint64][]byte
	holes map[uint64]bool
}

func newSparse(size uint64) *sparse {
	return &sparse{size: size, data: map[uint64][]byte{}, holes: map[uint64]bool{}}
}

func (s *sparse) Size() uint64 { return s.size }

func (s *sparse) ReadAt(off, n uint64) ([]byte, error) {
	if off+n > s.size {
		return nil, memory.ErrOutOfBounds
	}
	for p := off / pageBytes; p <= (off+n-1)/pageBytes; p++ {
		if s.holes[p] {
			return nil, errors.New("page not captured")
		}
	}
	out := make([]byte, n)
	for at, b := range s.data {
		for i, c := range b {
			if a := at + uint64(i); a >= off && a < off+n {
				out[a-off] = c
			}
		}
	}
	return out, nil
}

func (s *sparse) put(at uint64, b []byte) { s.data[at] = b }

type part struct {
	indicator, systemID uint8
	relative, total     uint32
}

func mbr(sig uint32, code byte, parts ...part) []byte {
	b := make([]byte, recordSize)
	for i := range 0x40 {
		b[i] = code
	}
	binary.LittleEndian.PutUint32(b[signatureOffset:], sig)
	for i, p := range parts {
		e := b[tableOffset+i*entrySize:]
		e[0], e[1], e[2], e[3] = p.indicator, 1, 1, 0
		e[4], e[5], e[6], e[7] = p.systemID, 0xFE, 0xFF, 0xFF
		binary.LittleEndian.PutUint32(e[8:], p.relative)
		binary.LittleEndian.PutUint32(e[12:], p.total)
	}
	b[markerOffset], b[markerOffset+1] = 0x55, 0xAA
	return b
}

func context(phys memory.MemoryReader, opts map[string]any) tools.Context {
	o := map[string]any{tools.OptionPhysicalMemory: phys}
	for k, v := range opts {
		o[k] = v
	}
	return tools.Context{Memory: phys, Symbols: symbols.NewTable("s66", 8), Profile: profiles.WindowsX64Profile{}, Options: o}
}

var ntfs = part{indicatorActive, 0x07, 2048, 1 << 20}

func TestARecordIsListedWithItsInUseEntries(t *testing.T) {
	m := newSparse(1 << 20)
	m.put(0x3000, mbr(0x12345678, 0x90, ntfs, part{0, 0x0F, 2048 + 1<<20, 4096}))
	rows, err := Run(context(m, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows %d, want a record and two entries", len(rows))
	}
	r := rows[0]
	if r.Depth != 0 || r.Offset != 0x3000 || r.DiskSignature != "12345678" || !r.ValidTable || r.TableProblem != "" {
		t.Errorf("record row %+v", r)
	}
	if len(r.Bootcode) != bootCodeSize || len(r.BootcodeMD5) != 32 || len(r.FullMBRMD5) != 32 || r.BootcodeMD5 == r.FullMBRMD5 {
		t.Errorf("hashes %q %q, boot code %d bytes", r.BootcodeMD5, r.FullMBRMD5, len(r.Bootcode))
	}
	if !strings.HasPrefix(r.Disasm, "0000 nop") {
		t.Errorf("listing starts %q", r.Disasm[:min(20, len(r.Disasm))])
	}
	p := rows[1]
	if p.Depth != 1 || p.PartitionIndex != 1 || !p.Bootable || p.PartitionTypeRaw != 7 ||
		p.PartitionType != "Installable File System (NTFS)" || p.RelativeSectors != 2048 || p.TotalSectors != 1<<20 {
		t.Errorf("first entry %+v", p)
	}
	if rows[2].PartitionIndex != 2 || rows[2].Bootable || rows[2].PartitionType != "Extended (INT 13h extensions)" {
		t.Errorf("second entry %+v", rows[2])
	}
}

func TestCHSFieldsSplitTheCylinderAcrossTwoBytes(t *testing.T) {
	e := parseEntry([]byte{0x80, 0xFE, 0xFF, 0xFF, 0x07, 0x10, 0xC1, 0x02, 0, 0, 0, 0, 0, 0, 0, 0}, 1)
	if e.startHead != 0xFE || e.startSector != 63 || e.startCylinder != 1023 {
		t.Errorf("start %d/%d/%d", e.startCylinder, e.startHead, e.startSector)
	}
	if e.endHead != 0x10 || e.endSector != 1 || e.endCylinder != 0x302 {
		t.Errorf("end %d/%d/%d", e.endCylinder, e.endHead, e.endSector)
	}
}

func TestEachTableRuleRefusesItsCase(t *testing.T) {
	cases := map[string][]byte{
		"boot indicator": mbr(1, 0x90, part{0x01, 0x07, 2048, 10}),
		"unused but not": func() []byte {
			b := mbr(1, 0x90, ntfs)
			b[tableOffset+entrySize+8] = 1
			return b
		}(),
		"no sectors":         mbr(1, 0x90, part{0, 0x07, 2048, 0}),
		"starts at the boot": mbr(1, 0x90, part{0, 0x07, 0, 10}),
		"runs past 2^32":     mbr(1, 0x90, part{0, 0x07, 0xFFFFFF00, 0x200}),
		"overlap":            mbr(1, 0x90, part{0, 0x07, 2048, 100}, part{0, 0x07, 2100, 100}),
		"no entry in use":    mbr(1, 0x90),
		"2 active entries":   mbr(1, 0x90, part{0x80, 0x07, 2048, 10}, part{0x80, 0x07, 4096, 10}),
		"CHS sector 0": func() []byte {
			b := mbr(1, 0x90, ntfs)
			b[tableOffset+2] = 0xC0
			return b
		}(),
	}
	for want, b := range cases {
		rec, ok := parseRecord(b)
		if !ok {
			t.Fatalf("%s: marker not seen", want)
		}
		if got := rec.tableProblem(); !strings.Contains(got, want) {
			t.Errorf("%s: problem %q", want, got)
		}
	}
	rec, _ := parseRecord(mbr(1, 0x90, part{0, 0xEE, 1, 0xFFFFFFFF}))
	if p := rec.tableProblem(); p != "" {
		t.Errorf("protective record refused: %s", p)
	}
}

func TestABrokenTableIsListedOnlyWithFull(t *testing.T) {
	m := newSparse(1 << 20)
	m.put(0x1000, mbr(1, 0x90, part{0x80, 0x07, 2048, 10}, part{0x80, 0x07, 4096, 10}))
	ctx := context(m, nil)
	var diags []string
	ctx.Options["diagnostics"] = &diags
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
	rows, err = Run(context(m, map[string]any{OptionFull: true}))
	if err != nil || len(rows) != 3 || rows[0].ValidTable || rows[0].TableProblem != "2 active entries" {
		t.Fatalf("full: rows %+v, err %v", rows, err)
	}
}

func TestARecordAcrossAChunkEndIsFoundOnce(t *testing.T) {
	for _, at := range []uint64{chunkBytes - 512, chunkBytes - 511, chunkBytes - 510, chunkBytes - 300, chunkBytes} {
		m := newSparse(2*chunkBytes + pageBytes)
		m.put(at, mbr(uint32(at), 0x90, ntfs))
		rows, err := Run(context(m, nil))
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 || rows[0].Offset != at {
			t.Errorf("record at %#x: rows %d, first at %#x", at, len(rows), rows[0].Offset)
		}
	}
}

func TestPagesThatDoNotReadAreCountedAndStrictModeFails(t *testing.T) {
	m := newSparse(1 << 20)
	m.put(0x2000, mbr(1, 0x90, ntfs))
	m.put(0x4F00, mbr(2, 0x90, ntfs))
	m.holes[4] = true
	ctx := context(m, nil)
	var diags []string
	ctx.Options["diagnostics"] = &diags
	rows, err := Run(ctx)
	if err != nil || len(rows) != 2 || rows[0].Offset != 0x2000 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
	joined := strings.Join(diags, "\n")
	if !strings.Contains(joined, "at 0x4000: 1 pages did not read") || !strings.Contains(joined, "1 records end in 0x55AA but lie partly") {
		t.Errorf("diagnostics %q", diags)
	}
	ctx = context(m, map[string]any{"strict": true})
	if _, err := Run(ctx); !errors.Is(err, ErrUnreadMemory) {
		t.Errorf("strict: %v", err)
	}
}

func TestTheRecordLimitStopsTheScan(t *testing.T) {
	m := newSparse(1 << 20)
	m.put(0x1000, mbr(1, 0x90, ntfs))
	m.put(0x3000, mbr(2, 0x90, ntfs))
	ctx := context(m, nil)
	ctx.Limits.MaxRowsPerObject = 1
	rows, err := Run(ctx)
	if err != nil || len(rows) != 2 || rows[0].Offset != 0x1000 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
}

func TestRefusals(t *testing.T) {
	m := newSparse(4096)
	ctx := context(m, nil)
	delete(ctx.Options, tools.OptionPhysicalMemory)
	if _, err := Run(ctx); !errors.Is(err, ErrNoPhysicalMemory) {
		t.Errorf("no physical layer: %v", err)
	}
	if _, err := Run(context(m, map[string]any{OptionFull: "maybe"})); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("bad full: %v", err)
	}
}

func TestTheListingDecodesRealModeAndShowsBytesItCannotDecode(t *testing.T) {
	code := []byte{0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0x0F, 0xFF}
	got, whole := listBootCode(code, 1<<10)
	want := "0000 xor ax, ax\n0002 mov ss, ax\n0004 mov sp, 0x7c00"
	if !whole || !strings.HasPrefix(got, want) || !strings.HasSuffix(got, "db 0xff") {
		t.Errorf("listing %q", got)
	}
	if cut, whole := listBootCode(code, 20); whole || len(cut) > 20 {
		t.Errorf("cut listing %q whole %v", cut, whole)
	}
}

func TestTheToolIsRegisteredWithItsOption(t *testing.T) {
	if _, err := tools.Get(Name); err != nil {
		t.Fatalf("%s: %v", Name, err)
	}
}
