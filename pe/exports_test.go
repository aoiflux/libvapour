package pe

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

const (
	exDir     = uint32(0x1000)
	exDirSize = uint32(0x800)
)

type exSlot struct {
	rva   uint32
	names []string
}

type exFixture struct {
	img   []byte
	dir   DataDirectory
	names map[string]uint32
}

// Slots are written in order; names go to the name table sorted as the
// specification requires, each pointing back at its slot.
func buildExports(base uint32, slots []exSlot, forwarders map[int]string) exFixture {
	return buildExportsAt(exDir, exDirSize, 0x4000, base, slots, forwarders)
}

func buildExportsAt(exDir, exDirSize uint32, imageSize int, base uint32, slots []exSlot, forwarders map[int]string) exFixture {
	img := make([]byte, imageSize)
	f := exFixture{img: img, dir: DataDirectory{exDir, exDirSize}, names: map[string]uint32{}}
	type named struct {
		name string
		slot int
	}
	var all []named
	for i, s := range slots {
		for _, n := range s.names {
			all = append(all, named{n, i})
		}
	}
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j].name < all[j-1].name; j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}
	eat := uint64(exDir) + ExportDirectorySize
	npt := eat + 4*uint64(len(slots))
	ot := npt + 4*uint64(len(all))
	strs := ot + 2*uint64(len(all))
	strs += strs % 2
	putString := func(s string) uint32 {
		at := strs
		copy(img[at:], s+"\x00")
		strs += uint64(len(s)) + 1
		return uint32(at)
	}
	put32(img, uint64(exDir)+12, putString("fixture.dll"))
	put32(img, uint64(exDir)+offExportOrdinalBase, base)
	put32(img, uint64(exDir)+offExportAddressEntries, uint32(len(slots)))
	put32(img, uint64(exDir)+offExportNamePointers, uint32(len(all)))
	put32(img, uint64(exDir)+offExportAddressTable, uint32(eat))
	put32(img, uint64(exDir)+offExportNamePointerRVA, uint32(npt))
	put32(img, uint64(exDir)+offExportOrdinalTable, uint32(ot))
	for i, s := range slots {
		rva := s.rva
		if fwd, ok := forwarders[i]; ok {
			rva = putString(fwd)
		}
		put32(img, eat+4*uint64(i), rva)
	}
	for i, n := range all {
		at := putString(n.name)
		f.names[n.name] = at
		put32(img, npt+4*uint64(i), at)
		put16(img, ot+2*uint64(i), uint16(n.slot))
	}
	return f
}

func TestExportsCarryTheirBiasedOrdinalInSlotOrder(t *testing.T) {
	f := buildExports(5, []exSlot{
		{0x2000, []string{"Zeta"}},
		{0, nil},
		{0x2010, nil},
		{0x2020, []string{"Beta", "Alpha"}},
		{0, []string{"Hollow"}},
	}, map[int]string{2: "OTHER.Target"})
	got, err := ParseExports(flat(f.img), f.dir, limits.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Export{
		{Name: "Zeta", Ordinal: 5, RVA: 0x2000},
		{Ordinal: 7, RVA: got[1].RVA, Forwarder: "OTHER.Target"},
		{Name: "Alpha", Ordinal: 8, RVA: 0x2020},
		{Name: "Beta", Ordinal: 8, RVA: 0x2020},
		{Name: "Hollow", Ordinal: 9},
	}
	if len(got) != len(want) {
		t.Fatalf("%d exports: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("export %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	if rva := uint64(got[1].RVA); rva < uint64(exDir) || rva >= uint64(exDir+exDirSize) {
		t.Errorf("forwarder RVA 0x%x outside the directory", rva)
	}
}

func TestLookupGivesAnAddressOnlyForCodeInThisImage(t *testing.T) {
	exports := []Export{
		{Name: "Fwd", Ordinal: 1, RVA: 0x1100, Forwarder: "NTDLL.Fwd"},
		{Name: "Lost", Ordinal: 2, RVA: 0x1200, ForwarderUnreadable: true},
		{Name: "Code", Ordinal: 3, RVA: 0x2000},
	}
	if at, ok := LookupExport(exports, "Code", 0x7FF800000000); !ok || at != 0x7FF800002000 {
		t.Errorf("Code: 0x%x %v", at, ok)
	}
	for _, name := range []string{"Fwd", "Lost", "code", "Absent"} {
		if _, ok := LookupExport(exports, name, 0x1000); ok {
			t.Errorf("%s resolved", name)
		}
	}
	if exports[2].Address(0x10000) != 0x12000 {
		t.Error("Address")
	}
}

func TestUnreadNamesAndForwardersAreFlaggedNotDropped(t *testing.T) {
	f := buildExports(1, []exSlot{{0x3100, []string{"Moved"}}, {0x2200, nil}}, nil)
	npt := uint64(exDir) + ExportDirectorySize + 2*4
	put32(f.img, npt, 0x2100)
	copy(f.img[0x2100:], "Moved\x00")
	copy(f.img[0x2200:], "A.B\x00")
	dir := DataDirectory{exDir, 0x2000}
	got, err := ParseExports(flat(f.img), dir, limits.Limits{})
	if err != nil || len(got) != 2 || got[0].Name != "Moved" || got[1].Forwarder != "A.B" {
		t.Fatalf("all pages read: %+v %v", got, err)
	}
	got, err = ParseExports(withHoles(f.img, 0x2000), dir, limits.Limits{})
	if err != nil || len(got) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	if !got[0].NameUnreadable || got[0].Name != "" || got[0].RVA != 0x3100 {
		t.Errorf("name on an unread page: %+v", got[0])
	}
	if !got[1].ForwarderUnreadable || got[1].Forwarder != "" {
		t.Errorf("forwarder on an unread page: %+v", got[1])
	}
	if _, ok := LookupExport(got, "", 0); ok {
		t.Error("an unread name resolved")
	}
}

func TestANameWhoseSlotIsPastTheAddressTableIsDropped(t *testing.T) {
	f := buildExports(1, []exSlot{{0x2000, []string{"A", "B"}}}, nil)
	ot := uint64(exDir) + ExportDirectorySize + 4 + 8
	put16(f.img, ot+2, 7)
	got, err := ParseExports(flat(f.img), f.dir, limits.Limits{})
	if err != nil || len(got) != 1 || got[0].Name != "A" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestExportDirectoryFailures(t *testing.T) {
	f := buildExports(1, []exSlot{{0x2000, []string{"A"}}, {0x2010, nil}}, nil)
	if _, err := ParseExports(flat(f.img), DataDirectory{}, limits.Limits{}); !errors.Is(err, ErrNoExportDirectory) {
		t.Errorf("no directory: %v", err)
	}
	if _, err := ParseExports(flat(f.img), f.dir, limits.Limits{MaxTableEntries: 1}); !errors.Is(err, ErrExportCountTooLarge) {
		t.Errorf("over MaxTableEntries: %v", err)
	}
	if _, err := ParseExports(flat(f.img), f.dir, limits.Limits{MaxBufferBytes: 4, MaxNameBytes: 4, MaxTextBytes: 4}); !errors.Is(err, ErrExportCountTooLarge) {
		t.Errorf("over MaxBufferBytes: %v", err)
	}
	wrap := append([]byte(nil), f.img...)
	put32(wrap, uint64(exDir)+offExportOrdinalBase, 0xFFFFFFFF)
	if _, err := ParseExports(flat(wrap), f.dir, limits.Limits{}); !errors.Is(err, ErrExportCountTooLarge) {
		t.Errorf("ordinals past 32 bits: %v", err)
	}
	if _, err := ParseExports(withHoles(f.img, 0x1000), f.dir, limits.Limits{}); !errors.Is(err, ErrUnreadable) {
		t.Errorf("unread directory: %v", err)
	}
	far := append([]byte(nil), f.img...)
	put32(far, uint64(exDir)+offExportAddressTable, 0x3FFC)
	if _, err := ParseExports(flat(far), f.dir, limits.Limits{}); !errors.Is(err, ErrOutsideImage) {
		t.Errorf("address table past the image: %v", err)
	}
}
