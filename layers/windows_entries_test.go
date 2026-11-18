package layers

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

func softwareTable(low, high [2]uint8, members ...string) *symbols.Table {
	bits := func(name string, at [2]uint8) symbols.Field {
		return symbols.Field{Name: name, Type: symbols.TypeRef{Name: "unsigned __int64", BitOffset: at[0], BitLength: at[1]}}
	}
	fields := []symbols.Field{bits("Valid", [2]uint8{0, 1}), bits("PageFileLow", low), bits("PageFileHigh", high)}
	for _, m := range members {
		fields = append(fields, bits(m, [2]uint8{4, 1}))
	}
	t := symbols.NewTable("s53", 8)
	t.AddStruct(symbols.StructType{Name: "_MMPTE_SOFTWARE", Size: 8, Fields: fields})
	return t
}

func TestThePagefileLayoutIsCheckedAgainstTheKernelsTypes(t *testing.T) {
	old := [2]uint8{1, 4}
	high := [2]uint8{32, 32}
	for name, low := range map[string][2]uint8{"14393": old, "19045": {12, 4}} {
		if err := CheckPagefilePTELayout(softwareTable(low, high)); err != nil {
			t.Errorf("the %s layout without a swizzle member: %v", name, err)
		}
	}
	for name, table := range map[string]*symbols.Table{
		"PageFileLow on Protection": softwareTable([2]uint8{5, 4}, high),
		"SwizzleBit":                softwareTable(old, high, "SwizzleBit"),
		"no type":                   symbols.NewTable("s53", 8),
	} {
		if err := CheckPagefilePTELayout(table); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	mask := softwareTable(old, high)
	mask.AddStruct(symbols.StructType{Name: "_MI_HARDWARE_STATE", Size: 0x100, Fields: []symbols.Field{{Name: "InvalidPteMask", Offset: 0xc0}}})
	if err := CheckPagefilePTELayout(mask); err == nil {
		t.Error("InvalidPteMask: accepted")
	}
	if err := CheckPagefilePTELayout(nil); err == nil {
		t.Error("no table: accepted")
	}
}

func TestThePagefileFieldsAreReadAtTheBitsTheKernelDeclares(t *testing.T) {
	high := [2]uint8{32, 32}
	layout19045, err := ReadSoftwareLayout(softwareTable([2]uint8{12, 4}, high, "SwizzleBit"))
	if err != nil {
		t.Fatalf("the 19045 layout: %v", err)
	}
	layout14393, err := ReadSoftwareLayout(softwareTable([2]uint8{1, 4}, high))
	if err != nil || layout14393 != DefaultSoftwareLayout {
		t.Fatalf("the 14393 layout: %+v, %v", layout14393, err)
	}
	entry := uint64(0x0000001200000000) | 5<<12 | 3<<1 | 4<<5
	for _, c := range []struct {
		name   string
		layout SoftwareLayout
		file   int
	}{{"19045", layout19045, 5}, {"14393", layout14393, 3}} {
		img := newPhys(0x100000)
		pt := newTables(img, ModeX64.WithSoftwareLayout(c.layout), 0x1000, 0x2000)
		pt.set(3, kva, entry)
		pagefile := newPhys(0x13000)
		pagefile.put8(0x12008, 0x1122334455667788)
		v := NewVirtualMemoryLayer(img, pt.translator())
		v.SetPagefiles(map[int]memory.MemoryReader{c.file: pagefile})
		b, err := v.ReadAt(kva+8, 8)
		if err != nil || binary.LittleEndian.Uint64(b) != 0x1122334455667788 {
			t.Errorf("%s: page read from pagefile %d at 0x12000: %x, %v", c.name, c.file, b, err)
		}
		_, err = c.layout.ResolveProtoPTE(entry, kva)
		if miss, ok := missOf(err); !ok || miss.Kind != PageInPagefile || miss.PageFileNumber != c.file {
			t.Errorf("%s prototype target: %v (%+v), want file %d", c.name, err, miss, c.file)
		}
	}
	for name, table := range map[string]*symbols.Table{
		"PageFileLow on Valid":     softwareTable([2]uint8{0, 4}, high),
		"PageFileLow on Prototype": softwareTable([2]uint8{10, 1}, high),
		"PageFileHigh past bit 63": softwareTable([2]uint8{12, 4}, [2]uint8{32, 33}),
		"PageFileHigh on Low":      softwareTable([2]uint8{12, 4}, [2]uint8{14, 50}),
		"PageFileLow of zero bits": softwareTable([2]uint8{12, 0}, high),
		"no _MMPTE_SOFTWARE":       symbols.NewTable("s53", 8),
	} {
		if l, err := ReadSoftwareLayout(table); err == nil {
			t.Errorf("%s: read as %+v", name, l)
		}
	}
	if _, err := ReadSoftwareLayout(nil); err == nil {
		t.Error("no table: read")
	}
}

func TestAPrototypeTargetIsReadValidFirst(t *testing.T) {
	for _, c := range []struct {
		pte, want uint64
		kind      PageErrorKind
	}{
		{0x80000 | fP | fPro, 0x80123, 0},
		{0x81000 | fTr | 6<<5, 0x81123, 0},
		{0xffffa00000001000 | fPro, 0, PagePrototype},
		{0x0000000500000000 | 4<<5, 0, PageInPagefile},
		{4 << 5, 0, PageDemandZero},
		{0, 0, PageInvalid},
	} {
		pa, err := ResolveProtoPTE(c.pte, 0x7ff00123)
		if c.want != 0 {
			if err != nil || pa != c.want {
				t.Errorf("0x%x: 0x%x, %v", c.pte, pa, err)
			}
			continue
		}
		miss, ok := missOf(err)
		if !ok || miss.Kind != c.kind || miss.VirtualAddress != 0x7ff00123 {
			t.Errorf("0x%x: %v", c.pte, err)
		}
	}
}

func TestAPrototypeEntryNamesItsTargetSignExtended(t *testing.T) {
	for _, c := range []struct {
		entry, want uint64
		ok          bool
	}{
		{0xdf09603560000000 | fPro | 0x8, 0xffffdf0960356000, true},
		{0x0000123456780000 | fPro, 0x12345678, true},
		{0xdf09603560000000 | fPro | fP, 0, false},
		{0xdf09603560000000 | fTr, 0, false},
		{0, 0, false},
	} {
		got, ok := PrototypeEntryAddress(c.entry)
		if ok != c.ok || got != c.want {
			t.Errorf("0x%x: 0x%x %v, want 0x%x %v", c.entry, got, ok, c.want, c.ok)
		}
	}
}

func TestEachKindUnwrapsToItsSentinel(t *testing.T) {
	for kind, want := range map[PageErrorKind]error{
		PageInvalid: ErrPageInvalid, PageDemandZero: ErrPageDemandZero, PageInPagefile: ErrPageInPagefile,
		PageNotCaptured: ErrPageNotCaptured, PagePrototype: ErrPagePrototype, PageErrorKind(42): ErrPageInvalid,
	} {
		err := error(UnmappedPageError{VirtualAddress: 0x1000, Kind: kind})
		if !errors.Is(err, want) || kind.String() == "" || err.Error() == "" {
			t.Errorf("kind %d: %v", kind, err)
		}
	}
}

func TestThePTEPredicatesReadTheirBits(t *testing.T) {
	e := uint64(0x0008_1234_5678_9000) | fP | fPro | fTr
	if !PTEIsHardwareValid(e) || !PTEIsPrototype(e) || !PTEIsTransition(e) || PTEIsHardwareValid(e&^fP) {
		t.Fatal("predicates")
	}
	if PTEHardwareFrame(e|fNX) != 0x0008_1234_5678_9000 || PTETransitionFrame(e) != 0x0008_1234_5678_9000 {
		t.Fatalf("frame 0x%x", PTEHardwareFrame(e))
	}
}
