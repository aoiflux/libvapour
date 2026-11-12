package layers

import (
	"errors"
	"testing"

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
	if err := CheckPagefilePTELayout(softwareTable(old, high)); err != nil {
		t.Fatalf("the pre-17134 layout: %v", err)
	}
	for name, table := range map[string]*symbols.Table{
		"PageFileLow at 15:12": softwareTable([2]uint8{12, 4}, high),
		"PageFileHigh short":   softwareTable(old, [2]uint8{32, 28}),
		"SwizzleBit":           softwareTable(old, high, "SwizzleBit"),
		"no type":              symbols.NewTable("s53", 8),
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
