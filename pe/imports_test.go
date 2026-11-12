package pe

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

type imEntry struct {
	ordinal uint16
	hint    uint16
	name    string
	raw     uint64
}

type imLibrary struct {
	name    string
	entries []imEntry
	noOFT   bool
	stamp   uint32
}

const imDir = uint32(0x1000)

type imLayout struct{ dir, lookup, iat, strs, size uint64 }

// Each library gets a lookup table at 0x1400+, an address table at 0x2400+
// holding resolved addresses, and hint/name entries at 0x3000+.
var imPages = imLayout{uint64(imDir), 0x1400, 0x2400, 0x3000, 0x5000}

func buildImports(plus bool, libs []imLibrary) []byte { return buildImportsAt(imPages, plus, libs) }

func buildImportsAt(at imLayout, plus bool, libs []imLibrary) []byte {
	img := make([]byte, at.size)
	width := uint64(4)
	flag := uint64(1) << 31
	if plus {
		width, flag = 8, 1<<63
	}
	put := func(at, v uint64) {
		if plus {
			put64(img, at, v)
		} else {
			put32(img, at, uint32(v))
		}
	}
	lookup, iat, strs := at.lookup, at.iat, at.strs
	putString := func(s string) uint64 {
		at := strs
		copy(img[at:], s+"\x00")
		strs += uint64(len(s)) + 1
		strs += strs % 2
		return at
	}
	for i, lib := range libs {
		d := at.dir + uint64(i)*ImportDescriptorSize
		if !lib.noOFT {
			put32(img, d+offImportLookupTable, uint32(lookup))
		}
		put32(img, d+offImportTimeDate, lib.stamp)
		put32(img, d+offImportName, uint32(putString(lib.name)))
		put32(img, d+offImportAddressTable, uint32(iat))
		for j, e := range lib.entries {
			v := e.raw
			switch {
			case v != 0:
			case e.name != "":
				at := strs
				put16(img, at, e.hint)
				strs += 2
				putString(e.name)
				v = at
			default:
				v = flag | uint64(e.ordinal)
			}
			put(lookup+uint64(j)*width, v)
			put(iat+uint64(j)*width, 0x7FFE0000+uint64(j)*0x10)
		}
		lookup += uint64(len(lib.entries)+1) * width
		iat += uint64(len(lib.entries)+1) * width
	}
	return img
}

func TestImportsByNameAndByOrdinal(t *testing.T) {
	for _, plus := range []bool{false, true} {
		img := buildImports(plus, []imLibrary{
			{name: "KERNEL32.dll", entries: []imEntry{{hint: 0x2A, name: "CreateFileW"}, {hint: 3, name: "CloseHandle"}}},
			{name: "WS2_32.dll", stamp: 0xFFFFFFFF, entries: []imEntry{{ordinal: 23}, {ordinal: 0x8001}}},
		})
		table, err := ParseImports(flat(img), plus, DataDirectory{imDir, 3 * ImportDescriptorSize}, limits.Limits{})
		if err != nil || len(table.Problems) != 0 || len(table.Descriptors) != 2 {
			t.Fatalf("plus %v: %+v %v", plus, table, err)
		}
		k32, ws := table.Descriptors[0], table.Descriptors[1]
		if k32.Library != "KERNEL32.dll" || ws.Library != "WS2_32.dll" || ws.TimeDateStamp != 0xFFFFFFFF {
			t.Errorf("descriptors %+v %+v", k32, ws)
		}
		width := uint32(4)
		if plus {
			width = 8
		}
		want := []Import{
			{Hint: 0x2A, Name: "CreateFileW", SlotRVA: k32.FirstThunk},
			{Hint: 3, Name: "CloseHandle", SlotRVA: k32.FirstThunk + width},
		}
		for i, imp := range k32.Imports {
			if imp != want[i] {
				t.Errorf("plus %v import %d: %+v, want %+v", plus, i, imp, want[i])
			}
		}
		if len(ws.Imports) != 2 || !ws.Imports[0].ByOrdinal || ws.Imports[0].Ordinal != 23 || ws.Imports[1].Ordinal != 0x8001 {
			t.Errorf("plus %v ordinals: %+v", plus, ws.Imports)
		}
		if ws.Imports[1].SlotAddress(0x400000) != 0x400000+uint64(ws.FirstThunk+width) {
			t.Error("SlotAddress")
		}
	}
}

func TestReservedBitsEndTheDescriptorsWalk(t *testing.T) {
	for _, tc := range []struct {
		plus bool
		raw  uint64
	}{
		{false, 1<<31 | 1<<16 | 5},
		{true, 1<<63 | 1<<40 | 5},
		{true, 1 << 31},
	} {
		img := buildImports(tc.plus, []imLibrary{{name: "a.dll", entries: []imEntry{{ordinal: 1}, {raw: tc.raw}, {ordinal: 3}}}})
		table, err := ParseImports(flat(img), tc.plus, DataDirectory{imDir, 40}, limits.Limits{})
		if err != nil || len(table.Problems) != 1 || !errors.Is(table.Problems[0], ErrReservedThunkBits) {
			t.Fatalf("0x%x: %+v %v", tc.raw, table, err)
		}
		if n := len(table.Descriptors[0].Imports); n != 1 {
			t.Errorf("0x%x: %d imports kept, want the 1 before the bad entry", tc.raw, n)
		}
	}
}

func TestWithoutALookupTableTheResolvedAddressTableIsRefused(t *testing.T) {
	img := buildImports(true, []imLibrary{{name: "a.dll", noOFT: true, entries: []imEntry{{name: "F"}}}})
	put64(img, 0x2400, 0x00007FF812345678)
	table, err := ParseImports(flat(img), true, DataDirectory{imDir, 40}, limits.Limits{})
	if err != nil || len(table.Problems) != 1 || !errors.Is(table.Problems[0], ErrReservedThunkBits) {
		t.Fatalf("%+v %v", table, err)
	}
	unbound := buildImports(true, []imLibrary{{name: "a.dll", noOFT: true, entries: []imEntry{{name: "F"}}}})
	copy(unbound[0x2400:0x2408], unbound[0x1400:0x1408])
	table, err = ParseImports(flat(unbound), true, DataDirectory{imDir, 40}, limits.Limits{})
	if err != nil || len(table.Problems) != 0 || table.Descriptors[0].Imports[0].Name != "F" {
		t.Errorf("an address table still holding names: %+v %v", table, err)
	}
}

func TestUnreadPartsAreFlaggedAndTheRestKept(t *testing.T) {
	img := buildImports(true, []imLibrary{
		{name: "one.dll", entries: []imEntry{{name: "A"}, {name: "B"}}},
		{name: "two.dll", entries: []imEntry{{ordinal: 9}}},
	})
	// The hint/name entries and library names share page 0x3000.
	table, err := ParseImports(withHoles(img, 0x3000), true, DataDirectory{imDir, 60}, limits.Limits{})
	if err != nil || len(table.Descriptors) != 2 {
		t.Fatalf("%+v %v", table, err)
	}
	one, two := table.Descriptors[0], table.Descriptors[1]
	if !errors.Is(one.LibraryErr, ErrUnreadable) || one.Library != "" {
		t.Errorf("library name: %q %v", one.Library, one.LibraryErr)
	}
	if len(one.Imports) != 2 || !errors.Is(one.Imports[0].NameErr, ErrUnreadable) {
		t.Errorf("names: %+v", one.Imports)
	}
	if len(two.Imports) != 1 || two.Imports[0].Ordinal != 9 {
		t.Errorf("ordinal import lost: %+v", two.Imports)
	}

	table, err = ParseImports(withHoles(img, 0x1000+0x1000), true, DataDirectory{imDir, 60}, limits.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Problems) != 0 {
		t.Errorf("an unread address table page is not read: %v", table.Problems)
	}
	table, err = ParseImports(withHoles(img, 0x1000), true, DataDirectory{imDir, 60}, limits.Limits{})
	if err == nil || !errors.Is(err, ErrUnreadable) || table != nil {
		t.Errorf("unread first descriptor: %v", err)
	}
}

func TestADescriptorPastAnUnreadPageEndsTheList(t *testing.T) {
	img := buildImports(false, []imLibrary{{name: "a.dll", entries: []imEntry{{ordinal: 1}}}})
	at := uint32(0x3000 - ImportDescriptorSize)
	copy(img[at:], img[imDir:imDir+ImportDescriptorSize])
	table, err := ParseImports(withHoles(img, 0x3000), false, DataDirectory{at, 40}, limits.Limits{})
	if err != nil || len(table.Descriptors) != 1 || len(table.Problems) != 1 || !errors.Is(table.Problems[0], ErrUnreadable) {
		t.Fatalf("%+v %v", table, err)
	}
}

func TestImportLimits(t *testing.T) {
	img := buildImports(false, []imLibrary{
		{name: "a.dll", entries: []imEntry{{ordinal: 1}, {ordinal: 2}, {ordinal: 3}}},
		{name: "b.dll", entries: []imEntry{{ordinal: 1}}},
		{name: "c.dll", entries: []imEntry{{ordinal: 1}}},
	})
	for _, tc := range []struct{ limit, descriptors, imports int }{{2, 1, 1}, {5, 2, 3}, {6, 2, 4}, {8, 3, 5}} {
		table, err := ParseImports(flat(img), false, DataDirectory{imDir, 80}, limits.Limits{MaxTableEntries: tc.limit})
		if err != nil {
			t.Fatal(err)
		}
		imports := 0
		for _, d := range table.Descriptors {
			imports += len(d.Imports)
		}
		if len(table.Descriptors) != tc.descriptors || imports != tc.imports || len(table.Problems) != 1 || !errors.Is(table.Problems[0], ErrImportLimit) {
			t.Errorf("limit %d: %d descriptors, %d imports, problems %v", tc.limit, len(table.Descriptors), imports, table.Problems)
		}
	}
	if table, err := ParseImports(flat(img), false, DataDirectory{imDir, 80}, limits.Limits{MaxTableEntries: 9}); err != nil || len(table.Problems) != 0 {
		t.Errorf("limit 9 covers 3 descriptors, 5 imports and the terminator: %v %v", table, err)
	}
	if _, err := ParseImports(flat(img), false, DataDirectory{}, limits.Limits{}); !errors.Is(err, ErrNoImportDirectory) {
		t.Errorf("no directory: %v", err)
	}
}

func TestTheWalkStopsAtTheDirectorySize(t *testing.T) {
	img := buildImports(false, []imLibrary{
		{name: "a.dll", entries: []imEntry{{ordinal: 1}}},
		{name: "b.dll", entries: []imEntry{{ordinal: 2}}},
	})
	table, err := ParseImports(flat(img), false, DataDirectory{imDir, 2*ImportDescriptorSize + 19}, limits.Limits{})
	if err != nil || len(table.Descriptors) != 2 || len(table.Problems) != 1 || !errors.Is(table.Problems[0], ErrImportLimit) {
		t.Fatalf("%+v %v", table, err)
	}
	if _, err := ParseImports(flat(img), false, DataDirectory{imDir, ImportDescriptorSize - 1}, limits.Limits{}); !errors.Is(err, ErrNoImportDirectory) {
		t.Errorf("Size below one descriptor: %v", err)
	}
}
