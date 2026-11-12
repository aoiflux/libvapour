package peparse

import (
	"strings"
	"testing"
)

func TestLibraryNamesFoldOnlyASCIICase(t *testing.T) {
	for _, dll := range []string{"ws2_32.dll", "WS2_32.DLL", "Ws2_32.Dll"} {
		if name, ok := OrdinalName(dll, true, 23); !ok || name != "socket" {
			t.Errorf("%s #23 = %q %v", dll, name, ok)
		}
		if !HasOrdinalTable(dll) {
			t.Errorf("%s has no table", dll)
		}
	}
	if HasOrdinalTable("ws2_32.dll ") || HasOrdinalTable("ws2_32") {
		t.Error("a different name matched")
	}
}

func TestEachWidthHasItsOwnTable(t *testing.T) {
	if _, ok := OrdinalName("ws2_32.dll", false, 23); ok {
		t.Error("the 64-bit names answered a 32-bit importer")
	}
	// Captured images import oleaut32.dll by ordinal only from 64-bit code;
	// its 32-bit table comes from the WoW64 copies the captures map.
	if name, ok := OrdinalName("OLEAUT32.dll", false, 2); !ok || name != "SysAllocString" {
		t.Errorf("32-bit oleaut32.dll #2 = %q %v", name, ok)
	}
	if _, ok := ordinalNames32["combase.dll"]; !ok {
		t.Fatal("no 32-bit combase.dll table")
	}
	for o, name := range ordinalNames32["combase.dll"] {
		if got, ok := OrdinalName("combase.dll", false, o); !ok || got != name {
			t.Fatalf("combase.dll #%d", o)
		}
	}
}

// The measured builds give ws2_32.dll ordinal 24 different names, so the
// table has none for it.
func TestOrdinalsTheBuildsNameApartAreAbsent(t *testing.T) {
	if name, ok := OrdinalName("ws2_32.dll", true, 24); ok {
		t.Errorf("ws2_32.dll #24 = %q", name)
	}
	if _, ok := OrdinalName("kernel32.dll", true, 1); ok || HasOrdinalTable("kernel32.dll") {
		t.Error("kernel32.dll has a table")
	}
}

func TestTheGeneratedTableIsWellFormed(t *testing.T) {
	for width, table := range map[string]map[string]map[uint16]string{"64": ordinalNames64, "32": ordinalNames32} {
		for dll, names := range table {
			if dll != foldASCII(dll) || dll == "" || len(names) == 0 {
				t.Errorf("%s-bit library %q with %d names", width, dll, len(names))
			}
			for o, name := range names {
				if name == "" || strings.ContainsRune(name, 0) {
					t.Errorf("%s-bit %s #%d = %q", width, dll, o, name)
				}
			}
		}
	}
}
