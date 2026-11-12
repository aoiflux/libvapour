package symbols

import (
	"errors"
	"strings"
	"testing"
)

// Hides FieldSize, as a table wrapper that does not size members does.
type noSizer struct{ SymbolTable }

func (n noSizer) Platform() Platform { return n.SymbolTable.(*Table).Platform() }

// Hides both FieldSize and Platform.
type opaque struct{ SymbolTable }

func entryTable(t *testing.T) *Table {
	pdb := &PDBBuild{Database: "ntkrnlmp.pdb", GUID: "0D960CE103763A6097E839406D8B369F", Age: 1}
	return mustBuild(t, Declaration{PointerWidth: 8, WindowsPDB: pdb, Records: []Record{{Name: "_HANDLE_TABLE_ENTRY", Width: 16, Members: []Member{
		{Name: "GrantedAccessBits", Offset: 8, Type: ref(t, "@0:25 unsigned long")},
		{Name: "NoRightsUpgrade", Offset: 8, Type: ref(t, "@25:1 unsigned long")},
		{Name: "Object", Offset: 0, Type: ref(t, "*void")},
		{Name: "Three", Offset: 12, Type: ref(t, "[3]unsigned char")},
		{Name: "Wide", Offset: 0, Type: ref(t, "[16]unsigned char")},
		{Name: "Name", Offset: 0, Type: ref(t, "[6]char")},
		{Name: "Plain", Offset: 0, Type: ref(t, "char")},
	}}}})
}

func TestAnIntegerMemberIsReadAtItsOwnWidth(t *testing.T) {
	table := entryTable(t)
	rec := []byte{1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xff, 0xff, 0x03, 0xaa, 0xbb, 0xcc, 0xdd}
	mem := flat{base: 0x100, data: rec}
	for _, tc := range []struct {
		field string
		width uint64
		want  uint64
	}{
		{"GrantedAccessBits", 4, 0x1ffffff},
		{"NoRightsUpgrade", 4, 1},
		{"Object", 8, 0x0807060504030201},
		{"Three", 3, 0xccbbaa},
	} {
		for _, tab := range []SymbolTable{table, noSizer{table}} {
			f, err := ResolveIntField(tab, "_HANDLE_TABLE_ENTRY", tc.field)
			if err != nil || f.Width != tc.width {
				t.Fatalf("%s: %+v %v", tc.field, f, err)
			}
			if got, err := f.Read(mem, 0x100); err != nil || got != tc.want {
				t.Errorf("Read %s = %#x %v, want %#x", tc.field, got, err, tc.want)
			}
			if got, err := f.Decode(rec); err != nil || got != tc.want {
				t.Errorf("Decode %s = %#x %v", tc.field, got, err)
			}
		}
	}
	if _, err := ResolveIntField(table, "_HANDLE_TABLE_ENTRY", "Wide"); err == nil || !strings.Contains(err.Error(), "16 bytes") {
		t.Errorf("a 16-byte member is no integer: %v", err)
	}
	if _, err := ResolveIntField(table, "_HANDLE_TABLE_ENTRY", "Absent"); err == nil {
		t.Error("absent member")
	}
	if _, err := ResolveIntField(nil, "a", "b"); err == nil {
		t.Error("nil table")
	}
	f, _ := ResolveIntField(table, "_HANDLE_TABLE_ENTRY", "Three")
	if _, err := f.Decode(rec[:14]); err == nil {
		t.Error("a member past the record")
	}
	if _, err := f.Read(mem, 0x102); err == nil {
		t.Error("a read past memory")
	}
	if _, err := f.Read(shortReader{}, 0); err == nil {
		t.Error("a short read")
	}
	for _, bad := range []IntField{{Width: 0}, {Width: 9}} {
		if _, err := bad.Read(mem, 0x100); err == nil {
			t.Errorf("width %d read", bad.Width)
		}
		if _, err := bad.Decode(rec); err == nil {
			t.Errorf("width %d decoded", bad.Width)
		}
	}
}

func TestACharArrayStopsAtItsEnd(t *testing.T) {
	table := entryTable(t)
	f, err := ResolveCharArray(table, "_HANDLE_TABLE_ENTRY", "Name", 0)
	if err != nil || f.Length != 6 || !f.Declared {
		t.Fatalf("%+v %v", f, err)
	}
	for data, want := range map[string]string{"abcdefgh": "abcdef", "ab\x00def": "ab", "\x00": ""} {
		mem := flat{data: []byte(data + strings.Repeat("\x00", 8))}
		if got, err := f.Read(mem, 0); err != nil || got != want {
			t.Errorf("%q: %q %v", data, got, err)
		}
	}
	g, err := ResolveCharArray(table, "_HANDLE_TABLE_ENTRY", "Plain", 4)
	if err != nil || g.Length != 4 || g.Declared {
		t.Errorf("fallback %+v %v", g, err)
	}
	if _, err := ResolveCharArray(table, "_HANDLE_TABLE_ENTRY", "Plain", 0); err == nil {
		t.Error("no length and no fallback")
	}
	if _, err := ResolveCharArray(table, "_HANDLE_TABLE_ENTRY", "Absent", 4); err == nil {
		t.Error("absent member")
	}
	if _, err := ResolveCharArray(nil, "a", "b", 4); err == nil {
		t.Error("nil table")
	}
	if _, err := (CharArrayField{}).Read(flat{}, 0); err == nil {
		t.Error("length 0 read")
	}
	if _, err := f.Read(flat{data: []byte("abc")}, 0); err == nil {
		t.Error("a read past memory")
	}
}

func TestAMemberWhoseWidthThePlatformDecidesNeedsAPlatform(t *testing.T) {
	hand := NewTable("hand", 8)
	hand.AddStruct(StructType{Name: "r", Size: 8, Fields: []Field{{Name: "n", Offset: 0, Type: TypeRef{Name: "unsigned long"}}}})
	for _, tab := range []SymbolTable{hand, noSizer{hand}} {
		if _, err := ResolveIntField(tab, "r", "n"); !errors.Is(err, ErrPlatformUnknown) {
			t.Errorf("no platform: %v", err)
		}
	}
	hand.SetPlatform(PlatformWindows)
	if _, err := ResolveIntField(opaque{hand}, "r", "n"); !errors.Is(err, ErrPlatformUnknown) {
		t.Errorf("a wrapper that hides the platform: %v", err)
	}
	for _, tc := range []struct {
		platform Platform
		want     uint64
	}{{PlatformWindows, 4}, {PlatformLinux, 8}} {
		hand.SetPlatform(tc.platform)
		for _, tab := range []SymbolTable{hand, noSizer{hand}} {
			if f, err := ResolveIntField(tab, "r", "n"); err != nil || f.Width != tc.want {
				t.Errorf("platform %d: %+v, %v", tc.platform, f, err)
			}
		}
	}
}
