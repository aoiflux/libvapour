package symbols

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
)

func linuxTable(t *testing.T) *Table {
	return mustBuild(t, Declaration{
		PointerWidth: 8,
		LinuxBanner:  []byte("Linux version 6.17.0\n"),
		Scalars:      linuxScalars,
		Records: []Record{
			{Name: "list_head", Width: 16, Members: []Member{
				{Name: "next", Offset: 0, Type: ref(t, "*list_head")},
				{Name: "prev", Offset: 8, Type: ref(t, "*list_head")},
			}},
			{Name: "thing", Width: 64, Members: []Member{
				{Name: "flags", Offset: 0, Type: ref(t, "@3:4 unsigned int")},
				{Name: "high", Offset: 0, Type: ref(t, "@28:4 unsigned int")},
				{Name: "list", Offset: 8, Type: ref(t, "list_head")},
				{Name: "comm", Offset: 24, Type: ref(t, "[4]char")},
				{Name: "ratio", Offset: 28, Type: ref(t, "double")},
				{Name: "addr", Offset: 36, Type: ref(t, "__be32")},
				{Name: "state", Offset: 40, Type: ref(t, "state")},
				{Name: "opaque", Offset: 44, Type: ref(t, "missing")},
				{Name: "tail", Offset: 48, Type: ref(t, "[0]long unsigned int")},
				{Name: "uncounted", Offset: 48, Type: ref(t, "[0]missing")},
				{Name: "len", Offset: 48, Type: ref(t, "long unsigned int")},
				{Name: "fn", Offset: 56, Type: ref(t, "*")},
			}},
			{Name: "state", Width: 2, Members: []Member{{Name: "v", Offset: 0, Type: ref(t, "unsigned int")}}},
			{Name: "sized_nothing", Members: []Member{{Name: "v", Offset: 0, Type: ref(t, "unsigned int")}}},
			{Name: "opaque_name", Width: 8},
		},
		Enumerations: []EnumType{
			{Name: "state", Size: 4, Values: []EnumValue{{Name: "RUN", Value: 0}}},
			{Name: "mode", Values: []EnumValue{{Name: "B", Value: 2}, {Name: "A", Value: 2}, {Name: "Z", Value: -1}}},
		},
		Addresses: []Address{
			{Name: "init_task", Address: 0xffffffff82a0c940, Type: refp(t, "thing")},
			{Name: "init_alias", Address: 0xffffffff82a0c940},
			{Name: "tables", Address: 0x10, Type: refp(t, "[4]*list_head")},
		},
	})
}

func TestLookupsByName(t *testing.T) {
	table := linuxTable(t)
	if f, err := table.Field("thing", "len"); err != nil || f.Offset != 48 || f.Type.Name != "long unsigned int" {
		t.Errorf("thing.len: %+v, %v", f, err)
	}
	var unknownField UnknownFieldError
	if _, err := table.Field("thing", "nope"); !errors.As(err, &unknownField) ||
		err.Error() != `symbols: type "thing" has no field "nope"` {
		t.Errorf("unknown field: %v", err)
	}
	var unknownType UnknownTypeError
	for _, name := range []string{"absent", "opaque_name"} {
		if _, err := table.Struct(name); !errors.As(err, &unknownType) {
			t.Errorf("Struct(%s): %v, want UnknownTypeError", name, err)
		}
	}
	if n, err := table.OffsetOf("list_head", "prev"); err != nil || n != 8 {
		t.Errorf("OffsetOf: %d, %v", n, err)
	}
	st, _ := table.Struct("thing")
	var order []string
	for _, f := range st.Fields {
		order = append(order, f.Name)
	}
	if strings.Join(order, " ") != "flags high list comm ratio addr state opaque tail uncounted len fn" {
		t.Errorf("members not in declared order: %v", order)
	}
	if typ, err := table.LookupType("state"); err != nil || typ.Kind != TypeKindStruct || len(typ.Fields) != 1 {
		t.Errorf("a record wins over an enumeration of its name: %+v, %v", typ, err)
	}
	if v, err := table.EnumValue("state", "RUN"); err != nil || v != 0 {
		t.Errorf("the enumeration is still there: %d, %v", v, err)
	}
	mode, err := table.LookupType("mode")
	if err != nil || mode.Kind != TypeKindEnum || mode.Size != 4 {
		t.Fatalf("mode: %+v, %v", mode, err)
	}
	if got := []string{mode.Enum[0].Name, mode.Enum[1].Name, mode.Enum[2].Name}; !slices.Equal(got, []string{"Z", "A", "B"}) {
		t.Errorf("constants by value, then name: %v", got)
	}
	if _, err := table.EnumValue("mode", "Q"); !errors.As(err, &unknownField) {
		t.Errorf("unknown constant: %v", err)
	}
	if _, err := table.EnumValue("thing", "Q"); !errors.As(err, &unknownType) {
		t.Errorf("a record is no enumeration: %v", err)
	}
	if b, ok := table.LinuxBanner(); !ok || string(b) != "Linux version 6.17.0\n" {
		t.Errorf("banner %q %v", b, ok)
	}
	if _, ok := table.WindowsPDB(); ok {
		t.Error("a Linux table names a PDB")
	}
	if table.Name() != "test" || table.PointerSize() != 8 {
		t.Errorf("%s %d", table.Name(), table.PointerSize())
	}
}

func TestSizes(t *testing.T) {
	table := linuxTable(t)
	for name, want := range map[string]uint64{
		"thing": 64, "mode": 4, "long unsigned int": 8, "*thing": 8, "[3]list_head": 48, "[2]unsigned int": 8,
	} {
		if got, err := table.SizeOf(name); err != nil || got != want {
			t.Errorf("SizeOf(%q) = %d, %v, want %d", name, got, err, want)
		}
	}
	for _, name := range []string{"sized_nothing", "opaque_name", "void", "unsigned long", "absent", "[2]absent", "[x"} {
		if _, err := table.SizeOf(name); !errors.As(err, new(UnknownTypeError)) {
			t.Errorf("SizeOf(%q): %v, want UnknownTypeError", name, err)
		}
	}
	for field, want := range map[string]uint64{"flags": 4, "list": 16, "comm": 4, "tail": 0, "opaque": 0, "fn": 8, "state": 2} {
		if got, err := table.FieldSize("thing", field); err != nil || got != want {
			t.Errorf("FieldSize(%s) = %d, %v, want %d", field, got, err, want)
		}
	}
	if _, err := table.FieldSize("thing", "nope"); err == nil {
		t.Error("FieldSize of a missing member")
	}
	records := []Record{{Name: "r", Members: []Member{
		{Name: "a", Offset: 0, Type: ref(t, "unsigned long")}, {Name: "p", Offset: 4, Type: ref(t, "*r")}}}}
	free := mustBuild(t, Declaration{PointerWidth: 4, Records: records})
	if got, err := free.SizeOf("unsigned int"); err != nil || got != 4 {
		t.Errorf("a table with no scalars sizes by name: %d, %v", got, err)
	}
	if got, _ := free.FieldSize("r", "p"); got != 4 {
		t.Errorf("4-byte pointer: %d", got)
	}
	if _, err := free.SizeOf("[2]unsigned long"); !errors.Is(err, ErrPlatformUnknown) {
		t.Errorf("an array of long in a table of no platform: %v", err)
	}
	if _, err := free.SizeOf("unsigned long"); !errors.Is(err, ErrPlatformUnknown) {
		t.Errorf("long in a table of no platform: %v", err)
	}
	if _, err := free.FieldSize("r", "a"); !errors.Is(err, ErrPlatformUnknown) {
		t.Errorf("long member in a table of no platform: %v", err)
	}
	pdb := &PDBBuild{Database: "ntkrnlmp.pdb", GUID: "0D960CE103763A6097E839406D8B369F", Age: 1}
	banner := []byte("Linux version 6.17.0\n")
	for _, tc := range []struct {
		d        Declaration
		platform Platform
		long     uint64
	}{
		{Declaration{PointerWidth: 8, WindowsPDB: pdb}, PlatformWindows, 4},
		{Declaration{PointerWidth: 8, LinuxBanner: banner}, PlatformLinux, 8},
		{Declaration{PointerWidth: 4, LinuxBanner: banner}, PlatformLinux, 4},
	} {
		tc.d.Records = records
		tab := mustBuild(t, tc.d)
		if tab.Platform() != tc.platform {
			t.Errorf("platform %d, want %d", tab.Platform(), tc.platform)
		}
		if got, err := tab.FieldSize("r", "a"); err != nil || got != tc.long {
			t.Errorf("platform %d: unsigned long %d, %v, want %d", tc.platform, got, err, tc.long)
		}
	}
	both := mustBuild(t, Declaration{PointerWidth: 8, WindowsPDB: pdb, LinuxBanner: banner, Records: records})
	if both.Platform() != PlatformUnknown {
		t.Errorf("a table naming both systems: platform %d", both.Platform())
	}
}

func TestReadStruct(t *testing.T) {
	table := linuxTable(t)
	mem := make([]byte, 64)
	mem[0] = 0b0101_1000
	mem[3] = 0xa0
	copy(mem[8:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	copy(mem[24:], "ab\x00d")
	mem[36] = 0x7f
	mem[40] = 9
	mem[48] = 0x30
	inst, err := table.ReadStruct(flat{base: 0x1000, data: mem}, "thing", 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]uint64{"flags": 0b1011, "high": 0xa, "len": 0x30, "fn": 0} {
		if got, ok := inst.Fields[name]; !ok || got != want {
			t.Errorf("%s = %#x %v, want %#x", name, got, ok, want)
		}
	}
	for name, n := range map[string]int{"list": 16, "comm": 4, "ratio": 8, "addr": 4, "state": 2, "tail": 0} {
		if raw, ok := inst.RawFields[name]; !ok || len(raw) != n {
			t.Errorf("raw %s = %v %v, want %d bytes", name, raw, ok, n)
		}
	}
	if !slices.Equal(inst.Unsized, []string{"opaque", "uncounted"}) {
		t.Errorf("unsized %v", inst.Unsized)
	}
	if inst.Offset != 0x1000 || inst.Type.Name != "thing" {
		t.Errorf("instance %+v", inst)
	}
	if _, err := table.ReadStruct(flat{base: 0x1000, data: mem[:40]}, "thing", 0x1000); err == nil {
		t.Error("a member past the readable memory is not an error")
	}
	if _, err := table.ReadStruct(shortReader{}, "thing", 0); err == nil {
		t.Error("a short read is not an error")
	}
	if _, err := table.ReadStruct(flat{}, "absent", 0); err == nil {
		t.Error("absent record")
	}
}

func TestAWideBitfieldStaysRaw(t *testing.T) {
	table := mustBuild(t, Declaration{PointerWidth: 8, Records: []Record{{Name: "r", Width: 16, Members: []Member{
		{Name: "a", Offset: 0, Type: ref(t, "@60:8 [16]unsigned char")},
		{Name: "b", Offset: 0, Type: ref(t, "@0:64 unsigned long long")},
	}}}})
	mem := make([]byte, 16)
	for i := range mem {
		mem[i] = 0xff
	}
	inst, err := table.ReadStruct(flat{data: mem}, "r", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(inst.RawFields["a"]) != 16 || inst.Fields["b"] != 1<<64-1 {
		t.Errorf("%+v", inst)
	}
}

func TestPointersOfBothWidths(t *testing.T) {
	mem := flat{data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	for width, want := range map[uint8]uint64{4: 0x04030201, 8: 0x0807060504030201} {
		table := NewTable("p", width)
		if got, err := table.ReadPointer(mem, 0); err != nil || got != want {
			t.Errorf("width %d: %#x, %v", width, got, err)
		}
	}
	table := NewTable("p", 0)
	if table.PointerSize() != 8 {
		t.Errorf("default pointer width %d", table.PointerSize())
	}
	if v, err := table.ReadUint32(mem, 4); err != nil || v != 0x08070605 {
		t.Errorf("ReadUint32 %#x %v", v, err)
	}
	if _, err := table.ReadUint64(mem, 4); err == nil {
		t.Error("ReadUint64 past the end")
	}
	if _, err := table.ReadUint64(shortReader{}, 0); err == nil {
		t.Error("short ReadUint64")
	}
}

func TestSymbols(t *testing.T) {
	table := linuxTable(t)
	s, err := table.LookupSymbol("init_task")
	if err != nil || s.Address != 0xffffffff82a0c940 || s.Type != "thing" {
		t.Errorf("init_task %+v %v", s, err)
	}
	if s, _ := table.LookupSymbol("tables"); s.Type != "*list_head" {
		t.Errorf("an array of pointers reads as a pointer: %q", s.Type)
	}
	if r, err := table.SymbolTypeRef("tables"); err != nil || formatTypeRef(r) != "[4]*list_head" {
		t.Errorf("SymbolTypeRef %+v %v", r, err)
	}
	if _, err := table.SymbolTypeRef("init_alias"); err == nil {
		t.Error("an untyped symbol has a type")
	}
	if _, err := table.SymbolTypeRef("absent"); err == nil {
		t.Error("an absent symbol has a type")
	}
	if _, err := table.LookupSymbol("absent"); err == nil {
		t.Error("absent symbol found")
	}
	if got := table.SymbolNames(); !slices.Equal(got, []string{"init_alias", "init_task", "tables"}) {
		t.Errorf("names %v", got)
	}
	if got := table.TableSymbols(); len(got) != 3 || got[0].Name != "init_alias" {
		t.Errorf("symbols %v", got)
	}
	if got := NamesAt(table, 0xffffffff82a0c940); !slices.Equal(got, []string{"init_alias", "init_task"}) {
		t.Errorf("NamesAt %v", got)
	}
	if NamesAt(table, 0x11) != nil || NamesAt(nil, 0) != nil {
		t.Error("nothing there is nil")
	}
	var none *Table
	if none.SymbolsAt(0) != nil {
		t.Error("nil table")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if len(table.SymbolsAt(0x10)) != 1 {
				t.Error("concurrent SymbolsAt")
			}
		}()
	}
	wg.Wait()
}

func TestADeclarationIsCheckedBeforeItIsBuilt(t *testing.T) {
	good := func() Declaration {
		return Declaration{PointerWidth: 8, Records: []Record{{Name: "r", Members: []Member{{Name: "a", Type: TypeRef{Name: "int"}}}}}}
	}
	for why, change := range map[string]func(*Declaration){
		"pointer width": func(d *Declaration) { d.PointerWidth = 2 },
		"GUID":          func(d *Declaration) { d.WindowsPDB = &PDBBuild{GUID: "12"} },
		"empty":         func(d *Declaration) { d.LinuxBanner = []byte{} },
		"kind":          func(d *Declaration) { d.Scalars = []Scalar{{Name: "x", Kind: "fixed"}} },
		`scalar "x" is`: func(d *Declaration) {
			d.Scalars = []Scalar{{Name: "x", Kind: ScalarVoid}, {Name: "x", Kind: ScalarVoid}}
		},
		`record "r" is`: func(d *Declaration) { d.Records = append(d.Records, d.Records[0]) },
		"record 1":      func(d *Declaration) { d.Records = append(d.Records, Record{}) },
		"named":         func(d *Declaration) { d.Records[0].Members = append(d.Records[0].Members, d.Records[0].Members[0]) },
		"neither":       func(d *Declaration) { d.Records[0].Members[0].Name = "" },
		"also has":      func(d *Declaration) { d.Records[0].Members[0].Embeds = "r" },
		"bit offset":    func(d *Declaration) { d.Records[0].Members[0].Type.BitOffset = 1 },
		`constant "a" is`: func(d *Declaration) {
			d.Enumerations = []EnumType{{Name: "e", Values: []EnumValue{{Name: "a"}, {Name: "a"}}}}
		},
		`enumeration "e" is`: func(d *Declaration) { d.Enumerations = []EnumType{{Name: "e"}, {Name: "e"}} },
		`address "a" is`:     func(d *Declaration) { d.Addresses = []Address{{Name: "a"}, {Name: "a"}} },
		"address \"a\"":      func(d *Declaration) { d.Addresses = []Address{{Name: "a", Type: &TypeRef{Name: "x", BitOffset: 2}}} },
	} {
		d := good()
		change(&d)
		if _, err := Build("bad", d); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v", why, err)
		}
	}
	if _, err := Build("good", good()); err != nil {
		t.Error(err)
	}
	if _, err := BuildWith("bad", good(), ReadOptions{MaxTableEntries: -1}); err == nil {
		t.Error("bad options accepted")
	}
}

func TestAPDBBuildIsNamed(t *testing.T) {
	b := PDBBuild{Database: "ntkrnlmp.pdb", GUID: "0D960CE103763A6097E839406D8B369F", Age: 1}
	if b.String() != "ntkrnlmp.pdb/0D960CE103763A6097E839406D8B369F-1" {
		t.Error(b.String())
	}
	b.Database = ""
	if b.String() != "0D960CE103763A6097E839406D8B369F-1" {
		t.Error(b.String())
	}
	table := mustBuild(t, Declaration{PointerWidth: 8, WindowsPDB: &b})
	if got, ok := table.WindowsPDB(); !ok || got != b {
		t.Errorf("%+v %v", got, ok)
	}
}
