package autoload

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
)

const (
	tULong   = 0x22
	tUChar   = 0x20
	tLong    = 0x12
	tInt4    = 0x74
	tQuad    = 0x13
	tUQuad   = 0x23
	tRChar   = 0x70
	tWChar   = 0x71
	tVoidP64 = 0x603
	tNoType  = 0x00
)

func graphOf(t *testing.T, records ...[]byte) *typeGraph {
	t.Helper()
	g, err := readTypeStream(typeStreamOf(records...))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func rendered(g *typeGraph, index uint32) string {
	var buf bytes.Buffer
	d := symbols.Declaration{PointerWidth: 8, Records: []symbols.Record{{Name: "r", Members: []symbols.Member{{Name: "m", Type: g.typeRef(index)}}}}}
	if err := symbols.Encode(&buf, d); err != nil {
		return "error: " + err.Error()
	}
	s := buf.String()
	i := strings.Index(s, `"type": "`)
	if i < 0 {
		return ""
	}
	s = s[i+len(`"type": "`):]
	return strings.ReplaceAll(s[:strings.Index(s, `"`)], `\\`, `\`)
}

func TestPrimitivesAreNamedByWidthAndSign(t *testing.T) {
	g := graphOf(t)
	cases := map[uint32]string{
		tULong: "unsigned int", tLong: "int", tInt4: "int", 0x75: "unsigned int", 0x08: "int",
		tQuad: "long long", tUQuad: "unsigned long long", 0x76: "long long", 0x77: "unsigned long long",
		0x11: "short", 0x21: "unsigned short", tUChar: "unsigned char", tRChar: "char", 0x10: "char",
		tWChar: "wchar_t", 0x30: "bool", 0x40: "float", 0x41: "double", 0x03: "void",
		tVoidP64: "*void", 0x622: "*unsigned int", 0x470: "*char", tNoType: "",
	}
	for index, want := range cases {
		if got := rendered(g, index); got != want {
			t.Errorf("type %#x renders %q, want %q", index, got, want)
		}
	}
	widths := map[uint32]uint64{tUChar: 1, 0x21: 2, tULong: 4, tUQuad: 8, 0x41: 8, 0x42: 10, 0x403: 4, tVoidP64: 8, 0x03: 0}
	for index, want := range widths {
		if got := g.width(index, 0); got != want {
			t.Errorf("type %#x is %d bytes, want %d", index, got, want)
		}
	}
}

func TestDerivedTypesRenderAsTypeExpressions(t *testing.T) {
	g := graphOf(t,
		structRecord(lfStructure, "_LIST_ENTRY", 16, 0, propForward), // 0x1000
		pointerRecord(0x1000, 8),                                   // 0x1001
		typeRecord(lfModifier, leafWriter(nil).u32(tULong).u16(1)), // 0x1002 const unsigned long
		arrayRecord(0x1002, 24),                                    // 0x1003 [6]
		arrayRecord(0x1003, 48),                                    // 0x1004 [2][6]
		typeRecord(lfProcedure, leafWriter(nil).u32(tLong).u8(0).u8(0).u16(0).u32(0)), // 0x1005
		pointerRecord(0x1005, 8), // 0x1006
		typeRecord(lfBitfield, leafWriter(nil).u32(tULong).u8(3).u8(5)), // 0x1007
		enumRecord("_POOL_TYPE", tInt4, 0, 0),                           // 0x1008
		pointerRecord(0x1008, 8),                                        // 0x1009
		pointerRecord(0x1001, 8),                                        // 0x100a
		arrayRecord(0x1006, 0),                                          // 0x100b
	)
	cases := map[uint32]string{
		0x1001: "*_LIST_ENTRY", 0x1002: "unsigned int", 0x1003: "[6]unsigned int", 0x1004: "[2][6]unsigned int",
		0x1005: "", 0x1006: "*", 0x1007: "@5:3 unsigned int", 0x1008: "int", 0x1009: "*int",
		0x100a: "**_LIST_ENTRY", 0x100b: "[0]*", 0x2000: "",
	}
	for index, want := range cases {
		if got := rendered(g, index); got != want {
			t.Errorf("type %#x renders %q, want %q", index, got, want)
		}
	}
}

func TestAnArrayCountsElementsOfItsDefinedStructure(t *testing.T) {
	g := graphOf(t,
		structRecord(lfStructure, "_KTHING", 0, 0, propForward), // 0x1000
		arrayRecord(0x1000, 96),                                 // 0x1001
		memberList(memberSpec{"A", tUQuad, 0}, memberSpec{"B", tUQuad, 8}, memberSpec{"C", tUQuad, 16}), // 0x1002
		structRecord(lfStructure, "_KTHING", 24, 0x1002, 0),                                             // 0x1003
		arrayRecord(0x1000, 4), // 0x1004
	)
	if got := rendered(g, 0x1001); got != "[4]_KTHING" {
		t.Errorf("array of a forward reference renders %q, want [4]_KTHING", got)
	}
	if got := rendered(g, 0x1004); got != "[0]_KTHING" {
		t.Errorf("an array smaller than its element renders %q", got)
	}
}

func TestAForwardReferenceResolvesByUniqueName(t *testing.T) {
	unique := func(name, uniq string, size uint64, fields uint32, prop uint16) []byte {
		w := leafWriter(nil).u16(0).u16(prop | propUniqueName).u32(fields).u32(0).u32(0).num(size).str(name).str(uniq)
		return typeRecord(lfStructure, w)
	}
	g := graphOf(t,
		unique("<unnamed-tag>", ".?AU<unnamed-tag>@a@@", 0, 0, propForward), // 0x1000
		unique("<unnamed-tag>", ".?AU<unnamed-tag>@b@@", 0, 0, propForward), // 0x1001
		memberList(memberSpec{"X", tUChar, 0}),                              // 0x1002
		unique("<unnamed-tag>", ".?AU<unnamed-tag>@a@@", 2, 0x1002, 0),      // 0x1003
		unique("<unnamed-tag>", ".?AU<unnamed-tag>@b@@", 8, 0x1002, 0),      // 0x1004
		arrayRecord(0x1000, 4),  // 0x1005
		arrayRecord(0x1001, 16), // 0x1006
	)
	if a, b := rendered(g, 0x1005), rendered(g, 0x1006); a != "[2]<unnamed-tag>" || b != "[2]<unnamed-tag>" {
		t.Errorf("arrays of the two anonymous types render %q and %q", a, b)
	}
	if _, kept := collectRecords(g)["<unnamed-tag>"]; kept {
		t.Error("a record under the compiler's placeholder name was kept")
	}
}

func TestTheFullestDefinitionOfANameIsKept(t *testing.T) {
	g := graphOf(t,
		memberList(memberSpec{"MinorVersion", 0x21, 0}, memberSpec{"MajorVersion", 0x21, 2}),                                     // 0x1000
		structRecord(lfStructure, "_KPRCB", 1792, 0x1000, 0),                                                                     // 0x1001
		memberList(memberSpec{"MinorVersion", 0x21, 0}, memberSpec{"MajorVersion", 0x21, 2}, memberSpec{"Number", tULong, 0x24}), // 0x1002
		structRecord(lfStructure, "_KPRCB", 52992, 0x1002, 0),                                                                    // 0x1003
		structRecord(lfStructure, "_KPRCB", 64, 0x1000, 0),                                                                       // 0x1004
		structRecord(lfStructure, "_KPRCB", 0, 0, propForward),
	)
	r := collectRecords(g)["_KPRCB"]
	if r.Size != 52992 || len(r.Fields) != 3 || r.Fields["Number"].Offset != 0x24 {
		t.Fatalf("kept %+v, want the 52992-byte definition with three members", r)
	}

	g = graphOf(t,
		memberList(memberSpec{"A", tULong, 0}), // 0x1000
		structRecord(lfStructure, "S", 8, 0x1000, 0),
		structRecord(lfStructure, "S", 16, 0x1000, 0),
		structRecord(lfStructure, "S", 16, 0x1000, 0),
	)
	if r := collectRecords(g)["S"]; r.Size != 16 || r.index != 0x1002 {
		t.Fatalf("kept the definition at %#x of %d bytes, want the first 16-byte one", r.index, r.Size)
	}
}

func TestUnionsAndStructuresKeepTheirMembers(t *testing.T) {
	g := graphOf(t,
		memberList(memberSpec{"LowPart", tULong, 0}, memberSpec{"HighPart", tLong, 4}, memberSpec{"QuadPart", tQuad, 0}), // 0x1000
		structRecord(lfUnion, "_LARGE_INTEGER", 8, 0x1000, 0),
		memberList(memberSpec{"Big", tUQuad, 0x10000}), // 0x1002, offset as LF_ULONG
		structRecord(lfStructure, "_FAR", 0x10008, 0x1002, 0),
	)
	records := collectRecords(g)
	li := records["_LARGE_INTEGER"]
	if li.Size != 8 || li.Fields["HighPart"].Offset != 4 || li.Fields["QuadPart"].Type.Name != "long long" {
		t.Errorf("_LARGE_INTEGER = %+v", li)
	}
	if far := records["_FAR"]; far.Size != 0x10008 || far.Fields["Big"].Offset != 0x10000 {
		t.Errorf("numeric leaves past 0x8000: %+v", far)
	}
}

func TestAFieldListContinuesThroughLFIndexAndStopsAtACycle(t *testing.T) {
	first := typeRecord(lfFieldList, leafWriter(nil).u16(lfMember).u16(3).u32(tULong).num(0).str("A").pad().u16(lfIndex).u16(0).u32(0x1001))
	second := typeRecord(lfFieldList, leafWriter(nil).u16(lfMember).u16(3).u32(tULong).num(4).str("B").pad())
	g := graphOf(t, first, second, structRecord(lfStructure, "S", 8, 0x1000, 0))
	members, _, whole := g.fieldList(0x1000)
	if !whole || len(members) != 2 || members[1].name != "B" {
		t.Fatalf("continued list read %+v whole=%v", members, whole)
	}
	loop := typeRecord(lfFieldList, leafWriter(nil).u16(lfIndex).u16(0).u32(0x1000))
	g = graphOf(t, loop)
	if _, _, whole := g.fieldList(0x1000); whole {
		t.Fatal("a list that continues into itself read whole")
	}
}

func TestEnumerationsAreReadWholeOrLeftOut(t *testing.T) {
	values := typeRecord(lfFieldList, leafWriter(nil).
		u16(lfEnumerate).u16(3).num(0).str("NonPagedPool").pad().
		u16(lfEnumerate).u16(3).u16(leafChar).u8(0xff).str("Minus").pad().
		u16(lfEnumerate).u16(3).u16(leafLong).u32(0x80000000).str("Low").pad())
	broken := typeRecord(lfFieldList, leafWriter(nil).u16(lfEnumerate).u16(3).u16(0x8005).u32(0).str("Real"))
	g := graphOf(t, values, enumRecord("_POOL_TYPE", tInt4, 0x1000, 0), broken, enumRecord("_BROKEN", tInt4, 0x1002, 0),
		enumRecord("_POOL_TYPE", tInt4, 0, propForward))
	enums := collectEnumerations(g)
	e, ok := enums["_POOL_TYPE"]
	if !ok || e.Size != 4 || e.Base != "int" || e.Constants["Minus"] != -1 || e.Constants["Low"] != -0x80000000 || e.Constants["NonPagedPool"] != 0 {
		t.Fatalf("_POOL_TYPE = %+v", e)
	}
	if _, ok := enums["_BROKEN"]; ok {
		t.Fatal("an enumerator list that does not read whole was kept")
	}
}

func TestTheTypeStreamMustHoldItsIndexRangeExactly(t *testing.T) {
	good := typeStreamOf(structRecord(lfStructure, "S", 0, 0, propForward))
	if _, err := readTypeStream(good); err != nil {
		t.Fatal(err)
	}
	mutate := func(at int, v uint32) []byte {
		b := bytes.Clone(good)
		copy(b[at:], leafWriter(nil).u32(v))
		return b
	}
	cases := map[string][]byte{
		"short":              good[:typeHeaderMin-1],
		"header too small":   mutate(4, 8),
		"bytes past stream":  mutate(16, 1<<20),
		"inverted range":     mutate(12, 0xfff),
		"one record missing": mutate(12, 0x1002),
		"range past bytes":   mutate(12, 0x1000+1<<24),
		"cut record":         mutate(16, uint32(len(good)-typeHeaderMin-1)),
	}
	for name, s := range cases {
		if _, err := readTypeStream(s); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

func TestATypeCycleFailsTheConversion(t *testing.T) {
	cycle := typeRecord(lfModifier, leafWriter(nil).u32(0x1000).u16(0))
	g := graphOf(t, cycle, memberList(memberSpec{"Loop", 0x1000, 0}), structRecord(lfStructure, "S", 4, 0x1001, 0))
	g.maxDepth = 50
	collectRecords(g)
	if !g.tooDeep {
		t.Fatal("a modifier of itself did not reach the depth limit")
	}

	f := newFixture()
	f.types = [][]byte{cycle, memberList(memberSpec{"Loop", 0x1000, 0}), structRecord(lfStructure, "S", 4, 0x1001, 0)}
	f.publics = []publicSpec{{kind: sPub32, name: "Anything", segment: 1}}
	if _, err := pdbToDeclaration(f.file(), f.fingerprint(), 64); err == nil || !strings.Contains(err.Error(), "MaxRecursionDepth (64)") {
		t.Fatalf("conversion of a cycle: %v", err)
	}
}

func TestOperatorChainsStopAtTheFormatLimit(t *testing.T) {
	records := [][]byte{pointerRecord(tULong, 8)}
	for i := range 40 {
		records = append(records, pointerRecord(0x1000+uint32(i), 8))
	}
	g := graphOf(t, records...)
	ref := g.typeRef(0x1000 + 40)
	depth := 0
	for r := &ref; r != nil; r = r.Element {
		depth++
	}
	if depth > symbols.MaxTypeOperators+1 {
		t.Fatalf("rendered %d levels, more than the format holds", depth)
	}
	var buf bytes.Buffer
	d := symbols.Declaration{PointerWidth: 8, Records: []symbols.Record{{Name: "r", Members: []symbols.Member{{Name: "m", Type: ref}}}}}
	if err := symbols.Encode(&buf, d); err != nil {
		t.Fatalf("a long chain does not encode: %v", err)
	}
}

func FuzzTypeStream(f *testing.F) {
	f.Add(typeStreamOf(
		memberList(memberSpec{"A", tULong, 0}, memberSpec{"B", 0x1002, 8}),
		structRecord(lfStructure, "S", 16, 0x1000, 0),
		pointerRecord(0x1001, 8),
		arrayRecord(0x1002, 16),
		enumRecord("E", tInt4, 0, propForward),
	))
	f.Fuzz(func(t *testing.T, data []byte) {
		g, err := readTypeStream(data)
		if err != nil {
			return
		}
		g.maxDepth = 64
		records := collectRecords(g)
		enums := collectEnumerations(g)
		for name, r := range records {
			for member, m := range r.Fields {
				var buf bytes.Buffer
				d := symbols.Declaration{PointerWidth: 8, Records: []symbols.Record{{Name: "r", Members: []symbols.Member{{Name: "m", Type: m.Type}}}}}
				if err := symbols.Encode(&buf, d); err != nil && !strings.Contains(err.Error(), "UTF-8") {
					t.Fatalf("%s.%s renders a type the format refuses: %v", name, member, err)
				}
			}
		}
		if _, err := json.Marshal(enums); err != nil {
			t.Fatal(err)
		}
	})
}
