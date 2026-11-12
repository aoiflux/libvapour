package generator

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/btf"
	"github.com/aoiflux/libvapour/symbols/btf/btftest"
)

const (
	kindInt    = 1
	kindStruct = 4
	kindUnion  = 5
)

func parse(t *testing.T, b *btftest.Builder) *btf.Spec {
	t.Helper()
	spec, err := btf.Parse(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func convert(t *testing.T, b *btftest.Builder) BTFTypes {
	t.Helper()
	out, err := TypesFromBTF(parse(t, b), 8, limits.Default())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func build(t *testing.T, out BTFTypes) *symbols.Table {
	t.Helper()
	table, err := symbols.Build("test", symbols.Declaration{PointerWidth: 8, Scalars: out.Scalars,
		Records: out.Records, Enumerations: out.Enumerations})
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func record(t *testing.T, out BTFTypes, name string) symbols.Record {
	t.Helper()
	for _, r := range out.Records {
		if r.Name == name {
			return r
		}
	}
	var names []string
	for _, r := range out.Records {
		names = append(names, r.Name)
	}
	t.Fatalf("no record %q in %v", name, names)
	return symbols.Record{}
}

func hasRecord(out BTFTypes, name string) bool {
	for _, r := range out.Records {
		if r.Name == name {
			return true
		}
	}
	return false
}

func member(t *testing.T, r symbols.Record, name string) symbols.Member {
	t.Helper()
	for _, m := range r.Members {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("record %q has no member %q: %+v", r.Name, name, r.Members)
	return symbols.Member{}
}

// The expression form is the table's own reading of a type, so a reference
// the generator builds must survive an encode and decode unchanged.
func expression(t *testing.T, ref symbols.TypeRef) string {
	t.Helper()
	d := symbols.Declaration{PointerWidth: 8, Records: []symbols.Record{{Name: "probe",
		Members: []symbols.Member{{Name: "m", Type: ref}}}}}
	var buf bytes.Buffer
	if err := symbols.Encode(&buf, d); err != nil {
		t.Fatal(err)
	}
	back, err := symbols.DecodeDeclaration(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got := back.Records[0].Members[0].Type; !reflect.DeepEqual(got, ref) {
		t.Fatalf("reference %+v reads back as %+v", ref, got)
	}
	var probe struct {
		Records []struct {
			Members []struct {
				Type string `json:"type"`
			} `json:"members"`
		} `json:"records"`
	}
	if err := json.Unmarshal(buf.Bytes(), &probe); err != nil {
		t.Fatal(err)
	}
	return probe.Records[0].Members[0].Type
}

func TestIntegerEncodingsGiveTheScalarKinds(t *testing.T) {
	b := btftest.New()
	b.Int("int", 4, btf.IntSigned)
	b.Int("unsigned int", 4, 0)
	b.Int("char", 1, btf.IntChar)
	b.Int("_Bool", 1, btf.IntBool)
	b.Float("double", 8)
	out := convert(t, b)
	want := map[string]symbols.Scalar{
		"int":          {Name: "int", Width: 4, Kind: symbols.ScalarInteger, Signed: true},
		"unsigned int": {Name: "unsigned int", Width: 4, Kind: symbols.ScalarInteger},
		"char":         {Name: "char", Width: 1, Kind: symbols.ScalarChar},
		"_Bool":        {Name: "_Bool", Width: 1, Kind: symbols.ScalarBool},
		"double":       {Name: "double", Width: 8, Kind: symbols.ScalarFloat},
		"void":         {Name: "void", Kind: symbols.ScalarVoid},
	}
	if len(out.Scalars) != len(want) {
		t.Fatalf("scalars %+v", out.Scalars)
	}
	for _, s := range out.Scalars {
		if want[s.Name] != s {
			t.Errorf("scalar %+v, want %+v", s, want[s.Name])
		}
	}
}

func TestIntegersOfOneNameThatDisagreeGiveNoScalar(t *testing.T) {
	b := btftest.New()
	b.Int("word", 4, 0)
	b.Int("word", 8, 0)
	out := convert(t, b)
	for _, s := range out.Scalars {
		if s.Name == "word" {
			t.Fatalf("scalar %+v kept", s)
		}
	}
	if out.Report.Refused[string(refuseScalarConflict)] != 1 {
		t.Fatalf("refused %v", out.Report.Refused)
	}
}

func TestMembersKeepTheirPlacesAndTypes(t *testing.T) {
	b := btftest.New()
	u8 := b.Int("unsigned char", 1, 0)
	i32 := b.Int("int", 4, btf.IntSigned)
	node := b.Fwd("node", false)
	typedef := b.Typedef("s32", b.Const(i32))
	proto := b.FuncProto(i32)
	b.Struct("thing", 48,
		btftest.Member{Name: "count", Type: typedef, BitOffset: 0},
		btftest.Member{Name: "next", Type: b.Ptr(node), BitOffset: 64},
		btftest.Member{Name: "name", Type: b.Array(u8, i32, 16), BitOffset: 128},
		btftest.Member{Name: "call", Type: b.Ptr(proto), BitOffset: 256},
		btftest.Member{Name: "any", Type: b.Ptr(0), BitOffset: 320},
		btftest.Member{Name: "tail", Type: b.Array(b.Ptr(b.Volatile(u8)), i32, 0), BitOffset: 384},
	)
	out := convert(t, b)
	r := record(t, out, "thing")
	if r.Width != 48 || len(r.Members) != 6 {
		t.Fatalf("record %+v", r)
	}
	for name, want := range map[string]struct {
		offset uint64
		expr   string
	}{
		"count": {0, "int"}, "next": {8, "*node"}, "name": {16, "[16]unsigned char"}, "call": {32, "*"},
		"any": {40, "*void"}, "tail": {48, "[0]*unsigned char"},
	} {
		m := member(t, r, name)
		if m.Offset != want.offset || expression(t, m.Type) != want.expr {
			t.Errorf("member %s at %d is %q, want %d %q", name, m.Offset, expression(t, m.Type), want.offset, want.expr)
		}
	}
	if !hasRecord(out, "node") || len(record(t, out, "node").Members) != 0 || out.Report.Forwards != 1 {
		t.Fatalf("forward declaration not written as a name: %+v", out.Report)
	}
}

func TestABitfieldSitsInAStorageUnitOfItsType(t *testing.T) {
	b := btftest.New()
	u32 := b.Int("unsigned int", 4, 0)
	b.Struct("flags", 8,
		btftest.Member{Name: "a", Type: u32, BitOffset: 0, BitSize: 3},
		btftest.Member{Name: "b", Type: u32, BitOffset: 3, BitSize: 29},
		btftest.Member{Name: "c", Type: u32, BitOffset: 37, BitSize: 5},
	)
	r := record(t, convert(t, b), "flags")
	for name, want := range map[string]struct {
		offset uint64
		expr   string
	}{"a": {0, "@0:3 unsigned int"}, "b": {0, "@3:29 unsigned int"}, "c": {4, "@5:5 unsigned int"}} {
		m := member(t, r, name)
		if m.Offset != want.offset || expression(t, m.Type) != want.expr {
			t.Errorf("member %s at %d is %q, want %d %q", name, m.Offset, expression(t, m.Type), want.offset, want.expr)
		}
	}
}

func TestABitfieldOfAPackedRecordFallsBackToItsFirstByte(t *testing.T) {
	b := btftest.New()
	u32 := b.Int("unsigned int", 4, 0)
	b.Struct("packed", 6,
		btftest.Member{Name: "x", Type: u32, BitOffset: 28, BitSize: 8},
		btftest.Member{Name: "y", Type: u32, BitOffset: 36, BitSize: 31},
	)
	out := convert(t, b)
	r := record(t, out, "packed")
	m := member(t, r, "x")
	if m.Offset != 3 || expression(t, m.Type) != "@4:8 unsigned int" {
		t.Fatalf("x at %d is %q", m.Offset, expression(t, m.Type))
	}
	if len(r.Members) != 1 || out.Report.Refused[string(refuseBitfieldFit)] != 1 {
		t.Fatalf("a field no unit holds was kept: %+v %v", r.Members, out.Report.Refused)
	}
}

func TestANarrowIntegerWithoutKindFlagIsABitfield(t *testing.T) {
	b := btftest.New()
	b.Int("unsigned int", 4, 0)
	narrow := b.Raw("unsigned int", btftest.Info(kindInt, 0, false), 4, 2<<16|4)
	b.Raw("old", btftest.Info(kindStruct, 1, false), 4, b.Name("f"), narrow, 8)
	out := convert(t, b)
	m := member(t, record(t, out, "old"), "f")
	if m.Offset != 0 || expression(t, m.Type) != "@10:4 unsigned int" {
		t.Fatalf("f at %d is %q", m.Offset, expression(t, m.Type))
	}
	for _, s := range out.Scalars {
		if s.Name == "unsigned int" && s.Width != 4 {
			t.Fatalf("scalar %+v", s)
		}
	}
}

func TestAKindFlagBitfieldNeedsARegularInteger(t *testing.T) {
	b := btftest.New()
	narrow := b.Raw("unsigned int", btftest.Info(kindInt, 0, false), 4, 4)
	b.Struct("bad", 4, btftest.Member{Name: "f", Type: narrow, BitOffset: 0, BitSize: 2})
	out := convert(t, b)
	if len(record(t, out, "bad").Members) != 0 || out.Report.Refused[string(refuseBitfieldRegular)] != 1 {
		t.Fatalf("refused %v", out.Report.Refused)
	}
}

func TestAnEnumerationCanHoldABitfield(t *testing.T) {
	b := btftest.New()
	e := b.Enum("mode", 4, false, btftest.Value{Name: "MODE_A", Value: 0}, btftest.Value{Name: "MODE_B", Value: 1})
	b.Struct("holder", 4, btftest.Member{Name: "m", Type: e, BitOffset: 2, BitSize: 2})
	m := member(t, record(t, convert(t, b), "holder"), "m")
	if m.Offset != 0 || expression(t, m.Type) != "@2:2 mode" {
		t.Fatalf("m at %d is %q", m.Offset, expression(t, m.Type))
	}
}

func TestMembersAgainstTheKernelsPlacementRulesAreRefused(t *testing.T) {
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	ptr := b.Ptr(i32)
	b.Union("u", 8,
		btftest.Member{Name: "ok", Type: i32},
		btftest.Member{Name: "moved", Type: i32, BitOffset: 32},
	)
	b.Struct("s", 16,
		btftest.Member{Name: "first", Type: i32, BitOffset: 64},
		btftest.Member{Name: "back", Type: i32, BitOffset: 32},
		btftest.Member{Name: "first", Type: i32, BitOffset: 96},
		btftest.Member{Name: "odd", Type: ptr, BitOffset: 100},
		btftest.Member{Name: "past", Type: i32, BitOffset: 136},
		btftest.Member{Name: "9bad", Type: i32, BitOffset: 136},
	)
	out := convert(t, b)
	if got := len(record(t, out, "u").Members); got != 1 {
		t.Fatalf("union kept %d members", got)
	}
	if got := record(t, out, "s").Members; len(got) != 1 || got[0].Name != "first" || got[0].Offset != 8 {
		t.Fatalf("struct kept %+v", got)
	}
	for _, r := range []refusal{refuseUnionOffset, refuseOffsetOrder, refuseDuplicateMember, refuseByteOffset,
		refuseOffsetPast, refuseMemberName} {
		if out.Report.Refused[string(r)] != 1 {
			t.Errorf("%q counted %d times", r, out.Report.Refused[string(r)])
		}
	}
}

func TestATypeTheTableCannotWriteRefusesTheMember(t *testing.T) {
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	deep := i32
	for range symbols.MaxTypeOperators + 1 {
		deep = b.Ptr(deep)
	}
	shallow := i32
	for range symbols.MaxTypeOperators {
		shallow = b.Ptr(shallow)
	}
	loopA := b.Raw("loop_a", btftest.Info(8, 0, false), 0)
	b.Typedef("loop_b", loopA)
	proto := b.FuncProto(i32)
	b.Struct("s", 64,
		btftest.Member{Name: "deep", Type: deep},
		btftest.Member{Name: "shallow", Type: shallow},
		btftest.Member{Name: "fn", Type: proto, BitOffset: 64},
		btftest.Member{Name: "var", Type: b.Var("v", i32, 0), BitOffset: 128},
	)
	spec := parse(t, b)
	spec.Types[loopA].Ref = loopA + 1
	out, err := TypesFromBTF(spec, 8, limits.Default())
	if err != nil {
		t.Fatal(err)
	}
	r := record(t, out, "s")
	if len(r.Members) != 1 || r.Members[0].Name != "shallow" {
		t.Fatalf("members %+v", r.Members)
	}
	for _, rf := range []refusal{refuseOperators, refuseFunction, refuseKind} {
		if out.Report.Refused[string(rf)] != 1 {
			t.Errorf("%q counted %d times: %v", rf, out.Report.Refused[string(rf)], out.Report.Refused)
		}
	}
	if out.Report.Refused[string(refuseUnresolvable)] == 0 {
		t.Errorf("the typedef loop was not refused: %v", out.Report.Refused)
	}
}

func TestAnUnnamedRecordMemberIsEmbedded(t *testing.T) {
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	inner := b.Struct("", 8, btftest.Member{Name: "x", Type: i32}, btftest.Member{Name: "y", Type: i32, BitOffset: 32})
	alt := b.Union("", 8, btftest.Member{Name: "whole", Type: b.Int("long", 8, btf.IntSigned)},
		btftest.Member{Type: inner})
	b.Struct("outer", 16,
		btftest.Member{Name: "head", Type: i32},
		btftest.Member{Type: i32, BitOffset: 32, BitSize: 4},
		btftest.Member{Type: alt, BitOffset: 64},
	)
	out := convert(t, b)
	r := record(t, out, "outer")
	if len(r.Members) != 2 || r.Members[1].Embeds != "union{whole,x,y}" || r.Members[1].Offset != 8 {
		t.Fatalf("members %+v", r.Members)
	}
	if out.Report.Padding != 1 || out.Report.NamedByMembers != 2 {
		t.Fatalf("report %+v", out.Report)
	}
	f, err := build(t, out).Field("outer", "y")
	if err != nil || f.Offset != 12 {
		t.Fatalf("outer.y: %+v %v", f, err)
	}
}

func TestIdenticalAnonymousTypesAreWrittenOnce(t *testing.T) {
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	one := b.Union("", 4, btftest.Member{Name: "event", Type: i32}, btftest.Member{Name: "handler", Type: i32})
	two := b.Union("", 4, btftest.Member{Name: "event", Type: i32}, btftest.Member{Name: "handler", Type: i32})
	other := b.Union("", 8, btftest.Member{Name: "event", Type: i32}, btftest.Member{Name: "handler", Type: b.Int("long", 8, btf.IntSigned)})
	b.Struct("a", 4, btftest.Member{Name: "u", Type: one})
	b.Struct("b", 4, btftest.Member{Name: "u", Type: two})
	b.Struct("c", 8, btftest.Member{Name: "u", Type: other})
	out := convert(t, b)
	if got := expression(t, member(t, record(t, out, "a"), "u").Type); got != "union{event,handler}" {
		t.Fatalf("a.u is %q", got)
	}
	if got := expression(t, member(t, record(t, out, "b"), "u").Type); got != "union{event,handler}" {
		t.Fatalf("b.u is %q", got)
	}
	if got := expression(t, member(t, record(t, out, "c"), "u").Type); got != "union{event,handler}~2" {
		t.Fatalf("c.u is %q", got)
	}
	if out.Report.Merged != 1 || out.Report.Suffixed != 1 {
		t.Fatalf("report %+v", out.Report)
	}
}

func TestAMemberListNameStaysWithinMaxNameBytes(t *testing.T) {
	names := []string{"alpha", "beta", "gamma", "delta"}
	if got := memberListName("struct", names, 4096); got != "struct{alpha,beta,gamma,delta}" {
		t.Fatalf("%q", got)
	}
	for limit := 1; limit <= 40; limit++ {
		got := memberListName("struct", names, limit)
		if len(got) > max(limit-suffixRoom, len("struct{...}")) || !strings.HasPrefix(got, "struct{") || !strings.HasSuffix(got, "}") {
			t.Fatalf("limit %d: %q", limit, got)
		}
	}
	if got := memberListName("struct", names, 30); got != "struct{alpha,beta,...}" {
		t.Fatalf("%q", got)
	}
}

func TestOneNameForDifferentDefinitionsIsSuffixedOnEvery(t *testing.T) {
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	i64 := b.Int("long", 8, btf.IntSigned)
	first := b.Struct("slot", 4, btftest.Member{Name: "n", Type: i32})
	second := b.Struct("slot", 8, btftest.Member{Name: "n", Type: i64})
	b.Struct("slot", 4, btftest.Member{Name: "n", Type: i32})
	b.Struct("user", 16, btftest.Member{Name: "a", Type: b.Ptr(first)}, btftest.Member{Name: "b", Type: b.Ptr(second), BitOffset: 64})
	out := convert(t, b)
	if hasRecord(out, "slot") || !hasRecord(out, "slot~1") || !hasRecord(out, "slot~2") || hasRecord(out, "slot~3") {
		t.Fatalf("records %+v", out.Records)
	}
	u := record(t, out, "user")
	if expression(t, member(t, u, "a").Type) != "*slot~1" || expression(t, member(t, u, "b").Type) != "*slot~2" {
		t.Fatalf("user %+v", u.Members)
	}
	if !reflect.DeepEqual(out.Report.Conflicts, []string{"slot"}) || out.Report.Merged != 1 {
		t.Fatalf("report %+v", out.Report)
	}
}

func TestDefinitionsDifferingOnlyInWhatTheyPointToAreTwo(t *testing.T) {
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	i64 := b.Int("long", 8, btf.IntSigned)
	bar1 := b.Struct("bar", 4, btftest.Member{Name: "v", Type: i32})
	bar2 := b.Struct("bar", 8, btftest.Member{Name: "v", Type: i64})
	b.Struct("foo", 8, btftest.Member{Name: "p", Type: b.Ptr(bar1)})
	b.Struct("foo", 8, btftest.Member{Name: "p", Type: b.Ptr(bar2)})
	out := convert(t, b)
	if !hasRecord(out, "foo~1") || !hasRecord(out, "foo~2") {
		t.Fatalf("records %+v", out.Records)
	}
	if expression(t, member(t, record(t, out, "foo~1"), "p").Type) != "*bar~1" ||
		expression(t, member(t, record(t, out, "foo~2"), "p").Type) != "*bar~2" {
		t.Fatalf("foo~1 %+v foo~2 %+v", record(t, out, "foo~1"), record(t, out, "foo~2"))
	}
}

func TestATypedefNamesItsAnonymousTypeAndAnswersForItsTarget(t *testing.T) {
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	anon := b.Struct("", 4, btftest.Member{Name: "counter", Type: i32})
	b.Typedef("atomic_t", anon)
	seq := b.Struct("seqcount", 4, btftest.Member{Name: "sequence", Type: i32})
	b.Typedef("seqcount_t", seq)
	b.Typedef("pid_t", b.Typedef("__kernel_pid_t", i32))
	mode := b.Enum("", 4, false, btftest.Value{Name: "M_A", Value: 1})
	b.Typedef("mode_t", mode)
	b.Typedef("handler_t", b.Ptr(b.FuncProto(i32)))
	b.Typedef("fn_t", b.FuncProto(i32))
	b.Typedef("int", i32)
	b.Struct("user", 12,
		btftest.Member{Name: "a", Type: b.Typedef("atomic_t", anon)},
		btftest.Member{Name: "s", Type: b.Typedef("seqcount_t", seq), BitOffset: 32},
		btftest.Member{Name: "m", Type: b.Typedef("mode_t", mode), BitOffset: 64},
	)
	out := convert(t, b)
	u := record(t, out, "user")
	for name, want := range map[string]string{"a": "atomic_t", "s": "seqcount", "m": "mode_t"} {
		if got := expression(t, member(t, u, name).Type); got != want {
			t.Errorf("user.%s is %q, want %q", name, got, want)
		}
	}
	table := build(t, out)
	if f, err := table.Field("seqcount_t", "sequence"); err != nil || f.Offset != 0 {
		t.Fatalf("seqcount_t.sequence: %+v %v", f, err)
	}
	if v, err := table.EnumValue("mode_t", "M_A"); err != nil || v != 1 {
		t.Fatalf("mode_t.M_A: %d %v", v, err)
	}
	var pid, kpid bool
	for _, s := range out.Scalars {
		pid = pid || s == symbols.Scalar{Name: "pid_t", Width: 4, Kind: symbols.ScalarInteger, Signed: true}
		kpid = kpid || s.Name == "__kernel_pid_t"
	}
	if !pid || !kpid {
		t.Fatalf("scalars %+v", out.Scalars)
	}
	if hasRecord(out, "handler_t") || hasRecord(out, "fn_t") || out.Report.Refused[string(refuseTypedefDerived)] != 2 {
		t.Fatalf("report %+v", out.Report)
	}
	if out.Report.Aliases != 3 {
		t.Fatalf("aliases %d", out.Report.Aliases)
	}
}

func TestAnEmptyAnonymousTypeIsNamedByItsMembersNotByATypedef(t *testing.T) {
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	empty := b.Struct("", 0)
	b.Typedef("lockdep_map_p", empty)
	b.Typedef("local_lock_t", empty)
	sized := b.Union("", 8)
	b.Typedef("release_pages_arg", sized)
	b.Struct("maple_tree", 4,
		btftest.Member{Name: "ma_external_lock", Type: b.Typedef("lockdep_map_p", empty)},
		btftest.Member{Name: "ma_flags", Type: i32})
	b.Struct("flex", 4, btftest.Member{Name: "__empty_data", Type: empty}, btftest.Member{Name: "n", Type: i32})
	out := convert(t, b)
	for rec, name := range map[string]string{"maple_tree": "ma_external_lock", "flex": "__empty_data"} {
		if got := expression(t, member(t, record(t, out, rec), name).Type); got != "struct{}" {
			t.Errorf("%s.%s is %q, want struct{}", rec, name, got)
		}
	}
	if r := record(t, out, "struct{}"); r.Width != 0 || r.Members == nil || len(r.Members) != 0 {
		t.Errorf("struct{} is %+v, want width 0 and an empty member list", r)
	}
	if r := record(t, out, "union{}"); r.Width != 8 || len(r.Members) != 0 {
		t.Errorf("union{} is %+v, want width 8 and no members", r)
	}
	for alias, target := range map[string]string{"lockdep_map_p": "struct{}", "local_lock_t": "struct{}", "release_pages_arg": "union{}"} {
		if r := record(t, out, alias); len(r.Members) != 1 || r.Members[0].Embeds != target {
			t.Errorf("%s is %+v, want an alias embedding %s", alias, r, target)
		}
	}
	if out.Report.NamedByMembers != 2 || out.Report.Aliases != 3 {
		t.Errorf("report %+v, want 2 named by members and 3 aliases", out.Report)
	}
	build(t, out)
}

func TestTheOutputKeepsConstantsByValueAndEmptyMemberLists(t *testing.T) {
	b := btftest.New()
	b.Enum("order", 4, true, btftest.Value{Name: "O_TWO", Value: 2}, btftest.Value{Name: "O_ZED", Value: 0xffffffff},
		btftest.Value{Name: "O_B", Value: 1}, btftest.Value{Name: "O_A", Value: 1})
	b.Typedef("order_t", b.Enum("", 4, false, btftest.Value{Name: "Q_TWO", Value: 2}, btftest.Value{Name: "Q_ONE", Value: 1}))
	b.Struct("lock_class_key", 0)
	b.Fwd("declared", false)
	out := convert(t, b)
	got := map[string][]string{}
	for _, e := range out.Enumerations {
		for _, v := range e.Values {
			got[e.Name] = append(got[e.Name], v.Name)
		}
	}
	for name, want := range map[string][]string{"order": {"O_ZED", "O_A", "O_B", "O_TWO"}, "order_t": {"Q_ONE", "Q_TWO"}} {
		if !reflect.DeepEqual(got[name], want) {
			t.Errorf("%s constants %v, want %v", name, got[name], want)
		}
	}
	for _, name := range []string{"lock_class_key", "declared"} {
		if r := record(t, out, name); r.Members == nil || len(r.Members) != 0 {
			t.Errorf("%s is %+v, want an empty member list", name, r)
		}
	}
}

func TestTypedefsOfOneNameForDifferentTypesNameNothing(t *testing.T) {
	b := btftest.New()
	b.Typedef("u8", b.Int("unsigned char", 1, 0))
	b.Typedef("u8", b.Int("char", 1, btf.IntChar))
	b.Typedef("u16", b.Int("short unsigned int", 2, 0))
	b.Typedef("u16", b.Int("short unsigned int", 2, 0))
	out := convert(t, b)
	names := map[string]bool{}
	for _, s := range out.Scalars {
		names[s.Name] = true
	}
	if names["u8"] || !names["u16"] || out.Report.Refused[string(refuseTypedefConflict)] != 1 {
		t.Fatalf("scalars %+v report %+v", out.Scalars, out.Report)
	}
}

func TestEnumerationConstantsFollowTheirSignedness(t *testing.T) {
	b := btftest.New()
	b.Enum("neg", 4, true, btftest.Value{Name: "N_MINUS", Value: 0xffffffff})
	b.Enum("pos", 4, false, btftest.Value{Name: "P_BIG", Value: 0xffffffff})
	b.Enum64("wide", 8, false, btftest.Value{Name: "W_TOP", Value: 1 << 63})
	b.Enum64("swide", 8, true, btftest.Value{Name: "S_MINUS", Value: ^uint64(0)})
	b.Enum("", 4, false, btftest.Value{Name: "X_ONE", Value: 1}, btftest.Value{Name: "X_TWO", Value: 2})
	b.Enum("odd", 3, false, btftest.Value{Name: "O_A", Value: 1})
	b.Enum("twice", 4, false, btftest.Value{Name: "T_A", Value: 1}, btftest.Value{Name: "T_A", Value: 2})
	b.Enum("decl", 4, false)
	out := convert(t, b)
	got := map[string]symbols.EnumType{}
	for _, e := range out.Enumerations {
		got[e.Name] = e
	}
	for name, want := range map[string]int64{"neg": -1, "pos": 0xffffffff, "wide": -1 << 63, "swide": -1} {
		if e := got[name]; len(e.Values) != 1 || e.Values[0].Value != want {
			t.Errorf("enumeration %s: %+v, want %d", name, e, want)
		}
	}
	if e, ok := got["enum{X_ONE,X_TWO}"]; !ok || e.Size != 4 {
		t.Errorf("anonymous enumeration missing: %+v", out.Enumerations)
	}
	if _, ok := got["odd"]; ok {
		t.Errorf("a 3-byte enumeration was kept")
	}
	if _, ok := got["twice"]; ok {
		t.Errorf("an enumeration with a repeated constant was kept")
	}
	if _, ok := got["decl"]; ok {
		t.Errorf("a declaration became an enumeration")
	}
	if out.Report.Refused[string(refuseEnumWidth)] != 1 || out.Report.Refused[string(refuseConstantRepeat)] != 1 {
		t.Errorf("refused %v", out.Report.Refused)
	}
}

func TestAMemberOfARefusedTypeIsRefused(t *testing.T) {
	b := btftest.New()
	bad := b.Enum("odd", 3, false, btftest.Value{Name: "O_A", Value: 1})
	weird := b.Struct("bad-name", 4, btftest.Member{Name: "x", Type: b.Int("int", 4, btf.IntSigned)})
	b.Struct("user", 8, btftest.Member{Name: "e", Type: bad}, btftest.Member{Name: "w", Type: b.Ptr(weird), BitOffset: 0})
	b.Typedef("odd_t", bad)
	out := convert(t, b)
	for _, e := range out.Enumerations {
		if e.Name == "odd_t" {
			t.Fatalf("a typedef of a refused type was written: %+v", e)
		}
	}
	if len(record(t, out, "user").Members) != 0 || out.Report.Refused[string(refuseRefusedType)] != 3 ||
		out.Report.Refused[string(refuseTypeName)] != 1 {
		t.Fatalf("report %+v", out.Report)
	}
}

func TestEveryConvertedTableBuildsAndRepeats(t *testing.T) {
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	list := b.Fwd("list_head", false)
	listDef := b.Struct("list_head", 16)
	_ = listDef
	b.Struct("task", 24, btftest.Member{Name: "pid", Type: i32},
		btftest.Member{Name: "tasks", Type: b.Ptr(list), BitOffset: 64},
		btftest.Member{Type: b.Union("", 8, btftest.Member{Name: "a", Type: i32}, btftest.Member{Name: "b", Type: i32}), BitOffset: 128})
	spec := parse(t, b)
	first, err := TypesFromBTF(spec, 8, limits.Default())
	if err != nil {
		t.Fatal(err)
	}
	second, err := TypesFromBTF(spec, 8, limits.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("two conversions of one BTF differ")
	}
	table := build(t, first)
	if f, err := table.Field("task", "b"); err != nil || f.Offset != 16 {
		t.Fatalf("task.b: %+v %v", f, err)
	}
	if first.Report.Forwards != 0 {
		t.Fatalf("a forward declaration with a definition was written: %+v", first.Report)
	}
}

func TestTypesFromBTFRefusesWhatItCannotStartOn(t *testing.T) {
	b := btftest.New()
	b.Int("int", 4, btf.IntSigned)
	spec := parse(t, b)
	for _, c := range []struct {
		spec    *btf.Spec
		pointer int64
		l       limits.Limits
		want    error
	}{
		{nil, 8, limits.Default(), ErrNoBTF},
		{spec, 2, limits.Default(), ErrPointerSize},
		{spec, 8, limits.Limits{MaxTableEntries: 0}, nil},
	} {
		if _, err := TypesFromBTF(c.spec, c.pointer, c.l); !errors.Is(err, c.want) {
			t.Errorf("error %v, want %v", err, c.want)
		}
	}
	small := limits.Default()
	small.MaxTableEntries = 1
	b.Int("long", 8, btf.IntSigned)
	if _, err := TypesFromBTF(parse(t, b), 8, small); !errors.Is(err, ErrTooManyTypes) {
		t.Fatalf("error %v", err)
	}
}

func TestQualifiersAndTypeTagsChangeNoLayout(t *testing.T) {
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	tagged := b.TypeTag("user", b.Restrict(b.Const(b.Volatile(i32))))
	b.Struct("q", 8, btftest.Member{Name: "p", Type: b.Ptr(tagged)})
	if got := expression(t, member(t, record(t, convert(t, b), "q"), "p").Type); got != "*int" {
		t.Fatalf("q.p is %q", got)
	}
}

func TestRecordUnionKindsAreBothRecords(t *testing.T) {
	b := btftest.New()
	i32 := b.Int("int", 4, btf.IntSigned)
	b.Raw("raw", btftest.Info(kindUnion, 1, false), 4, b.Name("x"), i32, 0)
	if r := record(t, convert(t, b), "raw"); r.Width != 4 || len(r.Members) != 1 {
		t.Fatalf("raw %+v", r)
	}
}
