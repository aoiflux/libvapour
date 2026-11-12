package symbols

import (
	"strings"
	"testing"
)

func TestTypeExpressionsReadBackAsWritten(t *testing.T) {
	for _, expr := range []string{
		"", "int", "*_LIST_ENTRY", "[16]unsigned char", "*[4]*void", "@0:3 unsigned long", "*",
		"[0]_LIST_ENTRY", "@63:1 unsigned long long", `\*odd`, `*\[odd`, `\@at`, `\\back`,
		"unsigned long long", "[18446744073709551615]char", "@255:255 x",
	} {
		r := ref(t, expr)
		if err := checkTypeRef(r); err != nil {
			t.Errorf("%q: %v", expr, err)
		}
		if got := formatTypeRef(r); got != expr {
			t.Errorf("format(parse(%q)) = %q", expr, got)
		}
	}
}

func TestEveryLevelCarriesTheInnermostName(t *testing.T) {
	r := ref(t, "*[4]@2:5 unsigned int")
	if !r.IsPointer || r.Name != "unsigned int" {
		t.Fatalf("outer %+v", r)
	}
	a := *r.Element
	if !a.IsArray || a.ArrayLength != 4 || a.Name != "unsigned int" {
		t.Fatalf("array %+v", a)
	}
	b := *a.Element
	if b.BitOffset != 2 || b.BitLength != 5 || b.Name != "unsigned int" {
		t.Fatalf("bitfield %+v", b)
	}
	if n := *b.Element; n.Element != nil || n.Name != "unsigned int" || n.IsPointer || n.isArray() || n.BitLength != 0 {
		t.Fatalf("name %+v", n)
	}
	if r := ref(t, "[0]x"); !r.IsArray || r.ArrayLength != 0 {
		t.Fatalf("[0]x = %+v, want an array of no elements", r)
	}
}

func TestMalformedTypeExpressionsAreRefused(t *testing.T) {
	for expr, why := range map[string]string{
		"[4x":                     "without ]",
		"[]x":                     "decimal",
		"[04]x":                   "decimal",
		"[-1]x":                   "decimal",
		"[18446744073709551616]x": "past",
		"@3 x":                    "@offset:length",
		"@0:3x":                   "space",
		"@0:0 x":                  "bit length",
		"@256:1 x":                "bit offset",
		"@0:256 x":                "bit length",
		`\x`:                      "needs no escape",
		`\`:                       "needs no escape",
		strings.Repeat("*", MaxTypeOperators+1) + "x": "operators",
	} {
		if _, err := parseTypeExpression(expr); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: %v, want an error saying %q", expr, err, why)
		}
	}
	if _, err := parseTypeExpression(strings.Repeat("*", MaxTypeOperators) + "x"); err != nil {
		t.Errorf("%d operators: %v", MaxTypeOperators, err)
	}
}

func TestATypeRefBuiltInCodeIsChecked(t *testing.T) {
	deep := TypeRef{Name: "x"}
	for range MaxTypeOperators + 1 {
		inner := deep
		deep = TypeRef{Name: "x", IsPointer: true, Element: &inner}
	}
	for name, r := range map[string]TypeRef{
		"two operators": {Name: "x", IsPointer: true, ArrayLength: 2},
		"offset only":   {Name: "x", BitOffset: 3},
		"named element": {Name: "x", Element: &TypeRef{Name: "y"}},
		"too deep":      deep,
	} {
		if err := checkTypeRef(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, r := range []TypeRef{{}, {Name: "x", IsPointer: true}, {Name: "x", ArrayLength: 3}, {Name: "x", BitLength: 1}} {
		if err := checkTypeRef(r); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	if got := formatTypeRef(TypeRef{Name: "x", ArrayLength: 3}); got != "[3]x" {
		t.Errorf("an array with no element and no flag is written %q", got)
	}
}
