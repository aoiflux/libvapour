package symbols

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func members(st StructType) string {
	var parts []string
	for _, f := range st.Fields {
		parts = append(parts, fmt.Sprintf("%s@%d", f.Name, f.Offset))
	}
	return strings.Join(parts, " ")
}

func TestEmbeddedMembersAreBroughtUpInPlace(t *testing.T) {
	u := TypeRef{Name: "unsigned int"}
	table := mustBuild(t, Declaration{PointerWidth: 8, Records: []Record{
		{Name: "outer", Width: 64, Members: []Member{
			{Name: "x", Offset: 0, Type: u},
			{Offset: 8, Embeds: "middle"},
			{Name: "z", Offset: 30, Type: u},
			{Name: "tail", Offset: 56, Embeds: "empty"},
		}},
		{Name: "middle", Width: 24, Members: []Member{
			{Name: "y", Offset: 0, Type: u},
			{Name: "x", Offset: 4, Type: u},
			{Offset: 8, Embeds: "inner"},
		}},
		{Name: "inner", Width: 8, Members: []Member{{Name: "a", Offset: 0, Type: u}, {Name: "b", Offset: 4, Type: u}}},
		{Name: "empty", Width: 8},
	}})
	for name, want := range map[string]string{
		"outer":  "x@12 y@8 a@16 b@20 z@30",
		"middle": "y@0 x@4 a@8 b@12",
		"inner":  "a@0 b@4",
	} {
		st, err := table.Struct(name)
		if err != nil || members(st) != want {
			t.Errorf("%s: %s, %v; want %s", name, members(st), err, want)
		}
		typ, _ := table.LookupType(name)
		if got := members(StructType{Fields: typ.Fields}); got != want {
			t.Errorf("LookupType(%s): %s", name, got)
		}
	}
}

func TestARecordWhoseEmbeddedMembersCannotBeBroughtUpIsUnreadable(t *testing.T) {
	u := TypeRef{Name: "unsigned int"}
	table := mustBuild(t, Declaration{PointerWidth: 8, Records: []Record{
		{Name: "missing", Members: []Member{{Name: "m", Offset: 0, Embeds: "nowhere"}}},
		{Name: "cycle_a", Members: []Member{{Offset: 0, Embeds: "cycle_b"}}},
		{Name: "cycle_b", Members: []Member{{Offset: 0, Embeds: "cycle_a"}}},
		{Name: "self", Members: []Member{{Offset: 0, Embeds: "self"}}},
		{Name: "overflow", Members: []Member{{Offset: 1<<64 - 1, Embeds: "fine"}}},
		{Name: "holder", Members: []Member{{Offset: 0, Embeds: "missing"}}},
		{Name: "fine", Width: 8, Members: []Member{{Name: "x", Offset: 4, Type: u}}},
	}})
	for name, why := range map[string]string{
		"missing": `"nowhere"`, "cycle_a": "holds itself", "cycle_b": "holds itself", "self": "self > self",
		"overflow": "offset", "holder": `"nowhere"`,
	} {
		_, err := table.Struct(name)
		var u UnusableTypeError
		if !errors.As(err, &u) || u.TypeName != name || !strings.Contains(err.Error(), why) {
			t.Errorf("Struct(%s) = %v, want unreadable saying %s", name, err, why)
		}
		if _, err := table.LookupType(name); !errors.As(err, &u) {
			t.Errorf("LookupType(%s) = %v", name, err)
		}
		if _, err := table.SizeOf(name); !errors.As(err, &u) {
			t.Errorf("SizeOf(%s) = %v", name, err)
		}
		if _, err := table.Field(name, "x"); !errors.As(err, &u) {
			t.Errorf("Field(%s) = %v", name, err)
		}
	}
	if f, err := table.Field("fine", "x"); err != nil || f.Offset != 4 {
		t.Errorf("fine.x %+v %v", f, err)
	}
}

func TestATableWhoseEmbeddingWouldExplodeIsRefused(t *testing.T) {
	const fanout, depth = 4, 8
	var records []Record
	for level := range depth {
		r := Record{Name: fmt.Sprintf("t%d", level)}
		for i := range fanout {
			if level == depth-1 {
				r.Members = append(r.Members, Member{Name: fmt.Sprintf("f%d", i), Offset: uint64(i), Type: TypeRef{Name: "int"}})
				continue
			}
			r.Members = append(r.Members, Member{Offset: 0, Embeds: fmt.Sprintf("t%d", level+1)})
		}
		records = append(records, r)
	}
	d := Declaration{PointerWidth: 8, Records: records}
	if _, err := BuildWith("explode", d, ReadOptions{MaxTableEntries: 1000}); err == nil || !strings.Contains(err.Error(), "anonymous members") {
		t.Fatalf("%d members bringing up %d accepted: %v", fanout*depth, 1<<(2*depth), err)
	}
	if _, err := BuildWith("explode", d, ReadOptions{MaxTableEntries: 100000}); err != nil {
		t.Fatalf("a larger MaxTableEntries lets it through: %v", err)
	}
}
