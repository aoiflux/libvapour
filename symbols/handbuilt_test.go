package symbols

import (
	"slices"
	"testing"
)

func TestAHandBuiltTable(t *testing.T) {
	table := NewTable("hand", 8)
	table.AddStruct(StructType{Name: "s", Size: 12, Fields: []Field{
		{Name: "b", Offset: 4, Type: TypeRef{Name: "unsigned int"}},
		{Name: "a", Offset: 4, Type: TypeRef{Name: "unsigned short"}},
		{Name: "z", Offset: 0, Type: TypeRef{Name: "e"}},
		{Name: "p", Offset: 8, Type: TypeRef{Name: "s", IsPointer: true}},
	}})
	table.AddStruct(StructType{Name: "nameless_members"})
	table.AddStruct(StructType{})
	table.AddEnum(EnumType{Name: "e", Values: []EnumValue{{Name: "Y", Value: 1}, {Name: "X", Value: 0}}})
	table.AddEnum(EnumType{})
	table.AddSymbol(Symbol{Name: "head", Address: 0x40})
	table.AddSymbol(Symbol{})
	var none *Table
	none.AddStruct(StructType{Name: "x"})
	none.AddEnum(EnumType{Name: "x"})
	none.AddSymbol(Symbol{Name: "x"})

	st, err := table.Struct("s")
	if err != nil {
		t.Fatal(err)
	}
	if got := members(st); got != "z@0 a@4 b@4 p@8" {
		t.Errorf("members by offset, then name: %s", got)
	}
	if _, err := table.Struct("nameless_members"); err != nil {
		t.Errorf("a hand-built record with no members is still a record: %v", err)
	}
	mem := flat{data: []byte{2, 0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
	inst, err := table.ReadStruct(mem, "s", 0)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Fields["z"] != 2 || inst.Fields["a"] != 0x109 || inst.Fields["b"] != 0x109 || inst.Fields["p"] != 0 {
		t.Errorf("%+v", inst.Fields)
	}
	if v, err := table.EnumValue("e", "Y"); err != nil || v != 1 {
		t.Errorf("Y %d %v", v, err)
	}
	if got := NamesAt(table, 0x40); !slices.Equal(got, []string{"head"}) {
		t.Errorf("%v", got)
	}
	table.AddSymbol(Symbol{Name: "alias", Address: 0x40})
	if got := NamesAt(table, 0x40); !slices.Equal(got, []string{"alias", "head"}) {
		t.Errorf("a symbol added after a lookup by address is found: %v", got)
	}
	if len(table.SymbolNames()) != 2 {
		t.Errorf("%v", table.SymbolNames())
	}
}
