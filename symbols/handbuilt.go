package symbols

import (
	"cmp"
	"slices"
	"strings"
)

// A table built in code, member by member. Its pointer width defaults to 8.
func NewTable(name string, pointerSize uint8) *Table {
	if pointerSize == 0 {
		pointerSize = 8
	}
	return &Table{
		name:        name,
		pointerSize: pointerSize,
		structs:     map[string]StructType{},
		enums:       map[string]EnumType{},
		symbols:     map[string]Symbol{},
		symbolRefs:  map[string]TypeRef{},
	}
}

// A hand-built table names no PDB or banner, so its builder states the
// platform that sizes names such as long.
func (t *Table) SetPlatform(p Platform) {
	if t != nil {
		t.platform = p
	}
}

// Code often gathers members from a map, so a hand-built record lists them by
// offset, then name, to give one order for one record.
func (t *Table) AddStruct(st StructType) {
	if t == nil || st.Name == "" {
		return
	}
	st.Fields = slices.Clone(st.Fields)
	slices.SortStableFunc(st.Fields, func(a, b Field) int {
		if c := cmp.Compare(a.Offset, b.Offset); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	t.structs[st.Name] = st
}

func (t *Table) AddEnum(en EnumType) {
	if t == nil || en.Name == "" {
		return
	}
	en.Values = slices.Clone(en.Values)
	sortConstants(en.Values)
	t.enums[en.Name] = en
}

func (t *Table) AddSymbol(sym Symbol) {
	if t == nil || sym.Name == "" {
		return
	}
	t.symbols[sym.Name] = sym
	t.byAddress.invalidate()
}

func sortConstants(values []EnumValue) {
	slices.SortFunc(values, func(a, b EnumValue) int {
		if c := cmp.Compare(a.Value, b.Value); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
}
