package symbols

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// Everything a table file says, before embedded members are brought up.
type Declaration struct {
	PointerWidth uint8
	WindowsPDB   *PDBBuild
	LinuxBanner  []byte
	// Nil declares no scalars, so widths follow from type names. Empty and not
	// nil declares that there are none: a member of a type the table does not
	// hold then has no width.
	Scalars      []Scalar
	Records      []Record
	Enumerations []EnumType
	Addresses    []Address
}

type ScalarKind string

const (
	ScalarInteger ScalarKind = "integer"
	ScalarFloat   ScalarKind = "float"
	ScalarChar    ScalarKind = "char"
	ScalarBool    ScalarKind = "bool"
	ScalarVoid    ScalarKind = "void"
)

func (k ScalarKind) known() bool {
	switch k {
	case ScalarInteger, ScalarFloat, ScalarChar, ScalarBool, ScalarVoid:
		return true
	}
	return false
}

type Scalar struct {
	Name      string
	Width     uint64
	Kind      ScalarKind
	Signed    bool
	BigEndian bool
}

type Record struct {
	Name    string
	Width   uint64
	Members []Member
}

// A member with Embeds set has no type of its own: it stands for the members
// of the record it names. Its Name, if any, is only for messages.
type Member struct {
	Name   string
	Offset uint64
	Type   TypeRef
	Embeds string
}

type Address struct {
	Name    string
	Address uint64
	Type    *TypeRef
}

func (d Declaration) check() error {
	if d.PointerWidth != 4 && d.PointerWidth != 8 {
		return fmt.Errorf("symbols: pointer width %d is not 4 or 8", d.PointerWidth)
	}
	if d.WindowsPDB != nil {
		if err := d.WindowsPDB.check(); err != nil {
			return err
		}
	}
	if d.LinuxBanner != nil && len(d.LinuxBanner) == 0 {
		return errors.New("symbols: Linux banner is empty")
	}
	if err := distinct("scalar", d.Scalars, func(s Scalar) string { return s.Name }); err != nil {
		return err
	}
	for _, s := range d.Scalars {
		if !s.Kind.known() {
			return fmt.Errorf("symbols: scalar %q: kind %q is not integer, float, char, bool or void", s.Name, s.Kind)
		}
	}
	if err := distinct("record", d.Records, func(r Record) string { return r.Name }); err != nil {
		return err
	}
	for _, r := range d.Records {
		if err := checkMembers(r.Members); err != nil {
			return fmt.Errorf("symbols: record %q: %w", r.Name, err)
		}
	}
	if err := distinct("enumeration", d.Enumerations, func(e EnumType) string { return e.Name }); err != nil {
		return err
	}
	for _, e := range d.Enumerations {
		if err := distinct("constant", e.Values, func(v EnumValue) string { return v.Name }); err != nil {
			return fmt.Errorf("symbols: enumeration %q: %w", e.Name, err)
		}
	}
	if err := distinct("address", d.Addresses, func(a Address) string { return a.Name }); err != nil {
		return err
	}
	for _, a := range d.Addresses {
		if a.Type == nil {
			continue
		}
		if err := checkTypeRef(*a.Type); err != nil {
			return fmt.Errorf("symbols: address %q: %w", a.Name, err)
		}
	}
	return nil
}

func checkMembers(members []Member) error {
	named := make(map[string]bool, len(members))
	for i, m := range members {
		if m.Embeds != "" {
			if m.Type != (TypeRef{}) {
				return fmt.Errorf("member %d embeds %q and also has a type", i, m.Embeds)
			}
			continue
		}
		if m.Name == "" {
			return fmt.Errorf("member %d has neither a name nor a record it embeds", i)
		}
		if named[m.Name] {
			return fmt.Errorf("two members are named %q", m.Name)
		}
		named[m.Name] = true
		if err := checkTypeRef(m.Type); err != nil {
			return fmt.Errorf("member %q: %w", m.Name, err)
		}
	}
	return nil
}

func distinct[T any](what string, items []T, name func(T) string) error {
	seen := make(map[string]bool, len(items))
	for i, item := range items {
		n := name(item)
		if n == "" {
			return fmt.Errorf("symbols: %s %d has no name", what, i)
		}
		if seen[n] {
			return fmt.Errorf("symbols: %s %q is named twice", what, n)
		}
		seen[n] = true
	}
	return nil
}

// The file is UTF-8 (FORMAT.md), so a name that is not cannot be written.
func (d Declaration) checkText() error {
	var bad string
	text := func(s string) {
		if bad == "" && !utf8.ValidString(s) {
			bad = s
		}
	}
	if d.LinuxBanner != nil {
		text(string(d.LinuxBanner))
	}
	if d.WindowsPDB != nil {
		text(d.WindowsPDB.Database)
	}
	for _, s := range d.Scalars {
		text(s.Name)
	}
	for _, r := range d.Records {
		text(r.Name)
		for _, m := range r.Members {
			text(m.Name)
			text(m.Embeds)
			text(formatTypeRef(m.Type))
		}
	}
	for _, e := range d.Enumerations {
		text(e.Name)
		for _, v := range e.Values {
			text(v.Name)
		}
	}
	for _, a := range d.Addresses {
		text(a.Name)
		if a.Type != nil {
			text(formatTypeRef(*a.Type))
		}
	}
	if bad != "" {
		return fmt.Errorf("symbols: %q is not UTF-8", bad)
	}
	return nil
}
