package symbols

import (
	"bytes"
	"fmt"
	"slices"
)

func Build(name string, d Declaration) (*Table, error) {
	return BuildWith(name, d, ReadOptions{})
}

func BuildWith(name string, d Declaration, opts ReadOptions) (*Table, error) {
	opts, err := opts.Resolved()
	if err != nil {
		return nil, err
	}
	if err := d.check(); err != nil {
		return nil, err
	}
	return assemble(name, d, opts.MaxTableEntries)
}

// d has passed check.
func assemble(name string, d Declaration, margin int) (*Table, error) {
	t := &Table{
		name:        name,
		pointerSize: d.PointerWidth,
		structs:     make(map[string]StructType, len(d.Records)),
		enums:       make(map[string]EnumType, len(d.Enumerations)),
		symbols:     make(map[string]Symbol, len(d.Addresses)),
		symbolRefs:  map[string]TypeRef{},
	}
	if d.WindowsPDB != nil {
		t.pdb, t.hasPDB = *d.WindowsPDB, true
	}
	if d.LinuxBanner != nil {
		t.banner = bytes.Clone(d.LinuxBanner)
	}
	// A table naming both systems, or neither, has no data model to fall back on.
	switch {
	case t.hasPDB && t.banner == nil:
		t.platform = PlatformWindows
	case t.banner != nil && !t.hasPDB:
		t.platform = PlatformLinux
	}
	if d.Scalars != nil {
		t.scalars = make(map[string]Scalar, len(d.Scalars))
		for _, s := range d.Scalars {
			t.scalars[s.Name] = s
		}
	}
	for _, e := range d.Enumerations {
		e.Values = slices.Clone(e.Values)
		sortConstants(e.Values)
		t.enums[e.Name] = e
	}
	if err := t.placeRecords(d.Records, margin); err != nil {
		return nil, err
	}
	for _, a := range d.Addresses {
		s := Symbol{Name: a.Name, Address: a.Address}
		if a.Type != nil {
			s.Type = symbolTypeText(*a.Type)
			t.symbolRefs[a.Name] = *a.Type
		}
		t.symbols[a.Name] = s
	}
	return t, nil
}

// A record with no members is a name only: tools cannot read it, though
// another record may embed it.
func (t *Table) placeRecords(records []Record, margin int) error {
	e := newEmbedder(records)
	var written, total uint64
	brought := make(map[string]uint64, len(records))
	for _, r := range records {
		if len(r.Members) == 0 {
			continue
		}
		written += uint64(len(r.Members))
		if !embeds(r) {
			brought[r.Name] = uint64(len(r.Members))
			total = addSaturating(total, uint64(len(r.Members)))
			continue
		}
		n, err := e.count(r.Name)
		if err != nil {
			t.markUnreadable(r.Name, err)
			continue
		}
		brought[r.Name] = n
		total = addSaturating(total, n)
	}
	if limit := addSaturating(2*written, uint64(margin)); total > limit {
		return fmt.Errorf("symbols: anonymous members would bring up %d members, more than twice the %d written plus "+
			"MaxTableEntries (%d)", total, written, margin)
	}
	for _, r := range records {
		n, ok := brought[r.Name]
		if !ok {
			continue
		}
		var fields []Field
		if embeds(r) {
			var err error
			if fields, err = e.fields(r, n); err != nil {
				t.markUnreadable(r.Name, err)
				continue
			}
		} else {
			fields = make([]Field, len(r.Members))
			for i, m := range r.Members {
				fields[i] = Field{Name: m.Name, Offset: m.Offset, Type: m.Type}
			}
		}
		t.structs[r.Name] = StructType{Name: r.Name, Size: r.Width, Fields: fields}
	}
	return nil
}

func (t *Table) markUnreadable(name string, why error) {
	if t.unreadable == nil {
		t.unreadable = map[string]UnusableTypeError{}
	}
	t.unreadable[name] = UnusableTypeError{TypeName: name, Reason: why.Error()}
}

// What a reader of the symbol's first element reads: an array's element, a
// bitfield's storage unit, and any pointer as one * before the innermost name,
// since every pointer has the table's pointer width.
func symbolTypeText(ref TypeRef) string {
	for range MaxTypeOperators + 1 {
		switch op, _ := ref.operators(); op {
		case opNone:
			return ref.Name
		case opPointer:
			if ref.Name == "" {
				return ""
			}
			return "*" + ref.Name
		}
		ref = ref.inner()
	}
	return ""
}
