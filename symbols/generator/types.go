package generator

import (
	"cmp"
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/btf"
)

const (
	voidName = "void"
	// include/asm-generic/vmlinux.lds.h opens the per-CPU output section
	// with this symbol.
	percpuSection = ".data..percpu"
	percpuStart   = "__per_cpu_start"
)

type converter struct {
	spec    *btf.Spec
	limits  limits.Limits
	maxName int
	report  *TypeReport

	typedefName map[uint32]string
	drafts      map[uint32]*draft
	order       []uint32
	class       map[uint32]int
	className   map[int]string
	rep         map[int]uint32
	records     map[string]int
	enums       map[string]int
	scalars     map[string]symbols.Scalar
}

func newConverter(spec *btf.Spec, l limits.Limits, report *TypeReport) *converter {
	l = l.Effective()
	return &converter{
		spec:        spec,
		limits:      l,
		maxName:     int(min(l.MaxNameBytes, int64(^uint(0)>>1))),
		report:      report,
		typedefName: map[uint32]string{},
		drafts:      map[uint32]*draft{},
		rep:         map[int]uint32{},
	}
}

func (c *converter) refuse(err error) {
	if c.report.Refused == nil {
		c.report.Refused = map[string]int{}
	}
	c.report.Refused[err.Error()]++
}

func (c *converter) convert() BTFTypes {
	c.nameAnonymousByTypedef()
	c.draftAll()
	c.partition()
	c.name()
	c.scalars = c.scalarTypes()
	out := BTFTypes{
		Scalars:      make([]symbols.Scalar, 0, len(c.scalars)),
		Records:      c.renderRecords(),
		Enumerations: c.renderEnums(),
	}
	c.addForwards(&out)
	c.addAliases(&out)
	for _, s := range c.scalars {
		out.Scalars = append(out.Scalars, s)
	}
	sort.Slice(out.Scalars, func(i, j int) bool { return out.Scalars[i].Name < out.Scalars[j].Name })
	sort.Slice(out.Records, func(i, j int) bool { return out.Records[i].Name < out.Records[j].Name })
	sort.Slice(out.Enumerations, func(i, j int) bool { return out.Enumerations[i].Name < out.Enumerations[j].Name })
	sort.Strings(c.report.Conflicts)
	return out
}

// C gives an anonymous structure, union or enumeration no name but the
// typedef declared with it. When several typedefs name one anonymous type,
// the first in type id order does; the others become aliases.
func (c *converter) nameAnonymousByTypedef() {
	for id := 1; id < len(c.spec.Types); id++ {
		t := c.spec.Types[id]
		if t.Kind != btf.KindTypedef || !identifier(t.Name, c.maxName) {
			continue
		}
		target := t.Ref
		for steps := 0; steps <= c.limits.MaxRecursionDepth; steps++ {
			k := c.spec.Types[target].Kind
			if k != btf.KindConst && k != btf.KindVolatile && k != btf.KindRestrict && k != btf.KindTypeTag {
				break
			}
			target = c.spec.Types[target].Ref
		}
		tt := c.spec.Types[target]
		if target == 0 || tt.Name != "" || !c.isComposite(tt) || c.memberless(tt) {
			continue
		}
		if _, ok := c.typedefName[target]; !ok {
			c.typedefName[target] = t.Name
		}
	}
}

func (c *converter) draftAll() {
	refused := map[uint32]bool{}
	for id := 1; id < len(c.spec.Types); id++ {
		t := c.spec.Types[id]
		if !c.isComposite(t) {
			continue
		}
		if t.Name != "" && !identifier(t.Name, c.maxName) {
			c.refuse(refuseTypeName)
			refused[uint32(id)] = true
			continue
		}
		if t.Kind == btf.KindEnum || t.Kind == btf.KindEnum64 {
			d, err := c.draftEnum(uint32(id))
			if err != nil {
				c.refuse(err)
				refused[uint32(id)] = true
				continue
			}
			c.drafts[uint32(id)] = d
		} else {
			c.drafts[uint32(id)] = c.draftRecord(uint32(id))
		}
		c.order = append(c.order, uint32(id))
	}
	if len(refused) == 0 {
		return
	}
	for _, id := range c.order {
		d := c.drafts[id]
		kept := d.members[:0]
		for _, m := range d.members {
			if m.typ.leaf == leafComposite && refused[m.typ.id] {
				c.refuse(refuseRefusedType)
				continue
			}
			kept = append(kept, m)
		}
		d.members = kept
	}
}

func (c *converter) leafName(s shape) string {
	switch s.leaf {
	case leafVoid:
		return voidName
	case leafScalar, leafForward:
		return s.name
	case leafComposite:
		if k, ok := c.class[s.id]; ok {
			return c.className[k]
		}
	}
	return ""
}

// A composite the converter refused has no class, and no name to refer to.
func (c *converter) written(s shape) bool {
	if s.leaf != leafComposite {
		return true
	}
	_, ok := c.class[s.id]
	return ok
}

// The table's reading of a type expression gives every level the innermost
// name and the level below it as Element; references are built the same way.
func (c *converter) typeRef(s shape, bitOffset, bitLength uint8) symbols.TypeRef {
	name := c.leafName(s)
	ref := symbols.TypeRef{Name: name}
	if bitLength > 0 {
		elem := ref
		ref = symbols.TypeRef{Name: name, BitOffset: bitOffset, BitLength: bitLength, Element: &elem}
	}
	for i := len(s.ops) - 1; i >= 0; i-- {
		elem := ref
		ref = symbols.TypeRef{Name: name, Element: &elem}
		if s.ops[i].kind == opPointer {
			ref.IsPointer = true
		} else {
			ref.IsArray, ref.ArrayLength = true, s.ops[i].count
		}
	}
	return ref
}

func (c *converter) renderRecords() []symbols.Record {
	var out []symbols.Record
	for name, k := range c.records {
		d := c.drafts[c.rep[k]]
		r := symbols.Record{Name: name, Width: d.size, Members: make([]symbols.Member, 0, len(d.members))}
		for _, m := range d.members {
			if m.embeds {
				r.Members = append(r.Members, symbols.Member{Offset: m.offset, Embeds: c.leafName(m.typ)})
				continue
			}
			r.Members = append(r.Members, symbols.Member{Name: m.name, Offset: m.offset,
				Type: c.typeRef(m.typ, m.bitOffset, m.bitLength)})
		}
		out = append(out, r)
	}
	return out
}

func (c *converter) renderEnums() []symbols.EnumType {
	var out []symbols.EnumType
	for name, k := range c.enums {
		d := c.drafts[c.rep[k]]
		out = append(out, symbols.EnumType{Name: name, Size: d.size, Values: byValue(d.values)})
	}
	return out
}

// symbols/FORMAT.md keeps constants by value, then name, so the generated
// declaration and the file it is written to hold them in one order.
func byValue(values []symbols.EnumValue) []symbols.EnumValue {
	out := slices.Clone(values)
	slices.SortStableFunc(out, func(a, b symbols.EnumValue) int {
		return cmp.Or(cmp.Compare(a.Value, b.Value), strings.Compare(a.Name, b.Name))
	})
	return out
}

func (c *converter) scalarTypes() map[string]symbols.Scalar {
	out := map[string]symbols.Scalar{voidName: {Name: voidName, Kind: symbols.ScalarVoid}}
	conflict := map[string]bool{}
	for id := 1; id < len(c.spec.Types); id++ {
		t := c.spec.Types[id]
		var s symbols.Scalar
		switch t.Kind {
		case btf.KindInt:
			s = symbols.Scalar{Name: t.Name, Width: uint64(t.Size), Kind: symbols.ScalarInteger,
				Signed: t.IntEncoding&btf.IntSigned != 0}
			switch {
			case t.IntEncoding&btf.IntBool != 0:
				s.Kind = symbols.ScalarBool
			case t.IntEncoding&btf.IntChar != 0:
				s.Kind = symbols.ScalarChar
			}
		case btf.KindFloat:
			s = symbols.Scalar{Name: t.Name, Width: uint64(t.Size), Kind: symbols.ScalarFloat}
		default:
			continue
		}
		if !scalarName(t.Name, c.maxName) || conflict[t.Name] {
			continue
		}
		if prev, ok := out[t.Name]; ok && prev != s {
			c.refuse(refuseScalarConflict)
			conflict[t.Name] = true
			delete(out, t.Name)
			continue
		}
		out[t.Name] = s
	}
	return out
}

// A forward declaration whose name no definition carries is written as a
// record with no members: the table then knows the name and that it cannot
// be read.
func (c *converter) addForwards(out *BTFTypes) {
	seen := map[string]bool{}
	for id := 1; id < len(c.spec.Types); id++ {
		t := c.spec.Types[id]
		if t.Kind != btf.KindFwd || !identifier(t.Name, c.maxName) || seen[t.Name] {
			continue
		}
		seen[t.Name] = true
		if _, ok := c.records[t.Name]; ok {
			continue
		}
		c.records[t.Name] = -1
		out.Records = append(out.Records, symbols.Record{Name: t.Name, Members: []symbols.Member{}})
		c.report.Forwards++
	}
}

// A typedef is a name the kernel's source uses for a type, so the table
// answers a lookup by it: a record that embeds its target, a copy of its
// enumeration, or a scalar with its target's encoding. A pointer, array or
// function type has no table name to give it.
func (c *converter) addAliases(out *BTFTypes) {
	type target struct {
		shape shape
		ok    bool
	}
	byName := map[string]target{}
	var names []string
	for id := 1; id < len(c.spec.Types); id++ {
		t := c.spec.Types[id]
		if t.Kind != btf.KindTypedef {
			continue
		}
		if !identifier(t.Name, c.maxName) {
			c.refuse(refuseTypedefName)
			continue
		}
		s, err := c.shapeOf(uint32(id))
		if errors.Is(err, refuseFunction) {
			s, err = shape{leaf: leafFunction}, nil
		}
		if err == nil && !c.written(s) {
			err = refuseRefusedType
		}
		if err != nil {
			c.refuse(err)
			continue
		}
		prev, seen := byName[t.Name]
		if !seen {
			names = append(names, t.Name)
			byName[t.Name] = target{shape: s, ok: true}
			continue
		}
		if prev.ok && !c.sameTarget(prev.shape, s) {
			c.refuse(refuseTypedefConflict)
			byName[t.Name] = target{}
		}
	}
	for _, name := range names {
		tg := byName[name]
		if !tg.ok {
			continue
		}
		s := tg.shape
		if s.bare() && s.leaf == leafForward {
			c.refuse(refuseTypedefForward)
			continue
		}
		if !s.bare() || s.leaf == leafVoid || s.leaf == leafFunction {
			c.refuse(refuseTypedefDerived)
			continue
		}
		target := c.leafName(s)
		if target == name || target == "" {
			continue
		}
		switch {
		case s.leaf == leafScalar:
			sc, ok := c.scalars[target]
			if _, taken := c.scalars[name]; taken || !ok {
				c.refuse(refuseTypedefTaken)
				continue
			}
			sc.Name = name
			c.scalars[name] = sc
		case c.isEnum(s.id):
			if _, taken := c.enums[name]; taken {
				c.refuse(refuseTypedefTaken)
				continue
			}
			d := c.drafts[c.rep[c.class[s.id]]]
			c.enums[name] = c.class[s.id]
			out.Enumerations = append(out.Enumerations, symbols.EnumType{Name: name, Size: d.size, Values: byValue(d.values)})
		default:
			if _, taken := c.records[name]; taken {
				c.refuse(refuseTypedefTaken)
				continue
			}
			d := c.drafts[c.rep[c.class[s.id]]]
			c.records[name] = c.class[s.id]
			out.Records = append(out.Records, symbols.Record{Name: name, Width: d.size,
				Members: []symbols.Member{{Embeds: target}}})
		}
		c.report.Aliases++
	}
}

func (c *converter) sameTarget(a, b shape) bool {
	if a.leaf != b.leaf || len(a.ops) != len(b.ops) || c.leafName(a) != c.leafName(b) {
		return false
	}
	for i := range a.ops {
		if a.ops[i] != b.ops[i] {
			return false
		}
	}
	return true
}
