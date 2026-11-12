package generator

import (
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/btf"
)

type opKind uint8

const (
	opPointer opKind = iota + 1
	opArray
)

type op struct {
	kind  opKind
	count uint64
}

type leafKind uint8

const (
	leafVoid leafKind = iota
	leafScalar
	leafComposite
	leafForward
	leafFunction
)

// A shape is a member's or variable's type with qualifiers and typedefs
// removed: the pointer and array operators, outermost first, then what they
// end at.
type shape struct {
	ops  []op
	leaf leafKind
	id   uint32
	name string
}

func (s shape) bare() bool { return len(s.ops) == 0 }

// Qualifiers and type tags change no layout, and a typedef is another name
// for its target, so all of them are seen through.
func seeThrough(k btf.Kind) bool {
	switch k {
	case btf.KindTypedef, btf.KindConst, btf.KindVolatile, btf.KindRestrict, btf.KindTypeTag:
		return true
	}
	return false
}

func (c *converter) chase(id uint32) (uint32, error) {
	for steps := 0; ; steps++ {
		if steps > c.limits.MaxRecursionDepth {
			return 0, refuseUnresolvable
		}
		if !seeThrough(c.spec.Types[id].Kind) {
			return id, nil
		}
		id = c.spec.Types[id].Ref
	}
}

func (c *converter) shapeOf(id uint32) (shape, error) {
	var s shape
	for steps := 0; ; steps++ {
		if steps > c.limits.MaxRecursionDepth {
			return shape{}, refuseUnresolvable
		}
		if len(s.ops) > symbols.MaxTypeOperators {
			return shape{}, refuseOperators
		}
		var err error
		if id, err = c.chase(id); err != nil {
			return shape{}, err
		}
		t := c.spec.Types[id]
		switch {
		case id == 0:
			s.leaf = leafVoid
			return s, nil
		case t.Kind == btf.KindPtr:
			s.ops = append(s.ops, op{kind: opPointer})
			id = t.Ref
		case t.Kind == btf.KindArray:
			s.ops = append(s.ops, op{kind: opArray, count: uint64(t.ArrayCount)})
			id = t.ArrayElem
		case t.Kind == btf.KindInt || t.Kind == btf.KindFloat:
			if !scalarName(t.Name, c.maxName) {
				return shape{}, refuseUnnamedScalar
			}
			s.leaf, s.id, s.name = leafScalar, id, t.Name
			return s, nil
		case t.Kind == btf.KindStruct || t.Kind == btf.KindUnion:
			s.leaf, s.id = leafComposite, id
			return s, nil
		case t.Kind == btf.KindEnum || t.Kind == btf.KindEnum64:
			// An enum with no constants is a declaration: C has no empty
			// enumeration.
			if len(t.Values) > 0 {
				s.leaf, s.id = leafComposite, id
				return s, nil
			}
			fallthrough
		case t.Kind == btf.KindFwd:
			if !identifier(t.Name, c.maxName) {
				return shape{}, refuseForwardName
			}
			s.leaf, s.id, s.name = leafForward, id, t.Name
			return s, nil
		case t.Kind == btf.KindFuncProto:
			if len(s.ops) == 0 || s.ops[len(s.ops)-1].kind != opPointer {
				return shape{}, refuseFunction
			}
			s.leaf = leafFunction
			return s, nil
		default:
			return shape{}, refuseKind
		}
	}
}
