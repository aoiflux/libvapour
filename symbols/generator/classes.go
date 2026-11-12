package generator

import (
	"strconv"
	"strings"

	"github.com/aoiflux/libvapour/symbols/btf"
)

// Two drafts are one type when they hold the same members at the same
// places with types that are, in turn, one type: the coarsest partition that
// respects every member reference, found by splitting classes until no split
// remains. Splitting can only raise the class count, and the count is at
// most the number of drafts, so the loop ends.
func (c *converter) partition() {
	c.class = make(map[uint32]int, len(c.drafts))
	var b strings.Builder
	sig := func(d *draft, next bool) string {
		b.Reset()
		if next {
			b.WriteString(strconv.Itoa(c.class[d.id]))
		}
		c.writeLocal(&b, d, next)
		return b.String()
	}
	count := c.assign(func(d *draft) string { return sig(d, false) })
	for range c.limits.MaxRecursionDepth {
		n := c.assign(func(d *draft) string { return sig(d, true) })
		if n == count {
			return
		}
		count = n
	}
}

func (c *converter) assign(sig func(*draft) string) int {
	ids := make(map[string]int, len(c.order))
	next := make(map[uint32]int, len(c.order))
	for _, id := range c.order {
		s := sig(c.drafts[id])
		n, ok := ids[s]
		if !ok {
			n = len(ids)
			ids[s] = n
		}
		next[id] = n
	}
	c.class = next
	return len(ids)
}

func (c *converter) writeLocal(b *strings.Builder, d *draft, byClass bool) {
	switch {
	case d.enum:
		b.WriteString("e")
	case d.union:
		b.WriteString("u")
	default:
		b.WriteString("s")
	}
	b.WriteString(strconv.FormatUint(d.size, 10))
	b.WriteByte('|')
	b.WriteString(c.ownName(d.id))
	for _, v := range d.values {
		b.WriteByte('|')
		b.WriteString(v.Name)
		b.WriteByte('=')
		b.WriteString(strconv.FormatInt(v.Value, 10))
	}
	for _, m := range d.members {
		b.WriteByte('|')
		b.WriteString(m.name)
		b.WriteByte('@')
		b.WriteString(strconv.FormatUint(m.offset, 10))
		if m.bitLength > 0 {
			b.WriteByte(':')
			b.WriteString(strconv.Itoa(int(m.bitOffset)))
			b.WriteByte('+')
			b.WriteString(strconv.Itoa(int(m.bitLength)))
		}
		if m.embeds {
			b.WriteByte('^')
		}
		for _, o := range m.typ.ops {
			if o.kind == opPointer {
				b.WriteByte('*')
				continue
			}
			b.WriteByte('[')
			b.WriteString(strconv.FormatUint(o.count, 10))
			b.WriteByte(']')
		}
		switch m.typ.leaf {
		case leafVoid:
			b.WriteString("v")
		case leafFunction:
			b.WriteString("f")
		case leafScalar:
			b.WriteString("n:")
			b.WriteString(m.typ.name)
		case leafForward:
			b.WriteString("d:")
			b.WriteString(m.typ.name)
		case leafComposite:
			if byClass {
				b.WriteString("c")
				b.WriteString(strconv.Itoa(c.class[m.typ.id]))
			} else {
				b.WriteString("t:")
				b.WriteString(c.ownName(m.typ.id))
			}
		}
	}
}

// A type's own name is its tag or, for an anonymous type, the typedef that
// declares it.
func (c *converter) ownName(id uint32) string {
	if n := c.spec.Types[id].Name; n != "" {
		return n
	}
	return c.typedefName[id]
}

type namespace uint8

const (
	nsRecord namespace = iota
	nsEnum
)

type classInfo struct {
	rep   uint32
	ns    namespace
	named bool
	base  string
}

// Named classes keep their name when no other class shares it; several
// definitions of one name are told apart by a suffix in type id order, and
// none of them takes the bare name, which would answer for the wrong one.
// Anonymous classes are named by their members; a suffix tells apart the
// ones whose member names are the same.
func (c *converter) name() {
	infos := map[int]*classInfo{}
	var classes []int
	for _, id := range c.order {
		k := c.class[id]
		if _, ok := infos[k]; ok {
			c.report.Merged++
			continue
		}
		d := c.drafts[id]
		ci := &classInfo{rep: id, ns: nsRecord}
		if d.enum {
			ci.ns = nsEnum
		}
		if own := c.ownName(id); own != "" {
			ci.named, ci.base = true, own
		} else {
			ci.base = c.memberName(d)
		}
		infos[k] = ci
		classes = append(classes, k)
	}
	groups := map[namespace]map[string][]int{nsRecord: {}, nsEnum: {}}
	var keys []struct {
		ns   namespace
		base string
	}
	for _, k := range classes {
		ci := infos[k]
		g := groups[ci.ns]
		if _, ok := g[ci.base]; !ok {
			keys = append(keys, struct {
				ns   namespace
				base string
			}{ci.ns, ci.base})
		}
		g[ci.base] = append(g[ci.base], k)
	}
	c.className = make(map[int]string, len(classes))
	for _, key := range keys {
		members := groups[key.ns][key.base]
		named := infos[members[0]].named
		if !named {
			c.report.NamedByMembers += len(members)
		}
		if len(members) == 1 {
			c.className[members[0]] = key.base
			continue
		}
		if named {
			c.report.Conflicts = append(c.report.Conflicts, key.base)
		}
		for i, k := range members {
			c.report.Suffixed++
			switch {
			case named:
				c.className[k] = suffixed(key.base, i+1)
			case i == 0:
				c.report.Suffixed--
				c.className[k] = key.base
			default:
				c.className[k] = suffixed(key.base, i+1)
			}
		}
	}
	c.records = map[string]int{}
	c.enums = map[string]int{}
	for _, k := range classes {
		if infos[k].ns == nsEnum {
			c.enums[c.className[k]] = k
		} else {
			c.records[c.className[k]] = k
		}
		c.rep[k] = infos[k].rep
	}
}

func (c *converter) memberName(d *draft) string {
	keyword := "struct"
	switch {
	case d.enum:
		keyword = "enum"
	case d.union:
		keyword = "union"
	}
	var names []string
	if d.enum {
		for _, v := range d.values {
			names = append(names, v.Name)
		}
	} else {
		names = c.reachableNames(d, 0, nil)
	}
	return memberListName(keyword, names, c.maxName)
}

// The names a record gives access to: its own, and those its embedded
// members bring up, in declaration order.
func (c *converter) reachableNames(d *draft, depth int, out []string) []string {
	for _, m := range d.members {
		if !m.embeds {
			out = append(out, m.name)
			continue
		}
		if inner, ok := c.drafts[m.typ.id]; ok && depth < c.limits.MaxRecursionDepth {
			out = c.reachableNames(inner, depth+1, out)
		}
	}
	return out
}

// The BTF keeps one empty anonymous structure or union of a size for every
// typedef and member declared that way (lockdep_map_p, local_lock_t and the
// flexible-array __empty_ members all share one), so no typedef's name
// describes it and it is named by its members.
func (c *converter) memberless(t btf.Type) bool {
	return (t.Kind == btf.KindStruct || t.Kind == btf.KindUnion) && len(t.Members) == 0
}

func (c *converter) isComposite(t btf.Type) bool {
	switch t.Kind {
	case btf.KindStruct, btf.KindUnion:
		return true
	case btf.KindEnum, btf.KindEnum64:
		return len(t.Values) > 0
	}
	return false
}
