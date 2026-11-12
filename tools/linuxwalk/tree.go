package linuxwalk

import (
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
)

type Tree struct {
	Entries      []uint64
	Indexes      []uint64
	Revisited    int
	Unread       int
	Inconsistent int
	Mismatched   int
	Values       int
	Capped       bool
}

type treeShape struct {
	xarray bool
	head   uint64
	shift  symbols.IntField
	offset *symbols.IntField
	parent *uint64
	owner  *uint64
	slots  uint64
	fanout uint64
	chunk  uint64
	span   uint64
}

// S02 4.1: the layout follows the root's members, because from v4.20 the
// source spelling radix_tree_root names an xarray.
func (r Reader) treeShape(rootType string) (treeShape, error) {
	var s treeShape
	if rootType == "" {
		return s, fmt.Errorf("linuxwalk: tree root: no type name: %w", ErrUnsupported)
	}
	nodeType, ownerName := "", ""
	switch {
	case r.has(rootType, "xa_head"):
		s.xarray, ownerName = true, "array"
		s.head, _ = r.offset(rootType, "xa_head")
		nodeType = "xa_node"
		if _, err := r.Sym.Struct(nodeType); err != nil {
			nodeType = "radix_tree_node"
		}
	case r.has(rootType, "rnode"):
		ownerName = "root"
		s.head, _ = r.offset(rootType, "rnode")
		nodeType = "radix_tree_node"
	default:
		return s, fmt.Errorf("linuxwalk: %s: no xa_head and no rnode: %w", rootType, ErrUnsupported)
	}
	slots, err := r.member(nodeType, "slots")
	if err != nil {
		return s, err
	}
	switch slots.Type.ArrayLength {
	case 16:
		s.chunk = 4
	case 64:
		s.chunk = 6
	default:
		return s, fmt.Errorf("linuxwalk: %s.slots: %d elements, want 16 or 64: %w", nodeType, slots.Type.ArrayLength, ErrUnsupported)
	}
	s.slots, s.fanout = slots.Offset, slots.Type.ArrayLength
	s.span = s.slots + s.fanout*r.width()
	if s.shift, err = r.intField(nodeType, "shift"); err != nil {
		return s, err
	}
	s.span = max(s.span, s.shift.Offset+s.shift.Width)
	if f, err := symbols.ResolveIntField(r.Sym, nodeType, "offset"); err == nil {
		s.offset = &f
		s.span = max(s.span, f.Offset+f.Width)
	}
	for _, m := range []struct {
		name string
		to   **uint64
	}{{"parent", &s.parent}, {ownerName, &s.owner}} {
		if off, err := r.offset(nodeType, m.name); err == nil {
			*m.to = &off
			s.span = max(s.span, off+r.width())
		}
	}
	return s, nil
}

type entryKind uint8

const (
	kindNone entryKind = iota
	kindPointer
	kindValue
	kindNode
	kindSkip
)

// S02 4.2: tag bits come from the raw slot value; the address form applies
// only to the address that results.
func (r Reader) classify(s treeShape, raw, node uint64) (entryKind, uint64) {
	if raw == 0 {
		return kindNone, 0
	}
	if s.xarray {
		switch {
		case raw&1 == 1:
			return kindValue, 0
		case raw&3 == 2 && raw > 4096:
			return kindNode, r.form(raw - 2)
		case raw&3 == 2:
			return kindSkip, 0
		}
		return kindPointer, r.form(raw)
	}
	switch raw & 3 {
	case 0:
		return kindPointer, r.form(raw)
	case 2, 3:
		return kindValue, 0
	}
	if raw == 1 {
		return kindSkip, 0
	}
	child := r.form(raw &^ 1)
	if node != 0 {
		slots := r.form(node + s.slots)
		if child >= slots && child < slots+s.fanout*r.width() {
			return kindSkip, 0
		}
	}
	return kindNode, child
}

type treeWalk struct {
	r        Reader
	s        treeShape
	root     uint64
	most     int
	depth    int
	nodes    int
	seen     map[uint64]struct{}
	t        Tree
	indexTop uint64
}

func (r Reader) Tree(root uint64, rootType string) (Tree, error) {
	if err := r.ready(); err != nil {
		return Tree{}, err
	}
	s, err := r.treeShape(rootType)
	if err != nil {
		return Tree{}, err
	}
	lim := r.bounds()
	w := &treeWalk{r: r, s: s, root: r.form(root), most: lim.MaxTableEntries, depth: lim.MaxRecursionDepth,
		seen: map[uint64]struct{}{}, indexTop: 8 * r.width()}
	raw, ok := r.rawPointer(root + s.head)
	if !ok {
		w.t.Unread++
		return w.t, nil
	}
	switch kind, at := r.classify(s, raw, 0); kind {
	case kindPointer:
		w.add(at, 0)
	case kindValue:
		w.t.Values++
	case kindNode:
		w.visit(at, 0, -1, 0, 0, 1)
	}
	return w.t, nil
}

func (w *treeWalk) add(entry, index uint64) bool {
	if len(w.t.Entries) >= w.most {
		w.t.Capped = true
		return false
	}
	w.t.Entries = append(w.t.Entries, entry)
	w.t.Indexes = append(w.t.Indexes, index)
	return true
}

func (w *treeWalk) visit(node, base uint64, want int, parent, slot uint64, depth int) {
	r, s := w.r, w.s
	if _, again := w.seen[node]; again {
		w.t.Revisited++
		return
	}
	if w.nodes >= w.most || depth > w.depth {
		w.t.Capped = true
		return
	}
	w.seen[node] = struct{}{}
	w.nodes++
	b, ok := r.read(node, s.span)
	if !ok {
		w.t.Unread++
		return
	}
	v, err := s.shift.Decode(b)
	if err != nil {
		w.t.Unread++
		return
	}
	shift := v
	if want < 0 && (shift%s.chunk != 0 || shift >= w.indexTop) || want >= 0 && shift != uint64(want) {
		w.t.Inconsistent++
		return
	}
	if w.mismatched(b, parent, slot, want < 0) {
		w.t.Mismatched++
	}
	for i := range s.fanout {
		raw := r.word(b, s.slots+i*r.width())
		index := base + i<<shift
		kind, at := r.classify(s, raw, node)
		switch kind {
		case kindPointer:
			if !w.add(at, index) {
				return
			}
		case kindValue:
			w.t.Values++
		case kindNode:
			if shift == 0 {
				w.t.Inconsistent++
				continue
			}
			w.visit(at, index, int(shift-s.chunk), node, i, depth+1)
		}
		if w.t.Capped {
			return
		}
	}
}

func (w *treeWalk) mismatched(b []byte, parent, slot uint64, top bool) bool {
	r, s := w.r, w.s
	if s.parent != nil && r.form(r.word(b, *s.parent)) != parent {
		return true
	}
	if s.owner != nil && r.form(r.word(b, *s.owner)) != w.root {
		return true
	}
	if s.offset != nil && !top {
		if v, err := s.offset.Decode(b); err == nil && v != slot {
			return true
		}
	}
	return false
}

func (r Reader) IDR(idr uint64) (Tree, error) {
	if err := r.ready(); err != nil {
		return Tree{}, err
	}
	rt, err := r.member("idr", "idr_rt")
	if err != nil {
		return Tree{}, err
	}
	t, err := r.Tree(idr+rt.Offset, rt.Type.Name)
	if err != nil {
		return t, err
	}
	f, err := symbols.ResolveIntField(r.Sym, "idr", "idr_base")
	if err != nil {
		return t, nil
	}
	base, err := f.Read(r.Mem, idr)
	if err != nil {
		t.Unread++
		return t, nil
	}
	for i := range t.Indexes {
		t.Indexes[i] += base
	}
	return t, nil
}
