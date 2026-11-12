package linuxwalk_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const (
	rootAt    = base + 0x1000
	nodeSlots = 24
	nodeBytes = nodeSlots + 64*8
	idrBase   = 16
)

func nodeAt(i int) uint64 { return base + 0x2000 + uint64(i)*0x1000 }
func ptrAt(i int) uint64  { return base + 0x10000 + uint64(i)*0x40 }

type tree struct {
	xarray bool
	root   string
	mem    *kerntest.Memory
	ty     *kerntest.Types
}

func treeTypes(ty *kerntest.Types, xarray bool, fanout uint64) {
	vp := kerntest.Ptr(kerntest.Void())
	u := kerntest.Base("unsigned int")
	root, node, head, owner := "radix_tree_root", "radix_tree_node", "rnode", "root"
	if xarray {
		root, node, head, owner = "xarray", "xa_node", "xa_head", "array"
	}
	ty.Struct(root, 16, map[string]kerntest.F{"xa_lock": {Off: 0, Type: u}, "flags": {Off: 4, Type: u}, head: {Off: 8, Type: vp}})
	ty.Struct(node, nodeSlots+fanout*8, map[string]kerntest.F{
		"shift":  {Off: 0, Type: kerntest.Base("unsigned char")},
		"offset": {Off: 1, Type: kerntest.Base("unsigned char")},
		"parent": {Off: 8, Type: kerntest.Ptr(kerntest.Struct(node))},
		owner:    {Off: 16, Type: kerntest.Ptr(kerntest.Struct(root))},
		"slots":  {Off: nodeSlots, Type: kerntest.Arr(fanout, vp)},
	})
	ty.Struct("idr", 24, map[string]kerntest.F{
		"idr_rt":   {Off: 0, Type: kerntest.Struct(root)},
		"idr_base": {Off: idrBase, Type: u},
		"idr_next": {Off: 20, Type: u},
	})
}

func newTree(xarray bool) tree {
	tr := tree{xarray: xarray, root: "radix_tree_root", mem: kerntest.NewMemory(), ty: kerntest.NewTypes(8)}
	if xarray {
		tr.root = "xarray"
	}
	treeTypes(tr.ty, xarray, 64)
	tr.mem.Map(rootAt, 16)
	return tr
}

// S02 X5 and R3: how each layout tags a node in a slot.
func (tr tree) nodeEntry(n uint64) uint64 {
	if tr.xarray {
		return n | 2
	}
	return n | 1
}

func (tr tree) head(v uint64) { tr.mem.U64(rootAt+8, v) }

func (tr tree) node(at uint64, shift, offset uint8, parent uint64) {
	tr.mem.Map(at, nodeBytes)
	tr.mem.U8(at, shift)
	tr.mem.U8(at+1, offset)
	tr.mem.U64(at+8, parent)
	tr.mem.U64(at+16, rootAt)
}

func (tr tree) slot(node uint64, i int, v uint64) { tr.mem.U64(node+nodeSlots+uint64(i)*8, v) }

// twoLevel builds a top node at shift 6 with two leaf nodes, a multi-index
// pointer, and one of each skipped entry kind in the first leaf.
func (tr tree) twoLevel() (entries, indexes []uint64, values int) {
	top, a, b := nodeAt(0), nodeAt(1), nodeAt(2)
	tr.head(tr.nodeEntry(top))
	tr.node(top, 6, 0, 0)
	tr.node(a, 0, 0, top)
	tr.node(b, 0, 2, top)
	tr.slot(top, 0, tr.nodeEntry(a))
	tr.slot(top, 2, tr.nodeEntry(b))
	tr.slot(top, 4, ptrAt(3))
	tr.slot(a, 3, ptrAt(0))
	tr.slot(a, 5, ptrAt(1))
	tr.slot(b, 1, ptrAt(2))
	if tr.xarray {
		tr.slot(a, 7, 2)
		tr.slot(a, 8, 256<<2|2)
		tr.slot(a, 9, 257<<2|2)
		tr.slot(a, 10, 42<<1|1)
		values = 1
	} else {
		tr.slot(a, 7, (a+nodeSlots+3*8)|1)
		tr.slot(a, 8, 1)
		tr.slot(a, 9, 42<<2|2)
		tr.slot(a, 10, 42<<2|3)
		values = 2
	}
	return []uint64{ptrAt(0), ptrAt(1), ptrAt(2), ptrAt(3)}, []uint64{3, 5, 129, 256}, values
}

func (tr tree) walk(t *testing.T, lim limits.Limits) linuxwalk.Tree {
	t.Helper()
	got, err := reader(t, tr.mem, tr.ty, lim).Tree(rootAt, tr.root)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func layoutName(xarray bool) string {
	if xarray {
		return "xarray"
	}
	return "radix"
}

func TestTreeWalksBothLayouts(t *testing.T) {
	for _, xa := range []bool{true, false} {
		t.Run(layoutName(xa), func(t *testing.T) {
			tr := newTree(xa)
			if got := tr.walk(t, limits.Limits{}); len(got.Entries) != 0 || got.Unread != 0 {
				t.Errorf("empty: %+v", got)
			}
			tr.head(ptrAt(0))
			if got := tr.walk(t, limits.Limits{}); !slices.Equal(got.Entries, []uint64{ptrAt(0)}) || !slices.Equal(got.Indexes, []uint64{0}) {
				t.Errorf("single entry: %+v", got)
			}
			entries, indexes, values := tr.twoLevel()
			got := tr.walk(t, limits.Limits{})
			if !slices.Equal(got.Entries, entries) || !slices.Equal(got.Indexes, indexes) {
				t.Errorf("entries %#x at %d, want %#x at %d", got.Entries, got.Indexes, entries, indexes)
			}
			if got.Values != values || got.Revisited+got.Unread+got.Inconsistent+got.Mismatched != 0 || got.Capped {
				t.Errorf("counts %+v", got)
			}
		})
	}
}

func TestTreeHeadValueIsNoEntry(t *testing.T) {
	tr := newTree(true)
	tr.head(7<<1 | 1)
	if got := tr.walk(t, limits.Limits{}); len(got.Entries) != 0 || got.Values != 1 {
		t.Errorf("value at the head: %+v", got)
	}
	tr.head(256<<2 | 2)
	if got := tr.walk(t, limits.Limits{}); len(got.Entries) != 0 {
		t.Errorf("retry at the head: %+v", got)
	}
}

func TestTreeCountsDamage(t *testing.T) {
	for _, xa := range []bool{true, false} {
		t.Run(layoutName(xa), func(t *testing.T) {
			tr := newTree(xa)
			tr.twoLevel()
			top, a := nodeAt(0), nodeAt(1)

			tr.slot(top, 1, tr.nodeEntry(a))
			got := tr.walk(t, limits.Limits{})
			if got.Revisited != 1 || len(got.Entries) != 4 {
				t.Errorf("node linked twice: %+v", got)
			}
			tr.slot(top, 1, tr.nodeEntry(top))
			if got = tr.walk(t, limits.Limits{}); got.Revisited != 1 || len(got.Entries) != 4 {
				t.Errorf("node in its own slot: %+v", got)
			}
			tr.slot(top, 1, 0)

			tr.mem.U8(a, 6)
			if got = tr.walk(t, limits.Limits{}); got.Inconsistent != 1 || len(got.Entries) != 2 {
				t.Errorf("child with the parent's shift: %+v", got)
			}
			tr.mem.U8(a, 0)

			tr.mem.U64(a+8, nodeAt(2))
			if got = tr.walk(t, limits.Limits{}); got.Mismatched != 1 || len(got.Entries) != 4 {
				t.Errorf("wrong parent: %+v", got)
			}
			tr.mem.U64(a+8, top)

			tr.slot(a, 11, tr.nodeEntry(nodeAt(2)))
			if got = tr.walk(t, limits.Limits{}); got.Inconsistent != 1 || len(got.Entries) != 4 {
				t.Errorf("node in a leaf slot: %+v", got)
			}
			tr.slot(a, 11, 0)

			tr.slot(top, 6, tr.nodeEntry(nodeAt(9)))
			if got = tr.walk(t, limits.Limits{}); got.Unread != 1 || len(got.Entries) != 4 {
				t.Errorf("child unmapped: %+v", got)
			}
		})
	}
}

func TestTreeRefusesAnImpossibleTopShift(t *testing.T) {
	for _, shift := range []uint8{5, 64, 66} {
		tr := newTree(true)
		tr.twoLevel()
		tr.mem.U8(nodeAt(0), shift)
		if got := tr.walk(t, limits.Limits{}); got.Inconsistent != 1 || len(got.Entries) != 0 {
			t.Errorf("top shift %d: %+v", shift, got)
		}
	}
}

func TestTreeStopsAtMaxTableEntries(t *testing.T) {
	tr := newTree(true)
	tr.twoLevel()
	got := tr.walk(t, limits.Limits{MaxTableEntries: 2})
	if !got.Capped || len(got.Entries) != 2 {
		t.Errorf("entries capped: %+v", got)
	}
	for _, i := range []int{3, 5} {
		tr.slot(nodeAt(1), i, 0)
	}
	tr.slot(nodeAt(2), 1, 0)
	tr.slot(nodeAt(0), 4, 0)
	if got = tr.walk(t, limits.Limits{MaxTableEntries: 2}); !got.Capped || len(got.Entries) != 0 {
		t.Errorf("nodes capped: %+v", got)
	}
}

func TestTreeRefusesUnknownLayouts(t *testing.T) {
	ty := kerntest.NewTypes(8)
	ty.Struct("odd_root", 8, map[string]kerntest.F{"top": {Off: 0, Type: kerntest.Ptr(kerntest.Void())}})
	treeTypes(ty, true, 32)
	r := reader(t, kerntest.NewMemory(), ty, limits.Limits{})
	for _, root := range []string{"odd_root", "", "xarray"} {
		if _, err := r.Tree(rootAt, root); !errors.Is(err, linuxwalk.ErrUnsupported) {
			t.Errorf("root %q: %v", root, err)
		}
	}
}

func TestIDRAddsItsBase(t *testing.T) {
	tr := newTree(true)
	tr.mem.Map(rootAt, 24)
	_, indexes, _ := tr.twoLevel()
	tr.mem.U32(rootAt+idrBase, 100)
	got, err := reader(t, tr.mem, tr.ty, limits.Limits{}).IDR(rootAt)
	if err != nil {
		t.Fatal(err)
	}
	for i := range indexes {
		indexes[i] += 100
	}
	if !slices.Equal(got.Indexes, indexes) {
		t.Errorf("ids %d, want %d", got.Indexes, indexes)
	}

	ty := kerntest.NewTypes(8)
	ty.Struct("idr", 16, map[string]kerntest.F{"top": {Off: 0, Type: kerntest.Ptr(kerntest.Void())}, "layers": {Off: 8, Type: kerntest.Base("int")}})
	if _, err := reader(t, tr.mem, ty, limits.Limits{}).IDR(rootAt); !errors.Is(err, linuxwalk.ErrUnsupported) {
		t.Errorf("layered idr: %v", err)
	}
}
