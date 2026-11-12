package linuxobj

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrLatchTreeCycle = errors.New("linuxobj: latch tree node reached twice")
	ErrLatchTreeDepth = errors.New("linuxobj: latch tree deeper than Limits.MaxRecursionDepth")
	ErrTreeModule     = errors.New("linuxobj: mod_tree gives a module that does not hold the address")
	ErrLatchTreeRead  = errors.New("linuxobj: latch tree sequence unreadable")
)

type LatchCompare func(node uint64) (int, error)

type latchLayout struct {
	seq, tree, rootSize, first, left, right, nodeSize, nodes uint64
}

func (k *Kernel) latchLayout() (latchLayout, error) {
	var l latchLayout
	var err error
	offsets := []struct {
		typ, member string
		into        *uint64
	}{
		{"latch_tree_root", "seq", &l.seq},
		{"latch_tree_root", "tree", &l.tree},
		{"rb_root", "rb_node", &l.first},
		{"rb_node", "rb_left", &l.left},
		{"rb_node", "rb_right", &l.right},
		{"latch_tree_node", "node", &l.nodes},
	}
	for _, o := range offsets {
		f, ferr := k.Member(o.typ, o.member)
		if ferr != nil {
			return l, fmt.Errorf("linuxobj: %s.%s: %w", o.typ, o.member, errors.Join(ferr, ErrUnsupported))
		}
		*o.into = f.Offset
	}
	if l.rootSize, err = k.SizeOf("rb_root"); err != nil {
		return l, errors.Join(err, ErrUnsupported)
	}
	if l.nodeSize, err = k.SizeOf("rb_node"); err != nil {
		return l, errors.Join(err, ErrUnsupported)
	}
	return l, nil
}

func (k *Kernel) LatchTreeFind(root uint64, compare LatchCompare) (uint64, bool, error) {
	l, err := k.latchLayout()
	if err != nil {
		return 0, false, err
	}
	b, err := k.mem.ReadAt(root+l.seq, 4)
	if err != nil || len(b) < 4 {
		return 0, false, fmt.Errorf("linuxobj: latch tree root at %#x: %w", root, ErrLatchTreeRead)
	}
	idx := uint64(binary.LittleEndian.Uint32(b) & 1)
	node, err := k.PointerAt(k.mem, root+l.tree+idx*l.rootSize+l.first)
	if err != nil {
		return 0, false, err
	}
	depth := k.ctx.Bounds().MaxRecursionDepth
	seen := map[uint64]bool{}
	for steps := 0; node != 0; steps++ {
		if steps >= depth {
			return 0, false, fmt.Errorf("linuxobj: latch tree root at %#x: %w", root, ErrLatchTreeDepth)
		}
		if seen[node] {
			return 0, false, fmt.Errorf("linuxobj: latch tree node at %#x: %w", node, ErrLatchTreeCycle)
		}
		seen[node] = true
		ltn := node - idx*l.nodeSize - l.nodes
		order, err := compare(ltn)
		if err != nil {
			return 0, false, err
		}
		switch {
		case order < 0:
			node, err = k.PointerAt(k.mem, node+l.left)
		case order > 0:
			node, err = k.PointerAt(k.mem, node+l.right)
		default:
			return ltn, true, nil
		}
		if err != nil {
			return 0, false, err
		}
	}
	return 0, false, nil
}

type moduleTree struct {
	root, min, max, dataMin, dataMax uint64
	data                             bool
	region                           string
	nodeIn, modIn                    uint64
}

// moduleTree is false when the kernel has no tree to look modules up in.
func (k *Kernel) moduleTree() (moduleTree, bool, error) {
	at, err := k.Symbol("mod_tree")
	if err != nil {
		return moduleTree{}, false, nil
	}
	t := moduleTree{}
	for _, region := range []string{"module_memory", "module_layout"} {
		if k.Has(region, "mtn") && k.Has(region, "base") && k.Has(region, "size") {
			t.region = region
			break
		}
	}
	if t.region == "" || !k.Has("mod_tree_root", "root") {
		return moduleTree{}, false, nil
	}
	mtn, err := k.Member(t.region, "mtn")
	if err != nil {
		return moduleTree{}, false, err
	}
	node, err := k.Member("mod_tree_node", "node")
	if err != nil {
		return moduleTree{}, false, errors.Join(err, ErrUnsupported)
	}
	mod, err := k.Member("mod_tree_node", "mod")
	if err != nil {
		return moduleTree{}, false, errors.Join(err, ErrUnsupported)
	}
	root, err := k.Member("mod_tree_root", "root")
	if err != nil {
		return moduleTree{}, false, err
	}
	t.root = at.Address + root.Offset
	t.nodeIn = mtn.Offset + node.Offset
	t.modIn = node.Offset - mod.Offset
	if t.min, err = k.Uint(k.mem, at.Address, "mod_tree_root", "addr_min"); err != nil {
		return moduleTree{}, false, err
	}
	if t.max, err = k.Uint(k.mem, at.Address, "mod_tree_root", "addr_max"); err != nil {
		return moduleTree{}, false, err
	}
	if k.Has("mod_tree_root", "data_addr_min") && k.Has("mod_tree_root", "data_addr_max") {
		if t.dataMin, err = k.Uint(k.mem, at.Address, "mod_tree_root", "data_addr_min"); err != nil {
			return moduleTree{}, false, err
		}
		if t.dataMax, err = k.Uint(k.mem, at.Address, "mod_tree_root", "data_addr_max"); err != nil {
			return moduleTree{}, false, err
		}
		t.data = true
	}
	t.min, t.max, t.dataMin, t.dataMax = k.Canonical(t.min), k.Canonical(t.max), k.Canonical(t.dataMin), k.Canonical(t.dataMax)
	return t, true, nil
}

func (t moduleTree) bounds(addr uint64) bool {
	return (addr >= t.min && addr <= t.max) || (t.data && addr >= t.dataMin && addr <= t.dataMax)
}

func (k *Kernel) treeOwner(t moduleTree, addr uint64) (uint64, error) {
	if !t.bounds(addr) {
		return 0, nil
	}
	ltn, found, err := k.LatchTreeFind(t.root, func(node uint64) (int, error) {
		region := node - t.nodeIn
		base, err := k.Pointer(k.mem, region, t.region, "base")
		if err != nil {
			return 0, err
		}
		size, err := k.Uint(k.mem, region, t.region, "size")
		if err != nil {
			return 0, err
		}
		switch {
		case addr < base:
			return -1, nil
		case addr-base >= size:
			return 1, nil
		}
		return 0, nil
	})
	if err != nil || !found {
		return 0, err
	}
	return k.PointerAt(k.mem, ltn-t.modIn)
}
