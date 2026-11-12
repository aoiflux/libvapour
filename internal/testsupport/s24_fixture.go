package testsupport

import "slices"

// VAD i keeps page i; only the links follow address order, as the kernel's
// tree does (S24 4.2).
type S24Links struct {
	Root                int
	Left, Right, Parent []int
}

// A balanced tree over the VADs in start order: each subtree's root is the
// middle of its span.
func S24VadLinks(vads []FixtureVAD) S24Links {
	n := len(vads)
	l := S24Links{Root: -1, Left: make([]int, n), Right: make([]int, n), Parent: make([]int, n)}
	for i := range n {
		l.Left[i], l.Right[i], l.Parent[i] = -1, -1, -1
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int {
		switch {
		case vads[a].Start < vads[b].Start:
			return -1
		case vads[a].Start > vads[b].Start:
			return 1
		}
		return 0
	})
	var build func(lo, hi, parent int) int
	build = func(lo, hi, parent int) int {
		if lo > hi {
			return -1
		}
		mid := (lo + hi) / 2
		node := order[mid]
		l.Parent[node] = parent
		l.Left[node] = build(lo, mid-1, node)
		l.Right[node] = build(mid+1, hi, node)
		return node
	}
	l.Root = build(0, n-1, -1)
	if l.Root < 0 {
		l.Root = 0
	}
	return l
}
