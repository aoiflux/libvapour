package processtree

import (
	"cmp"
	"slices"
	"time"
)

type node struct {
	pid, ppid      uint64
	ppidKnown      bool
	created, ended time.Time
	// Its CreateTime is set after the processes the kernel itself starts
	// (S56 M11), so the creation-time test does not apply to it.
	systemProcess bool
}

type placement struct {
	parent   int
	reused   bool
	children []int
	depth    int
}

func (n node) selfParented() bool { return n.ppidKnown && n.ppid == n.pid }

func (n node) aliveAt(t time.Time) bool {
	if n.created.IsZero() || t.IsZero() {
		return false
	}
	return !n.created.After(t) && (n.ended.IsZero() || !n.ended.Before(t))
}

// place returns, for each node in list order, its parent index (-1 for a
// root), whether its parent PID names a reused PID, its children and depth.
func place(nodes []node) []placement {
	byPID := map[uint64][]int{}
	for i, n := range nodes {
		byPID[n.pid] = append(byPID[n.pid], i)
	}
	out := make([]placement, len(nodes))
	for i, n := range nodes {
		out[i].parent = -1
		if !n.ppidKnown || n.selfParented() {
			continue
		}
		p := pickParent(nodes, byPID[n.ppid], i)
		if p < 0 || nodes[p].selfParented() {
			continue
		}
		parent := nodes[p]
		if !parent.systemProcess && !parent.created.IsZero() && !n.created.IsZero() && parent.created.After(n.created) {
			out[i].reused = true
			continue
		}
		out[i].parent = p
	}
	breakCycles(out)
	for i := range out {
		if p := out[i].parent; p >= 0 {
			out[p].children = append(out[p].children, i)
		}
	}
	order := func(a, b int) int { return cmp.Or(cmp.Compare(nodes[a].pid, nodes[b].pid), cmp.Compare(a, b)) }
	for i := range out {
		slices.SortFunc(out[i].children, order)
	}
	for i := range out {
		if out[i].parent < 0 {
			setDepth(out, i, 0)
		}
	}
	return out
}

func pickParent(nodes []node, candidates []int, child int) int {
	first := -1
	for _, c := range candidates {
		if c == child {
			continue
		}
		if first < 0 {
			first = c
		}
		if nodes[c].aliveAt(nodes[child].created) {
			return c
		}
	}
	return first
}

// Walking up from every node, a node reached twice on the same walk closes a
// cycle; the cycle's member first in list order becomes a root.
func breakCycles(out []placement) {
	const (
		unseen = iota
		onWalk
		done
	)
	state := make([]int, len(out))
	for start := range out {
		var walk []int
		cur := start
		for cur >= 0 && state[cur] == unseen {
			state[cur] = onWalk
			walk = append(walk, cur)
			cur = out[cur].parent
		}
		if cur >= 0 && state[cur] == onWalk {
			cycle := walk[slices.Index(walk, cur):]
			out[slices.Min(cycle)].parent = -1
		}
		for _, i := range walk {
			state[i] = done
		}
	}
}

func setDepth(out []placement, root, depth int) {
	stack := [][2]int{{root, depth}}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		out[top[0]].depth = top[1]
		for _, c := range out[top[0]].children {
			stack = append(stack, [2]int{c, top[1] + 1})
		}
	}
}
