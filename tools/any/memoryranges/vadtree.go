package memoryranges

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

var (
	ErrVADTreeTooDeep    = errors.New("memoryranges: vad tree is taller than an avl tree of the node budget")
	ErrVADReachedTwice   = errors.New("memoryranges: vad reached by a second link")
	ErrVADUnread         = errors.New("memoryranges: vad links or range do not read")
	ErrVADInverted       = errors.New("memoryranges: vad ends before it starts")
	ErrVADOutOfOrder     = errors.New("memoryranges: vad range outside the interval its ancestors allow")
	ErrVADAboveUserSpace = errors.New("memoryranges: vad ends above the highest user address")
	ErrVADBudget         = errors.New("memoryranges: vad tree holds more nodes than the node budget")
)

var cutReasons = []struct {
	err   error
	label string
}{
	{ErrVADReachedTwice, "reached twice"},
	{ErrVADUnread, "unreadable"},
	{ErrVADInverted, "inverted"},
	{ErrVADOutOfOrder, "out of order"},
	{ErrVADAboveUserSpace, "above user space"},
	{ErrVADBudget, "past the node budget"},
}

const (
	pageShift      = 12
	pageOffsetMask = 1<<pageShift - 1
)

type vadNode struct {
	base             uint64
	node             uint64
	left, right      uint64
	startVPN, endVPN uint64
}

func (n vadNode) start() uint64 { return n.startVPN << pageShift }
func (n vadNode) end() uint64   { return n.endVPN<<pageShift | pageOffsetMask }

type treeWalk struct {
	nodes []vadNode
	cut   map[error]int
	first error
}

func (w *treeWalk) leaveOut(at uint64, why error) {
	if w.cut == nil {
		w.cut = map[error]int{}
	}
	for _, r := range cutReasons {
		if errors.Is(why, r.err) {
			w.cut[r.err]++
			break
		}
	}
	if w.first == nil {
		w.first = fmt.Errorf("vad node at 0x%x: %w", at, why)
	}
}

func (w treeWalk) summary() (int, string) {
	total := 0
	parts := make([]string, 0, len(cutReasons))
	for _, r := range cutReasons {
		if n := w.cut[r.err]; n > 0 {
			total += n
			parts = append(parts, fmt.Sprintf("%d %s", n, r.label))
		}
	}
	return total, strings.Join(parts, ", ")
}

// N(1)=1, N(2)=2, N(h)=N(h-1)+N(h-2)+1 is the fewest nodes an AVL tree of
// height h holds (S24 4.2 step 2).
func avlHeightBound(budget int) int {
	if budget < 1 {
		return 0
	}
	h, prev, cur := 1, 0, 1
	for {
		next := cur + prev + 1
		if next > budget || next < cur {
			return h
		}
		prev, cur = cur, next
		h++
	}
}

type pendingNode struct {
	node         uint64
	depth        int
	lo, hi       uint64
	hasLo, hasHi bool
}

func (l vadLayout) walk(ctx tools.Context, eprocess, userLimit uint64) (treeWalk, error) {
	var w treeWalk
	root, err := ctx.Symbols.ReadPointer(ctx.Memory, eprocess+l.rootAt)
	if err != nil {
		return w, fmt.Errorf("VadRoot at 0x%x: %w", eprocess+l.rootAt, err)
	}
	if root == 0 {
		return w, nil
	}
	budget := ctx.Bounds().MaxListEntries
	bound := avlHeightBound(budget)
	seen := map[uint64]bool{}
	stack := []pendingNode{{node: root, depth: 1}}
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[p.node] {
			w.leaveOut(p.node, ErrVADReachedTwice)
			continue
		}
		seen[p.node] = true
		n, err := l.readNode(ctx, p.node)
		if err != nil {
			w.leaveOut(p.node, err)
			continue
		}
		switch {
		case n.endVPN < n.startVPN:
			w.leaveOut(p.node, ErrVADInverted)
			continue
		case (p.hasLo && n.startVPN <= p.lo) || (p.hasHi && n.endVPN >= p.hi):
			w.leaveOut(p.node, ErrVADOutOfOrder)
			continue
		case n.endVPN > userLimit>>pageShift || n.end() > userLimit:
			w.leaveOut(p.node, ErrVADAboveUserSpace)
			continue
		}
		if p.depth > bound {
			return treeWalk{}, fmt.Errorf("vad node at 0x%x depth %d: %w (%d)", p.node, p.depth, ErrVADTreeTooDeep, bound)
		}
		if len(w.nodes) >= budget {
			w.leaveOut(p.node, ErrVADBudget)
			break
		}
		w.nodes = append(w.nodes, n)
		if n.right != 0 {
			stack = append(stack, pendingNode{node: n.right, depth: p.depth + 1, lo: n.endVPN, hasLo: true, hi: p.hi, hasHi: p.hasHi})
		}
		if n.left != 0 {
			stack = append(stack, pendingNode{node: n.left, depth: p.depth + 1, lo: p.lo, hasLo: p.hasLo, hi: n.startVPN, hasHi: true})
		}
	}
	slices.SortFunc(w.nodes, func(a, b vadNode) int {
		switch {
		case a.startVPN < b.startVPN:
			return -1
		case a.startVPN > b.startVPN:
			return 1
		}
		return 0
	})
	return w, nil
}

func (l vadLayout) readNode(ctx tools.Context, node uint64) (vadNode, error) {
	if node < l.vadNode {
		return vadNode{}, ErrVADUnread
	}
	n := vadNode{node: node, base: node - l.vadNode}
	var err error
	if n.left, err = ctx.Symbols.ReadPointer(ctx.Memory, node+l.left); err != nil {
		return n, fmt.Errorf("%w: Left: %w", ErrVADUnread, err)
	}
	if n.right, err = ctx.Symbols.ReadPointer(ctx.Memory, node+l.right); err != nil {
		return n, fmt.Errorf("%w: Right: %w", ErrVADUnread, err)
	}
	if n.startVPN, err = l.vpn(ctx, n.base, l.startLow, l.startHigh); err != nil {
		return n, fmt.Errorf("%w: start: %w", ErrVADUnread, err)
	}
	if n.endVPN, err = l.vpn(ctx, n.base, l.endLow, l.endHigh); err != nil {
		return n, fmt.Errorf("%w: end: %w", ErrVADUnread, err)
	}
	return n, nil
}

func (l vadLayout) vpn(ctx tools.Context, base uint64, low, high symbols.IntField) (uint64, error) {
	v, err := low.Read(ctx.Memory, base)
	if err != nil || !l.haveHigh {
		return v, err
	}
	h, err := high.Read(ctx.Memory, base)
	if err != nil {
		return 0, err
	}
	return v | h<<(8*low.Width), nil
}

func (l vadLayout) tree(ctx tools.Context, proc processlist.Process, userLimit uint64) ([]vadNode, error) {
	w, err := l.walk(ctx, proc.EPROCESS, userLimit)
	if err != nil {
		return nil, err
	}
	if total, reasons := w.summary(); total > 0 {
		if ctx.StrictMode() {
			return nil, w.first
		}
		ctx.AddDiagnostic("%s: pid %d _EPROCESS at 0x%x: %d VAD tree nodes left out: %s",
			walkLabel(ctx), proc.PID, proc.EPROCESS, total, reasons)
	}
	return w.nodes, nil
}

// MmHighestUserAddress when it reads; otherwise the top of user space that
// Learn documents for the pointer width (S24 D3).
const (
	userTop64 = uint64(0x7FFF_FFFF_FFFF)
	userTop32 = uint64(0xBFFF_FFFF)
)

func userLimit(ctx tools.Context) uint64 {
	limit := userTop64
	if ctx.Symbols.PointerSize() == 4 {
		limit = userTop32
	}
	sym, err := ctx.Symbols.LookupSymbol("MmHighestUserAddress")
	if err != nil {
		return limit
	}
	v, err := ctx.Symbols.ReadPointer(ctx.Memory, sym.Address)
	if err != nil {
		ctx.AddDiagnostic("%s: MmHighestUserAddress at 0x%x: not read, user space taken to end at 0x%x: %v",
			walkLabel(ctx), sym.Address, limit, err)
		return limit
	}
	if v == 0 || v > limit {
		ctx.AddDiagnostic("%s: MmHighestUserAddress at 0x%x: holds 0x%x, user space taken to end at 0x%x",
			walkLabel(ctx), sym.Address, v, limit)
		return limit
	}
	return v
}
