package consolelist

import (
	"errors"
	"fmt"
	"math"

	"github.com/aoiflux/libvapour/util"
)

var (
	ErrStringShape = errors.New("consolelist: string length or capacity out of shape")
	ErrVectorShape = errors.New("consolelist: vector bounds out of order or not whole elements")
	ErrListLink    = errors.New("consolelist: list node does not link back to the node before it")
	ErrListCount   = errors.New("consolelist: list holds a different number of nodes than its size")
	ErrListLong    = errors.New("consolelist: list longer than MaxListEntries")
	ErrTooLong     = errors.New("consolelist: string longer than MaxTextBytes")
)

const wideBytes = 2

// The characters live inside the string while they fit the bytes before its
// length member, NUL included; past that they are behind the pointer (S33 F6).
func (l *Layout) inlineChars() uint64 {
	return uint64(l.text.length.off-l.text.chars)/wideBytes - 1
}

type wideText struct {
	Text             string
	Length, Capacity uint64
	Inline           bool
	At               uint64
}

func (l *Layout) wideShape(s Space, at uint64) (wideText, error) {
	length, err := s.value(at, l.text.length)
	if err != nil {
		return wideText{}, err
	}
	capacity, err := s.value(at, l.text.capacity)
	if err != nil {
		return wideText{}, err
	}
	w := wideText{Length: uint64(length), Capacity: uint64(capacity)}
	if length < 0 || capacity < 0 || w.Capacity < l.inlineChars() || w.Length > w.Capacity || w.Capacity >= math.MaxUint64/wideBytes {
		return w, fmt.Errorf("string at 0x%x: length %d, capacity %d: %w", at, length, capacity, ErrStringShape)
	}
	w.Inline = w.Capacity <= l.inlineChars()
	w.At = s.member(at, l.text.chars)
	if !w.Inline {
		if w.At, err = s.pointer(s.member(at, l.text.pointer)); err != nil {
			return w, err
		}
		if !s.Holds(w.At, (w.Capacity+1)*wideBytes) {
			return w, fmt.Errorf("string at 0x%x: buffer 0x%x for %d characters: %w", at, w.At, w.Capacity+1, ErrOutside)
		}
	}
	return w, nil
}

func (l *Layout) wideString(s Space, at uint64, maxBytes int64) (wideText, error) {
	w, err := l.wideShape(s, at)
	if err != nil {
		return w, err
	}
	if maxBytes > 0 && w.Length*wideBytes > uint64(maxBytes) {
		return w, fmt.Errorf("string at 0x%x: %d characters: %w", at, w.Length, ErrTooLong)
	}
	if w.Length == 0 {
		return w, nil
	}
	b, err := s.read(w.At, w.Length*wideBytes)
	if err != nil {
		return w, err
	}
	w.Text = util.DecodeUTF16LE(b)
	return w, nil
}

type listNodes struct {
	Head  uint64
	Nodes []uint64
}

// Doubly linked through the head node (S33 F3, 4.6.2): the walk must come
// back to the head, each back link must match the walk, and the count must
// equal the size member.
// The head pointer and the size are members of the object at base.
func (l *Layout) walkList(s Space, base uint64, headOff int64, size prim, maxEntries int) (listNodes, error) {
	listAt := s.member(base, headOff)
	head, err := s.pointer(listAt)
	if err != nil {
		return listNodes{}, err
	}
	want, err := s.value(base, size)
	if err != nil {
		return listNodes{Head: head}, err
	}
	out := listNodes{Head: head}
	prevOff := l.node.next + pointerBytes
	if _, err := s.read(head, l.node.size); err != nil {
		return out, err
	}
	prev := head
	cur, err := s.pointer(s.member(head, l.node.next))
	if err != nil {
		return out, err
	}
	for cur != head {
		if maxEntries > 0 && len(out.Nodes) >= maxEntries {
			return out, fmt.Errorf("list at 0x%x: %w (%d)", listAt, ErrListLong, maxEntries)
		}
		back, err := s.pointer(s.member(cur, prevOff))
		if err != nil {
			return out, err
		}
		if back != prev {
			return out, fmt.Errorf("list at 0x%x: node 0x%x names 0x%x before it, walked from 0x%x: %w",
				listAt, cur, back, prev, ErrListLink)
		}
		out.Nodes = append(out.Nodes, cur)
		prev = cur
		if cur, err = s.pointer(s.member(cur, l.node.next)); err != nil {
			return out, err
		}
	}
	last, err := s.pointer(s.member(head, prevOff))
	if err != nil {
		return out, err
	}
	if last != prev {
		return out, fmt.Errorf("list at 0x%x: head names 0x%x last, walk ended at 0x%x: %w", listAt, last, prev, ErrListLink)
	}
	if want < 0 || uint64(want) != uint64(len(out.Nodes)) {
		return out, fmt.Errorf("list at 0x%x: size %d, %d nodes: %w", listAt, want, len(out.Nodes), ErrListCount)
	}
	return out, nil
}

// A node's own links must point back at it; a candidate that fails is not
// a node of any list (S33 rule H1).
func (l *Layout) linkedNode(s Space, node uint64) error {
	prevOff := l.node.next + pointerBytes
	next, err := s.pointer(s.member(node, l.node.next))
	if err != nil {
		return err
	}
	prev, err := s.pointer(s.member(node, prevOff))
	if err != nil {
		return err
	}
	nextBack, err := s.pointer(s.member(next, prevOff))
	if err != nil {
		return err
	}
	prevFwd, err := s.pointer(s.member(prev, l.node.next))
	if err != nil {
		return err
	}
	if nextBack != node || prevFwd != node {
		return fmt.Errorf("node 0x%x: next 0x%x names 0x%x, previous 0x%x names 0x%x: %w",
			node, next, nextBack, prev, prevFwd, ErrListLink)
	}
	return nil
}

type vectorSpan struct {
	Begin, End, CapacityEnd uint64
}

func (v vectorSpan) count(element uint64) uint64 { return (v.End - v.Begin) / element }

// Three pointers in order, each step a whole number of elements; an empty
// vector may hold three nulls (S33 F5).
func (l *Layout) vectorAt(s Space, at, element uint64) (vectorSpan, error) {
	var v vectorSpan
	var err error
	if v.Begin, err = s.pointer(s.member(at, l.vector.begin)); err != nil {
		return v, err
	}
	if v.End, err = s.pointer(s.member(at, l.vector.end)); err != nil {
		return v, err
	}
	if v.CapacityEnd, err = s.pointer(s.member(at, l.vector.capacityEnd)); err != nil {
		return v, err
	}
	if v.Begin > v.End || v.End > v.CapacityEnd || (v.End-v.Begin)%element != 0 || (v.CapacityEnd-v.Begin)%element != 0 {
		return v, fmt.Errorf("vector at 0x%x: 0x%x 0x%x 0x%x: %w", at, v.Begin, v.End, v.CapacityEnd, ErrVectorShape)
	}
	if v.CapacityEnd > v.Begin && !s.Holds(v.Begin, v.CapacityEnd-v.Begin) {
		return v, fmt.Errorf("vector at 0x%x: 0x%x..0x%x: %w", at, v.Begin, v.CapacityEnd, ErrOutside)
	}
	return v, nil
}
