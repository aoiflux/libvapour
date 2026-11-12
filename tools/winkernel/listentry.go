package winkernel

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

var (
	ErrListNull       = errors.New("list link is null")
	ErrListUnreadable = errors.New("list entry does not read")
	ErrListCycle      = errors.New("list link returns to an entry already walked")
	ErrListBackLink   = errors.New("list entry does not link back to the entry before it")
	ErrListLimit      = errors.New("list is longer than MaxListEntries")
	ErrListLayout     = errors.New("list entry layout unusable")
)

type ListLayout struct {
	Width    uint64
	Flink    uint64
	Blink    uint64
	HasBlink bool
}

func ListLayoutOf(table symbols.SymbolTable, typeName string, width uint64) (ListLayout, error) {
	l := ListLayout{Width: width}
	if err := l.check(); err != nil {
		return ListLayout{}, fmt.Errorf("%s: %w", typeName, err)
	}
	flink, err := table.Field(typeName, "Flink")
	if err != nil {
		return ListLayout{}, fmt.Errorf("%s.Flink: %w", typeName, err)
	}
	l.Flink = flink.Offset
	if blink, err := table.Field(typeName, "Blink"); err == nil {
		l.Blink, l.HasBlink = blink.Offset, true
	}
	return l, nil
}

func NativeListLayout(table symbols.SymbolTable) (ListLayout, error) {
	return ListLayoutOf(table, "_LIST_ENTRY", uint64(table.PointerSize()))
}

func (l ListLayout) check() error {
	if l.Width != 4 && l.Width != 8 {
		return fmt.Errorf("%w: pointer width %d", ErrListLayout, l.Width)
	}
	return nil
}

func (l ListLayout) span() uint64 {
	end := l.Flink
	if l.HasBlink && l.Blink > end {
		end = l.Blink
	}
	return end + l.Width
}

func Container(entry, member uint64) (uint64, bool) {
	if entry < member {
		return 0, false
	}
	return entry - member, true
}

type ListWalker struct {
	Tool   string
	Memory memory.MemoryReader
	Layout ListLayout
	Limit  int
	Strict bool
	Report func(format string, args ...any)
}

type ListWalk struct {
	Entries  []uint64
	Backward int
	Forward  error
	Back     error
}

type links struct{ flink, blink uint64 }

type direction struct {
	name string
	on   func(links) uint64
	back func(links) uint64
}

var (
	forward  = direction{"Flink", func(l links) uint64 { return l.flink }, func(l links) uint64 { return l.blink }}
	backward = direction{"Blink", func(l links) uint64 { return l.blink }, func(l links) uint64 { return l.flink }}
)

type walkState struct {
	head      uint64
	headLinks links
	label     string
	walked    map[uint64]bool
	limit     int
	count     int
}

func (w ListWalker) Walk(head uint64, label string) (ListWalk, error) {
	st, err := w.start(head, label)
	if err != nil {
		return ListWalk{}, err
	}
	var out ListWalk
	out.Entries, out.Forward = w.follow(st, forward, nil)
	if out.Forward != nil {
		if w.Strict {
			return ListWalk{}, out.Forward
		}
		w.report(out.Forward)
	}
	return out, nil
}

func (w ListWalker) WalkRecovering(head uint64, label string) (ListWalk, error) {
	st, err := w.start(head, label)
	if err != nil {
		return ListWalk{}, err
	}
	var out ListWalk
	out.Entries, out.Forward = w.follow(st, forward, nil)
	if out.Forward == nil {
		return out, nil
	}
	if w.Strict {
		return ListWalk{}, out.Forward
	}
	w.report(out.Forward)
	// The cap bounds the whole list, so a walk that reached it has nothing
	// left to spend on the other direction.
	if !w.Layout.HasBlink || errors.Is(out.Forward, ErrListLimit) {
		return out, nil
	}
	met := make(map[uint64]bool, len(out.Entries))
	for _, e := range out.Entries {
		met[e] = true
	}
	back, backErr := w.follow(st, backward, met)
	out.Entries = append(out.Entries, back...)
	out.Backward = len(back)
	out.Back = backErr
	if backErr != nil {
		w.report(backErr)
	}
	return out, nil
}

func (w ListWalker) start(head uint64, label string) (*walkState, error) {
	if err := w.Layout.check(); err != nil {
		return nil, fmt.Errorf("%s: %s head at 0x%x: %w", w.Tool, label, head, err)
	}
	if w.Memory == nil {
		return nil, fmt.Errorf("%s: %s head at 0x%x: %w: no memory reader", w.Tool, label, head, ErrListUnreadable)
	}
	headLinks, err := w.read(head)
	if err != nil {
		return nil, fmt.Errorf("%s: %s head at 0x%x: %w: %w", w.Tool, label, head, ErrListUnreadable, err)
	}
	limit := w.Limit
	if limit <= 0 {
		limit = limits.DefaultMaxListEntries
	}
	return &walkState{
		head:      head,
		headLinks: headLinks,
		label:     label,
		walked:    map[uint64]bool{head: true},
		limit:     limit,
	}, nil
}

func (w ListWalker) follow(st *walkState, d direction, met map[uint64]bool) ([]uint64, error) {
	var entries []uint64
	prev, prevLinks := st.head, st.headLinks
	for {
		next := d.on(prevLinks)
		if next == st.head {
			if w.Layout.HasBlink && d.back(st.headLinks) != prev {
				return entries, fmt.Errorf("%s: %s head at 0x%x: %s is 0x%x, not the last entry walked, 0x%x: %w",
					w.Tool, st.label, st.head, d.backName(), d.back(st.headLinks), prev, ErrListBackLink)
			}
			return entries, nil
		}
		if met[next] {
			return entries, nil
		}
		if next == 0 {
			return entries, fmt.Errorf("%s: %s %s at 0x%x: %s: %w", w.Tool, st.label, st.kind(prev), prev, d.name, ErrListNull)
		}
		if st.walked[next] {
			return entries, fmt.Errorf("%s: %s %s at 0x%x: %s 0x%x: %w", w.Tool, st.label, st.kind(prev), prev, d.name, next, ErrListCycle)
		}
		nextLinks, err := w.read(next)
		if err != nil {
			return entries, fmt.Errorf("%s: %s entry at 0x%x: %w: %w", w.Tool, st.label, next, ErrListUnreadable, err)
		}
		if w.Layout.HasBlink && d.back(nextLinks) != prev {
			return entries, fmt.Errorf("%s: %s entry at 0x%x: %s is 0x%x, not the entry before it, 0x%x: %w",
				w.Tool, st.label, next, d.backName(), d.back(nextLinks), prev, ErrListBackLink)
		}
		if st.count >= st.limit {
			return entries, fmt.Errorf("%s: %s head at 0x%x: more than %d entries: %w", w.Tool, st.label, st.head, st.limit, ErrListLimit)
		}
		st.walked[next] = true
		st.count++
		entries = append(entries, next)
		prev, prevLinks = next, nextLinks
	}
}

func (st *walkState) kind(at uint64) string {
	if at == st.head {
		return "head"
	}
	return "entry"
}

func (d direction) backName() string {
	if d.name == forward.name {
		return backward.name
	}
	return forward.name
}

func (w ListWalker) read(at uint64) (links, error) {
	n := w.Layout.span()
	if at+n < at {
		return links{}, fmt.Errorf("0x%x bytes at 0x%x pass the end of the address space", n, at)
	}
	raw, err := w.Memory.ReadAt(at, n)
	if err != nil {
		return links{}, err
	}
	if uint64(len(raw)) < n {
		return links{}, fmt.Errorf("read 0x%x bytes, got 0x%x", n, len(raw))
	}
	l := links{flink: w.Layout.pointer(raw[w.Layout.Flink:])}
	if w.Layout.HasBlink {
		l.blink = w.Layout.pointer(raw[w.Layout.Blink:])
	}
	return l, nil
}

func (l ListLayout) pointer(b []byte) uint64 {
	if l.Width == 4 {
		return uint64(binary.LittleEndian.Uint32(b))
	}
	return binary.LittleEndian.Uint64(b)
}

func (w ListWalker) report(err error) {
	if w.Report != nil {
		w.Report("%v", err)
	}
}
