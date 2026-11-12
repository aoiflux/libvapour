package handlelist

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

const (
	pageSize = 0x1000

	// The low two bits of TableCode give the depth below the top page; the
	// rest is the top page's address (S66 HM2).
	levelMask = 0x3
	maxLevel  = 2

	// Every entry stands for four handle values (S66 HM3).
	valuesPerEntry = 4

	// Kernel Objects: "The per-process limit on kernel handles is 2^24".
	maxHandlesPerProcess = 1 << 24
)

type tableLayout struct {
	objectTable uint64
	tableCode   uint64
	next        symbols.IntField
	hasNext     bool
	entry       entryLayout
	pointer     uint64
}

func readTableLayout(table symbols.SymbolTable) (tableLayout, error) {
	member := func(typ, name string) (uint64, error) {
		f, err := table.Field(typ, name)
		if err != nil {
			return 0, fmt.Errorf("%w: %s.%s: %w", ErrNoHandleLayout, typ, name, err)
		}
		return f.Offset, nil
	}
	var l tableLayout
	var err error
	if l.objectTable, err = member("_EPROCESS", "ObjectTable"); err != nil {
		return tableLayout{}, err
	}
	if l.tableCode, err = member("_HANDLE_TABLE", "TableCode"); err != nil {
		return tableLayout{}, err
	}
	l.next, err = symbols.ResolveIntField(table, "_HANDLE_TABLE", "NextHandleNeedingPool")
	l.hasNext = err == nil
	if l.entry, err = readEntryLayout(table); err != nil {
		return tableLayout{}, err
	}
	l.pointer = uint64(table.PointerSize())
	if l.pointer != 4 && l.pointer != 8 {
		return tableLayout{}, fmt.Errorf("%w: pointer size %d", ErrNoHandleLayout, l.pointer)
	}
	return l, nil
}

func (l tableLayout) entriesPerLeaf() uint64 { return pageSize / l.entry.size }

func (l tableLayout) pointersPerPage() uint64 { return pageSize / l.pointer }

type tableEntry struct {
	value  uint64
	header uint64
	access uint64
}

// tableRead collects what one table walk could not read, for one diagnostic
// per table.
type tableRead struct {
	leaves       uint64
	leafUnread   uint64
	misplaced    uint64
	pointerPages uint64
	pageUnread   uint64
	pastCeiling  uint64
	firstErr     error
	misplaceErr  error
	capped       bool
}

func cmpOr(first, next error) error {
	if first != nil {
		return first
	}
	return next
}

func (r *tableRead) fail(err error) { r.firstErr = cmpOr(r.firstErr, err) }

func (w *Walker) readTable(p processlist.Process) ([]tableEntry, bool) {
	ctx, l := w.ctx, w.layout
	objectTable, err := ctx.Symbols.ReadPointer(ctx.Memory, p.EPROCESS+l.objectTable)
	if err != nil {
		ctx.AddDiagnostic("%s: process %d at 0x%x: ObjectTable does not read, its handles are unknown: %v",
			Name, p.PID, p.EPROCESS, err)
		return nil, false
	}
	if objectTable == 0 {
		return nil, true
	}
	code, err := ctx.Symbols.ReadPointer(ctx.Memory, objectTable+l.tableCode)
	if err != nil {
		ctx.AddDiagnostic("%s: handle table of process %d at 0x%x: TableCode does not read, its handles are unknown: %v",
			Name, p.PID, objectTable, err)
		return nil, false
	}
	level, top := code&levelMask, code&^levelMask
	switch {
	case level > maxLevel:
		ctx.AddDiagnostic("%s: handle table of process %d at 0x%x: TableCode 0x%x: %v", Name, p.PID, objectTable, code,
			errTableLevel)
		return nil, false
	case top%pageSize != 0:
		ctx.AddDiagnostic("%s: handle table of process %d at 0x%x: TableCode 0x%x: %v", Name, p.PID, objectTable, code,
			errTableCodeMisplace)
		return nil, false
	}

	ceiling, from := w.ceiling(objectTable)
	t := tableWalk{w: w, ceiling: ceiling, read: &tableRead{}}
	t.page(top, level, 0)
	r := t.read
	if r.misplaced > 0 {
		ctx.AddDiagnostic("%s: handle table of process %d at 0x%x: %d of %d entry pages do not start at the handle "+
			"value of their place, their entries are not listed: %v", Name, p.PID, objectTable, r.misplaced, r.leaves,
			r.misplaceErr)
	}
	if r.leafUnread > 0 || r.pageUnread > 0 {
		ctx.AddDiagnostic("%s: handle table of process %d at 0x%x: %d of %d entry pages and %d of %d pointer pages do "+
			"not read, its handles are incomplete: %v", Name, p.PID, objectTable, r.leafUnread, r.leaves, r.pageUnread,
			r.pointerPages, r.firstErr)
	}
	if r.pastCeiling > 0 {
		ctx.AddDiagnostic("%s: handle table of process %d at 0x%x: %d page pointers at or past %s are not followed",
			Name, p.PID, objectTable, r.pastCeiling, from)
	}
	if r.capped {
		ctx.AddDiagnostic("%s: handle table of process %d at 0x%x: stopped at %s, its rows may be a prefix",
			Name, p.PID, objectTable, from)
	}
	return t.entries, r.leafUnread == 0 && r.pageUnread == 0 && r.misplaced == 0 && !r.capped
}

// The table grows a page of entries at a time, and NextHandleNeedingPool is
// the first value no page holds yet (S66 HM3), so no entry lies at or past it.
func (w *Walker) ceiling(objectTable uint64) (uint64, string) {
	limit := uint64(w.ctx.Bounds().MaxTableEntries) * valuesPerEntry
	from := fmt.Sprintf("MaxTableEntries (%d)", w.ctx.Bounds().MaxTableEntries)
	if limit > maxHandlesPerProcess*valuesPerEntry {
		limit = maxHandlesPerProcess * valuesPerEntry
		from = fmt.Sprintf("the per-process limit of %d handles", maxHandlesPerProcess)
	}
	if !w.layout.hasNext {
		return limit, from
	}
	next, err := w.layout.next.Read(w.ctx.Memory, objectTable)
	leafSpan := w.layout.entriesPerLeaf() * valuesPerEntry
	if err != nil || next == 0 || next%leafSpan != 0 || next > limit {
		return limit, from
	}
	return next, fmt.Sprintf("NextHandleNeedingPool 0x%x", next)
}

type tableWalk struct {
	w       *Walker
	ceiling uint64
	read    *tableRead
	entries []tableEntry
}

// first is the handle value the page's first entry stands for.
func (t *tableWalk) page(at, level, first uint64) {
	l := t.w.layout
	if level == 0 {
		t.leaf(at, first)
		return
	}
	t.read.pointerPages++
	raw, err := t.w.ctx.Memory.ReadAt(at, pageSize)
	if err != nil || len(raw) != pageSize {
		t.read.pageUnread++
		t.read.fail(fmt.Errorf("pointer page at 0x%x: %v", at, err))
		return
	}
	span := l.entriesPerLeaf() * valuesPerEntry
	for range level - 1 {
		span *= l.pointersPerPage()
	}
	for i := range l.pointersPerPage() {
		next := readPointer(raw[i*l.pointer:], l.pointer)
		if next == 0 {
			continue
		}
		start := first + i*span
		if start >= t.ceiling {
			if t.ceiling >= t.w.limitValue() {
				t.read.capped = true
				return
			}
			t.read.pastCeiling++
			continue
		}
		t.page(next, level-1, start)
		if t.read.capped {
			return
		}
	}
}

func (t *tableWalk) leaf(at, first uint64) {
	l := t.w.layout
	t.read.leaves++
	raw, err := t.w.ctx.Memory.ReadAt(at, pageSize)
	if err != nil || len(raw) != pageSize {
		t.read.leafUnread++
		t.read.fail(fmt.Errorf("entry page at 0x%x: %v", at, err))
		return
	}
	if got, ok := l.entry.pageStartsAt(raw[:l.entry.size], first); !ok {
		t.read.misplaced++
		t.read.misplaceErr = cmpOr(t.read.misplaceErr, fmt.Errorf("entry page at 0x%x: LeafHandleValue 0x%x, want 0x%x", at, got, first))
		return
	}
	// The first entry of each page is never a handle (S66 HM4).
	for i := uint64(1); i < l.entriesPerLeaf(); i++ {
		value := first + i*valuesPerEntry
		if value >= t.ceiling {
			if value >= t.w.limitValue() {
				t.read.capped = true
			}
			return
		}
		e, inUse := l.entry.decode(raw[i*l.entry.size : (i+1)*l.entry.size])
		if !inUse {
			continue
		}
		e.value = value
		t.entries = append(t.entries, e)
	}
}

func (w *Walker) limitValue() uint64 {
	limit := uint64(w.ctx.Bounds().MaxTableEntries) * valuesPerEntry
	return min(limit, maxHandlesPerProcess*valuesPerEntry)
}

func readPointer(b []byte, size uint64) uint64 {
	if size == 4 {
		return uint64(binary.LittleEndian.Uint32(b))
	}
	return binary.LittleEndian.Uint64(b)
}
