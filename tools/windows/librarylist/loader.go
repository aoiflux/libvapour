package librarylist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/winkernel"
	"github.com/aoiflux/libvapour/util"
)

var (
	ErrLoaderLayout = errors.New("librarylist: symbol table lacks a loader member")
	ErrNoWow64      = errors.New("librarylist: symbol table lacks _PEB32 or LIST_ENTRY32")
	ErrBaseUnread   = errors.New("librarylist: DllBase does not read")
)

type loaderList int

const (
	inLoadOrder loaderList = iota
	inMemoryOrder
	inInitializationOrder
	loaderLists
)

var (
	listLabels = [loaderLists]string{"InLoadOrderModuleList", "InMemoryOrderModuleList", "InInitializationOrderModuleList"}
	linkNames  = [loaderLists]string{"InLoadOrderLinks", "InMemoryOrderLinks", "InInitializationOrderLinks"}
)

type loaderLayout struct {
	pointer     uint64
	ldr         uint64
	list        winkernel.ListLayout
	walks       [loaderLists]bool
	heads       [loaderLists]uint64
	links       [loaderLists]uint64
	dllBase     uint64
	sizeOfImage uint64
	fullName    uint64
	baseName    uint64
	unicode     util.UnicodeStringLayout

	loadCount     bool
	ddagNode      uint64
	ddagLoadCount symbols.IntField
	loadTime      bool
	loadTimeAt    uint64
}

func member(t symbols.SymbolTable, typ, name string) (uint64, error) {
	f, err := t.Field(typ, name)
	if err != nil {
		return 0, fmt.Errorf("%s.%s: %w: %w", typ, name, ErrLoaderLayout, err)
	}
	return f.Offset, nil
}

func nativeLayout(t symbols.SymbolTable) (loaderLayout, error) {
	l := loaderLayout{pointer: uint64(t.PointerSize()), unicode: util.ResolveUnicodeStringLayout(t)}
	var err error
	if l.list, err = winkernel.NativeListLayout(t); err != nil {
		return loaderLayout{}, fmt.Errorf("%w: %w", ErrLoaderLayout, err)
	}
	for _, m := range []struct {
		at        *uint64
		typ, name string
	}{
		{&l.ldr, "_PEB", "Ldr"},
		{&l.heads[inLoadOrder], "_PEB_LDR_DATA", "InLoadOrderModuleList"},
		{&l.links[inLoadOrder], "_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"},
		{&l.dllBase, "_LDR_DATA_TABLE_ENTRY", "DllBase"},
		{&l.sizeOfImage, "_LDR_DATA_TABLE_ENTRY", "SizeOfImage"},
		{&l.fullName, "_LDR_DATA_TABLE_ENTRY", "FullDllName"},
		{&l.baseName, "_LDR_DATA_TABLE_ENTRY", "BaseDllName"},
	} {
		if *m.at, err = member(t, m.typ, m.name); err != nil {
			return loaderLayout{}, err
		}
	}
	l.walks[inLoadOrder] = true
	for _, list := range []loaderList{inMemoryOrder, inInitializationOrder} {
		head, err1 := t.Field("_PEB_LDR_DATA", listLabels[list])
		link, err2 := t.Field("_LDR_DATA_TABLE_ENTRY", linkNames[list])
		if err1 == nil && err2 == nil {
			l.heads[list], l.links[list], l.walks[list] = head.Offset, link.Offset, true
		}
	}
	if node, err := t.Field("_LDR_DATA_TABLE_ENTRY", "DdagNode"); err == nil {
		if count, err := symbols.ResolveIntField(t, "_LDR_DDAG_NODE", "LoadCount"); err == nil {
			l.loadCount, l.ddagNode, l.ddagLoadCount = true, node.Offset, count
		}
	}
	if f, err := t.Field("_LDR_DATA_TABLE_ENTRY", "LoadTime"); err == nil {
		l.loadTime, l.loadTimeAt = true, f.Offset
	}
	return l, nil
}

// No table describes the 32-bit loader structures; the offsets re-lay the
// 64-bit member order with 4-byte pointers (S56 L1).
func wow64Layout(t symbols.SymbolTable) (loaderLayout, error) {
	ldr, err := t.Field("_PEB32", "Ldr")
	if err != nil {
		return loaderLayout{}, fmt.Errorf("%w: %w", ErrNoWow64, err)
	}
	list, err := winkernel.ListLayoutOf(t, "LIST_ENTRY32", 4)
	if err != nil {
		return loaderLayout{}, fmt.Errorf("%w: %w", ErrNoWow64, err)
	}
	unicode := util.UnicodeStringLayout{LengthOffset: 0, MaximumLengthOffset: 2, BufferOffset: 4, Size: 8}
	for _, m := range []struct {
		at   *uint64
		name string
	}{{&unicode.LengthOffset, "Length"}, {&unicode.MaximumLengthOffset, "MaximumLength"}, {&unicode.BufferOffset, "Buffer"}} {
		if f, err := t.Field("_STRING32", m.name); err == nil {
			*m.at = f.Offset
		}
	}
	return loaderLayout{
		pointer: 4, ldr: ldr.Offset, list: list, unicode: unicode, walks: [loaderLists]bool{true, true, true},
		heads:   [loaderLists]uint64{0x0c, 0x14, 0x1c},
		links:   [loaderLists]uint64{0x00, 0x08, 0x10},
		dllBase: 0x18, sizeOfImage: 0x20, fullName: 0x24, baseName: 0x2c,
	}, nil
}

type record struct {
	at     uint64
	in     [loaderLists]bool
	fields DLL
}

type loaderWalk struct {
	records    []record
	baseUnread int
	headErrs   []error
}

func readPointer(r memory.MemoryReader, at, width uint64) (uint64, error) {
	raw, err := r.ReadAt(at, width)
	if err != nil {
		return 0, err
	}
	if uint64(len(raw)) < width {
		return 0, fmt.Errorf("read 0x%x bytes at 0x%x, got 0x%x", width, at, len(raw))
	}
	if width == 4 {
		return uint64(binary.LittleEndian.Uint32(raw)), nil
	}
	return binary.LittleEndian.Uint64(raw), nil
}

// The rows follow the load-order list, then add what only the other lists
// reach: a record cut from one list, or behind a page the capture lacks,
// still shows.
func walkLoader(w winkernel.ListWalker, space memory.MemoryReader, ldr uint64, l loaderLayout) (loaderWalk, error) {
	var out loaderWalk
	index := map[uint64]int{}
	for list := range loaderLists {
		if !l.walks[list] {
			continue
		}
		walk, err := w.WalkRecovering(ldr+l.heads[list], listLabels[list])
		if err != nil {
			if w.Strict {
				return loaderWalk{}, err
			}
			out.headErrs = append(out.headErrs, err)
			continue
		}
		for _, link := range walk.Entries {
			at, ok := winkernel.Container(link, l.links[list])
			if !ok {
				continue
			}
			i, seen := index[at]
			if !seen {
				i = len(out.records)
				index[at] = i
				out.records = append(out.records, record{at: at})
			}
			out.records[i].in[list] = true
		}
	}
	for i := range out.records {
		readRecord(space, l, &out.records[i])
		if out.records[i].fields.BaseUnreadable {
			out.baseUnread++
		}
	}
	return out, nil
}

func readRecord(space memory.MemoryReader, l loaderLayout, r *record) {
	d := &r.fields
	d.Entry = r.at
	d.InLoadOrder, d.InMemoryOrder, d.InInitializationOrder = r.in[inLoadOrder], r.in[inMemoryOrder], r.in[inInitializationOrder]
	base, err := readPointer(space, r.at+l.dllBase, l.pointer)
	d.Base, d.BaseUnreadable = base, err != nil
	size, err := readPointer(space, r.at+l.sizeOfImage, 4)
	d.Size, d.SizeUnreadable = size, err != nil
	if s, err := util.ReadUnicodeString(space, r.at+l.baseName, l.unicode, 0); err == nil {
		d.Name = s.Text()
	} else {
		d.NameUnreadable = true
	}
	if s, err := util.ReadUnicodeString(space, r.at+l.fullName, l.unicode, 0); err == nil {
		d.FullPath = s.Text()
	} else {
		d.FullPathUnreadable = true
	}
	d.LoadCount, d.LoadCountUnreadable = readLoadCount(space, l, r.at)
	d.LoadTime, d.LoadTimeUnreadable = readLoadTime(space, l, r.at)
}

func readLoadCount(space memory.MemoryReader, l loaderLayout, at uint64) (uint32, bool) {
	if !l.loadCount {
		return 0, true
	}
	node, err := readPointer(space, at+l.ddagNode, l.pointer)
	if err != nil || node == 0 {
		return 0, true
	}
	v, err := l.ddagLoadCount.Read(space, node)
	if err != nil {
		return 0, true
	}
	return uint32(v), false
}

func readLoadTime(space memory.MemoryReader, l loaderLayout, at uint64) (time.Time, bool) {
	if !l.loadTime {
		return time.Time{}, true
	}
	v, err := readPointer(space, at+l.loadTimeAt, 8)
	if err != nil {
		return time.Time{}, true
	}
	t, _ := util.FiletimeToTime(v)
	return t, false
}
