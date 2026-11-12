package layers

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/memory"
)

type IntelTranslator struct {
	Physical memory.MemoryReader
	CR3      uint64
	Mode     PagingMode
	cache    *entryCache
}

type X8664PageTableTranslator = IntelTranslator

func (t *IntelTranslator) EnableCache(maxEntries int) {
	t.cache = newEntryCache(maxEntries)
}

type walkEnd struct {
	physical uint64
	entry    uint64
	atLeaf   bool
	err      error
}

func (t *IntelTranslator) walk(va uint64) walkEnd {
	m := t.Mode.effective()
	table := m.root(t.CR3)
	for level := range m.levels {
		e, ok := t.entry(m, table, m.index(va, level))
		if !ok {
			miss := UnmappedPageError{VirtualAddress: va, Kind: PageNotCaptured}
			if level > 0 {
				miss.Span = m.span(level - 1)
			}
			return walkEnd{err: miss}
		}
		s := m.step(level, e)
		last := level == m.leaf()
		switch s.kind {
		case stepTable:
			table = s.addr
			continue
		case stepPage:
			return walkEnd{physical: s.addr | va&(s.size-1), entry: e, atLeaf: true}
		case stepSoftware:
			return walkEnd{entry: e, atLeaf: true, err: softwareFault(e, va)}
		}
		miss := UnmappedPageError{VirtualAddress: va, Kind: PageInvalid}
		if !last {
			miss.Span = m.span(level)
		}
		return walkEnd{entry: e, atLeaf: last, err: miss}
	}
	return walkEnd{err: UnmappedPageError{VirtualAddress: va, Kind: PageInvalid}}
}

func (t *IntelTranslator) entry(m PagingMode, table, index uint64) (uint64, bool) {
	at := table + index*m.entryBytes
	if t.cache != nil {
		if v, ok := t.cache.lookup(at); ok {
			return v, true
		}
	}
	if t.Physical == nil {
		return 0, false
	}
	b, err := t.Physical.ReadAt(at, m.entryBytes)
	if err != nil || uint64(len(b)) < m.entryBytes {
		return 0, false
	}
	var v uint64
	if m.entryBytes == 8 {
		v = binary.LittleEndian.Uint64(b)
	} else {
		v = uint64(binary.LittleEndian.Uint32(b))
	}
	if t.cache != nil {
		t.cache.store(at, v)
	}
	return v, true
}

func (t *IntelTranslator) Translate(virtualAddress uint64) (uint64, error) {
	end := t.walk(virtualAddress)
	if end.err != nil {
		return 0, end.err
	}
	return end.physical, nil
}

// The entry that ended the walk at the leaf level, or the large-page entry
// above it, whatever it says; a walk that ends above the leaf is an error.
func (t *IntelTranslator) LeafEntry(virtualAddress uint64) (uint64, error) {
	end := t.walk(virtualAddress)
	if end.atLeaf {
		return end.entry, nil
	}
	return 0, end.err
}
