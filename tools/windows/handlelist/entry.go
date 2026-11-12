package handlelist

import (
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

// The entry keeps the header address without its low four bits: object
// headers are 16-byte aligned (S66 HT2, HM5).
const headerAlignBits = 4

type entryLayout struct {
	size    uint64
	pointer symbols.IntField
	access  symbols.IntField
	leaf    symbols.IntField
	hasLeaf bool
}

func readEntryLayout(table symbols.SymbolTable) (entryLayout, error) {
	st, err := table.Struct("_HANDLE_TABLE_ENTRY")
	if err != nil {
		return entryLayout{}, fmt.Errorf("%w: _HANDLE_TABLE_ENTRY: %w", ErrNoHandleLayout, err)
	}
	if st.Size == 0 || pageSize%st.Size != 0 {
		return entryLayout{}, fmt.Errorf("%w: _HANDLE_TABLE_ENTRY is %d bytes, which does not divide a page",
			ErrNoHandleLayout, st.Size)
	}
	l := entryLayout{size: st.Size}
	for _, m := range []struct {
		name string
		dst  *symbols.IntField
	}{{"ObjectPointerBits", &l.pointer}, {"GrantedAccessBits", &l.access}} {
		f, err := symbols.ResolveIntField(table, "_HANDLE_TABLE_ENTRY", m.name)
		if err != nil {
			return entryLayout{}, fmt.Errorf("%w: %w", ErrNoHandleLayout, err)
		}
		if f.Offset+f.Width > st.Size || f.Width == 0 || f.Width > 8 {
			return entryLayout{}, fmt.Errorf("%w: _HANDLE_TABLE_ENTRY.%s lies outside the entry", ErrNoHandleLayout, m.name)
		}
		*m.dst = f
	}
	if l.pointer.BitLength == 0 || int(l.pointer.BitLength)+headerAlignBits > 64 {
		return entryLayout{}, fmt.Errorf("%w: _HANDLE_TABLE_ENTRY.ObjectPointerBits is not a bit field of at most 60 bits",
			ErrNoHandleLayout)
	}
	if f, err := table.Field("_HANDLE_TABLE_ENTRY", "LeafHandleValue"); err == nil && f.Offset+8 <= st.Size {
		l.leaf, l.hasLeaf = symbols.IntField{Offset: f.Offset, Width: 8}, true
	}
	return l, nil
}

// The first entry of a page holds the handle value of the page's first entry
// (S66 HM4). A page whose first entry says otherwise is not this table's page
// at this place.
func (l entryLayout) pageStartsAt(rec []byte, first uint64) (uint64, bool) {
	if !l.hasLeaf {
		return 0, true
	}
	v, err := l.leaf.Decode(rec)
	return v, err == nil && v == first
}

// An entry is in use when it holds an object; its header address is the
// stored bits shifted back into place and put in canonical form.
func (l entryLayout) decode(rec []byte) (tableEntry, bool) {
	bits, err := l.pointer.Decode(rec)
	if err != nil || bits == 0 {
		return tableEntry{}, false
	}
	access, err := l.access.Decode(rec)
	if err != nil {
		return tableEntry{}, false
	}
	width := uint(l.pointer.BitLength) + headerAlignBits
	mask := ^uint64(0)
	if width < 64 {
		mask = 1<<width - 1
	}
	header := modulelist.CanonicalAddress(bits<<headerAlignBits, mask, 8)
	return tableEntry{header: header, access: access}, true
}
