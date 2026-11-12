package poolbig

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

var (
	ErrNoTable      = errors.New("poolbig: symbol table has no big-page table")
	ErrTableAddress = errors.New("poolbig: big-page table address not usable")
	ErrTableSize    = errors.New("poolbig: big-page table size not usable")
	errShortRead    = errors.New("poolbig: short read")
)

const (
	entryType     = "_POOL_TRACKER_BIG_PAGES"
	tableGlobal   = "PoolBigPageTable"
	sizeGlobal    = "PoolBigPageTableSize"
	pageSize      = 0x1000
	readSpanBytes = 1 << 20
)

type field struct {
	symbols.IntField
	present bool
}

func optionalField(t symbols.SymbolTable, member string) (field, error) {
	if _, err := t.Field(entryType, member); err != nil {
		return field{}, nil
	}
	f, err := symbols.ResolveIntField(t, entryType, member)
	if err != nil {
		return field{}, err
	}
	return field{f, true}, nil
}

type entryLayout struct {
	stride    uint64
	va, key   symbols.IntField
	bytes     field
	poolType  field
	poolFlags field
}

func resolveEntryLayout(t symbols.SymbolTable) (entryLayout, error) {
	st, err := t.Struct(entryType)
	if err != nil {
		return entryLayout{}, fmt.Errorf("%w: %s: %w", ErrNoTable, entryType, err)
	}
	l := entryLayout{stride: st.Size}
	if l.va, err = symbols.ResolveIntField(t, entryType, "Va"); err != nil {
		return entryLayout{}, fmt.Errorf("%w: %w", ErrNoTable, err)
	}
	if l.key, err = symbols.ResolveIntField(t, entryType, "Key"); err != nil {
		return entryLayout{}, fmt.Errorf("%w: %w", ErrNoTable, err)
	}
	for _, o := range []struct {
		dst  *field
		name string
	}{{&l.bytes, "NumberOfBytes"}, {&l.poolType, "PoolType"}, {&l.poolFlags, "PoolFlags"}} {
		if *o.dst, err = optionalField(t, o.name); err != nil {
			return entryLayout{}, fmt.Errorf("%w: %w", ErrNoTable, err)
		}
	}
	for _, f := range []field{{l.va, true}, {l.key, true}, l.bytes, l.poolType, l.poolFlags} {
		if f.present && f.Offset+f.Width > l.stride {
			return entryLayout{}, fmt.Errorf("%w: %s member at +0x%x runs past the %d-byte entry",
				ErrNoTable, entryType, f.Offset, l.stride)
		}
	}
	if l.stride == 0 {
		return entryLayout{}, fmt.Errorf("%w: %s has no size", ErrNoTable, entryType)
	}
	return l, nil
}

type rawEntry struct {
	slot                       uint64
	va, key, bytes, typ, flags uint64
}

func (l entryLayout) decode(slot uint64, rec []byte) rawEntry {
	e := rawEntry{slot: slot}
	e.va, _ = l.va.Decode(rec)
	e.key, _ = l.key.Decode(rec)
	if l.bytes.present {
		e.bytes, _ = l.bytes.Decode(rec)
	}
	if l.poolType.present {
		e.typ, _ = l.poolType.Decode(rec)
	}
	if l.poolFlags.present {
		e.flags, _ = l.poolFlags.Decode(rec)
	}
	return e
}

type tableLocation struct {
	pointerAt, sizeAt uint64
	base, slots       uint64
}

func locateTable(t symbols.SymbolTable, kernel memory.MemoryReader, maxSlots uint64) (tableLocation, error) {
	tableSym, err := t.LookupSymbol(tableGlobal)
	if err != nil {
		return tableLocation{}, fmt.Errorf("%w: %s: %w", ErrNoTable, tableGlobal, err)
	}
	sizeSym, err := t.LookupSymbol(sizeGlobal)
	if err != nil {
		return tableLocation{}, fmt.Errorf("%w: %s: %w", ErrNoTable, sizeGlobal, err)
	}
	loc := tableLocation{pointerAt: tableSym.Address, sizeAt: sizeSym.Address}
	if loc.base, err = t.ReadPointer(kernel, loc.pointerAt); err != nil {
		return loc, fmt.Errorf("%s at 0x%x: not readable: %w", tableGlobal, loc.pointerAt, err)
	}
	// The table spans pages of its own, so its address is a page boundary on
	// every measured build; any other value is not the table.
	if loc.base == 0 || loc.base%pageSize != 0 {
		return loc, fmt.Errorf("%s at 0x%x: holds 0x%x: %w", tableGlobal, loc.pointerAt, loc.base, ErrTableAddress)
	}
	n, err := t.ReadUint32(kernel, loc.sizeAt)
	if err != nil {
		return loc, fmt.Errorf("%s at 0x%x: not readable: %w", sizeGlobal, loc.sizeAt, err)
	}
	loc.slots = uint64(n)
	if loc.slots == 0 || loc.slots > maxSlots {
		return loc, fmt.Errorf("%s at 0x%x: %d slots, limit %d: %w", sizeGlobal, loc.sizeAt, loc.slots, maxSlots,
			ErrTableSize)
	}
	return loc, nil
}

type unreadableRun struct {
	address, bytes uint64
	err            error
}

// A page that does not read loses only the entries that touch it.
func readEntries(kernel memory.MemoryReader, loc tableLocation, l entryLayout) ([]rawEntry, []unreadableRun) {
	var out []rawEntry
	var gaps []unreadableRun
	perSpan := max(readSpanBytes/l.stride, 1)
	for first := uint64(0); first < loc.slots; first += perSpan {
		count := min(perSpan, loc.slots-first)
		start := loc.base + first*l.stride
		length := count * l.stride
		raw, err := kernel.ReadAt(start, length)
		var valid func(off uint64) bool
		if err == nil && uint64(len(raw)) >= length {
			valid = func(uint64) bool { return true }
		} else {
			raw, valid, gaps = readByPage(kernel, start, length, gaps)
		}
		for i := uint64(0); i < count; i++ {
			off := i * l.stride
			if !valid(off) || !valid(off+l.stride-1) {
				continue
			}
			out = append(out, l.decode(first+i, raw[off:off+l.stride]))
		}
	}
	return out, gaps
}

func readByPage(kernel memory.MemoryReader, start, length uint64, gaps []unreadableRun) ([]byte, func(uint64) bool, []unreadableRun) {
	raw := make([]byte, length)
	var bad []bool
	firstPage := start &^ (pageSize - 1)
	for page := firstPage; page < start+length; page += pageSize {
		from, to := max(page, start), min(page+pageSize, start+length)
		b, err := kernel.ReadAt(from, to-from)
		ok := err == nil && uint64(len(b)) >= to-from
		if ok {
			copy(raw[from-start:], b)
		} else {
			if err == nil {
				err = errShortRead
			}
			if n := len(gaps); n > 0 && gaps[n-1].address+gaps[n-1].bytes == from {
				gaps[n-1].bytes += to - from
			} else {
				gaps = append(gaps, unreadableRun{address: from, bytes: to - from, err: err})
			}
		}
		bad = append(bad, !ok)
	}
	return raw, func(off uint64) bool { return !bad[(start+off-firstPage)/pageSize] }, gaps
}
