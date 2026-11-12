package memorycode

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

var (
	ErrNoPageEntries      = errors.New("memorycode: process address space gives no page-table entries")
	ErrRegionScanCut      = errors.New("memorycode: region page walk reached MaxRegionScanBytes")
	errProtectionUnusable = errors.New("memorycode: no 5-bit page protection field in symbols")
)

const pageSize = uint64(0x1000)

// Intel SDM Vol. 3A paging entry bits (S35 D7, T1).
const (
	entryPresent = uint64(1) << 0
	entryDirty   = uint64(1) << 6
	entryNoExec  = uint64(1) << 63
)

// Memory-manager forms of a not-present entry (S35 T2).
const (
	entryPrototype  = uint64(1) << 10
	entryTransition = uint64(1) << 11
)

// PAGE_EXECUTE through PAGE_EXECUTE_WRITECOPY (S35 D5).
const executeRights = uint32(0xF0)

func executable(protect uint32) bool { return protect&executeRights != 0 }

type leafEntries interface {
	LeafEntry(virtualAddress uint64) (uint64, error)
}

type pageProtections struct {
	software, transition symbols.IntField
	table                []uint32
}

func (p pageProtections) usable() bool { return len(p.table) > 0 }

func readPageProtections(ctx tools.Context) (pageProtections, error) {
	var p pageProtections
	var err error
	if p.software, err = symbols.ResolveIntField(ctx.Symbols, "_MMPTE_SOFTWARE", "Protection"); err != nil {
		return p, err
	}
	if p.transition, err = symbols.ResolveIntField(ctx.Symbols, "_MMPTE_TRANSITION", "Protection"); err != nil {
		return p, err
	}
	bits := p.software.BitLength
	if bits == 0 || bits > 8 || p.transition.BitLength != bits {
		return p, errProtectionUnusable
	}
	sym, err := ctx.Symbols.LookupSymbol("MmProtectToValue")
	if err != nil {
		return p, err
	}
	n := uint64(1) << bits
	raw, err := ctx.Memory.ReadAt(sym.Address, n*4)
	if err != nil {
		return p, fmt.Errorf("at 0x%x: %w", sym.Address, err)
	}
	if uint64(len(raw)) < n*4 {
		return p, fmt.Errorf("at 0x%x: %d of %d bytes", sym.Address, len(raw), n*4)
	}
	p.table = make([]uint32, n)
	for i := range p.table {
		p.table[i] = binary.LittleEndian.Uint32(raw[4*i:])
	}
	return p, nil
}

type pageState struct {
	resident   bool
	written    bool
	ownProtect bool
	executable bool
}

func (p pageProtections) decode(entry uint64) pageState {
	switch {
	case entry&entryPresent != 0:
		return pageState{resident: true, written: entry&entryDirty != 0, ownProtect: true, executable: entry&entryNoExec == 0}
	case entry&entryPrototype != 0, entry == 0:
		return pageState{}
	case entry&entryTransition != 0:
		s := pageState{resident: true}
		s.ownProtect, s.executable = p.protection(entry, p.transition)
		return s
	}
	var s pageState
	s.ownProtect, s.executable = p.protection(entry, p.software)
	return s
}

func (p pageProtections) protection(entry uint64, f symbols.IntField) (known, exec bool) {
	if !p.usable() {
		return false, false
	}
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], entry)
	index, err := f.Decode(raw[:])
	if err != nil || index >= uint64(len(p.table)) {
		return false, false
	}
	return true, executable(p.table[index])
}

type regionPages struct {
	pages, executable, resident, written uint64
	ownExecutable                        uint64
	executableAt                         []uint64
	visited                              uint64
	cut                                  bool
}

// A reservation of terabytes walks only the entries its tables hold: a miss
// above the leaf skips the span that entry covers.
func walkRegion(le leafEntries, prot pageProtections, start, end uint64, allocExec bool, budget uint64) regionPages {
	r := regionPages{pages: (end-start)/pageSize + 1}
	for page := start &^ (pageSize - 1); ; {
		step := pageSize
		entry, err := le.LeafEntry(page)
		var miss layers.UnmappedPageError
		switch {
		case err == nil:
			r.visited++
			if r.visited > budget {
				r.cut = true
				return r
			}
			s := prot.decode(entry)
			if s.resident {
				r.resident++
			}
			if s.written {
				r.written++
			}
			if s.ownProtect && s.executable {
				r.ownExecutable++
			}
			if (s.ownProtect && s.executable) || (!s.ownProtect && allocExec) {
				r.executable++
				r.executableAt = append(r.executableAt, page)
			}
		case errors.As(err, &miss) && miss.Span > pageSize:
			step = miss.Span - page&(miss.Span-1)
		}
		if end-page < step {
			return r
		}
		page += step
	}
}
