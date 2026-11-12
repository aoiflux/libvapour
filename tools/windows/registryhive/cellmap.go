package registryhive

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
)

var (
	ErrCellOutside    = errors.New("registryhive: cell index past the end of its storage")
	ErrCellUnmapped   = errors.New("registryhive: cell index has no map entry")
	ErrCellUnreadable = errors.New("registryhive: cell does not read")
	ErrCellFree       = errors.New("registryhive: cell is not allocated")
	ErrCellSize       = errors.New("registryhive: cell too small for its contents")
	ErrCellSignature  = errors.New("registryhive: cell signature does not match")
	ErrBinHeader      = errors.New("registryhive: bin header does not match its map entry")
)

type mapEntry struct {
	bin         uint64
	blockOffset uint64
}

func (h *HiveLayer) pointer(r memory.MemoryReader, at uint64) (uint64, error) {
	b, err := r.ReadAt(at, h.l.width)
	if err != nil {
		return 0, err
	}
	if uint64(len(b)) < h.l.width {
		return 0, fmt.Errorf("0x%x: short read", at)
	}
	if h.l.width == 4 {
		return uint64(binary.LittleEndian.Uint32(b)), nil
	}
	return binary.LittleEndian.Uint64(b), nil
}

func (h *HiveLayer) entry(storage, dir, table uint64) (mapEntry, error) {
	key := storage<<40 | dir<<20 | table
	if e, ok := h.entries[key]; ok {
		return e, nil
	}
	tableAt, ok := h.tables[storage<<40|dir]
	if !ok {
		at, err := h.pointer(h.ctx.Memory, h.mapAt[storage]+dir*h.l.width)
		if err != nil {
			return mapEntry{}, fmt.Errorf("%w: map directory slot %d: %w", ErrCellUnmapped, dir, err)
		}
		tableAt = at
		h.tables[storage<<40|dir] = at
	}
	if tableAt == 0 {
		return mapEntry{}, fmt.Errorf("%w: map directory slot %d is null", ErrCellUnmapped, dir)
	}
	// Only the two members are read: an entry can end on a page that is out
	// of memory past them (M15).
	lo := min(h.l.entryBlockOffset, h.l.entryBin)
	hi := max(h.l.entryBlockOffset, h.l.entryBin) + h.l.width
	raw, err := h.ctx.Memory.ReadAt(tableAt+table*h.l.entrySize+lo, hi-lo)
	if err != nil || uint64(len(raw)) < hi-lo {
		return mapEntry{}, fmt.Errorf("%w: map table at 0x%x slot %d does not read", ErrCellUnmapped, tableAt, table)
	}
	member := func(off uint64) uint64 {
		if h.l.width == 4 {
			return uint64(binary.LittleEndian.Uint32(raw[off-lo:]))
		}
		return binary.LittleEndian.Uint64(raw[off-lo:])
	}
	e := mapEntry{blockOffset: member(h.l.entryBlockOffset), bin: member(h.l.entryBin)}
	e.bin &^= binFlagMask
	h.entries[key] = e
	return e, nil
}

func (h *HiveLayer) cellAddress(index uint32) (uint64, error) {
	storage, dir, table, offset := h.l.shape.split(index)
	if uint64(index&0x7fffffff) >= h.length[storage] {
		return 0, fmt.Errorf("%w: cell 0x%x, storage %d is 0x%x bytes", ErrCellOutside, index, storage, h.length[storage])
	}
	e, err := h.entry(storage, dir, table)
	if err != nil {
		return 0, fmt.Errorf("cell 0x%x: %w", index, err)
	}
	if e.bin == 0 {
		return 0, fmt.Errorf("cell 0x%x: %w: bin address is null", index, ErrCellUnmapped)
	}
	if h.checkBins {
		if err := h.checkBin(index, e); err != nil {
			return 0, fmt.Errorf("cell 0x%x: %w", index, err)
		}
	}
	return e.bin + e.blockOffset + offset, nil
}

// A bin's FileOffset is the storage offset of its first block, which the
// map entry gives as the block's own offset less its offset in the bin.
func (h *HiveLayer) checkBin(index uint32, e mapEntry) error {
	if err, ok := h.bins[e.bin]; ok {
		return err
	}
	block := uint64(index&0x7fffffff) &^ (h.l.shape.blockSize - 1)
	var err error
	raw, rerr := h.cells.ReadAt(e.bin, h.l.bin.headerSize)
	switch {
	case rerr != nil || uint64(len(raw)) < h.l.bin.headerSize || h.l.bin.headerSize < max(h.l.bin.fileOffset, h.l.bin.signature)+4:
		err = fmt.Errorf("%w: header at 0x%x does not read", ErrBinHeader, e.bin)
	case string(raw[h.l.bin.signature:h.l.bin.signature+4]) != "hbin":
		err = fmt.Errorf("%w: no hbin signature at 0x%x", ErrBinHeader, e.bin)
	case index>>31 == 0 && uint64(binary.LittleEndian.Uint32(raw[h.l.bin.fileOffset:])) != block-e.blockOffset:
		err = fmt.Errorf("%w: bin at 0x%x starts at 0x%x, map says 0x%x", ErrBinHeader, e.bin,
			binary.LittleEndian.Uint32(raw[h.l.bin.fileOffset:]), block-e.blockOffset)
	}
	h.bins[e.bin] = err
	return err
}

// The size word is negative for an allocated cell; its magnitude counts the
// word itself.
func (h *HiveLayer) cellExtent(index uint32) (addr, capacity uint64, err error) {
	at, err := h.cellAddress(index)
	if err != nil {
		return 0, 0, err
	}
	raw, err := h.cells.ReadAt(at, 4)
	if err != nil || len(raw) < 4 {
		return 0, 0, fmt.Errorf("cell 0x%x at 0x%x: %w: size word: %v", index, at, ErrCellUnreadable, err)
	}
	size := int32(binary.LittleEndian.Uint32(raw))
	if size >= 0 {
		return 0, 0, fmt.Errorf("cell 0x%x at 0x%x: %w: size word %d", index, at, ErrCellFree, size)
	}
	n := uint64(-int64(size))
	if n < 4 {
		return 0, 0, fmt.Errorf("cell 0x%x at 0x%x: %w: size word %d", index, at, ErrCellSize, size)
	}
	return at + 4, n - 4, nil
}

type cellView struct {
	index uint32
	addr  uint64
	b     []byte
	gaps  extract.GapMap
}

func (c cellView) has(off, n uint64) bool {
	if off+n > uint64(len(c.b)) || off+n < off {
		return false
	}
	start, end := c.addr+off, c.addr+off+n
	for _, g := range c.gaps {
		if g.Start < end && start < g.End() {
			return false
		}
	}
	return true
}

func (c cellView) u16(off uint64) (uint16, bool) {
	if !c.has(off, 2) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(c.b[off:]), true
}

func (c cellView) u32(off uint64) (uint32, bool) {
	if !c.has(off, 4) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(c.b[off:]), true
}

func (c cellView) u64(off uint64) (uint64, bool) {
	if !c.has(off, 8) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(c.b[off:]), true
}

// Read page by page so that one page out of memory costs only the members on it.
func (h *HiveLayer) readCell(index uint32, want uint64) (cellView, uint64, error) {
	addr, capacity, err := h.cellExtent(index)
	if err != nil {
		return cellView{}, 0, err
	}
	n := min(want, capacity)
	if limit := uint64(h.bounds.MaxBufferBytes); limit > 0 && n > limit {
		n = limit
	}
	b, gaps := extract.ReadPadded(h.cells, addr, n)
	return cellView{index: index, addr: addr, b: b, gaps: gaps}, capacity, nil
}

// The fixed members and the name are read apart, so a name that does not
// read leaves the members before it readable.
func (h *HiveLayer) readCellSplit(index uint32, split, want uint64) (cellView, error) {
	c, capacity, err := h.readCell(index, split)
	if err != nil || uint64(len(c.b)) < split {
		return c, err
	}
	n := min(want, capacity)
	if limit := uint64(h.bounds.MaxBufferBytes); limit > 0 && n > limit {
		n = limit
	}
	if n > split {
		rest, gaps := extract.ReadPadded(h.cells, c.addr+split, n-split)
		c.b = append(c.b, rest...)
		c.gaps = append(c.gaps, gaps...)
	}
	return c, nil
}
