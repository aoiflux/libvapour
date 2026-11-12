package layers

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
)

// A read's length often comes from the image, so the result grows page by
// page past this much instead of being allocated whole before the first page
// is known to read.
const MaxReadPrealloc = uint64(1 << 20)

type AddressTranslator interface {
	Translate(virtualAddress uint64) (physicalAddress uint64, err error)
}

type EntryTranslator interface {
	AddressTranslator
	LeafEntry(virtualAddress uint64) (entry uint64, err error)
}

type DirectTranslator struct{}

func (DirectTranslator) Translate(virtualAddress uint64) (uint64, error) {
	return virtualAddress, nil
}

type VirtualMemoryLayer struct {
	physical   memory.MemoryReader
	translator AddressTranslator
	pagefiles  map[int]memory.MemoryReader
}

func NewVirtualMemoryLayer(physical memory.MemoryReader, translator AddressTranslator) *VirtualMemoryLayer {
	return &VirtualMemoryLayer{physical: physical, translator: translator}
}

func NewProcessLayer(physical memory.MemoryReader, directoryTableBase uint64, cacheEntries int) *VirtualMemoryLayer {
	t := &IntelTranslator{Physical: physical, CR3: directoryTableBase}
	if memory.IsImmutableSnapshot(physical) {
		t.EnableCache(cacheEntries)
	}
	return NewVirtualMemoryLayer(physical, t)
}

func (v *VirtualMemoryLayer) SetPagefiles(pagefiles map[int]memory.MemoryReader) {
	v.pagefiles = pagefiles
}

func (v *VirtualMemoryLayer) Translate(virtualAddress uint64) (uint64, error) {
	return v.translator.Translate(virtualAddress)
}

// The physical layer's size: a virtual space has no end of its own to report.
func (v *VirtualMemoryLayer) Size() uint64 { return v.physical.Size() }

func (v *VirtualMemoryLayer) ReadAt(offset, size uint64) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil
	}
	if size > uint64(^uint(0)>>1) {
		return nil, memory.ErrSizeOverflow
	}
	if offset+(size-1) < offset {
		return nil, memory.ErrOutOfBounds
	}
	out := make([]byte, 0, min(size, MaxReadPrealloc))
	for at, end := offset, offset+(size-1); ; {
		n := min(end-at+1, pageBytes-at%pageBytes)
		part, err := v.readPage(at, n)
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
		if end-at < n {
			return out, nil
		}
		at += n
	}
}

func (v *VirtualMemoryLayer) readPage(va, n uint64) ([]byte, error) {
	pa, err := v.translator.Translate(va)
	if err == nil {
		return v.physical.ReadAt(pa, n)
	}
	var miss UnmappedPageError
	if v.pagefiles == nil || !errors.As(err, &miss) || miss.Kind != PageInPagefile {
		return nil, err
	}
	file, ok := v.pagefiles[miss.PageFileNumber]
	if !ok {
		return nil, err
	}
	return file.ReadAt(miss.PageFileOffset+va%pageBytes, n)
}

func (v *VirtualMemoryLayer) LeafEntry(virtualAddress uint64) (uint64, error) {
	t, ok := v.translator.(EntryTranslator)
	if !ok {
		return 0, fmt.Errorf("layers: translator %T reads no page-table entries", v.translator)
	}
	return t.LeafEntry(virtualAddress &^ (pageBytes - 1))
}

// Dirty (bit 6) is a hardware bit, so only a present entry has one; in a
// not-present Windows entry bit 6 is part of Protection.
func (v *VirtualMemoryLayer) IsDirty(virtualAddress uint64) (bool, error) {
	e, err := v.LeafEntry(virtualAddress)
	if err != nil {
		return false, err
	}
	return e&bitPresent != 0 && e&bitDirty != 0, nil
}
