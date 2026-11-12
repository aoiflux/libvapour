package gui

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
)

type leafEntries interface {
	LeafEntry(virtualAddress uint64) (uint64, error)
}

// A kernel image page the memory manager shares through the image's section
// has a prototype leaf entry, which the processor never follows; the entry it
// names gives the frame (S57 4.1 step 2, M10).
type prototypeReader struct {
	kernel   memory.MemoryReader
	leaves   leafEntries
	physical memory.MemoryReader
	system   uint64
}

func newPrototypeReader(kernel, physical memory.MemoryReader, system uint64) (prototypeReader, bool) {
	leaves, ok := kernel.(leafEntries)
	if !ok || physical == nil {
		return prototypeReader{}, false
	}
	return prototypeReader{kernel: kernel, leaves: leaves, physical: physical, system: system}, true
}

func (p prototypeReader) Size() uint64 { return p.kernel.Size() }

func (p prototypeReader) ReadAt(at, n uint64) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	if n-1 > ^uint64(0)-at {
		return nil, memory.ErrOutOfBounds
	}
	out := make([]byte, 0, min(n, headerPage))
	for n > 0 {
		chunk := min(n, headerPage-at%headerPage)
		b, err := p.page(at, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
		at += chunk
		n -= chunk
	}
	return out, nil
}

func (p prototypeReader) page(at, n uint64) ([]byte, error) {
	b, err := p.kernel.ReadAt(at, n)
	if err == nil {
		return b, nil
	}
	var miss layers.UnmappedPageError
	if !errors.As(err, &miss) || miss.Kind != layers.PagePrototype {
		return nil, err
	}
	entry, lerr := p.leaves.LeafEntry(at)
	if lerr != nil {
		return nil, err
	}
	proto, ok := layers.PrototypeEntryAddress(entry)
	if !ok || proto < p.system || proto%pointerSize != 0 {
		return nil, fmt.Errorf("%w: prototype entry at 0x%x: %w", err, proto, ErrNotSystemSpace)
	}
	target, rerr := readU64(p.kernel, proto)
	if rerr != nil {
		return nil, fmt.Errorf("%w: prototype entry at 0x%x: %w", err, proto, rerr)
	}
	pa, rerr := layers.ResolveProtoPTE(target, at)
	if rerr != nil {
		return nil, fmt.Errorf("%w: prototype entry at 0x%x: %w", err, proto, rerr)
	}
	b, rerr = p.physical.ReadAt(pa, n)
	if rerr != nil {
		return nil, fmt.Errorf("%w: prototype frame 0x%x: %w", err, pa&^(headerPage-1), rerr)
	}
	return b, nil
}
