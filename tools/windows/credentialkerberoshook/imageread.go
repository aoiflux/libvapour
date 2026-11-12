package credentialkerberoshook

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/subsection"
	"github.com/aoiflux/libvapour/tools"
)

// Reads the unwritten pages of an image view. A page the process never wrote
// is shared, and its leaf PTE may hold no frame; the view's prototype PTE then
// gives it (S23 4.2). A page the process wrote is private, so a leaf PTE that
// names a paging file is not followed to the prototype, which holds the file's
// bytes and not the process's.
type imageReader struct {
	space    memory.MemoryReader
	physical memory.MemoryReader
	resolver *subsection.Resolver
	vad      uint64
	start    uint64
	end      uint64
}

func (r imageReader) Size() uint64 { return r.space.Size() }

func (r imageReader) ReadAt(at, n uint64) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	if at < r.start || at > r.end || n-1 > r.end-at {
		return nil, fmt.Errorf("credentialkerberoshook: read 0x%x+%d outside the view", at, n)
	}
	out := make([]byte, 0, n)
	for n > 0 {
		chunk := min(n, tools.PageSize-at%tools.PageSize)
		b, err := r.page(at, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
		at += chunk
		n -= chunk
	}
	return out, nil
}

func (r imageReader) page(at, n uint64) ([]byte, error) {
	b, err := r.space.ReadAt(at, n)
	if err == nil && uint64(len(b)) == n {
		return b, nil
	}
	if err == nil {
		err = fmt.Errorf("credentialkerberoshook: short read at 0x%x", at)
	}
	var unmapped layers.UnmappedPageError
	if r.resolver == nil || r.physical == nil || !errors.As(err, &unmapped) ||
		(unmapped.Kind != layers.PagePrototype && unmapped.Kind != layers.PageInvalid) {
		return nil, err
	}
	pa, perr := r.resolver.ResolveVA(r.vad, at)
	if perr != nil {
		return nil, fmt.Errorf("%w; prototype: %v", err, perr)
	}
	b, perr = r.physical.ReadAt(pa, n)
	if perr != nil || uint64(len(b)) != n {
		return nil, fmt.Errorf("%w; prototype frame 0x%x: %v", err, pa, perr)
	}
	return b, nil
}
