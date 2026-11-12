package libvapour

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
)

// CR3 bits 11:0 are flags or a PCID (S04 A5), so roots that differ only there
// name one address space.
const rootFlagBits = 0xfff

func rootFrame(cr3 uint64) uint64 { return cr3 &^ rootFlagBits }

// One reader per page-table root: a capture never changes, so a root's
// translations and entry cache stay valid for the whole session (S76 4.6).
type spaceCache struct {
	physical memory.MemoryReader
	build    func(root uint64) memory.MemoryReader

	mu     sync.Mutex
	byRoot map[uint64]memory.MemoryReader
}

func newSpaceCache(physical memory.MemoryReader, build func(root uint64) memory.MemoryReader) *spaceCache {
	return &spaceCache{physical: physical, build: build, byRoot: map[uint64]memory.MemoryReader{}}
}

func (c *spaceCache) get(cr3 uint64) (memory.MemoryReader, error) {
	root := rootFrame(cr3)
	if root == 0 {
		return nil, fmt.Errorf("libvapour: page-table root 0x%x has no frame", cr3)
	}
	if root >= c.physical.Size() {
		return nil, fmt.Errorf("libvapour: page-table root 0x%x is past the capture's end 0x%x", root, c.physical.Size())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.byRoot[root]; ok {
		return r, nil
	}
	r := c.build(root)
	c.byRoot[root] = r
	return r, nil
}

// The paging mode is processor state (S04 A1), not per root, so every process
// is walked in the mode found for the kernel.
func windowsSpaceBuilder(physical memory.MemoryReader, mode layers.PagingMode, cacheEntries int,
	pagefiles map[int]memory.MemoryReader) func(root uint64) memory.MemoryReader {
	cached := memory.IsImmutableSnapshot(physical)
	return func(root uint64) memory.MemoryReader {
		t := &layers.IntelTranslator{Physical: physical, CR3: root, Mode: mode}
		if cached {
			t.EnableCache(cacheEntries)
		}
		v := layers.NewVirtualMemoryLayer(physical, t)
		if pagefiles != nil {
			v.SetPagefiles(pagefiles)
		}
		return v
	}
}

// The slice index is the pagefile number a not-present entry names (S53
// 4.3); an empty path leaves that number unsupplied.
func openPagefiles(paths []string) (map[int]memory.MemoryReader, []io.Closer, error) {
	files := map[int]memory.MemoryReader{}
	var closers []io.Closer
	for number, path := range paths {
		if path == "" {
			continue
		}
		f, err := memory.NewFileMemoryReader(path)
		if err != nil {
			return nil, nil, errors.Join(fmt.Errorf("libvapour: open pagefile %d %s: %w", number, path, err), closeAll(closers))
		}
		files[number] = f
		closers = append(closers, f)
	}
	if len(files) == 0 {
		return nil, nil, nil
	}
	return files, closers, nil
}

func closeAll(closers []io.Closer) error {
	var errs []error
	for i := len(closers) - 1; i >= 0; i-- {
		errs = append(errs, closers[i].Close())
	}
	return errors.Join(errs...)
}
