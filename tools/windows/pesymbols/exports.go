package pesymbols

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools"
)

// The kernel page tables are not tried when a process space fails: they
// belong to some other process and would credit its exports to this one.
func Exports(ctx tools.Context, m Module) ([]pe.Export, error) {
	reader, err := instanceReader(ctx, m)
	if err != nil {
		return nil, err
	}
	headers, err := extract.ReadHeaders(reader, m.Base)
	if err != nil {
		return nil, err
	}
	span := m.Size
	if span == 0 {
		span = uint64(headers.Optional.SizeOfImage)
	}
	read := ReadRVAAt(reader, m.Base, span)
	dir, err := headers.ReadDataDirectory(read, pe.DirectoryEntryExport)
	if err != nil {
		return nil, fmt.Errorf("export data directory: %w", err)
	}
	bounds := ctx.Bounds()
	return pe.ParseExports(withDirectoryBlock(read, dir, bounds.MaxBufferBytes), dir, bounds)
}

func instanceReader(ctx tools.Context, m Module) (memory.MemoryReader, error) {
	if m.DirectoryTableBase == 0 {
		return ctx.Memory, nil
	}
	return ctx.ProcessSpace(m.DirectoryTableBase)
}

// The export directory's arrays and names normally lie inside the span the
// data directory gives, so one read serves the many small ones the parser
// makes. A span that does not read whole is left to page reads.
func withDirectoryBlock(read pe.ReadRVA, dir pe.DataDirectory, limit int64) pe.ReadRVA {
	if dir.Size == 0 || int64(dir.Size) > limit {
		return read
	}
	block, err := read(dir.VirtualAddress, int(dir.Size))
	if err != nil {
		return read
	}
	start, end := uint64(dir.VirtualAddress), uint64(dir.VirtualAddress)+uint64(dir.Size)
	return func(rva uint32, n int) ([]byte, error) {
		if n < 0 || uint64(rva) < start || uint64(rva)+uint64(n) > end {
			return read(rva, n)
		}
		at := uint64(rva) - start
		return block[at : at+uint64(n)], nil
	}
}

// size 0 leaves reads unbounded, for a caller that knows no image size.
func ReadRVAAt(reader memory.MemoryReader, base, size uint64) pe.ReadRVA {
	return func(rva uint32, n int) ([]byte, error) {
		if n < 0 {
			return nil, fmt.Errorf("pesymbols: read of %d bytes at rva 0x%x", n, rva)
		}
		if size != 0 && uint64(rva)+uint64(n) > size {
			return nil, fmt.Errorf("%w: rva 0x%x+%d, image size 0x%x", pe.ErrOutsideImage, rva, n, size)
		}
		b, err := reader.ReadAt(base+uint64(rva), uint64(n))
		if err != nil {
			return nil, err
		}
		if len(b) != n {
			return nil, fmt.Errorf("%w: rva 0x%x: %d of %d bytes", pe.ErrUnreadable, rva, len(b), n)
		}
		return b, nil
	}
}

// The union over instances serves a name paged out in one process and
// resident in another. Forwarders are left out: their code is in another
// module.
func CopyExports(ctx tools.Context, instances []Module, keep func(name string) bool) (syms []Symbol, unread int) {
	seen := map[uint64]map[string]bool{}
	for _, m := range instances {
		exports, err := Exports(ctx, m)
		if err != nil {
			unread++
			continue
		}
		names := seen[m.Base]
		if names == nil {
			names = map[string]bool{}
			seen[m.Base] = names
		}
		for _, e := range exports {
			if e.Name == "" || e.Forwarder != "" || e.ForwarderUnreadable || names[e.Name] || !keep(e.Name) {
				continue
			}
			names[e.Name] = true
			syms = append(syms, Symbol{Module: m.Name, Name: e.Name, Address: e.Address(m.Base), FoundInPID: m.PID})
		}
	}
	slices.SortStableFunc(syms, func(a, b Symbol) int {
		return cmp.Or(cmp.Compare(a.Address, b.Address), strings.Compare(a.Name, b.Name))
	})
	return syms, unread
}
