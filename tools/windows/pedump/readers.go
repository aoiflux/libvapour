package pedump

import (
	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

// The kernel page-table root maps system space as well as user space, so a
// base option may name an image in either half.
func (w writer) processSpace(eprocess uint64) (memory.MemoryReader, error) {
	root, err := processlist.KernelDirectoryTableBase(w.ctx, eprocess)
	if err != nil {
		return nil, err
	}
	return w.ctx.ProcessSpace(root)
}

// Session-space drivers are mapped only in the page tables of a process in
// their session (S55 M5), so one reader per session follows the kernel's.
func KernelReaders(ctx tools.Context) []memory.MemoryReader {
	readers := []memory.MemoryReader{ctx.Memory}
	procs, err := processlist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		ctx.AddDiagnostic("%s: processes not listed, session-space images are read through the kernel space only: %v", Name, err)
		return readers
	}
	sessions := processlist.NewSessionResolver(ctx)
	covered := map[int64]bool{}
	for _, p := range procs {
		id := sessions.SessionID(ctx, p.EPROCESS)
		if id < 0 || covered[id] {
			continue
		}
		root, err := processlist.KernelDirectoryTableBase(ctx, p.EPROCESS)
		if err != nil || root == 0 {
			continue
		}
		r, err := ctx.ProcessSpace(root)
		if err != nil {
			ctx.AddDiagnostic("%s: pid %d: no address space for session %d: %v", Name, p.PID, id, err)
			continue
		}
		covered[id] = true
		readers = append(readers, r)
	}
	return readers
}

// The first reader whose headers parse at the base wins; with none, the
// kernel reader is used so the failure names the kernel space.
func ReaderForModule(readers []memory.MemoryReader, base uint64) memory.MemoryReader {
	for _, r := range readers {
		if _, err := extract.ReadHeaders(r, base); err == nil {
			return r
		}
	}
	if len(readers) == 0 {
		return nil
	}
	return readers[0]
}
