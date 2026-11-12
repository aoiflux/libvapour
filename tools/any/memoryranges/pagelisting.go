package memoryranges

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

var ErrNoPhysicalLayer = errors.New("memoryranges: page listing needs the physical layer")

type PageRun struct {
	PID        uint64
	Virtual    uint64
	Physical   uint64
	Size       uint64
	FileOffset uint64
}

func RunPagesAny(ctx tools.Context) (any, error) { return RunPages(ctx) }

func RunPages(ctx tools.Context) ([]PageRun, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q (%s lists Linux VMAs)", Name, ctx.Profile.OS(), MemoryListName)
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	lister, err := NewPageLister(ctx)
	if err != nil {
		return nil, err
	}
	pids := ctx.PIDs()
	var out []PageRun
	var missed layers.MappingStats
	for _, proc := range procs {
		if !pids.Keep(proc.PID) {
			continue
		}
		stats, err := lister.Pages(ctx, proc, func(r PageRun) error {
			out = append(out, r)
			return nil
		})
		if err != nil {
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: pid %d _EPROCESS at 0x%x: %w", Name, proc.PID, proc.EPROCESS, err)
			}
			ctx.AddDiagnostic("%s: pid %d _EPROCESS at 0x%x: pages not listed: %v", Name, proc.PID, proc.EPROCESS, err)
			continue
		}
		missed.UnreadableTables += stats.UnreadableTables
		missed.RepeatedTables += stats.RepeatedTables
		missed.UncapturedPages += stats.UncapturedPages
	}
	if missed.UnreadableTables+missed.RepeatedTables+missed.UncapturedPages > 0 {
		ctx.AddDiagnostic("%s: %d page tables unreadable, %d filled with one repeated entry, %d pages outside "+
			"the image; their ranges are left out", Name, missed.UnreadableTables, missed.RepeatedTables,
			missed.UncapturedPages)
	}
	return out, nil
}

type PageLister struct {
	rootAt   uint64
	physical memory.MemoryReader
	mode     layers.PagingMode
}

func NewPageLister(ctx tools.Context) (PageLister, error) {
	pcb, err := required(ctx.Symbols, "_EPROCESS", "Pcb")
	if err != nil {
		return PageLister{}, fmt.Errorf("%s: %w", Name, err)
	}
	dtb, err := required(ctx.Symbols, "_KPROCESS", "DirectoryTableBase")
	if err != nil {
		return PageLister{}, fmt.Errorf("%s: %w", Name, err)
	}
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return PageLister{}, fmt.Errorf("%s: %w", Name, ErrNoPhysicalLayer)
	}
	var mode layers.PagingMode
	if name := ctx.PagingMode(); name != "" {
		var ok bool
		if mode, ok = layers.PagingModeByName(name); !ok {
			return PageLister{}, fmt.Errorf("%s: paging mode %q cannot be walked", Name, name)
		}
	}
	return PageLister{rootAt: pcb + dtb, physical: physical, mode: mode}, nil
}

// The kernel root maps both halves; the user root the process list prefers
// maps little of system space under KVA shadowing (S24 4.9 step 1).
func (l PageLister) Pages(ctx tools.Context, proc processlist.Process, fn func(PageRun) error) (layers.MappingStats, error) {
	root, err := ctx.Symbols.ReadPointer(ctx.Memory, proc.EPROCESS+l.rootAt)
	if err != nil {
		return layers.MappingStats{}, fmt.Errorf("DirectoryTableBase at 0x%x: %w", proc.EPROCESS+l.rootAt, err)
	}
	tr := &layers.IntelTranslator{Physical: l.physical, CR3: root, Mode: l.mode}
	var offset uint64
	return tr.Mapping(func(r layers.MappedRun) error {
		run := PageRun{PID: proc.PID, Virtual: r.Virtual, Physical: r.Physical, Size: r.Size, FileOffset: offset}
		offset += r.Size
		return fn(run)
	})
}
