package imagestrings

import (
	"fmt"
	"slices"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const pageSize = uint64(0x1000)

type space struct {
	kernel  bool
	pid     uint64
	process string
	root    uint64
}

// mapPages lists every page each address space maps and, for the pages that
// hold a string, adds the string's virtual address. The kernel space gives the
// system half; each process gives only its user half, which is the part of its
// page tables that differs from the kernel's.
func mapPages(ctx tools.Context, phys memory.MemoryReader, pages map[uint64][]int, rows []Located) error {
	if len(pages) == 0 {
		return nil
	}
	mode, ok := layers.PagingModeByName(ctx.PagingMode())
	if !ok {
		return fmt.Errorf("paging mode %q is not known", ctx.PagingMode())
	}
	kernelRoot, ok := ctx.KernelDTB()
	if !ok {
		return ErrNoKernelRoot
	}
	wanted := make([]uint64, 0, len(pages))
	for p := range pages {
		wanted = append(wanted, p)
	}
	slices.Sort(wanted)
	userEnd := modulelist.KernelHalfStart(ctx)

	spaces := []space{{kernel: true, root: kernelRoot}}
	procs, err := processlist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		ctx.AddDiagnostic("%s: process list: %v: only the kernel space is mapped", Name, err)
	}
	pids := ctx.PIDs()
	skipped := 0
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		root, err := processlist.KernelDirectoryTableBase(ctx, p.EPROCESS)
		if err != nil || root == 0 {
			skipped++
			ctx.AddDiagnostic("%s: _EPROCESS at 0x%x: pid %d page-table root does not read: left out: %v", Name, p.EPROCESS, p.PID, err)
			continue
		}
		spaces = append(spaces, space{pid: p.PID, process: p.Name, root: root})
	}

	var lost layers.MappingStats
	for _, s := range spaces {
		tr := &layers.IntelTranslator{Physical: phys, CR3: s.root, Mode: mode}
		stats, err := tr.Mapping(func(run layers.MappedRun) error {
			if !s.kernel && run.Virtual >= userEnd {
				return nil
			}
			first := run.Physical / pageSize
			last := (run.Physical + run.Size - 1) / pageSize
			i, _ := slices.BinarySearch(wanted, first)
			for ; i < len(wanted) && wanted[i] <= last; i++ {
				va := run.Virtual + wanted[i]*pageSize - run.Physical
				for _, r := range pages[wanted[i]] {
					rows[r].Mappings = append(rows[r].Mappings, Mapping{Kernel: s.kernel, PID: s.pid, Process: s.process,
						Address: va + rows[r].PhysicalAddress%pageSize})
				}
			}
			return nil
		})
		lost.UnreadableTables += stats.UnreadableTables
		if err != nil {
			if s.kernel {
				return fmt.Errorf("kernel space at root 0x%x: %w", s.root, err)
			}
			skipped++
			ctx.AddDiagnostic("%s: pid %d page tables at root 0x%x do not list: left out: %v", Name, s.pid, s.root, err)
		}
	}
	if lost.UnreadableTables > 0 {
		ctx.AddDiagnostic("%s: %d page tables did not read: the pages they map are not listed, so a string may lack some of its addresses",
			Name, lost.UnreadableTables)
	}
	if skipped > 0 {
		ctx.AddDiagnostic("%s: %d processes left out of the mapping", Name, skipped)
	}
	return nil
}
