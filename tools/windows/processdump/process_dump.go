package processdump

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/minidump"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.process.dump"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Write each process as a user-mode minidump: system values, modules, threads with their stacks and registers, handles, and the contents of its VAD ranges",
		},
		RunAny,
	)
}

var (
	ErrNoOutputDir = errors.New("processdump: no output directory, set the " + tools.OptionOutputDir + " option")
	ErrNoRoot      = errors.New("processdump: process has no page-table root")
)

type Artifact struct {
	PID                    uint64
	Process                string
	FileName               string
	Size                   uint64
	Modules                int
	Threads                int
	ThreadsWithContext     int
	Handles                int
	Regions                int
	RegionsWithoutContents int
	BytesWithoutContents   uint64
	MemoryBytes            uint64
	Gaps                   extract.GapMap
	Skipped                string
}

func (a Artifact) Written() bool { return a.Skipped == "" }

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Artifact, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	dir, ok := ctx.OutputDir()
	if !ok {
		return nil, ErrNoOutputDir
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	pids := ctx.PIDs()
	var kept []processlist.Process
	for _, p := range procs {
		if pids.Keep(p.PID) {
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		return nil, nil
	}

	g := newGatherer(ctx, kept)
	system := g.system()
	modules := g.modules()
	threads := g.threads()
	handles := g.handles()
	regions := g.regions()
	g.report()

	out := make([]Artifact, 0, len(kept))
	for _, p := range kept {
		art, err := writeDump(ctx, dir, g, p, minidump.Input{
			System:  system,
			Modules: modules[p.PID],
			Threads: threads[p.PID],
			Handles: handles[p.PID],
			Regions: regions[p.PID],
		})
		if err != nil {
			if ctx.StrictMode() {
				return nil, err
			}
			ctx.AddDiagnostic("%v", err)
		}
		out = append(out, art)
	}
	return out, nil
}

func writeDump(ctx tools.Context, dir string, g *gatherer, p processlist.Process, in minidump.Input) (Artifact, error) {
	art := Artifact{
		PID:     p.PID,
		Process: util.ReplaceInvalidUTF8(p.Name),
		FileName: extract.Name{Kind: extract.KindProcess, Scope: extract.Process(p.PID), Width: ctx.Symbols.PointerSize(),
			Addresses: []uint64{p.EPROCESS}, Labels: []string{p.Name}, Ext: extract.ExtMinidump}.String(),
		Modules: len(in.Modules),
		Threads: len(in.Threads),
		Handles: len(in.Handles),
		Regions: len(in.Regions),
	}
	for _, t := range in.Threads {
		if len(t.Context) > 0 {
			art.ThreadsWithContext++
		}
	}
	if space := g.space(p.PID); space != nil {
		in.ReadMemory = func(base, size uint64) ([]byte, extract.GapMap) {
			return extract.ReadPadded(space, base, size)
		}
	} else {
		for i := range in.Regions {
			in.Regions[i].Dumpable = false
		}
	}
	for _, r := range in.Regions {
		if !r.Dumpable {
			art.RegionsWithoutContents++
			art.BytesWithoutContents += r.Size
		}
	}

	file, err := extract.CreateNew(dir, art.FileName)
	if err != nil {
		art.Skipped = err.Error()
		return art, fmt.Errorf("%s: pid %d _EPROCESS at 0x%x: minidump not written: %w", Name, p.PID, p.EPROCESS, err)
	}
	res, err := minidump.Write(file, in)
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		extract.RemoveArtifact(dir, art.FileName)
		art.Skipped = err.Error()
		return art, fmt.Errorf("%s: pid %d _EPROCESS at 0x%x: minidump not written: %w", Name, p.PID, p.EPROCESS, err)
	}
	art.Size = res.Size
	art.MemoryBytes = res.MemoryBytes
	art.Gaps = res.MemoryGaps
	return art, nil
}

type gatherer struct {
	ctx    tools.Context
	procs  []processlist.Process
	kept   map[uint64]bool
	roots  map[uint64]uint64
	spaces map[uint64]memory.MemoryReader
	failed map[uint64]error
	ranges map[uint64][]memoryranges.Mapping
	notes  []string
}

func newGatherer(ctx tools.Context, procs []processlist.Process) *gatherer {
	g := &gatherer{ctx: ctx, procs: procs, kept: map[uint64]bool{}, roots: map[uint64]uint64{},
		spaces: map[uint64]memory.MemoryReader{}, failed: map[uint64]error{}}
	for _, p := range procs {
		g.kept[p.PID] = true
		g.roots[p.PID] = p.DirectoryTableBase
	}
	for _, p := range procs {
		g.space(p.PID)
	}
	g.ranges = map[uint64][]memoryranges.Mapping{}
	if rows, err := memoryranges.Run(ctx); err == nil {
		for _, m := range rows {
			if g.kept[m.PID] {
				g.ranges[m.PID] = append(g.ranges[m.PID], m)
			}
		}
	} else {
		g.note("VAD ranges not read, no memory or stacks written: %v", err)
	}
	return g
}

// The kernel's own reader would resolve a user address under whichever
// process the capture's root belongs to, so a process without a usable root
// of its own has no readable user memory here.
func (g *gatherer) space(pid uint64) memory.MemoryReader {
	if r, ok := g.spaces[pid]; ok {
		return r
	}
	var r memory.MemoryReader
	root, known := g.roots[pid]
	switch {
	case !known:
	case root == 0:
		g.failed[pid] = ErrNoRoot
	default:
		var err error
		if r, err = g.ctx.ProcessSpace(root); err != nil {
			g.failed[pid] = err
			r = nil
		}
	}
	g.spaces[pid] = r
	return r
}

func (g *gatherer) note(format string, args ...any) {
	g.notes = append(g.notes, fmt.Sprintf(format, args...))
}

func (g *gatherer) report() {
	for _, p := range g.procs {
		if err, ok := g.failed[p.PID]; ok {
			g.ctx.AddDiagnostic("%s: pid %d _EPROCESS at 0x%x: user memory not read, regions listed without contents: %v",
				Name, p.PID, p.EPROCESS, err)
		}
	}
	for _, n := range g.notes {
		g.ctx.AddDiagnostic("%s: %s", Name, n)
	}
}
