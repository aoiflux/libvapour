package poolscan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/tools"
)

const Name = "windows.pool.scan"

type Allocation struct {
	Type              string
	Tag               string
	Physical          uint64
	Address           uint64
	OtherCopyPhysical uint64
	Name              string
	Mappings          uint64
	MappingsKnown     bool
	TypeIndexFailed   bool
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name: Name,
			Description: "Scan physical memory for pool allocations of processes, threads, files, mutants, " +
				"drivers, symbolic links, atom tables and loaded-module entries, one row per allocation " +
				"with its kernel address and name",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

type sweep struct {
	ctx      tools.Context
	physical memory.MemoryReader
	frames   *layers.FrameMap
	matches  []scan.TagMatch
	placed   []scan.Placed[Allocation]
	counts   map[string]int
}

func Run(ctx tools.Context) ([]Allocation, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return nil, fmt.Errorf("%s: no physical memory in the session", Name)
	}
	if err := ctx.RequirePoolScanBuild(Name); err != nil {
		return nil, err
	}
	s := sweep{ctx: ctx, physical: physical, counts: map[string]int{}}
	if frames, err := ctx.KernelFrames(); err != nil {
		ctx.AddDiagnostic("%s: %v; rows get no kernel address and TypeIndex is not tested", Name, err)
	} else {
		s.frames = frames
		if frames.UnreadableTables > 0 {
			ctx.AddDiagnostic("%s: %d kernel page tables not readable; frames behind them count as unmapped",
				Name, frames.UnreadableTables)
		}
	}

	var namer *scan.ObjectNamer
	if n, ok := scan.NewObjectNamer(ctx.Symbols); ok {
		namer = &n
	}
	objects := objectKinds(ctx, namer)
	structures := structureKinds(ctx)
	var tags []string
	for _, k := range objects {
		tags = append(tags, k.filter.Tag)
	}
	for _, k := range structures {
		tags = append(tags, k.filter.Tag)
	}
	var err error
	if s.matches, err = scan.SweepTags(physical, tags, ctx.Bounds().Workers); err != nil {
		return nil, fmt.Errorf("%s: tag sweep: %w", Name, err)
	}
	if err := s.objects(objects); err != nil {
		return nil, err
	}
	if err := s.structures(structures); err != nil {
		return nil, err
	}

	scan.InPlaceOrder(s.placed)
	out := make([]Allocation, len(s.placed))
	for i, p := range s.placed {
		out[i] = p.Row
		out[i].Address = p.Place.PoolAddress()
		if len(p.OtherMapped) > 0 {
			out[i].OtherCopyPhysical = p.OtherMapped[0]
		}
		out[i].TypeIndexFailed = p.TypeIndexFailed
		if s.frames != nil {
			out[i].Mappings, out[i].MappingsKnown = s.frames.Mappings(p.Place.Pool), true
		}
	}
	ctx.AddDiagnostic("%s: %d rows: %s", Name, len(out), describeCounts(s.counts))
	return out, nil
}

func (s *sweep) objects(kinds []objectKind) error {
	layout, err := scan.ResolveObjectLayout(s.ctx.Symbols)
	if err != nil {
		return fmt.Errorf("%s: %w", Name, err)
	}
	if s.frames != nil {
		layout = layout.WithResidency(s.frames)
	}
	for _, k := range kinds {
		if _, err := layout.MinimumSize(k.filter); err != nil {
			s.ctx.AddDiagnostic("%s: %s (%s): %v; not scanned", Name, k.filter.Body, k.filter.Tag, err)
			continue
		}
		identity, err := scan.ResolveObjectIdentity(s.ctx.Symbols, s.ctx.Memory, k.filter, k.tag)
		if err != nil {
			s.ctx.AddDiagnostic("%s: %s (%s): %v; judged on the body type only", Name, k.filter.Body, k.filter.Tag, err)
		}
		identity.KeepIndexMismatch = k.keepMismatch && k.tag.Resolved
		rows, stats, err := scan.FindEveryExecutiveObjectPlaced(s.physical, s.matches, k.filter, layout, identity,
			func(pool, body uint64) (Allocation, bool) {
				name, ok := k.read(s.physical, body-layout.BodyOffset, body)
				if !ok {
					return Allocation{}, false
				}
				return Allocation{Type: k.filter.Body, Tag: k.filter.Tag, Physical: pool, Name: name}, true
			})
		if err != nil {
			return fmt.Errorf("%s: %s (%s): %w", Name, k.filter.Body, k.filter.Tag, err)
		}
		s.ctx.AddDiagnostic("%s: %s (%s): %s", Name, k.filter.Body, k.filter.Tag, stats.Describe())
		s.counts[k.filter.Body] += len(rows)
		s.placed = append(s.placed, rows...)
	}
	return nil
}

func (s *sweep) structures(kinds []structureKind) error {
	layout, err := scan.ResolvePoolHeaderLayout(s.ctx.Symbols)
	if err != nil {
		return fmt.Errorf("%s: %w", Name, err)
	}
	if s.frames != nil {
		layout = layout.WithResidency(s.frames)
	}
	for _, k := range kinds {
		if _, err := layout.MinimumSize(k.filter); err != nil {
			s.ctx.AddDiagnostic("%s: %s (%s): %v; not scanned", Name, k.filter.Body, k.filter.Tag, err)
			continue
		}
		rows, stats, err := scan.FindFilteredStructsInPlaced(s.physical, s.matches, layout, []scan.PoolFilter{k.filter},
			func(f scan.PoolFilter, body uint64, h scan.PoolHeader) (Allocation, bool) {
				return Allocation{Type: f.Body, Tag: f.Tag, Physical: h.Offset, Name: k.read(s.physical, body)}, true
			})
		if err != nil {
			return fmt.Errorf("%s: %s (%s): %w", Name, k.filter.Body, k.filter.Tag, err)
		}
		// An allocation below a page never crosses one, so a header whose size
		// runs past its page is not an allocation.
		s.ctx.AddDiagnostic("%s: %s (%s): %d accepted of %d tag hits; %d past their page, %d withheld as copies",
			Name, k.filter.Body, k.filter.Tag, stats.Accepted, stats.TagHits, stats.PageCrossing, stats.DuplicateCopies)
		s.counts[k.filter.Body] += len(rows)
		s.placed = append(s.placed, rows...)
	}
	return nil
}

func describeCounts(counts map[string]int) string {
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%d %s", counts[n], n)
	}
	return strings.Join(parts, ", ")
}
