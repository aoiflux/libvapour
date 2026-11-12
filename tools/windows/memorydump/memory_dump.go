package memorydump

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
)

const Name = "windows.memory.dump"

const OptionAddress = "windows.memory.dump.address"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Write each VAD range of each process to its own file, with the pages that did not read listed as gaps",
		},
		RunAny,
	)
}

var (
	ErrNoOutputDir = errors.New("memorydump: no output directory, set the " + tools.OptionOutputDir + " option")
	ErrOverLimit   = errors.New("memorydump: range larger than the dump limit")
	ErrNoRoot      = errors.New("memorydump: process has no page-table root")
	ErrNothingRead = errors.New("memorydump: no page of the range is in the capture")
)

type Artifact struct {
	PID        uint64
	Process    string
	VadAddress uint64
	Start      uint64
	End        uint64
	Protection string
	Type       string
	Path       string
	Tag        string
	FileName   string
	Size       uint64
	Captured   uint64
	Gaps       extract.GapMap
	Skipped    string
}

func (a Artifact) Written() bool { return a.Skipped == "" }

func (a Artifact) Complete() bool { return a.Written() && len(a.Gaps) == 0 }

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type run struct {
	ctx      tools.Context
	dir      string
	limit    uint64
	spaces   map[uint64]memory.MemoryReader
	noSpace  map[uint64]error
	over     int
	overLow  uint64
	overHigh uint64
	empty    int
}

func Run(ctx tools.Context) ([]Artifact, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	filter, err := memoryranges.ReadAddressFilter(ctx, OptionAddress)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	dir, ok := ctx.OutputDir()
	if !ok {
		return nil, ErrNoOutputDir
	}
	mappings, err := memoryranges.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: VAD ranges: %w", Name, err)
	}
	mappings = filter.Apply(ctx, Name, mappings)

	r := &run{ctx: ctx, dir: dir, limit: ctx.DumpLimit(), spaces: map[uint64]memory.MemoryReader{}, noSpace: map[uint64]error{}}
	out := make([]Artifact, 0, len(mappings))
	for _, m := range mappings {
		art, err := r.write(m)
		if err != nil {
			if ctx.StrictMode() {
				return nil, err
			}
			ctx.AddDiagnostic("%v", err)
		}
		out = append(out, art)
	}
	r.report()
	return out, nil
}

func (r *run) write(m memoryranges.Mapping) (Artifact, error) {
	art := Artifact{PID: m.PID, Process: m.Process, VadAddress: m.VadAddress, Start: m.Start, End: m.End,
		Protection: m.Protection, Type: m.Type, Tag: m.Tag}
	if !m.PathUnreadable {
		art.Path = m.Path
	}
	size, ok := extract.RegionSize(m.Start, m.End)
	if !ok {
		art.Skipped = extract.ErrInvalidRange.Error()
		return art, fmt.Errorf("%s: pid %d VAD at 0x%x: not written: %w", Name, m.PID, m.VadAddress, extract.ErrInvalidRange)
	}
	art.Size = size
	art.FileName = extract.Name{Kind: extract.KindRegion, Scope: extract.Process(m.PID), Width: r.ctx.Symbols.PointerSize(),
		Addresses: []uint64{m.Start, m.End}, Ext: extract.ExtBytes}.String()

	// A size refusal is the examiner's limit, not unreadable data, so strict
	// mode does not stop on it.
	if size > r.limit {
		art.Skipped = fmt.Sprintf("%v: %d bytes, limit %d", ErrOverLimit, size, r.limit)
		r.over++
		if r.overLow == 0 || size < r.overLow {
			r.overLow = size
		}
		r.overHigh = max(r.overHigh, size)
		return art, nil
	}
	space, err := r.space(m)
	if err != nil {
		art.Skipped = err.Error()
		if r.ctx.StrictMode() {
			return art, fmt.Errorf("%s: pid %d VAD at 0x%x: not written: %w", Name, m.PID, m.VadAddress, err)
		}
		return art, nil
	}
	file, err := extract.CreateNew(r.dir, art.FileName)
	if err != nil {
		art.Skipped = err.Error()
		return art, fmt.Errorf("%s: pid %d VAD at 0x%x: not written: %w", Name, m.PID, m.VadAddress, err)
	}
	res, err := extract.Region(space, m.Start, m.End, file, extract.Options{MaxSize: r.limit})
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		// A cut file left behind would pass for a whole range.
		extract.RemoveArtifact(r.dir, art.FileName)
		art.Skipped = err.Error()
		return art, fmt.Errorf("%s: pid %d VAD at 0x%x: not written: %w", Name, m.PID, m.VadAddress, err)
	}
	// A file of zero fill alone holds nothing from the capture.
	if res.Captured == 0 {
		extract.RemoveArtifact(r.dir, art.FileName)
		art.Skipped = ErrNothingRead.Error()
		r.empty++
		return art, nil
	}
	art.Captured = res.Captured
	art.Gaps = res.Gaps
	return art, nil
}

// User addresses resolve only under the owner's root: the kernel reader would
// hand back another process's pages.
func (r *run) space(m memoryranges.Mapping) (memory.MemoryReader, error) {
	if s, ok := r.spaces[m.PID]; ok {
		return s, nil
	}
	if err, ok := r.noSpace[m.PID]; ok {
		return nil, err
	}
	if m.DirectoryTableBase == 0 {
		r.noSpace[m.PID] = ErrNoRoot
		return nil, ErrNoRoot
	}
	s, err := r.ctx.ProcessSpace(m.DirectoryTableBase)
	if err != nil {
		r.noSpace[m.PID] = err
		return nil, err
	}
	r.spaces[m.PID] = s
	return s, nil
}

func (r *run) report() {
	if r.over > 0 {
		r.ctx.AddDiagnostic("%s: %d ranges of %d to %d bytes over the %d-byte dump limit, not written",
			Name, r.over, r.overLow, r.overHigh, r.limit)
	}
	if r.empty > 0 {
		r.ctx.AddDiagnostic("%s: %d ranges with no page in the capture, not written", Name, r.empty)
	}
	for _, pid := range slices.Sorted(maps.Keys(r.noSpace)) {
		r.ctx.AddDiagnostic("%s: pid %d: user memory not read, its ranges not written: %v", Name, pid, r.noSpace[pid])
	}
}
