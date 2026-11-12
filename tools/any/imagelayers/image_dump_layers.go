package imagelayers

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

const Name = "any.image.dump_layers"

const (
	OptionList      = "any.image.dump_layers.list"
	OptionLayers    = "any.image.dump_layers.layers"
	OptionBlockSize = "any.image.dump_layers.block_size"
)

const (
	PhysicalLayer = "physical"
	KernelLayer   = "kernel"
)

const (
	TypeFlat      = "flat"
	TypeSegmented = "segmented"
)

var (
	ErrNoOutputDir = errors.New("imagelayers: needs " + tools.OptionOutputDir)
	ErrNoPhysical  = errors.New("imagelayers: session has no physical layer")
	ErrTooLarge    = errors.New("imagelayers: layer exceeds the size limit")
	ErrUnavailable = errors.New("imagelayers: layer unavailable")
	ErrTooManyRuns = errors.New("imagelayers: kernel layer has more mapped runs than MaxListEntries")
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the session's memory layers, or write the physical layer as a flat file and the kernel's address space as an ELF core file",
		},
		RunAny,
	)
}

type Layer struct {
	Name        string
	Type        string
	Size        uint64
	Held        uint64
	Runs        uint64
	Unavailable string
}

type Status struct {
	Layer    string
	Artifact string
	Size     uint64
	Read     uint64
	Zeroed   uint64
	Runs     uint64
}

func RunAny(ctx tools.Context) (any, error) {
	list, err := ctx.BoolOption(OptionList)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if list {
		return List(ctx)
	}
	return Run(ctx)
}

type source struct {
	Layer
	physical memory.MemoryReader
	ranges   []memory.Range
	runs     []layers.MappedRun
	machine  uint16
}

func List(ctx tools.Context) ([]Layer, error) {
	srcs, err := sources(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Layer, len(srcs))
	for i, s := range srcs {
		out[i] = s.Layer
	}
	return out, nil
}

func sources(ctx tools.Context) ([]source, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPhysical)
	}
	p := source{Layer: Layer{Name: PhysicalLayer, Type: TypeFlat}, physical: physical, ranges: memory.MappedRanges(physical)}
	if _, ok := physical.(interface{ Segments() []memory.Segment }); ok {
		p.Type = TypeSegmented
	}
	for _, r := range p.ranges {
		p.Held += r.End - r.Start
		p.Size = max(p.Size, r.End)
	}
	out := []source{p}
	if k, ok := kernelSource(ctx, physical); ok {
		out = append(out, k)
	}
	return out, nil
}

func kernelSource(ctx tools.Context, physical memory.MemoryReader) (source, bool) {
	dtb, ok := ctx.KernelDTB()
	if !ok {
		return source{}, false
	}
	mode, machine, ok := walkMode(ctx.PagingMode())
	if !ok {
		return source{}, false
	}
	s := source{Layer: Layer{Name: KernelLayer, Type: ctx.PagingMode()}, physical: physical, machine: machine}
	cap := ctx.Bounds().MaxListEntries
	tr := &layers.IntelTranslator{Physical: physical, CR3: dtb, Mode: mode}
	_, err := tr.Mapping(func(r layers.MappedRun) error {
		if len(s.runs) >= cap {
			return ErrTooManyRuns
		}
		s.runs = append(s.runs, r)
		return nil
	})
	if err != nil {
		s.Unavailable = err.Error()
		s.runs = nil
		return s, true
	}
	for _, r := range s.runs {
		s.Held += r.Size
	}
	s.Runs = uint64(len(s.runs))
	s.Size = elfSize(s.runs)
	return s, true
}

// S47 F1: EM_X86_64 for 4- and 5-level paging, EM_386 for the 32-bit modes.
const (
	machineX8664 = 62
	machine386   = 3
)

func walkMode(name string) (layers.PagingMode, uint16, bool) {
	base, linux := strings.CutPrefix(name, "linux-")
	m, ok := layers.PagingModeByName(base)
	if !ok {
		return layers.PagingMode{}, 0, false
	}
	machine := uint16(machine386)
	if m.Name() == layers.ModeX64.Name() || m.Name() == layers.ModeLA57.Name() {
		machine = machineX8664
	}
	if linux {
		m = layers.LinuxMode(m, 0, 0)
	}
	return m, machine, true
}

type writer struct {
	ctx   tools.Context
	dir   string
	block uint64

	zeroed, firstZeroed uint64
	pieces              int
}

func Run(ctx tools.Context) ([]Status, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	names, block, err := readOptions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	dir, ok := ctx.OutputDir()
	if !ok {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoOutputDir)
	}
	srcs, err := sources(ctx)
	if err != nil {
		return nil, err
	}
	limit := ctx.MaxDumpSize()
	if limit == 0 {
		limit = uint64(ctx.Bounds().MaxImageBytes)
	}
	chosen := make([]source, 0, len(names))
	for _, name := range names {
		i := slices.IndexFunc(srcs, func(s source) bool { return s.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("%s: option %q: %w: no layer %q", Name, OptionLayers, tools.ErrOptionType, name)
		}
		s := srcs[i]
		if s.Unavailable != "" {
			return nil, fmt.Errorf("%s: %w: %s: %s", Name, ErrUnavailable, s.Name, s.Unavailable)
		}
		if s.Size > limit {
			return nil, fmt.Errorf("%s: %w: %s is %d bytes, limit %d", Name, ErrTooLarge, s.Name, s.Size, limit)
		}
		chosen = append(chosen, s)
	}

	w := &writer{ctx: ctx, dir: dir, block: block}
	out := make([]Status, 0, len(chosen))
	for _, s := range chosen {
		w.zeroed, w.pieces, w.firstZeroed = 0, 0, 0
		st, err := w.layer(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", Name, s.Name, err)
		}
		if w.pieces > 0 {
			if ctx.StrictMode() {
				err := fmt.Errorf("%s: %s: %d bytes in %d pieces did not read, first at 0x%x", Name, s.Name,
					w.zeroed, w.pieces, w.firstZeroed)
				return nil, errors.Join(err, extract.RemoveArtifact(dir, st.Artifact))
			}
			ctx.AddDiagnostic("%s: %s: %d bytes in %d pieces did not read and are zeros, first at 0x%x", Name, s.Name,
				w.zeroed, w.pieces, w.firstZeroed)
		}
		out = append(out, st)
	}
	return out, nil
}

func readOptions(ctx tools.Context) ([]string, uint64, error) {
	bounds := ctx.Bounds()
	names, err := ctx.StringListOption(OptionLayers)
	if err != nil {
		return nil, 0, err
	}
	if len(names) == 0 {
		names = []string{PhysicalLayer}
	}
	block, set, err := ctx.UintOption(OptionBlockSize)
	if err != nil {
		return nil, 0, err
	}
	if !set {
		block = uint64(bounds.MaxBufferBytes)
	}
	if block == 0 || block > uint64(bounds.MaxBufferBytes) {
		return nil, 0, fmt.Errorf("option %q: %w: %d bytes, not 1 to MaxBufferBytes (%d)", OptionBlockSize,
			tools.ErrOptionType, block, bounds.MaxBufferBytes)
	}
	return names, block, nil
}

func (w *writer) layer(s source) (Status, error) {
	name := extract.Name{Kind: extract.KindRegion, Scope: extract.Physical, Ext: extract.ExtBytes}
	if s.Name == KernelLayer {
		name = extract.Name{Kind: extract.KindRegion, Scope: extract.Kernel, Ext: extract.ExtELF}
	}
	file, artifact, err := extract.CreateUnique(w.dir, name.String(), w.ctx.Bounds().NameAttempts)
	if err != nil {
		return Status{}, err
	}
	st := Status{Layer: s.Name, Artifact: artifact, Size: s.Size, Runs: s.Runs}
	if s.Name == KernelLayer {
		st.Read, err = w.kernel(file, s)
	} else {
		st.Read, err = w.physical(file, s)
	}
	if err == nil {
		err = file.Truncate(int64(s.Size))
	}
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		if rerr := extract.RemoveArtifact(w.dir, artifact); rerr != nil {
			return Status{}, errors.Join(err, rerr)
		}
		return Status{}, err
	}
	st.Zeroed = w.zeroed
	return st, nil
}

// Gaps and unread pieces are never written: the final size leaves them as
// zeros (S47 F4).
func (w *writer) physical(f *os.File, s source) (uint64, error) {
	var read uint64
	for _, r := range s.ranges {
		n, err := w.copy(f, s.physical, r.Start, r.End-r.Start, r.Start)
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func (w *writer) copy(f *os.File, r memory.MemoryReader, from, size, at uint64) (uint64, error) {
	var read uint64
	for done := uint64(0); done < size; {
		n := min(w.block, size-done)
		b, err := r.ReadAt(from+done, n)
		if err != nil || uint64(len(b)) != n {
			if w.pieces == 0 {
				w.firstZeroed = from + done
			}
			w.pieces++
			w.zeroed += n
		} else {
			if _, err := f.WriteAt(b, int64(at+done)); err != nil {
				return read, err
			}
			read += n
		}
		done += n
	}
	return read, nil
}
