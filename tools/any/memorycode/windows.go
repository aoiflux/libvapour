package memorycode

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/disasm"
	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

var ErrUnsupportedOS = errors.New("memorycode: profile os is not windows")

type Rule string

const (
	RuleAllocation Rule = "allocation-executable"
	RulePage       Rule = "page-executable"
)

type Backing string

const (
	BackingNone    Backing = "none"
	BackingSection Backing = "section"
	BackingFile    Backing = "file"
	BackingUnknown Backing = "unknown"
)

type Finding struct {
	PID        uint64
	Process    string
	VadAddress uint64
	Start      uint64
	End        uint64
	Protection string
	Kind       string
	Backing    Backing
	Path       string
	Rule       Rule

	Pages           uint64
	ExecutablePages uint64
	ResidentPages   uint64
	WrittenPages    uint64
	ContentPages    uint64
	FirstContent    uint64

	Header        Header
	HeaderMachine uint16

	Transfer             Transfer
	TransferTarget       uint64
	TransferTargetUnread bool
	TransferImage        string

	Preview  []byte
	Artifact string
}

type windowsOptions struct {
	preview   uint64
	dump      bool
	outputDir string
	dumpLimit uint64
}

func readWindowsOptions(ctx tools.Context) (windowsOptions, error) {
	bounds := ctx.Bounds()
	o := windowsOptions{preview: uint64(bounds.RowPreviewBytes), dumpLimit: ctx.DumpLimit()}
	n, set, err := ctx.UintOption(OptionHexdumpSize)
	if err != nil {
		return o, err
	}
	if set {
		if n > uint64(bounds.MaxArtifactBytes) {
			return o, fmt.Errorf("option %q: %w: %d bytes exceeds MaxArtifactBytes (%d)",
				OptionHexdumpSize, tools.ErrOptionType, n, bounds.MaxArtifactBytes)
		}
		o.preview = n
	}
	if o.dump, err = ctx.BoolOption(OptionDumpRegions); err != nil {
		return o, err
	}
	if o.dump {
		dir, ok := ctx.OutputDir()
		if !ok {
			return o, fmt.Errorf("option %q needs %q: %w", OptionDumpRegions, tools.OptionOutputDir, tools.ErrOptionType)
		}
		o.outputDir = dir
	}
	return o, nil
}

type windowsRun struct {
	ctx     tools.Context
	opts    windowsOptions
	decoder memoryranges.Decoder
	files   memoryranges.FileNames
	filesOK bool
	prot    pageProtections
	budget  uint64

	withoutContent   int
	dumpFailed       int
	firstDumpFailure string
}

func Run(ctx tools.Context) ([]Finding, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %w: %q", Name, ErrUnsupportedOS, ctx.Profile.OS())
	}
	opts, err := readWindowsOptions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	decoder, err := memoryranges.NewDecoder(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	r := &windowsRun{ctx: ctx, opts: opts, decoder: decoder, budget: regionBudget(ctx)}
	r.files, err = memoryranges.ResolveFileNames(ctx)
	r.filesOK = err == nil
	if r.prot, err = readPageProtections(ctx); err != nil {
		r.prot = pageProtections{}
		ctx.AddDiagnostic("%s: MmProtectToValue: not read, protections of not-present pages unknown: %v", Name, err)
	}

	pids := ctx.PIDs()
	var out []Finding
	for _, proc := range procs {
		if !pids.Keep(proc.PID) {
			continue
		}
		rows, err := r.process(proc)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	if r.withoutContent > 0 {
		ctx.AddDiagnostic("%s: %d executable regions hold no readable nonzero byte in an executable page and are not listed", Name, r.withoutContent)
	}
	if r.dumpFailed > 0 {
		ctx.AddDiagnostic("%s: %d regions not written, first: %s", Name, r.dumpFailed, r.firstDumpFailure)
	}
	return out, nil
}

func regionBudget(ctx tools.Context) uint64 {
	n := uint64(ctx.Bounds().MaxRegionScanBytes) / pageSize
	return max(n, 1)
}

// In strict mode the first problem fails the run; otherwise it becomes one
// diagnostic and the object is passed over.
func (r *windowsRun) problem(object string, addr uint64, what string, err error) error {
	if r.ctx.StrictMode() {
		return fmt.Errorf("%s: %s at 0x%x: %s: %w", Name, object, addr, what, err)
	}
	r.ctx.AddDiagnostic("%s: %s at 0x%x: %s: %v", Name, object, addr, what, err)
	return nil
}

func (r *windowsRun) process(proc processlist.Process) ([]Finding, error) {
	object := fmt.Sprintf("pid %d _EPROCESS", proc.PID)
	maps, err := r.decoder.Mappings(r.ctx, proc)
	if err != nil {
		return nil, r.problem(object, proc.EPROCESS, "VAD tree not read", err)
	}
	space, err := r.ctx.ProcessSpace(proc.DirectoryTableBase)
	if err != nil {
		return nil, r.problem(object, proc.EPROCESS, "address space not built", err)
	}
	le, ok := space.(leafEntries)
	if !ok {
		return nil, r.problem(object, proc.EPROCESS, "page-table entries not read", ErrNoPageEntries)
	}
	mode := disasm.Mode64
	if proc.Wow64 && !proc.Wow64Unreadable {
		mode = disasm.Mode32
	}
	name := util.ReplaceInvalidUTF8(proc.Name)
	var out []Finding
	for _, m := range maps {
		if m.Type != memoryranges.KindPrivate && m.Type != memoryranges.KindMapped || m.End < m.Start {
			continue
		}
		f, ok, err := r.region(proc, name, m, space, le, mode, maps)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, f)
		}
	}
	return out, nil
}

func (r *windowsRun) region(proc processlist.Process, name string, m memoryranges.Mapping, space memory.MemoryReader,
	le leafEntries, mode disasm.Mode, maps []memoryranges.Mapping) (Finding, bool, error) {
	value, known := memoryranges.Win32Protection(m.Protection)
	allocExec := known && executable(value)
	pages := walkRegion(le, r.prot, m.Start, m.End, allocExec, r.budget)
	if pages.cut {
		object := fmt.Sprintf("pid %d VAD", proc.PID)
		what := fmt.Sprintf("page walk stopped after %d entries", r.budget)
		if err := r.problem(object, m.VadAddress, what, ErrRegionScanCut); err != nil {
			return Finding{}, false, err
		}
	}
	rule := RuleAllocation
	if !allocExec {
		if pages.ownExecutable == 0 {
			return Finding{}, false, nil
		}
		rule = RulePage
	}

	content, first := uint64(0), uint64(0)
	for _, at := range pages.executableAt {
		b, err := space.ReadAt(at, pageSize)
		if err != nil || !hasNonzero(b) {
			continue
		}
		if content == 0 {
			first = at
		}
		content++
	}
	if content == 0 {
		r.withoutContent++
		return Finding{}, false, nil
	}

	f := Finding{
		PID: proc.PID, Process: name, VadAddress: m.VadAddress, Start: m.Start, End: m.End,
		Protection: m.Protection, Kind: m.Type, Rule: rule,
		Pages: pages.pages, ExecutablePages: pages.executable, ResidentPages: pages.resident,
		WrittenPages: pages.written, ContentPages: content, FirstContent: first,
	}
	f.Backing, f.Path = r.backing(m)
	r.startFacts(&f, space, mode, maps)
	f.Preview, _ = extract.ReadPadded(space, first, r.opts.preview)
	if r.opts.dump {
		f.Artifact = r.dump(proc.PID, space, m.Start, m.End)
	}
	return f, true, nil
}

func hasNonzero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return true
		}
	}
	return false
}

func (r *windowsRun) backing(m memoryranges.Mapping) (Backing, string) {
	if m.Type == memoryranges.KindPrivate {
		return BackingNone, ""
	}
	if !r.filesOK {
		return BackingUnknown, ""
	}
	mf, ok := r.files.Resolve(r.ctx, m.VadAddress)
	switch {
	case ok:
		return BackingFile, mf.Path
	case mf.NoFile && mf.ControlArea != 0:
		return BackingSection, ""
	}
	return BackingUnknown, ""
}

// Enough bytes for the longest form of S35 4.8 (12) and the DOS header's
// signature offset; a page holds every header the captures show.
func (r *windowsRun) startFacts(f *Finding, space memory.MemoryReader, mode disasm.Mode, maps []memoryranges.Mapping) {
	n := min(pageSize, f.End-f.Start+1)
	b, err := space.ReadAt(f.Start, n)
	if err != nil || uint64(len(b)) != n {
		f.Header = HeaderUnread
		return
	}
	f.Header, f.HeaderMachine = headerKind(b)
	t := firstTransfer(b, f.Start, mode, space)
	f.Transfer, f.TransferTarget, f.TransferTargetUnread = t.kind, t.target, t.unread
	if t.kind == TransferNone || t.unread {
		return
	}
	for _, m := range maps {
		if m.Type == memoryranges.KindImage && m.Start <= t.target && t.target <= m.End {
			f.TransferImage = m.Path
			return
		}
	}
}

func (r *windowsRun) dump(pid uint64, space memory.MemoryReader, start, end uint64) string {
	name := extract.Name{Kind: extract.KindRegion, Scope: extract.Process(pid),
		Addresses: []uint64{start, end}, Ext: extract.ExtBytes}.String()
	fail := func(why string) string {
		r.dumpFailed++
		if r.firstDumpFailure == "" {
			r.firstDumpFailure = name + ": " + why
		}
		return ""
	}
	size, ok := extract.RegionSize(start, end)
	if !ok || size >= r.opts.dumpLimit {
		return fail(fmt.Sprintf("%d bytes, limit %d", size, r.opts.dumpLimit))
	}
	file, err := extract.CreateNew(r.opts.outputDir, name)
	if err != nil {
		return fail(err.Error())
	}
	_, werr := extract.Region(space, start, end, file, extract.Options{Unlimited: true})
	cerr := file.Close()
	if werr != nil || cerr != nil {
		why := errors.Join(werr, cerr)
		if rerr := extract.RemoveArtifact(r.opts.outputDir, name); rerr != nil {
			return fail(fmt.Sprintf("%v; %v", why, rerr))
		}
		return fail(why.Error())
	}
	return name
}
