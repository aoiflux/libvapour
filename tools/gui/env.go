package gui

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

var (
	ErrNot64Bit      = errors.New("gui: 64-bit kernels only")
	ErrNoWin32kBase  = errors.New("gui: win32kbase.sys is not in the module list")
	ErrNoDebugRecord = errors.New("gui: win32kbase.sys debug record does not read")
)

const win32kBaseName = "win32kbase.sys"

type Env struct {
	ctx    tools.Context
	tool   string
	Layout Layout
	k      kernel
	spaces map[uint32]memory.MemoryReader
	noted  map[uint32]bool
	procs  map[processKey]Owner
	system uint64
}

type processKey struct {
	session uint32
	address uint64
}

func OpenTool(ctx tools.Context, tool string) (*Env, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", tool, ctx.Profile.OS())
	}
	return Open(ctx, tool)
}

func Open(ctx tools.Context, tool string) (*Env, error) {
	if err := check64(ctx); err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	spaces := sessionSpaces(ctx, tool)
	layout, err := identify(ctx, spaces)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	return open(ctx, tool, layout, spaces)
}

// For a caller that has chosen the layout itself, such as a fixture.
func OpenLayout(ctx tools.Context, tool string, layout Layout) (*Env, error) {
	if err := check64(ctx); err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	return open(ctx, tool, layout, sessionSpaces(ctx, tool))
}

func check64(ctx tools.Context) error {
	if ctx.Symbols == nil || ctx.Memory == nil {
		return tools.ErrMissingSymbolTable
	}
	if ctx.Symbols.PointerSize() != pointerSize {
		return ErrNot64Bit
	}
	return nil
}

func open(ctx tools.Context, tool string, layout Layout, spaces spaceSet) (*Env, error) {
	k, err := resolveKernel(ctx.Symbols, ctx.Memory)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tool, err)
	}
	return &Env{ctx: ctx, tool: tool, Layout: layout, k: k, spaces: spaces.bySession, noted: map[uint32]bool{},
		procs: map[processKey]Owner{}, system: modulelist.KernelHalfStart(ctx)}, nil
}

type spaceSet struct {
	bySession map[uint32]memory.MemoryReader
	// Every session process's page tables in list order: an image page that
	// is not resident in one process can be in another.
	tables []uint64
}

// Session-space addresses mean different memory in each session, so every
// object below a window station is read through a process of its session.
func sessionSpaces(ctx tools.Context, tool string) spaceSet {
	set := spaceSet{bySession: map[uint32]memory.MemoryReader{}}
	procs, err := processlist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		ctx.AddDiagnostic("%s: process list: %v; session objects are read through kernel memory", tool, err)
		return set
	}
	for _, p := range procs {
		if p.SessionID < 0 || p.DirectoryTableBase == 0 {
			continue
		}
		set.tables = append(set.tables, p.DirectoryTableBase)
		id := uint32(p.SessionID)
		if _, ok := set.bySession[id]; ok {
			continue
		}
		if r, err := ctx.ProcessSpace(p.DirectoryTableBase); err == nil {
			set.bySession[id] = r
		}
	}
	return set
}

func (e *Env) space(session uint32) memory.MemoryReader {
	if r, ok := e.spaces[session]; ok {
		return r
	}
	if !e.noted[session] {
		e.noted[session] = true
		e.ctx.AddDiagnostic("%s: session %d: no process of the session has an address space; its objects are read "+
			"through kernel memory", e.tool, session)
	}
	return e.ctx.Memory
}

// Only the debug record names the exact win32kbase.sys build: two builds
// with equal image sizes may differ in layout (S57 O2).
func identify(ctx tools.Context, spaces spaceSet) (Layout, error) {
	mods, err := modulelist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		return Layout{}, fmt.Errorf("%w: %w", ErrNoWin32kBase, err)
	}
	base, ok := moduleNamed(mods, win32kBaseName)
	if !ok {
		return Layout{}, ErrNoWin32kBase
	}
	fp, err := win32kBaseRecord(ctx, spaces, base.Base)
	if err != nil {
		return Layout{}, err
	}
	return LayoutFor(fp)
}

func moduleNamed(mods []modulelist.Module, name string) (modulelist.Module, bool) {
	i := slices.IndexFunc(mods, func(m modulelist.Module) bool { return strings.EqualFold(m.Name, name) })
	if i < 0 {
		return modulelist.Module{}, false
	}
	return mods[i], true
}

func win32kBaseRecord(ctx tools.Context, spaces spaceSet, base uint64) (autoload.Fingerprint, error) {
	ids := make([]uint32, 0, len(spaces.bySession))
	for id := range spaces.bySession {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	readers := make([]memory.MemoryReader, 0, len(ids)+1)
	for _, id := range ids {
		readers = append(readers, spaces.bySession[id])
	}
	kernelReader := ctx.Memory
	if p, ok := newPrototypeReader(ctx.Memory, ctx.PhysicalMemory(), modulelist.KernelHalfStart(ctx)); ok {
		kernelReader = p
	}
	readers = append(readers, kernelReader)
	var last error
	for _, r := range readers {
		fp, err := debugRecord(r, base)
		if err == nil {
			return fp, nil
		}
		last = err
	}
	for _, dtb := range spaces.tables {
		r, err := ctx.ProcessSpace(dtb)
		if err != nil {
			continue
		}
		if fp, err := debugRecord(r, base); err == nil {
			return fp, nil
		}
	}
	return autoload.Fingerprint{}, fmt.Errorf("%w: image at 0x%x: %w", ErrNoDebugRecord, base, last)
}

const headerPage = 0x1000

func debugRecord(r memory.MemoryReader, base uint64) (autoload.Fingerprint, error) {
	head, err := r.ReadAt(base, headerPage)
	if err != nil {
		return autoload.Fingerprint{}, err
	}
	h, err := pe.ParseHeaders(head)
	if err != nil {
		return autoload.Fingerprint{}, err
	}
	dir, err := h.DataDirectory(head, pe.DirectoryEntryDebug)
	if err != nil {
		return autoload.Fingerprint{}, err
	}
	cv, err := pe.ReadCodeView(func(rva uint32, n int) ([]byte, error) {
		return r.ReadAt(base+uint64(rva), uint64(n))
	}, dir)
	if err != nil {
		return autoload.Fingerprint{}, err
	}
	return autoload.Fingerprint{PDBName: cv.PDBName(), GUID: autoload.FormatGUID(cv.GUID[:]), Age: cv.Age}, nil
}
