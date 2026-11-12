package librarylist

import (
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/any/processscan"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

const Name = "windows.library.list"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Loaded DLLs of each process from the three PEB loader lists, native and WoW64",
		},
		RunAny,
	)
}

type DLL struct {
	PID                uint64
	ProcName           string
	EPROCESS           uint64
	DirectoryTableBase uint64

	Entry              uint64
	Base               uint64
	BaseUnreadable     bool
	Size               uint64
	SizeUnreadable     bool
	Name               string
	NameUnreadable     bool
	FullPath           string
	FullPathUnreadable bool

	LoadCount           uint32
	LoadCountUnreadable bool
	LoadTime            time.Time
	LoadTimeUnreadable  bool

	Wow64                 bool
	InLoadOrder           bool
	InMemoryOrder         bool
	InInitializationOrder bool
}

func RunAny(ctx tools.Context) (any, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	f, err := readFilter(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	procs, set, err := processscan.ProcessesAtOffset(ctx, Name, OptionOffset)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !set {
		if procs, err = listedProcesses(ctx); err != nil {
			return nil, err
		}
	}
	rows, err := list(ctx, procs)
	if err != nil {
		return nil, err
	}
	return f.apply(ctx, rows), nil
}

func Run(ctx tools.Context) ([]DLL, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	procs, err := listedProcesses(ctx)
	if err != nil {
		return nil, err
	}
	return list(ctx, procs)
}

func listedProcesses(ctx tools.Context) ([]processlist.Process, error) {
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	pids := ctx.PIDs()
	kept := procs[:0:0]
	for _, p := range procs {
		if pids.Keep(p.PID) {
			kept = append(kept, p)
		}
	}
	return kept, nil
}

type lister struct {
	ctx      tools.Context
	native   loaderLayout
	wow      loaderLayout
	wowErr   error
	peb      uint64
	wowField uint64
	hasWow   bool
	wowPeb   uint64
	strict   bool
	rows     []DLL
}

func newLister(ctx tools.Context) (*lister, error) {
	native, err := nativeLayout(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	peb, err := member(ctx.Symbols, "_EPROCESS", "Peb")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	l := &lister{ctx: ctx, native: native, peb: peb, strict: ctx.StrictMode()}
	if f, err := ctx.Symbols.Field("_EPROCESS", "WoW64Process"); err == nil {
		if p, err := ctx.Symbols.Field("_EWOW64PROCESS", "Peb"); err == nil {
			l.hasWow, l.wowField, l.wowPeb = true, f.Offset, p.Offset
		}
	}
	if l.hasWow {
		l.wow, l.wowErr = wow64Layout(ctx.Symbols)
	}
	return l, nil
}

func list(ctx tools.Context, procs []processlist.Process) ([]DLL, error) {
	l, err := newLister(ctx)
	if err != nil {
		return nil, err
	}
	if !l.native.loadCount {
		ctx.AddDiagnostic("%s: symbol table lacks _LDR_DATA_TABLE_ENTRY.DdagNode or _LDR_DDAG_NODE.LoadCount: no load counts", Name)
	}
	if !l.native.walks[inMemoryOrder] || !l.native.walks[inInitializationOrder] {
		ctx.AddDiagnostic("%s: symbol table lacks a loader list other than InLoadOrderModuleList: only the lists it describes are walked", Name)
	}
	if !l.native.loadTime {
		ctx.AddDiagnostic("%s: symbol table lacks _LDR_DATA_TABLE_ENTRY.LoadTime: no load times", Name)
	}
	wowReported := false
	for _, p := range procs {
		if err := l.process(p, &wowReported); err != nil {
			return nil, err
		}
	}
	l.reportNames()
	return l.rows, nil
}

func (l *lister) fail(err error) error {
	if l.strict {
		return err
	}
	l.ctx.AddDiagnostic("%v", err)
	return nil
}

func (l *lister) process(p processlist.Process, wowReported *bool) error {
	where := fmt.Sprintf("%s: process %d at 0x%x", Name, p.PID, p.EPROCESS)
	peb, err := readPointer(l.ctx.Memory, p.EPROCESS+l.peb, uint64(l.ctx.Symbols.PointerSize()))
	if err != nil {
		return l.fail(fmt.Errorf("%s: PEB pointer does not read: %w", where, err))
	}
	var wowPeb uint64
	if l.hasWow {
		if ew, err := readPointer(l.ctx.Memory, p.EPROCESS+l.wowField, uint64(l.ctx.Symbols.PointerSize())); err != nil {
			if err := l.fail(fmt.Errorf("%s: WoW64Process does not read: %w", where, err)); err != nil {
				return err
			}
		} else if ew != 0 {
			if wowPeb, err = readPointer(l.ctx.Memory, ew+l.wowPeb, uint64(l.ctx.Symbols.PointerSize())); err != nil {
				if err := l.fail(fmt.Errorf("%s: _EWOW64PROCESS at 0x%x: Peb does not read: %w", where, ew, err)); err != nil {
					return err
				}
			}
		}
	}
	if peb == 0 && wowPeb == 0 {
		return nil
	}
	space, err := l.ctx.ProcessSpace(p.DirectoryTableBase)
	if err != nil {
		l.ctx.AddDiagnostic("%s: no process space, no libraries listed: %v", where, err)
		return nil
	}
	if peb != 0 {
		if err := l.loader(p, where, space, peb, l.native, false); err != nil {
			return err
		}
	}
	if wowPeb == 0 {
		return nil
	}
	if l.wowErr != nil {
		if !*wowReported {
			*wowReported = true
			l.ctx.AddDiagnostic("%s: %v: no 32-bit libraries listed", Name, l.wowErr)
		}
		return nil
	}
	return l.loader(p, where, space, wowPeb, l.wow, true)
}

func (l *lister) loader(p processlist.Process, where string, space memory.MemoryReader, peb uint64, layout loaderLayout, wow bool) error {
	ldr, err := readPointer(space, peb+layout.ldr, layout.pointer)
	if err != nil {
		return l.fail(fmt.Errorf("%s: PEB at 0x%x: loader data does not read: %w", where, peb, err))
	}
	if ldr == 0 {
		return l.fail(fmt.Errorf("%s: PEB at 0x%x: loader data pointer is 0", where, peb))
	}
	walker := winkernel.ListWalker{Tool: Name, Memory: space, Layout: layout.list,
		Limit: l.ctx.Bounds().MaxListEntries, Strict: l.strict, Report: l.ctx.AddDiagnostic}
	w, err := walkLoader(walker, space, ldr, layout)
	if err != nil {
		return err
	}
	for _, e := range w.headErrs {
		l.ctx.AddDiagnostic("%v", e)
	}
	if w.baseUnread > 0 {
		if err := l.fail(fmt.Errorf("%s: %d loader records flagged: %w", where, w.baseUnread, ErrBaseUnread)); err != nil {
			return err
		}
	}
	for _, r := range w.records {
		d := r.fields
		d.PID, d.ProcName, d.EPROCESS, d.DirectoryTableBase = p.PID, p.Name, p.EPROCESS, p.DirectoryTableBase
		if wow {
			d.Wow64, d.LoadCount, d.LoadCountUnreadable, d.LoadTime, d.LoadTimeUnreadable = true, 0, true, time.Time{}, true
		}
		l.rows = append(l.rows, d)
	}
	return nil
}

func (l *lister) reportNames() {
	names, paths := 0, 0
	for _, d := range l.rows {
		if d.NameUnreadable {
			names++
		}
		if d.FullPathUnreadable {
			paths++
		}
	}
	if names+paths > 0 {
		l.ctx.AddDiagnostic("%s: BaseDllName does not read for %d and FullDllName for %d of %d libraries; the rows are flagged",
			Name, names, paths, len(l.rows))
	}
}
