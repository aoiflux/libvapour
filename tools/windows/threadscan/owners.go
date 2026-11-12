package threadscan

import (
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

type lookup int

const (
	notTried lookup = iota
	found
	failed
)

type ownerRanges struct {
	state lookup
	vads  []memoryranges.VAD
}

// Each lookup runs once per tool run and only on first need: a thread list
// with no user-space start address never walks a VAD tree (S50 4.4 step 3).
type owners struct {
	tool       string
	known      map[uint64]processlist.Process
	byAddress  map[uint64]*ownerRanges
	check      processlist.ProcessCheck
	checkReady bool

	filesState lookup
	files      memoryranges.FileNames

	modulesState lookup
	modules      []modulelist.Module
}

func newOwners(tool string) *owners {
	return &owners{tool: tool, known: map[uint64]processlist.Process{}, byAddress: map[uint64]*ownerRanges{}}
}

func (o *owners) path(ctx tools.Context, owner uint64, ownerUnread bool, address uint64) string {
	if address == 0 || ctx.Symbols == nil {
		return ""
	}
	if inSystemSpace(address, ctx.Symbols.PointerSize()) {
		return o.module(ctx, address)
	}
	if ownerUnread || owner == 0 {
		return ""
	}
	return o.file(ctx, owner, address)
}

// S50 D5: user space ends at 0x7FFF'FFFFFFFF on 64-bit Windows and at 2 GB on
// 32-bit Windows.
func inSystemSpace(address uint64, pointer uint8) bool {
	if pointer == 4 {
		return address >= 0x80000000
	}
	return address>>63 == 1
}

func (o *owners) module(ctx tools.Context, address uint64) string {
	if o.modulesState == notTried {
		mods, err := modulelist.Run(ctx)
		if err != nil {
			o.modulesState = failed
			ctx.AddDiagnostic("%s: kernel modules not listed, start addresses in system space have no module: %v", o.tool, err)
			return ""
		}
		o.modules, o.modulesState = mods, found
	}
	for _, m := range modulelist.Containing(o.modules, address) {
		if m.Path != "" && !m.PathUnreadable {
			return m.Path
		}
		if m.Name != "" && !m.NameUnreadable {
			return m.Name
		}
	}
	return ""
}

func (o *owners) file(ctx tools.Context, owner, address uint64) string {
	r := o.ranges(ctx, owner)
	if r.state != found || !o.haveFiles(ctx) {
		return ""
	}
	for _, v := range r.vads {
		if v.Start <= address && address <= v.End {
			name, _ := o.files.Name(ctx, v.Base)
			return name
		}
	}
	return ""
}

func (o *owners) ranges(ctx tools.Context, owner uint64) *ownerRanges {
	if r, ok := o.byAddress[owner]; ok {
		return r
	}
	r := &ownerRanges{state: failed}
	o.byAddress[owner] = r
	proc, ok := o.known[owner]
	if !ok {
		// A scanned thread's owner may be freed; one that fails the S17 check
		// is not walked (S50 4.4 step 3).
		if !o.checkReady {
			o.check, o.checkReady = processlist.NewProcessCheck(ctx), true
		}
		id, err := o.check.Check(ctx.Memory, owner)
		if err != nil {
			ctx.AddDiagnostic("%s: _EPROCESS at 0x%x: owning file of start addresses not found: %v", o.tool, owner, err)
			return r
		}
		proc = processlist.Process{PID: id.PID, Name: id.Name, EPROCESS: owner}
	}
	vads, err := memoryranges.ProcessVADs(ctx, proc)
	if err != nil {
		ctx.AddDiagnostic("%s: _EPROCESS at 0x%x: owning file of start addresses not found: %v", o.tool, owner, err)
		return r
	}
	r.vads, r.state = vads, found
	return r
}

func (o *owners) haveFiles(ctx tools.Context) bool {
	if o.filesState == notTried {
		f, err := memoryranges.ResolveFileNames(ctx)
		if err != nil {
			o.filesState = failed
			ctx.AddDiagnostic("%s: VAD file names not resolved, start addresses in user space have no file: %v", o.tool, err)
			return false
		}
		o.files, o.filesState = f, found
	}
	return o.filesState == found
}
