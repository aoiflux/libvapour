package handlelist

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/any/processscan"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.handle.list"

const OptionOffset = "windows.handle.list.offset"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the handles in each process's handle table, with object type, granted access and name",
		},
		RunAny,
	)
}

var (
	ErrNotWindows        = errors.New("handlelist: profile os is not windows")
	ErrNoHandleLayout    = errors.New("handlelist: symbol table does not describe the handle table")
	ErrTableIncomplete   = errors.New("handlelist: a handle table was not read whole")
	errTableLevel        = errors.New("handlelist: handle table level not 0, 1 or 2")
	errTableCodeMisplace = errors.New("handlelist: handle table page is not page-aligned")
)

// Object is the _OBJECT_HEADER address the entry holds; the body follows at
// _OBJECT_HEADER.Body.
type Handle struct {
	PID            uint64
	ProcessName    string
	HandleValue    uint64
	Object         uint64
	GrantedAccess  uint64
	TypeIndex      uint64
	TypeName       string
	ObjectName     string
	NameUnreadable bool
}

func RunAny(ctx tools.Context) (any, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %q: %w", Name, ctx.Profile.OS(), ErrNotWindows)
	}
	procs, set, err := processscan.ProcessesAtOffset(ctx, Name, OptionOffset)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !set {
		return Run(ctx)
	}
	w, err := NewWalker(ctx)
	if err != nil {
		return nil, err
	}
	return w.all(procs)
}

func Run(ctx tools.Context) ([]Handle, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %q: %w", Name, ctx.Profile.OS(), ErrNotWindows)
	}
	w, err := NewWalker(ctx)
	if err != nil {
		return nil, err
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	pids := ctx.PIDs()
	kept := make([]processlist.Process, 0, len(procs))
	for _, p := range procs {
		if pids.Keep(p.PID) {
			kept = append(kept, p)
		}
	}
	return w.all(kept)
}

func (w *Walker) all(procs []processlist.Process) ([]Handle, error) {
	var out []Handle
	for _, p := range procs {
		out = append(out, w.Process(p)...)
	}
	w.Finish()
	if w.incomplete > 0 && w.ctx.StrictMode() {
		return out, fmt.Errorf("%s: strict mode: %d handle tables: %w", Name, w.incomplete, ErrTableIncomplete)
	}
	return out, nil
}

// A Walker reads the handle tables of the processes given to it, one at a
// time, so callers that need a few processes skip the full process list.
type Walker struct {
	ctx        tools.Context
	layout     tableLayout
	types      *typeResolver
	names      *nameReader
	untyped    int
	incomplete int
}

func NewWalker(ctx tools.Context) (*Walker, error) {
	layout, err := readTableLayout(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	return &Walker{
		ctx:    ctx,
		layout: layout,
		types:  newTypeResolver(ctx),
		names:  newNameReader(ctx.Symbols, ctx.Bounds().MaxPathSteps),
	}, nil
}

func (w *Walker) Process(p processlist.Process) []Handle {
	entries, ok := w.readTable(p)
	if !ok {
		w.incomplete++
	}
	out := make([]Handle, 0, len(entries))
	for _, e := range entries {
		h := Handle{PID: p.PID, ProcessName: p.Name, HandleValue: e.value, Object: e.header, GrantedAccess: e.access}
		var typed bool
		h.TypeIndex, h.TypeName, typed = w.types.resolve(e.header)
		if typed {
			h.ObjectName, h.NameUnreadable = w.names.read(w.ctx, h.TypeName, e.header)
		} else {
			w.untyped++
			h.NameUnreadable = true
		}
		out = append(out, h)
	}
	return out
}

func (w *Walker) Finish() {
	if w.untyped > 0 {
		w.ctx.AddDiagnostic("%s: %d handles hold an object header whose type does not resolve: listed without a type "+
			"or name", Name, w.untyped)
		w.untyped = 0
	}
	if w.types.err != nil {
		w.ctx.AddDiagnostic("%s: object types not read, every handle is listed without a type: %v", Name, w.types.err)
	}
	w.names.report(w.ctx)
}

// FileObjectName is the name a File handle to the object would show (S30
// 4.2), for tools that select file objects by the name examiners see here.
func FileObjectName(ctx tools.Context, fileObject uint64) (string, bool) {
	n := newNameReader(ctx.Symbols, ctx.Bounds().MaxPathSteps)
	if n.layoutErr[formFile] != nil {
		return "", false
	}
	name, err := n.name(ctx, formFile, fileObject-n.body)
	return name, err == nil
}

// Names keep embedded NULs visible (S30 4.1 step 2).
func readUnicodeStringAt(ctx tools.Context, at uint64) (string, error) {
	s, err := util.ReadUnicodeString(ctx.Memory, at, util.ResolveUnicodeStringLayout(ctx.Symbols), util.MaxUnicodeStringBytes)
	if err != nil {
		return "", err
	}
	return util.CountedText(s.Value), nil
}
