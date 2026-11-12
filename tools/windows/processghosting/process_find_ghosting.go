package processghosting

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.process.find_ghosting"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name: Name,
			Description: "Find image views and process image files whose file object is delete pending, " +
				"has no name, or whose image section has no file object",
		},
		RunAny,
	)
}

type Finding string

const (
	FindingDeletePending      Finding = "file_delete_pending"
	FindingFileNameEmpty      Finding = "file_name_empty"
	FindingSectionWithoutFile Finding = "section_without_file"
)

type Source string

const (
	SourceImageView        Source = "image_view"
	SourceImageFilePointer Source = "image_file_pointer"
)

type Row struct {
	PID           uint64
	Process       string
	EPROCESS      uint64
	Source        Source
	Main          bool
	Base          uint64
	End           uint64
	ControlArea   uint64
	FileObject    uint64
	Path          string
	DeletePending bool
	DeleteOnClose bool
	NameEmpty     bool
	NoFileObject  bool
	Findings      []Finding
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	e, err := newExaminer(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	pids := ctx.PIDs()
	active := processlist.ResolveActiveProcessFilter(ctx)
	var rows []Row
	kept, examined := 0, 0
	skipped := map[string]int{}
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		kept++
		if why := active.Why(ctx, p); why != nil {
			skipped[inactiveReason(why)]++
			continue
		}
		found, err := e.examine(p)
		if err != nil {
			skipped["VAD tree not read"]++
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: pid %d _EPROCESS at 0x%x: %w", Name, p.PID, p.EPROCESS, err)
			}
			ctx.AddDiagnostic("%s: pid %d _EPROCESS at 0x%x: not examined: VAD tree not read: %v", Name, p.PID, p.EPROCESS, err)
			continue
		}
		examined++
		rows = append(rows, found...)
	}
	ctx.AddDiagnostic("%s: %d processes, %d examined, %d image views, %d with DeleteOnClose set in their control area%s",
		Name, kept, examined, e.views, e.deleteOnClose, reasons(skipped))
	e.report()
	return rows, nil
}

func inactiveReason(err error) string {
	switch {
	case errors.Is(err, processlist.ErrSystemProcess):
		return "system process"
	case errors.Is(err, processlist.ErrExited):
		return "exited"
	case errors.Is(err, processlist.ErrNoThreads):
		return "no threads"
	}
	return "failed the process check"
}

func reasons(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
	}
	return "; not examined: " + strings.Join(parts, ", ")
}

type examiner struct {
	ctx    tools.Context
	l      layout
	ranges memoryranges.Decoder
	files  memoryranges.FileNames

	views         int
	deleteOnClose int
	unread        map[string]int
}

func newExaminer(ctx tools.Context) (*examiner, error) {
	l, err := resolveLayout(ctx)
	if err != nil {
		return nil, err
	}
	ranges, err := memoryranges.NewDecoder(ctx)
	if err != nil {
		return nil, err
	}
	files, err := memoryranges.ResolveFileNames(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLayout, err)
	}
	return &examiner{ctx: ctx, l: l, ranges: ranges, files: files, unread: map[string]int{}}, nil
}

func (e *examiner) report() {
	if len(e.unread) == 0 {
		return
	}
	keys := make([]string, 0, len(e.unread))
	for k := range e.unread {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, e.unread[k]))
	}
	e.ctx.AddDiagnostic("%s: values that did not read, their rules not applied: %s", Name, strings.Join(parts, ", "))
}

func (e *examiner) examine(p processlist.Process) ([]Row, error) {
	ctx := e.ctx
	maps, err := e.ranges.Mappings(ctx, p)
	if err != nil {
		return nil, err
	}
	sectionBase, err := ctx.Symbols.ReadPointer(ctx.Memory, p.EPROCESS+e.l.sectionBase)
	haveBase := err == nil && sectionBase != 0
	if err != nil {
		e.unread["SectionBaseAddress"]++
	}
	var rows []Row
	mainFile := uint64(0)
	for _, m := range maps {
		mf, ok := e.imageView(m)
		if !ok {
			continue
		}
		e.views++
		r := Row{PID: p.PID, Process: util.ReplaceInvalidUTF8(p.Name), EPROCESS: p.EPROCESS, Source: SourceImageView,
			Main: haveBase && m.Start == sectionBase, Base: m.Start, End: m.End, ControlArea: mf.ControlArea,
			FileObject: mf.FileObject, Path: m.Path}
		if r.Main {
			mainFile = mf.FileObject
		}
		if e.l.haveDelete {
			if v, err := e.l.deleteOnClose.Read(ctx.Memory, mf.ControlArea); err == nil && v != 0 {
				r.DeleteOnClose = true
				e.deleteOnClose++
			}
		}
		switch {
		case mf.FileObject != 0:
			e.fileObjectState(&r)
		case mf.NoFile:
			r.NoFileObject = true
			r.Findings = append(r.Findings, FindingSectionWithoutFile)
		default:
			e.unread["image view file object"]++
		}
		if len(r.Findings) > 0 {
			rows = append(rows, r)
		}
	}
	if e.l.haveFilePointer && haveBase {
		if r, ok := e.filePointerRow(p, sectionBase, mainFile); ok {
			rows = append(rows, r)
		}
	}
	return rows, nil
}

func (e *examiner) imageView(m memoryranges.Mapping) (memoryranges.MappedFile, bool) {
	switch {
	case m.Type == memoryranges.KindImage:
	case m.Type == memoryranges.KindMapped && m.PrivateMemoryKnown && !m.PrivateMemory && e.l.haveImage:
	default:
		return memoryranges.MappedFile{}, false
	}
	mf, _ := e.files.Resolve(e.ctx, m.VadAddress)
	if mf.ControlArea == 0 {
		if m.Type == memoryranges.KindImage {
			e.unread["image view control area"]++
		}
		return memoryranges.MappedFile{}, false
	}
	if m.Type == memoryranges.KindImage {
		return mf, true
	}
	v, err := e.l.image.Read(e.ctx.Memory, mf.ControlArea)
	return mf, err == nil && v != 0
}

func (e *examiner) fileObjectState(r *Row) {
	ctx := e.ctx
	b, err := ctx.Memory.ReadAt(r.FileObject+e.l.deletePending, 1)
	if err != nil || len(b) < 1 {
		e.unread["FILE_OBJECT.DeletePending"]++
	} else if b[0] != 0 {
		r.DeletePending = true
		r.Findings = append(r.Findings, FindingDeletePending)
	}
	name, err := util.ReadUnicodeString(ctx.Memory, r.FileObject+e.l.fileName, e.l.unicode, util.MaxUnicodeStringBytes)
	switch {
	case err != nil:
		e.unread["FILE_OBJECT.FileName"]++
	case name.Length == 0:
		r.NameEmpty = true
		r.Findings = append(r.Findings, FindingFileNameEmpty)
	case r.Path == "":
		r.Path = name.Text()
	}
}

func (e *examiner) filePointerRow(p processlist.Process, sectionBase, mainFile uint64) (Row, bool) {
	fo, err := e.ctx.Symbols.ReadPointer(e.ctx.Memory, p.EPROCESS+e.l.filePointer)
	if err != nil {
		e.unread["ImageFilePointer"]++
		return Row{}, false
	}
	if fo == 0 || fo == mainFile {
		return Row{}, false
	}
	r := Row{PID: p.PID, Process: util.ReplaceInvalidUTF8(p.Name), EPROCESS: p.EPROCESS, Source: SourceImageFilePointer,
		Main: true, Base: sectionBase, FileObject: fo}
	e.fileObjectState(&r)
	return r, len(r.Findings) > 0
}
