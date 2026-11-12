package joblist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/winkernel"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.job.list"

const OptionPhysical = "windows.job.list.physical"

// The job's own row describes the job, not an image, so its Process column
// carries this mark instead of a path.
const OriginalProcessLabel = "<job holder>"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List each job object a process belongs to, with the job's accounting and the processes on its list",
		},
		RunAny,
	)
}

var (
	ErrNotWindows = errors.New("joblist: profile is not windows")
	ErrNoJobType  = errors.New("joblist: symbol table lacks a job member")
	ErrNoFrames   = errors.New("joblist: the kernel address space cannot translate to physical addresses")
	ErrJobUnread  = errors.New("joblist: job object does not read")
	ErrOtherJob   = errors.New("joblist: process on the job's list belongs to another job")
)

type Row struct {
	Depth                  int
	EPROCESS               uint64
	Physical               uint64
	PhysicalUnknown        bool
	Job                    uint64
	Name                   string
	PID                    uint64
	PPID                   uint64
	PPIDUnreadable         bool
	SessionID              int64
	JobSessionID           uint32
	JobSessionIDUnreadable bool
	Wow64                  bool
	Total                  uint32
	TotalUnreadable        bool
	Active                 uint32
	ActiveUnreadable       bool
	Terminated             uint32
	TerminatedUnreadable   bool
	IsJobLink              bool
	Process                string
	ProcessUnreadable      bool
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

type translator interface {
	Translate(virtualAddress uint64) (uint64, error)
}

type layout struct {
	job       uint64
	jobLinks  uint64
	listHead  uint64
	counters  [4]counter
	auditInfo uint64
	auditName uint64
	hasAudit  bool
	unicode   util.UnicodeStringLayout
	walker    winkernel.ListWalker
	check     processlist.ProcessCheck
	columns   *processlist.ColumnReader
	frames    translator
	pids      tools.PIDSet
}

type counter struct {
	offset uint64
	ok     bool
}

const (
	total = iota
	active
	terminated
	session
)

var counterMembers = [4]string{"TotalProcesses", "ActiveProcesses", "TotalTerminatedProcesses", "SessionId"}

func resolve(ctx tools.Context) (layout, error) {
	t := ctx.Symbols
	l := layout{unicode: util.ResolveUnicodeStringLayout(t)}
	for _, m := range []struct {
		typ, member string
		at          *uint64
	}{
		{"_EPROCESS", "Job", &l.job},
		{"_EPROCESS", "JobLinks", &l.jobLinks},
		{"_EJOB", "ProcessListHead", &l.listHead},
	} {
		f, err := t.Field(m.typ, m.member)
		if err != nil {
			return l, fmt.Errorf("%s.%s: %w", m.typ, m.member, ErrNoJobType)
		}
		*m.at = f.Offset
	}
	for i, name := range counterMembers {
		if f, err := t.Field("_EJOB", name); err == nil {
			l.counters[i] = counter{offset: f.Offset, ok: true}
		}
	}
	audit, errA := t.Field("_EPROCESS", "SeAuditProcessCreationInfo")
	file, errF := t.Field("_SE_AUDIT_PROCESS_CREATION_INFO", "ImageFileName")
	name, errN := t.Field("_OBJECT_NAME_INFORMATION", "Name")
	if errA == nil && errF == nil && errN == nil {
		l.auditInfo, l.auditName, l.hasAudit = audit.Offset+file.Offset, name.Offset, true
	}
	list, err := winkernel.NativeListLayout(t)
	if err != nil {
		return l, fmt.Errorf("%w: %w", ErrNoJobType, err)
	}
	l.walker = winkernel.ListWalker{Tool: Name, Memory: ctx.Memory, Layout: list, Limit: ctx.Bounds().MaxListEntries,
		Strict: ctx.StrictMode(), Report: ctx.AddDiagnostic}
	l.check = processlist.NewProcessCheck(ctx)
	if !l.check.Usable() {
		return l, fmt.Errorf("_EPROCESS identity: %w", ErrNoJobType)
	}
	l.columns = processlist.NewColumnReader(ctx)
	l.pids = ctx.PIDs()
	return l, nil
}

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	physical, err := ctx.BoolOption(OptionPhysical)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %q: %w", Name, ctx.Profile.OS(), ErrNotWindows)
	}
	l, err := resolve(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if physical {
		tr, ok := ctx.Memory.(translator)
		if !ok {
			return nil, fmt.Errorf("%s: %s: %w", Name, OptionPhysical, ErrNoFrames)
		}
		l.frames = tr
	}
	for i, name := range counterMembers {
		if !l.counters[i].ok {
			ctx.AddDiagnostic("%s: symbol table lacks _EJOB.%s: marked unreadable on every job", Name, name)
		}
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	listed := map[uint64]bool{}
	var out []Row
	for _, p := range procs {
		if !l.pids.Keep(p.PID) {
			continue
		}
		job, err := ctx.Symbols.ReadPointer(ctx.Memory, p.EPROCESS+l.job)
		if err != nil {
			ctx.AddDiagnostic("%s: process at 0x%x: Job: %v", Name, p.EPROCESS, err)
			continue
		}
		if job == 0 || listed[job] {
			continue
		}
		listed[job] = true
		rows, err := l.group(ctx, p, job)
		out = append(out, rows...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// One group per job: the first listed process that names the job heads it
// with the job's accounting, and every process on the job's ProcessListHead
// follows. A later process of the same job is one of those members.
func (l layout) group(ctx tools.Context, holder processlist.Process, job uint64) ([]Row, error) {
	head := Row{Depth: 0, EPROCESS: holder.EPROCESS, Job: job, Name: holder.Name, PID: holder.PID,
		PPID: holder.PPID, PPIDUnreadable: holder.PPIDUnreadable, SessionID: holder.SessionID, Wow64: holder.Wow64,
		Process: OriginalProcessLabel}
	raw, readErr := l.readJob(ctx.Memory, job)
	values := [4]uint32{}
	unread := [4]bool{}
	for i, c := range l.counters {
		if !c.ok || readErr != nil {
			unread[i] = true
			continue
		}
		values[i] = binary.LittleEndian.Uint32(raw[c.offset:])
	}
	head.Total, head.TotalUnreadable = values[total], unread[total]
	head.Active, head.ActiveUnreadable = values[active], unread[active]
	head.Terminated, head.TerminatedUnreadable = values[terminated], unread[terminated]
	head.JobSessionID, head.JobSessionIDUnreadable = values[session], unread[session]
	rows := []Row{l.place(head)}
	if readErr != nil {
		ctx.AddDiagnostic("%s: job at 0x%x: %v", Name, job, readErr)
		return rows, nil
	}
	walk, err := l.walker.Walk(job+l.listHead, "job process list")
	if err != nil {
		return rows, fmt.Errorf("%s: job at 0x%x: %w", Name, job, err)
	}
	for _, entry := range walk.Entries {
		member, ok := winkernel.Container(entry, l.jobLinks)
		if !ok {
			continue
		}
		row, err := l.member(ctx, job, member)
		if err != nil {
			ctx.AddDiagnostic("%s: job at 0x%x: process at 0x%x: %v", Name, job, member, err)
			continue
		}
		if l.pids.Keep(row.PID) {
			rows = append(rows, l.place(row))
		}
	}
	return rows, nil
}

func (l layout) readJob(kernel memory.MemoryReader, job uint64) ([]byte, error) {
	end := uint64(0)
	for _, c := range l.counters {
		if c.ok {
			end = max(end, c.offset+4)
		}
	}
	if end == 0 {
		if _, err := kernel.ReadAt(job+l.listHead, 1); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrJobUnread, err)
		}
		return nil, nil
	}
	raw, err := kernel.ReadAt(job, end)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJobUnread, err)
	}
	if uint64(len(raw)) != end {
		return nil, ErrJobUnread
	}
	return raw, nil
}

// A process is on the list of its innermost job only, and its Job names
// that job (S69 M9); a list entry that does not is not a member.
func (l layout) member(ctx tools.Context, job, eprocess uint64) (Row, error) {
	id, err := l.check.Check(ctx.Memory, eprocess)
	if err != nil {
		return Row{}, err
	}
	own, err := ctx.Symbols.ReadPointer(ctx.Memory, eprocess+l.job)
	if err != nil {
		return Row{}, err
	}
	if own != job {
		return Row{}, fmt.Errorf("%w: 0x%x", ErrOtherJob, own)
	}
	c := l.columns.Read(ctx, ctx.Memory, eprocess)
	r := Row{Depth: 1, EPROCESS: eprocess, Job: job, Name: id.Name, PID: id.PID, PPID: c.PPID,
		PPIDUnreadable: c.PPIDUnreadable, SessionID: c.SessionID, Wow64: c.Wow64, IsJobLink: true}
	r.Process, r.ProcessUnreadable = l.imagePath(ctx, eprocess)
	return r, nil
}

func (l layout) imagePath(ctx tools.Context, eprocess uint64) (string, bool) {
	if !l.hasAudit {
		return "", true
	}
	info, err := ctx.Symbols.ReadPointer(ctx.Memory, eprocess+l.auditInfo)
	if err != nil || info == 0 {
		return "", true
	}
	s, err := util.ReadUnicodeString(ctx.Memory, info+l.auditName, l.unicode, util.MaxUnicodeStringBytes)
	if err != nil {
		return "", true
	}
	return s.Text(), false
}

func (l layout) place(r Row) Row {
	if l.frames == nil {
		return r
	}
	pa, err := l.frames.Translate(r.EPROCESS)
	if err != nil {
		r.PhysicalUnknown = true
		return r
	}
	r.Physical = pa
	return r
}
