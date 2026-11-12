package threadlist

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/threadscan"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

const Name = "windows.thread.list"

var ErrNoListMember = errors.New("threadlist: symbol table lacks a member the thread list needs")

type Thread struct {
	PID                    uint64
	ProcessName            string
	TID                    uint64
	ETHREAD                uint64
	ListEPROCESS           uint64
	Teb                    uint64
	TebUnreadable          bool
	TrapFrame              uint64
	TrapFrameUnreadable    bool
	SuspendCount           int32
	SuspendCountUnreadable bool
	Priority               int32
	PriorityUnreadable     bool
	State                  uint64
	StateName              string
	StateUnreadable        bool
	WaitReason             uint64
	WaitReasonName         string
	WaitReasonUnreadable   bool
	threadscan.Columns
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List each process's threads with state, wait reason, times, start addresses and their files",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) {
	rows, err := Run(ctx)
	if err != nil {
		return nil, err
	}
	columns := threadscan.NewColumnReader(ctx, Name)
	columns.ReportAbsent(ctx)
	for _, t := range rows {
		if err := columns.ReportUnread(ctx, t.PID, t.TID, t.ETHREAD, t.Columns); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

type listMembers struct {
	head   uint64
	entry  uint64
	tid    threadscan.Member
	layout winkernel.ListLayout
}

func resolveListMembers(t symbols.SymbolTable) (listMembers, error) {
	head, err := t.Field("_EPROCESS", "ThreadListHead")
	if err != nil {
		return listMembers{}, fmt.Errorf("%s: _EPROCESS.ThreadListHead: %w: %w", Name, ErrNoListMember, err)
	}
	entry, err := t.Field("_ETHREAD", "ThreadListEntry")
	if err != nil {
		return listMembers{}, fmt.Errorf("%s: _ETHREAD.ThreadListEntry: %w: %w", Name, ErrNoListMember, err)
	}
	pointer := uint64(t.PointerSize())
	cid := threadscan.ResolveMember(t, "_ETHREAD", "Cid", pointer)
	tid := threadscan.ResolveMember(t, "_CLIENT_ID", "UniqueThread", pointer)
	if !cid.Present || !tid.Present {
		return listMembers{}, fmt.Errorf("%s: _ETHREAD.Cid.UniqueThread: %w", Name, ErrNoListMember)
	}
	tid.Field.Offset += cid.Field.Offset
	tid.Field.Width = pointer
	layout, err := winkernel.NativeListLayout(t)
	if err != nil {
		return listMembers{}, fmt.Errorf("%s: %w: %w", Name, ErrNoListMember, err)
	}
	return listMembers{head: head.Offset, entry: entry.Offset, tid: tid, layout: layout}, nil
}

type kernelMembers struct {
	teb, trapFrame, suspend, priority, state, wait threadscan.Member
	states, waits                                  map[uint64]string
}

// Widths are those of S50 T3, for tables that declare none.
func resolveKernelMembers(ctx tools.Context) kernelMembers {
	t := ctx.Symbols
	pointer := uint64(t.PointerSize())
	k := kernelMembers{
		teb:       threadscan.ResolveMember(t, "_KTHREAD", "Teb", pointer),
		trapFrame: threadscan.ResolveMember(t, "_KTHREAD", "TrapFrame", pointer),
		suspend:   threadscan.ResolveMember(t, "_KTHREAD", "SuspendCount", 1),
		priority:  threadscan.ResolveMember(t, "_KTHREAD", "Priority", 1),
		state:     threadscan.ResolveMember(t, "_KTHREAD", "State", 1),
		wait:      threadscan.ResolveMember(t, "_KTHREAD", "WaitReason", 1),
	}
	k.states = enumNames(ctx, "_KTHREAD_STATE", "StateName")
	k.waits = enumNames(ctx, "_KWAIT_REASON", "WaitReasonName")
	return k
}

func enumNames(ctx tools.Context, enum, column string) map[uint64]string {
	names := map[uint64]string{}
	if lookup, ok := ctx.Symbols.(symbols.DeterministicLookup); ok {
		if typ, err := lookup.LookupType(enum); err == nil && typ.Kind == symbols.TypeKindEnum {
			for _, v := range typ.Enum {
				if v.Value >= 0 {
					names[uint64(v.Value)] = v.Name
				}
			}
			return names
		}
	}
	ctx.AddDiagnostic("%s: symbol table has no %s: %s names empty", Name, enum, column)
	return names
}

func Run(ctx tools.Context) ([]Thread, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	m, err := resolveListMembers(ctx.Symbols)
	if err != nil {
		return nil, err
	}
	procs, err := processlist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	k := resolveKernelMembers(ctx)
	columns := threadscan.NewColumnReader(ctx, Name)
	columns.KnowProcesses(procs)
	check := processlist.NewThreadCheck(ctx)
	walker := winkernel.ListWalker{
		Tool:   Name,
		Memory: ctx.Memory,
		Layout: m.layout,
		Limit:  ctx.Bounds().MaxListEntries,
		Strict: ctx.StrictMode(),
		Report: ctx.AddDiagnostic,
	}
	pids := ctx.PIDs()

	var out []Thread
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		walk, err := walker.WalkRecovering(p.EPROCESS+m.head, "_EPROCESS.ThreadListHead")
		if err != nil {
			if ctx.StrictMode() {
				return nil, err
			}
			ctx.AddDiagnostic("%v", err)
			continue
		}
		for _, entry := range walk.Entries {
			ethread, ok := winkernel.Container(entry, m.entry)
			if !ok {
				continue
			}
			tid, err := m.tid.Read(ctx.Memory, ethread)
			if err != nil {
				err = fmt.Errorf("%s: _ETHREAD at 0x%x: thread id does not read: %w", Name, ethread, err)
				if ctx.StrictMode() {
					return nil, err
				}
				ctx.AddDiagnostic("%v", err)
				continue
			}
			if err := check.Check(ctx.Memory, ethread); err != nil {
				ctx.AddDiagnostic("%s: _ETHREAD at 0x%x: thread check: %v", Name, ethread, err)
			}
			t := Thread{PID: p.PID, ProcessName: p.Name, TID: tid, ETHREAD: ethread, ListEPROCESS: p.EPROCESS,
				Columns: columns.Read(ctx.Memory, ethread)}
			k.read(ctx.Memory, &t)
			columns.AddPaths(ctx, &t.Columns)
			out = append(out, t)
		}
	}
	return out, nil
}

func (k kernelMembers) read(r memory.MemoryReader, t *Thread) {
	var err error
	t.Teb, err = k.teb.Read(r, t.ETHREAD)
	t.TebUnreadable = err != nil
	t.TrapFrame, err = k.trapFrame.Read(r, t.ETHREAD)
	t.TrapFrameUnreadable = err != nil
	t.SuspendCount, t.SuspendCountUnreadable = readSigned(k.suspend, r, t.ETHREAD)
	t.Priority, t.PriorityUnreadable = readSigned(k.priority, r, t.ETHREAD)
	t.State, err = k.state.Read(r, t.ETHREAD)
	t.StateUnreadable = err != nil
	if !t.StateUnreadable {
		t.StateName = k.states[t.State]
	}
	t.WaitReason, err = k.wait.Read(r, t.ETHREAD)
	t.WaitReasonUnreadable = err != nil
	if !t.WaitReasonUnreadable {
		t.WaitReasonName = k.waits[t.WaitReason]
	}
}

func readSigned(m threadscan.Member, r memory.MemoryReader, ethread uint64) (int32, bool) {
	v, err := m.Read(r, ethread)
	if err != nil {
		return 0, true
	}
	return int32(m.Signed(v)), false
}
