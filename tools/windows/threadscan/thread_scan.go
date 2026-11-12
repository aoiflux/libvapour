package threadscan

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

const Name = "windows.thread.scan"

var (
	ErrNoThreadCheck    = errors.New("threadscan: symbol table lacks the thread id members")
	ErrNoPhysicalMemory = errors.New("threadscan: no physical memory to scan")
)

type Thread struct {
	Offset          uint64
	VirtualOffset   uint64
	PID             uint64
	TID             uint64
	OtherCopy       uint64
	TypeIndexFailed bool
	Columns
}

type Owned struct {
	Offset  uint64
	Process uint64
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Find threads by their pool allocations, threads that no list holds included",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) {
	rows, err := Run(ctx)
	if err != nil {
		return nil, err
	}
	columns := NewColumnReader(ctx, Name)
	columns.ReportAbsent(ctx)
	for _, t := range rows {
		if err := columns.ReportUnread(ctx, t.PID, t.TID, t.Offset, t.Columns); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

func Run(ctx tools.Context) ([]Thread, error) {
	sweep, err := newSweep(ctx)
	if err != nil {
		return nil, err
	}
	columns := NewColumnReader(ctx, Name)
	cid := resolveIDs(ctx)
	placed, stats, err := find(ctx, sweep, func(body uint64) (Thread, bool) {
		if sweep.check.Check(sweep.physical, body) != nil {
			return Thread{}, false
		}
		pid, _ := cid.pid.Read(sweep.physical, body)
		tid, _ := cid.tid.Read(sweep.physical, body)
		return Thread{PID: pid, TID: tid, Columns: columns.Read(sweep.physical, body)}, true
	})
	if err != nil {
		return nil, err
	}
	out := make([]Thread, len(placed))
	for i, p := range placed {
		t := p.Row
		t.Offset = p.Place.Body
		t.VirtualOffset = p.Place.BodyAddress()
		t.OtherCopy = p.OtherMappedBody()
		t.TypeIndexFailed = p.TypeIndexFailed
		columns.AddPaths(ctx, &t.Columns)
		out[i] = t
	}
	report(ctx, len(out), stats)
	return out, nil
}

func ScanOwners(ctx tools.Context) ([]Owned, error) {
	sweep, err := newSweep(ctx)
	if err != nil {
		return nil, err
	}
	process := resolveColumnMembers(ctx.Symbols).process
	if !process.Present {
		return nil, fmt.Errorf("%s: _KTHREAD.Process: %w", Name, ErrNoThreadCheck)
	}
	placed, stats, err := find(ctx, sweep, func(body uint64) (Owned, bool) {
		if sweep.check.Check(sweep.physical, body) != nil {
			return Owned{}, false
		}
		owner, err := process.Read(sweep.physical, body)
		if err != nil {
			return Owned{}, false
		}
		return Owned{Offset: body, Process: owner}, true
	})
	if err != nil {
		return nil, err
	}
	report(ctx, len(placed), stats)
	return scan.Rows(placed), nil
}

type sweep struct {
	physical memory.MemoryReader
	check    processlist.ThreadCheck
	layout   scan.ObjectLayout
	identity scan.ObjectIdentity
}

func newSweep(ctx tools.Context) (sweep, error) {
	if err := ctx.Validate(); err != nil {
		return sweep{}, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return sweep{}, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return sweep{}, fmt.Errorf("%s: %w", Name, ErrNoPhysicalMemory)
	}
	check := processlist.NewThreadCheck(ctx)
	if !check.Usable() {
		return sweep{}, fmt.Errorf("%s: _ETHREAD.Cid: %w", Name, ErrNoThreadCheck)
	}
	tag := scan.ResolveTypeTag(ctx.Symbols, scan.ThreadObject,
		scan.Member{Struct: "_ETHREAD", Field: "Tcb"},
		scan.Member{Struct: "_KTHREAD", Field: "Header"},
		scan.Member{Struct: "_DISPATCHER_HEADER", Field: "Type"})
	if !tag.Resolved {
		ctx.AddDiagnostic("%s: symbol table has no _ETHREAD.Tcb.Header.Type: bodies are judged by the thread check alone", Name)
	}
	layout, identity, err := ctx.ExecutiveScan(Name, scan.ThreadFilter, tag)
	if err != nil {
		return sweep{}, err
	}
	// A freed thread loses its header's TypeIndex while its body stays (S31 M2).
	identity.KeepIndexMismatch = true
	return sweep{physical: physical, check: check, layout: layout, identity: identity}, nil
}

func find[T any](ctx tools.Context, s sweep, decode func(body uint64) (T, bool)) ([]scan.Placed[T], scan.ObjectScanStats, error) {
	placed, stats, err := scan.FindExecutiveObjectsPlaced(s.physical, scan.ThreadFilter, s.layout, s.identity, decode,
		ctx.Bounds().Workers)
	if err != nil {
		return nil, stats, fmt.Errorf("%s: pool tag %q: %w", Name, scan.ThreadFilter.Tag, err)
	}
	return placed, stats, nil
}

func report(ctx tools.Context, rows int, stats scan.ObjectScanStats) {
	ctx.AddDiagnostic("%s: %d threads from %d tag hits (%s)", Name, rows, stats.TagHits, stats.Describe())
}

type ids struct{ pid, tid Member }

func resolveIDs(ctx tools.Context) ids {
	pointer := uint64(ctx.Symbols.PointerSize())
	cid := ResolveMember(ctx.Symbols, "_ETHREAD", "Cid", pointer)
	pid := ResolveMember(ctx.Symbols, "_CLIENT_ID", "UniqueProcess", pointer)
	tid := ResolveMember(ctx.Symbols, "_CLIENT_ID", "UniqueThread", pointer)
	pid.Field.Offset += cid.Field.Offset
	tid.Field.Offset += cid.Field.Offset
	pid.Field.Width, tid.Field.Width = pointer, pointer
	return ids{pid: pid, tid: tid}
}
