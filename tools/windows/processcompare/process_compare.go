package processcompare

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/any/processscan"
	"github.com/aoiflux/libvapour/tools/windows/handlelist"
	"github.com/aoiflux/libvapour/tools/windows/threadscan"
	"github.com/aoiflux/libvapour/tools/winkernel"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.process.compare"

var (
	ErrNoPhysicalMemory = errors.New("processcompare: session has no physical memory")
	ErrNoTranslation    = errors.New("processcompare: kernel memory does not translate addresses")
	ErrViewUnavailable  = errors.New("processcompare: symbol table lacks a member the view needs")
	ErrNoCsrss          = errors.New("processcompare: no csrss.exe on the active list")
)

type Verdict string

const (
	VerdictListed   Verdict = "listed"
	VerdictExited   Verdict = "exited"
	VerdictCopy     Verdict = "copy"
	VerdictUnlisted Verdict = "unlisted"
	VerdictHidden   Verdict = "hidden"
)

type Row struct {
	Physical             uint64
	Address              uint64
	PID                  uint64
	Name                 string
	ActiveList           bool
	KernelList           bool
	SessionRing          bool
	PoolScan             bool
	ThreadOwner          bool
	CsrssHandle          bool
	TypeIndexUnconfirmed bool
	ExitTime             time.Time
	ExitTimeRead         bool
	Verdict              Verdict
	Hidden               bool
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Match the processes that the kernel's lists, the pool scan, thread owners and csrss.exe handles know, and flag running processes missing from the active list",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

type view int

const (
	activeList view = iota
	kernelList
	sessionRing
	poolScan
	threadOwner
	csrssHandle
	viewCount
)

var viewNames = [viewCount]string{"active list", "kernel process list", "session rings", "pool scan",
	"thread owners", "csrss.exe handles"}

type sources struct {
	list    func(tools.Context) (processlist.Listing, error)
	pool    func(tools.Context) ([]processscan.Process, error)
	owners  func(tools.Context) ([]threadscan.Owned, error)
	handles func(tools.Context, []processlist.Process) ([]uint64, error)
}

var system = sources{list: processlist.RunListing, pool: processscan.Run, owners: threadscan.ScanOwners, handles: csrssHandles}

func Run(ctx tools.Context) ([]Row, error) {
	return run(ctx, system)
}

func run(ctx tools.Context, src sources) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return nil, ErrNoPhysicalMemory
	}
	listing, err := src.list(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w", Name, viewNames[activeList], err)
	}

	m := newMatcher(ctx)
	for _, p := range listing.Processes {
		m.add(activeList, ctx.Memory, p.EPROCESS, true, false)
	}
	failed := func(v view, err error) error {
		if ctx.StrictMode() && !errors.Is(err, ErrViewUnavailable) && !errors.Is(err, ErrNoCsrss) {
			return fmt.Errorf("%s: %s: %w", Name, viewNames[v], err)
		}
		ctx.AddDiagnostic("%s: %s: failed, left out: %v", Name, viewNames[v], err)
		return nil
	}
	pointerView := func(v view, found []uint64, err error) error {
		if err != nil {
			return failed(v, err)
		}
		for _, at := range found {
			m.add(v, ctx.Memory, at, true, false)
		}
		return nil
	}
	found, err := kernelProcessList(ctx)
	if err := pointerView(kernelList, found, err); err != nil {
		return nil, err
	}
	found, err = sessionRings(ctx, listing.Processes)
	if err := pointerView(sessionRing, found, err); err != nil {
		return nil, err
	}
	if scanned, err := src.pool(ctx); err != nil {
		if err := failed(poolScan, err); err != nil {
			return nil, err
		}
	} else {
		for _, p := range scanned {
			m.add(poolScan, physical, p.Offset, false, p.TypeIndexFailed)
		}
	}
	if owned, err := src.owners(ctx); err != nil {
		if err := failed(threadOwner, err); err != nil {
			return nil, err
		}
	} else {
		owners := make([]uint64, 0, len(owned))
		seen := map[uint64]bool{}
		for _, o := range owned {
			if !seen[o.Process] {
				seen[o.Process] = true
				owners = append(owners, o.Process)
			}
		}
		if err := pointerView(threadOwner, owners, nil); err != nil {
			return nil, err
		}
	}
	held, err := src.handles(ctx, listing.Processes)
	if err := pointerView(csrssHandle, held, err); err != nil {
		return nil, err
	}

	m.summarise()
	rows := m.verdicts(listing)
	pids := ctx.PIDs()
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		if pids.Keep(r.PID) {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, CompareRows)
	return out, nil
}

func kernelProcessList(ctx tools.Context) ([]uint64, error) {
	head, err := ctx.Symbols.LookupSymbol("KiProcessListHead")
	if err != nil {
		return nil, fmt.Errorf("KiProcessListHead: %w: %w", ErrViewUnavailable, err)
	}
	entry, err := ctx.Symbols.Field("_KPROCESS", "ProcessListEntry")
	if err != nil {
		return nil, fmt.Errorf("_KPROCESS.ProcessListEntry: %w: %w", ErrViewUnavailable, err)
	}
	member := entry.Offset
	if pcb, err := ctx.Symbols.Field("_EPROCESS", "Pcb"); err == nil {
		member += pcb.Offset
	}
	w, err := listWalker(ctx)
	if err != nil {
		return nil, err
	}
	walk, err := w.WalkRecovering(head.Address, "KiProcessListHead")
	if err != nil {
		return nil, err
	}
	return enclosing(walk.Entries, member), nil
}

// The ring's head lies in the session space, not in a process, so the S17
// check is what tells it from the processes (S26 M2).
func sessionRings(ctx tools.Context, listed []processlist.Process) ([]uint64, error) {
	links, err := ctx.Symbols.Field("_EPROCESS", "SessionProcessLinks")
	if err != nil {
		return nil, fmt.Errorf("_EPROCESS.SessionProcessLinks: %w: %w", ErrViewUnavailable, err)
	}
	session, err := ctx.Symbols.Field("_EPROCESS", "Session")
	if err != nil {
		return nil, fmt.Errorf("_EPROCESS.Session: %w: %w", ErrViewUnavailable, err)
	}
	w, err := listWalker(ctx)
	if err != nil {
		return nil, err
	}
	check := processlist.NewProcessCheck(ctx)
	walked := map[uint64]bool{}
	var out []uint64
	for _, p := range listed {
		space, err := ctx.Symbols.ReadPointer(ctx.Memory, p.EPROCESS+session.Offset)
		if err != nil || space == 0 || walked[space] {
			continue
		}
		walked[space] = true
		start := p.EPROCESS + links.Offset
		walk, err := w.WalkRecovering(start, "SessionProcessLinks")
		if err != nil {
			return nil, err
		}
		for _, eprocess := range enclosing(append([]uint64{start}, walk.Entries...), links.Offset) {
			if _, err := check.Check(ctx.Memory, eprocess); err == nil {
				out = append(out, eprocess)
			}
		}
	}
	return out, nil
}

func listWalker(ctx tools.Context) (winkernel.ListWalker, error) {
	layout, err := winkernel.NativeListLayout(ctx.Symbols)
	if err != nil {
		return winkernel.ListWalker{}, fmt.Errorf("%w: %w", ErrViewUnavailable, err)
	}
	return winkernel.ListWalker{Tool: Name, Memory: ctx.Memory, Layout: layout, Limit: ctx.Bounds().MaxListEntries,
		Strict: ctx.StrictMode(), Report: ctx.AddDiagnostic}, nil
}

func enclosing(entries []uint64, member uint64) []uint64 {
	out := make([]uint64, 0, len(entries))
	for _, e := range entries {
		if at, ok := winkernel.Container(e, member); ok {
			out = append(out, at)
		}
	}
	return out
}

func csrssHandles(ctx tools.Context, listed []processlist.Process) ([]uint64, error) {
	body, err := ctx.Symbols.Field("_OBJECT_HEADER", "Body")
	if err != nil {
		return nil, fmt.Errorf("_OBJECT_HEADER.Body: %w: %w", ErrViewUnavailable, err)
	}
	var w *handlelist.Walker
	var out []uint64
	for _, p := range listed {
		if util.DecodeUTF8Z([]byte(p.Name)) != "csrss.exe" {
			continue
		}
		if w == nil {
			if w, err = handlelist.NewWalker(ctx); err != nil {
				return nil, err
			}
		}
		for _, h := range w.Process(p) {
			if h.TypeName == "Process" {
				out = append(out, h.Object+body.Offset)
			}
		}
	}
	if w == nil {
		return nil, ErrNoCsrss
	}
	w.Finish()
	return out, nil
}

type rowKey struct {
	address uint64
	virtual bool
}

type entry struct {
	row     Row
	reader  memory.MemoryReader
	at      uint64
	rawName string
}

type matcher struct {
	ctx       tools.Context
	check     processlist.ProcessCheck
	translate func(uint64) (uint64, bool)
	rows      map[rowKey]*entry
	order     []rowKey
	seen      [viewCount]map[rowKey]bool
	rejected  [viewCount]int
}

type translator interface {
	Translate(virtualAddress uint64) (uint64, error)
}

func newMatcher(ctx tools.Context) *matcher {
	m := &matcher{ctx: ctx, check: processlist.NewProcessCheck(ctx), rows: map[rowKey]*entry{}}
	for i := range m.seen {
		m.seen[i] = map[rowKey]bool{}
	}
	if tr, ok := ctx.Memory.(translator); ok {
		m.translate = func(va uint64) (uint64, bool) {
			pa, err := tr.Translate(va)
			return pa, err == nil
		}
	} else {
		ctx.AddDiagnostic("%s: %v, rows keyed by virtual address", Name, ErrNoTranslation)
		m.translate = func(uint64) (uint64, bool) { return 0, false }
	}
	return m
}

func (m *matcher) add(v view, r memory.MemoryReader, at uint64, virtual, typeUnconfirmed bool) {
	id, err := m.check.Check(r, at)
	if err != nil {
		m.rejected[v]++
		return
	}
	key := rowKey{address: at}
	if virtual {
		if pa, ok := m.translate(at); ok {
			key.address = pa
		} else {
			key.virtual = true
		}
	}
	e, ok := m.rows[key]
	if !ok {
		e = &entry{row: Row{PID: id.PID, Name: util.DecodeUTF8Z([]byte(id.Name))}, reader: r, at: at, rawName: id.Name}
		if !key.virtual {
			e.row.Physical = key.address
		}
		m.rows[key] = e
		m.order = append(m.order, key)
	}
	if virtual && e.row.Address == 0 {
		e.row.Address = at
	}
	e.row.TypeIndexUnconfirmed = e.row.TypeIndexUnconfirmed || typeUnconfirmed
	m.seen[v][key] = true
	switch v {
	case activeList:
		e.row.ActiveList = true
	case kernelList:
		e.row.KernelList = true
	case sessionRing:
		e.row.SessionRing = true
	case poolScan:
		e.row.PoolScan = true
	case threadOwner:
		e.row.ThreadOwner = true
	case csrssHandle:
		e.row.CsrssHandle = true
	}
}

func (m *matcher) summarise() {
	parts := make([]string, 0, viewCount)
	for v := range viewCount {
		parts = append(parts, fmt.Sprintf("%s %d (%d rejected by the process check)", viewNames[v], len(m.seen[v]), m.rejected[v]))
	}
	m.ctx.AddDiagnostic("%s: views: %s", Name, strings.Join(parts, ", "))
}

type identity struct {
	pid     uint64
	name    string
	root    uint64
	created uint64
}

type nameKey struct {
	pid  uint64
	name string
}

type member struct {
	at uint64
	ok bool
}

type members struct {
	exit, created, root member
}

func resolveMembers(ctx tools.Context) members {
	of := func(typ, name string) member {
		f, err := ctx.Symbols.Field(typ, name)
		return member{at: f.Offset, ok: err == nil}
	}
	ms := members{exit: of("_EPROCESS", "ExitTime"), created: of("_EPROCESS", "CreateTime"), root: of("_KPROCESS", "DirectoryTableBase")}
	if pcb := of("_EPROCESS", "Pcb"); pcb.ok && ms.root.ok {
		ms.root.at += pcb.at
	}
	return ms
}

// An absent or unreadable member reads as 0 on both sides of a comparison.
func (m member) read(ctx tools.Context, r memory.MemoryReader, base uint64) uint64 {
	if !m.ok {
		return 0
	}
	v, err := ctx.Symbols.ReadUint64(r, base+m.at)
	if err != nil {
		return 0
	}
	return v
}

func (m *matcher) verdicts(listing processlist.Listing) []Row {
	ctx := m.ctx
	ms := resolveMembers(ctx)
	listed := map[identity]bool{}
	listedRoot := map[nameKey]uint64{}
	for _, p := range listing.Processes {
		id := identity{pid: p.PID, name: p.Name, root: ms.root.read(ctx, ctx.Memory, p.EPROCESS),
			created: ms.created.read(ctx, ctx.Memory, p.EPROCESS)}
		listed[id] = true
		listedRoot[nameKey{p.PID, p.Name}] = id.root
	}
	window := m.check.Window()
	out := make([]Row, 0, len(m.order))
	unlisted := 0
	for _, key := range m.order {
		e := m.rows[key]
		r := &e.row
		exited := false
		if ms.exit.ok {
			if ft, err := ctx.Symbols.ReadUint64(e.reader, e.at+ms.exit.at); err == nil {
				r.ExitTimeRead = true
				if t, ok := util.FiletimeToTime(ft); ok && ft != 0 {
					r.ExitTime = t
				}
				exited = ft != 0 && window.Holds(ft)
			}
		}
		id := identity{pid: r.PID, name: e.rawName, root: ms.root.read(ctx, e.reader, e.at),
			created: ms.created.read(ctx, e.reader, e.at)}
		switch {
		case r.ActiveList:
			r.Verdict = VerdictListed
		case exited:
			r.Verdict = VerdictExited
		case listed[id]:
			r.Verdict = VerdictCopy
		case !listing.Closed:
			r.Verdict = VerdictUnlisted
			unlisted++
		default:
			r.Verdict = VerdictHidden
			r.Hidden = true
			at := r.Physical
			if at == 0 {
				at = r.Address
			}
			ctx.AddDiagnostic("%s: _EPROCESS at 0x%x: pid %d: hidden, held by %s", Name, at, r.PID, heldBy(*r))
			if root, ok := listedRoot[nameKey{r.PID, e.rawName}]; ok && root != id.root {
				ctx.AddDiagnostic("%s: _EPROCESS at 0x%x: pid %d: a listed process has this pid and name with page-table root 0x%x, this one 0x%x",
					Name, at, r.PID, root, id.root)
			}
		}
		out = append(out, *r)
	}
	if !listing.Closed {
		ctx.AddDiagnostic("%s: active list walk did not close: %d running unlisted processes may lie in the part not walked",
			Name, unlisted)
	}
	return out
}

func heldBy(r Row) string {
	var by []string
	for _, v := range []struct {
		in   bool
		name view
	}{{r.KernelList, kernelList}, {r.SessionRing, sessionRing}, {r.PoolScan, poolScan},
		{r.ThreadOwner, threadOwner}, {r.CsrssHandle, csrssHandle}} {
		if v.in {
			by = append(by, viewNames[v.name])
		}
	}
	return strings.Join(by, ", ")
}

func CompareRows(a, b Row) int {
	if c := cmp.Compare(a.PID, b.PID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	if a.ActiveList != b.ActiveList {
		if a.ActiveList {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(a.Physical, b.Physical); c != 0 {
		return c
	}
	return cmp.Compare(a.Address, b.Address)
}
