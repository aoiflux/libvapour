package processlist

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// Member offsets of build 26100 (S25 T1 to T5).
const (
	s25PID        = uint64(0x1d0)
	s25Links      = uint64(0x1d8)
	s25Created    = uint64(0x1f8)
	s25Peb        = uint64(0x2e0)
	s25Session    = uint64(0x2e8)
	s25Parent     = uint64(0x2d0)
	s25ObjTable   = uint64(0x300)
	s25Wow64      = uint64(0x310)
	s25Name       = uint64(0x338)
	s25Threads    = uint64(0x380)
	s25Exited     = uint64(0x5c0)
	s25Root       = uint64(0x28)
	s25UserRoot   = uint64(0x158)
	s25Head       = uint64(0xfffff8037e035a80)
	s25SystemPtr  = uint64(0xfffff8037e0f5af0)
	s25FirstProc  = uint64(0xffff9e03f66a0040)
	s25ProcStride = uint64(0x1000)
	s25SessionAt  = uint64(0xffff9e03ffd76c00)
)

var s25Boot = checkFileTime(time.Date(2026, 5, 6, 8, 0, 0, 0, time.UTC))

func s25Symbols(omit ...string) *symbols.Table {
	skip := map[string]bool{}
	for _, o := range omit {
		skip[o] = true
	}
	keep := func(typ string, fs ...symbols.Field) []symbols.Field {
		out := []symbols.Field{}
		for _, f := range fs {
			if !skip[typ+"."+f.Name] {
				out = append(out, f)
			}
		}
		return out
	}
	t := symbols.NewTable("s25", 8)
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x840, Fields: keep("_EPROCESS",
		symbols.Field{Name: "Pcb", Offset: 0},
		symbols.Field{Name: "UniqueProcessId", Offset: s25PID},
		symbols.Field{Name: "ActiveProcessLinks", Offset: s25Links},
		symbols.Field{Name: "CreateTime", Offset: s25Created},
		symbols.Field{Name: "Peb", Offset: s25Peb},
		symbols.Field{Name: "Session", Offset: s25Session},
		symbols.Field{Name: "InheritedFromUniqueProcessId", Offset: s25Parent},
		symbols.Field{Name: "ObjectTable", Offset: s25ObjTable},
		symbols.Field{Name: "WoW64Process", Offset: s25Wow64},
		symbols.Field{Name: "ImageFileName", Offset: s25Name, Type: symbols.TypeRef{Name: "unsigned char", ArrayLength: 15}},
		symbols.Field{Name: "ActiveThreads", Offset: s25Threads, Type: symbols.TypeRef{Name: "unsigned int"}},
		symbols.Field{Name: "ExitTime", Offset: s25Exited},
	)})
	t.AddStruct(symbols.StructType{Name: "_KPROCESS", Size: 0x1c8, Fields: keep("_KPROCESS",
		symbols.Field{Name: "DirectoryTableBase", Offset: s25Root},
		symbols.Field{Name: "UserDirectoryTableBase", Offset: s25UserRoot},
	)})
	t.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 0x10, Fields: []symbols.Field{
		{Name: "Flink", Offset: 0}, {Name: "Blink", Offset: 8},
	}})
	if !skip["PsActiveProcessHead"] {
		t.AddSymbol(symbols.Symbol{Name: "PsActiveProcessHead", Address: s25Head})
	}
	if !skip["PsInitialSystemProcess"] {
		t.AddSymbol(symbols.Symbol{Name: "PsInitialSystemProcess", Address: s25SystemPtr})
	}
	return t
}

type s25Proc struct {
	pid, parent uint64
	name        string
	created     uint64
	exited      uint64
	threads     uint32
	session     uint64
	root, user  uint64
}

type s25Image struct {
	mem   ckMemory
	procs []uint64
}

func s25At(i int) uint64 { return s25FirstProc + uint64(i)*s25ProcStride }

// A list of the given processes in order, the first of them the System
// process that PsInitialSystemProcess names.
func newS25Image(procs ...s25Proc) s25Image {
	im := s25Image{mem: ckMemory{}}
	for i, p := range procs {
		at := s25At(i)
		im.procs = append(im.procs, at)
		var name [15]byte
		copy(name[:], p.name)
		im.mem.put(at+s25Name, name[:])
		im.mem.put64(at+s25PID, p.pid)
		im.mem.put64(at+s25Parent, p.parent)
		created := p.created
		if created == 0 {
			created = s25Boot + uint64(i+1)*ckTick
		}
		im.mem.put64(at+s25Created, created)
		im.mem.put64(at+s25Exited, p.exited)
		im.mem.put(at+s25Threads, []byte{byte(p.threads), byte(p.threads >> 8), 0, 0})
		im.mem.put64(at+s25Session, p.session)
		root := p.root
		if root == 0 {
			root = 0x1aa000 + uint64(i)*0x1000
		}
		im.mem.put64(at+s25Root, root)
		im.mem.put64(at+s25UserRoot, p.user)
	}
	im.link()
	if len(procs) > 0 {
		im.mem.put64(s25SystemPtr, s25At(0))
	}
	im.mem.put(s25SessionAt+8, []byte{1, 0, 0, 0})
	return im
}

func (im s25Image) link() {
	ring := []uint64{s25Head}
	for _, at := range im.procs {
		ring = append(ring, at+s25Links)
	}
	for i, e := range ring {
		im.mem.put64(e, ring[(i+1)%len(ring)])
		im.mem.put64(e+8, ring[(i+len(ring)-1)%len(ring)])
	}
}

func (im s25Image) ctx(options map[string]any, omit ...string) (tools.Context, *[]string) {
	diags := []string{}
	opts := map[string]any{"diagnostics": &diags}
	for k, v := range options {
		opts[k] = v
	}
	return tools.Context{Memory: im.mem, Symbols: s25Symbols(omit...), Profile: profiles.WindowsX64Profile{}, Options: opts}, &diags
}

func running(pid uint64, name string) s25Proc {
	return s25Proc{pid: pid, parent: 4, name: name, threads: 3, session: s25SessionAt}
}

func ordinaryList() []s25Proc {
	return []s25Proc{
		{pid: 4, name: "System", threads: 200},
		{pid: 120, parent: 4, name: "Registry", threads: 4},
		running(1300, "svchost.exe"),
		running(2400, "cmd.exe"),
	}
}

type gapReader struct {
	memory.MemoryReader
	gaps []uint64
}

func (g gapReader) ReadAt(at, size uint64) ([]byte, error) {
	for _, h := range g.gaps {
		if h >= at && h < at+size {
			return nil, memory.ErrOutOfBounds
		}
	}
	return g.MemoryReader.ReadAt(at, size)
}

type holeMemory struct {
	*testsupport.PagedMemory
	holes []uint64
}

func (m holeMemory) ReadAt(at, size uint64) ([]byte, error) {
	return gapReader{MemoryReader: m.PagedMemory, gaps: m.holes}.ReadAt(at, size)
}

func pidsOf(rows []Process) []uint64 {
	out := make([]uint64, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.PID)
	}
	return out
}

func saidSo(diags []string, part string) bool {
	return slices.ContainsFunc(diags, func(d string) bool { return strings.Contains(d, part) })
}

func TestAClosedListComesBackInWalkOrder(t *testing.T) {
	im := newS25Image(ordinaryList()...)
	ctx, diags := im.ctx(nil)
	l, err := RunListing(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(l.Processes); !slices.Equal(got, []uint64{4, 120, 1300, 2400}) || !l.Closed {
		t.Fatalf("pids %v closed %v (diagnostics %q)", got, l.Closed, *diags)
	}
	for i, p := range l.Processes {
		if p.EPROCESS != s25At(i) {
			t.Errorf("row %d at 0x%x, want 0x%x", i, p.EPROCESS, s25At(i))
		}
	}
	if l.Processes[2].Name != "svchost.exe" || l.Processes[2].PPID != 4 || l.Processes[2].Threads != 3 {
		t.Errorf("svchost row %+v", l.Processes[2])
	}
}

func TestABrokenFlinkIsClosedFromTheBlinkSide(t *testing.T) {
	im := newS25Image(ordinaryList()...)
	im.mem.put64(s25At(1)+s25Links, 0xffff9e0500000000)
	ctx, diags := im.ctx(nil)
	l, err := RunListing(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(l.Processes); !slices.Equal(got, []uint64{4, 120, 2400, 1300}) || !l.Closed {
		t.Fatalf("pids %v closed %v, want the Blink side to add 2400 and 1300 and close the walk", got, l.Closed)
	}
	if len(*diags) == 0 {
		t.Error("the break was not reported")
	}
}

func TestAWalkBrokenFromBothSidesIsNotClosed(t *testing.T) {
	im := newS25Image(ordinaryList()...)
	im.mem.put64(s25At(1)+s25Links, 0xffff9e0500000000)
	im.mem.put64(s25At(2)+s25Links+8, 0xffff9e0500000000)
	ctx, _ := im.ctx(nil)
	l, err := RunListing(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(l.Processes); !slices.Equal(got, []uint64{4, 120, 2400, 1300}) || l.Closed {
		t.Fatalf("pids %v closed %v, want every entry found and the walk not closed", got, l.Closed)
	}

	ctx, _ = im.ctx(map[string]any{"strict": true})
	if _, err := Run(ctx); err == nil {
		t.Error("strict mode accepted a broken walk")
	}
}

func TestAHeadOutsideSystemSpaceGivesWayToTheStartEntry(t *testing.T) {
	im := newS25Image(ordinaryList()...)
	table := s25Symbols("PsActiveProcessHead")
	table.AddSymbol(symbols.Symbol{Name: "PsActiveProcessHead", Address: 0x35a80})
	ctx, diags := im.ctx(map[string]any{optionStartFlink: s25At(1) + s25Links})
	ctx.Symbols = table
	l, err := RunListing(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(l.Processes); !slices.Equal(got, []uint64{120, 1300, 2400, 4}) || !l.Closed {
		t.Fatalf("pids %v closed %v, want the ring from Registry with System last", got, l.Closed)
	}
	dropped := 0
	for _, d := range *diags {
		if strings.Contains(d, "dropped from the ring walk") {
			dropped++
			if !strings.Contains(d, "0xfffff8037e035a80") {
				t.Errorf("dropped entry %q is not the head", d)
			}
		}
	}
	if dropped != 1 {
		t.Errorf("%d ring entries dropped, want only the head: %q", dropped, *diags)
	}
}

func TestWithNoHeadAndNoStartEntryTheToolFails(t *testing.T) {
	im := newS25Image(ordinaryList()...)
	ctx, _ := im.ctx(nil, "PsActiveProcessHead")
	if _, err := Run(ctx); !errors.Is(err, ErrNoListHead) {
		t.Fatalf("err %v, want ErrNoListHead", err)
	}
	ctx, _ = im.ctx(map[string]any{optionStartFlink: s25At(1) + s25Links}, "PsActiveProcessHead")
	if got, err := Run(ctx); err != nil || len(got) != 4 {
		t.Fatalf("with a start entry: %v, %v", pidsOf(got), err)
	}
}

func TestEachRequiredMemberIsRequired(t *testing.T) {
	im := newS25Image(ordinaryList()...)
	for _, m := range []string{"_EPROCESS.ActiveProcessLinks", "_EPROCESS.UniqueProcessId", "_EPROCESS.ImageFileName"} {
		ctx, _ := im.ctx(nil, m)
		if _, err := Run(ctx); !errors.Is(err, ErrNoListMember) {
			t.Errorf("without %s: %v, want ErrNoListMember", m, err)
		}
	}
}

func TestAnEntryWhoseIDDoesNotReadIsSkipped(t *testing.T) {
	im := newS25Image(ordinaryList()...)
	ctx, diags := im.ctx(nil)
	ctx.Memory = gapReader{MemoryReader: im.mem, gaps: []uint64{s25At(2) + s25PID}}
	got, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pidsOf(got), []uint64{4, 120, 2400}) || !saidSo(*diags, "pid and image name do not read") {
		t.Fatalf("pids %v diagnostics %q", pidsOf(got), *diags)
	}
	ctx, _ = im.ctx(map[string]any{"strict": true})
	ctx.Memory = gapReader{MemoryReader: im.mem, gaps: []uint64{s25At(2) + s25PID}}
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "0xffff9e03f66a2040") {
		t.Errorf("strict: %v, want an error naming the entry", err)
	}
}

func TestAnEmptyNameStaysEmpty(t *testing.T) {
	list := ordinaryList()
	list[3].name = ""
	ctx, _ := newS25Image(list...).ctx(nil)
	got, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got[3].Name != "" {
		t.Errorf("name %q, want empty", got[3].Name)
	}
}

func TestTheSanityFilterDropsWhatTheProcessCheckRejects(t *testing.T) {
	list := ordinaryList()
	list[3].pid = 2402
	im := newS25Image(list...)
	ctx, _ := im.ctx(nil)
	if got, _ := Run(ctx); len(got) != 4 {
		t.Fatalf("unfiltered %v", pidsOf(got))
	}
	ctx, diags := im.ctx(map[string]any{optionSanityFilter: true})
	got, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pidsOf(got), []uint64{4, 120, 1300}) || !saidSo(*diags, ErrBadID.Error()) {
		t.Errorf("filtered %v diagnostics %q", pidsOf(got), *diags)
	}
}

func TestTheActiveFilterRules(t *testing.T) {
	list := append(ordinaryList(),
		s25Proc{pid: 3000, parent: 1300, name: "gone.exe", exited: s25Boot + 900*ckTick, session: s25SessionAt},
		s25Proc{pid: 3100, parent: 4, name: "Secure System"},
	)
	im := newS25Image(list...)
	ctx, _ := im.ctx(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f := ResolveActiveProcessFilter(ctx)
	want := []error{ErrSystemProcess, nil, nil, nil, ErrExited, ErrNoThreads}
	for i, p := range rows {
		if err := f.Why(ctx, p); !errors.Is(err, want[i]) || (want[i] == nil) != (err == nil) {
			t.Errorf("pid %d: %v, want %v", p.PID, err, want[i])
		}
	}
	if kept := f.Active(ctx, rows); !slices.Equal(pidsOf(kept), []uint64{120, 1300, 2400}) {
		t.Errorf("active %v", pidsOf(kept))
	}

	ctx, diags := im.ctx(map[string]any{optionActiveOnlyFilter: true})
	got, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pidsOf(got), []uint64{120, 1300, 2400}) || !saidSo(*diags, ErrExited.Error()) {
		t.Errorf("active_only %v diagnostics %q", pidsOf(got), *diags)
	}
}

func TestWithoutTheSystemGlobalPID4IsTheSystemProcess(t *testing.T) {
	list := ordinaryList()
	list[0].pid, list[1].pid = 8, 4
	ctx, _ := newS25Image(list...).ctx(nil, "PsInitialSystemProcess")
	rows, _ := Run(ctx)
	f := ResolveActiveProcessFilter(ctx)
	if err := f.Why(ctx, rows[0]); err != nil {
		t.Errorf("pid 8 at the first entry: %v", err)
	}
	if err := f.Why(ctx, rows[1]); !errors.Is(err, ErrSystemProcess) {
		t.Errorf("pid 4: %v, want ErrSystemProcess", err)
	}
}

func TestTheActiveFilterRejectsWhatItCannotRead(t *testing.T) {
	im := newS25Image(ordinaryList()...)
	ctx, _ := im.ctx(nil)
	rows, _ := Run(ctx)
	ctx.Memory = gapReader{MemoryReader: im.mem, gaps: []uint64{s25At(2) + s25Threads}}
	if err := ResolveActiveProcessFilter(ctx).Why(ctx, rows[2]); !errors.Is(err, ErrMemberUnread) {
		t.Errorf("threads unread: %v", err)
	}
	ctx.Memory = im.mem
	im.mem.put64(s25At(2)+s25Created, 0)
	if err := ResolveActiveProcessFilter(ctx).Why(ctx, rows[2]); !errors.Is(err, ErrCreateTime) {
		t.Errorf("creation time 0: %v, want the S17 sentinel", err)
	}
	ctx, _ = im.ctx(nil, "_EPROCESS.ActiveThreads", "_EPROCESS.ExitTime")
	if err := ResolveActiveProcessFilter(ctx).Why(ctx, rows[3]); err != nil {
		t.Errorf("absent members: %v, want their rules dropped", err)
	}
}

type s25Checker struct {
	refuse map[uint64]bool
	err    error
}

func (c s25Checker) Confirm(p Process) (bool, error) { return !c.refuse[p.PID], c.err }

func TestTheCrossChecker(t *testing.T) {
	im := newS25Image(ordinaryList()...)
	ctx, diags := im.ctx(map[string]any{optionCrossChecker: s25Checker{refuse: map[uint64]bool{1300: true}}})
	got, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pidsOf(got), []uint64{4, 120, 2400}) || !saidSo(*diags, "not confirmed by the cross-checker") {
		t.Errorf("refused %v %q", pidsOf(got), *diags)
	}
	broken := s25Checker{err: errors.New("snapshot unreadable")}
	ctx, diags = im.ctx(map[string]any{optionCrossChecker: broken})
	if got, _ := Run(ctx); len(got) != 4 || !saidSo(*diags, "cross-checker failed, kept") {
		t.Errorf("checker error: %v %q", pidsOf(got), *diags)
	}
	ctx, _ = im.ctx(map[string]any{optionCrossChecker: broken, "strict": true})
	if _, err := Run(ctx); err == nil {
		t.Error("strict mode kept a checker error")
	}
	ctx, _ = im.ctx(map[string]any{optionCrossChecker: "yes"})
	if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("wrong type: %v", err)
	}
}

func TestThePIDOptionNarrowsTheTool(t *testing.T) {
	im := newS25Image(ordinaryList()...)
	for _, c := range []struct {
		pid  any
		want []uint64
	}{
		{uint64(1300), []uint64{1300}},
		{[]uint64{2400, 4}, []uint64{4, 2400}},
		{uint64(0), []uint64{}},
	} {
		ctx, _ := im.ctx(map[string]any{"pid": c.pid})
		got, err := RunAny(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if p := pidsOf(got.([]Process)); !slices.Equal(p, c.want) {
			t.Errorf("pid %v: %v, want %v", c.pid, p, c.want)
		}
	}
}

func TestTheSessionID(t *testing.T) {
	list := ordinaryList()
	im := newS25Image(list...)
	ctx, diags := im.ctx(nil)
	rows, _ := Run(ctx)
	if rows[0].SessionID != SessionIDNotApplicable || rows[2].SessionID != 1 || rows[3].SessionID != 1 {
		t.Errorf("untyped: %d %d %d", rows[0].SessionID, rows[2].SessionID, rows[3].SessionID)
	}
	n := 0
	for _, d := range *diags {
		if strings.Contains(d, "no typed SessionId") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the fixed offset was reported %d times, want once", n)
	}

	table := s25Symbols()
	table.AddStruct(symbols.StructType{Name: "_MM_SESSION_SPACE", Size: 0x100, Fields: []symbols.Field{
		{Name: "SessionId", Offset: 0x20, Type: symbols.TypeRef{Name: "unsigned int"}},
	}})
	im.mem.put(s25SessionAt+0x20, []byte{7, 0, 0, 0})
	ctx, diags = im.ctx(nil)
	ctx.Symbols = table
	if id := NewSessionResolver(ctx).SessionID(ctx, s25At(2)); id != 7 || saidSo(*diags, "no typed SessionId") {
		t.Errorf("typed: %d %q", id, *diags)
	}
	ctx.Memory = gapReader{MemoryReader: im.mem, gaps: []uint64{s25SessionAt + 0x20}}
	if id := NewSessionResolver(ctx).SessionID(ctx, s25At(2)); id != SessionIDUnreadable {
		t.Errorf("unread: %d", id)
	}
	ctx, _ = im.ctx(nil, "_EPROCESS.Session")
	if id := NewSessionResolver(ctx).SessionID(ctx, s25At(2)); id != SessionIDUnreadable {
		t.Errorf("no member: %d", id)
	}
}

func TestThePageTableRoots(t *testing.T) {
	list := ordinaryList()
	list[2].root, list[2].user = 0x1aa000, 0x2bb000
	list[3].root, list[3].user = 0x1cc000, 1
	im := newS25Image(list...)
	ctx, _ := im.ctx(nil)
	rows, _ := Run(ctx)
	if rows[2].DirectoryTableBase != 0x2bb000 || rows[3].DirectoryTableBase != 0x1cc000 {
		t.Errorf("roots 0x%x 0x%x", rows[2].DirectoryTableBase, rows[3].DirectoryTableBase)
	}
	if k, err := KernelDirectoryTableBase(ctx, rows[2].EPROCESS); err != nil || k != 0x1aa000 {
		t.Errorf("kernel root 0x%x %v", k, err)
	}

	ctx, _ = im.ctx(nil, "_KPROCESS.DirectoryTableBase", "_KPROCESS.UserDirectoryTableBase")
	if _, err := KernelDirectoryTableBase(ctx, rows[2].EPROCESS); !errors.Is(err, ErrNoPageTableRoot) {
		t.Errorf("no member: %v", err)
	}
	if NewUserSpaceDTBResolver(ctx).Described() {
		t.Error("a table without either root is described")
	}
	flat := s25Symbols("_KPROCESS.DirectoryTableBase", "_KPROCESS.UserDirectoryTableBase")
	flat.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x840, Fields: append(append([]symbols.Field(nil),
		mustStruct(t, s25Symbols(), "_EPROCESS").Fields...), symbols.Field{Name: "DirectoryTableBase", Offset: s25Root})})
	ctx.Symbols = flat
	if k, err := KernelDirectoryTableBase(ctx, rows[2].EPROCESS); err != nil || k != 0x1aa000 {
		t.Errorf("_EPROCESS member: 0x%x %v", k, err)
	}
}

func mustStruct(t *testing.T, table symbols.SymbolTable, name string) symbols.StructType {
	t.Helper()
	s, err := table.Struct(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestProcessAtReadsOneProcess(t *testing.T) {
	im := newS25Image(ordinaryList()...)
	ctx, _ := im.ctx(nil)
	p, err := ProcessAt(ctx, s25At(2))
	if err != nil || p.PID != 1300 || p.Name != "svchost.exe" || p.DirectoryTableBase != 0x1ac000 || p.PPID != 4 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := ProcessAt(ctx, 0xffff9e0700000000); err == nil {
		t.Error("an unmapped address gave a process")
	}
}

func TestTheListingIsReusedAndCopied(t *testing.T) {
	im := newS25Image(ordinaryList()...)
	ctx, _ := im.ctx(nil)
	first, _ := Run(ctx)
	first[0].PID = 99
	im.mem.put64(s25At(3)+s25PID, 2404)
	again, _ := Run(ctx)
	if again[0].PID != 4 || again[3].PID != 2400 {
		t.Errorf("second run %v, want the first listing unchanged by the caller or the memory", pidsOf(again))
	}
}
