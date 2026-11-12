package processcompare

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/any/processscan"
	"github.com/aoiflux/libvapour/tools/windows/threadscan"
)

// Member offsets of build 26100 (S25 T1 to T5, S26 T1 and T2).
const (
	offPID         = uint64(0x1d0)
	offLinks       = uint64(0x1d8)
	offCreated     = uint64(0x1f8)
	offSessionLink = uint64(0x230)
	offSession     = uint64(0x2e8)
	offName        = uint64(0x338)
	offThreads     = uint64(0x380)
	offExited      = uint64(0x5c0)
	offRoot        = uint64(0x28)
	offKernelLink  = uint64(0x110)

	poolBase   = uint64(0xffff9e0000000000)
	imageBase  = uint64(0xfffff80000000000)
	imagePhys  = uint64(0x40_0000_0000)
	activeHead = uint64(0xfffff8037e035a80)
	kernelHead = uint64(0xfffff8037e052080)
	firstProc  = uint64(0xffff9e03f66a0040)
	stride     = uint64(0x1000)
	spaceAt    = uint64(0xffff9e03ffd76c00)
	tick       = uint64(10_000_000)
)

var boot = uint64(time.Date(2026, 5, 6, 8, 0, 0, 0, time.UTC).Unix()+11644473600) * tick

// Pages keyed by physical address; kernel addresses translate by a fixed
// offset per region.
type store map[uint64]*[4096]byte

func (s store) put(pa uint64, b []byte) {
	for i, v := range b {
		a := pa + uint64(i)
		p, ok := s[a&^0xFFF]
		if !ok {
			p = new([4096]byte)
			s[a&^0xFFF] = p
		}
		p[a&0xFFF] = v
	}
}

func (s store) ReadAt(pa, size uint64) ([]byte, error) {
	out := make([]byte, size)
	for i := range size {
		p, ok := s[(pa+i)&^0xFFF]
		if !ok {
			return nil, memory.ErrOutOfBounds
		}
		out[i] = p[(pa+i)&0xFFF]
	}
	return out, nil
}

func (s store) Size() uint64 { return 1 << 48 }

func translate(va uint64) (uint64, error) {
	switch {
	case va >= imageBase:
		return va - imageBase + imagePhys, nil
	case va >= poolBase:
		return va - poolBase, nil
	}
	return 0, memory.ErrOutOfBounds
}

type kernel struct{ s store }

func (k kernel) Translate(va uint64) (uint64, error) { return translate(va) }
func (k kernel) Size() uint64                        { return 1<<64 - 1 }
func (k kernel) ReadAt(va, size uint64) ([]byte, error) {
	pa, err := translate(va)
	if err != nil {
		return nil, err
	}
	return k.s.ReadAt(pa, size)
}

type flatKernel struct{ k kernel }

func (f flatKernel) ReadAt(va, size uint64) ([]byte, error) { return f.k.ReadAt(va, size) }
func (f flatKernel) Size() uint64                           { return f.k.Size() }

func (k kernel) put(va uint64, b []byte) {
	pa, err := translate(va)
	if err != nil {
		panic(err)
	}
	k.s.put(pa, b)
}

func (k kernel) put64(va, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	k.put(va, b[:])
}

func table(omit ...string) *symbols.Table {
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
	t := symbols.NewTable("s26", 8)
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x840, Fields: keep("_EPROCESS",
		symbols.Field{Name: "Pcb", Offset: 0},
		symbols.Field{Name: "UniqueProcessId", Offset: offPID},
		symbols.Field{Name: "ActiveProcessLinks", Offset: offLinks},
		symbols.Field{Name: "CreateTime", Offset: offCreated},
		symbols.Field{Name: "SessionProcessLinks", Offset: offSessionLink},
		symbols.Field{Name: "Session", Offset: offSession},
		symbols.Field{Name: "ImageFileName", Offset: offName, Type: symbols.TypeRef{Name: "unsigned char", ArrayLength: 15}},
		symbols.Field{Name: "ActiveThreads", Offset: offThreads, Type: symbols.TypeRef{Name: "unsigned int"}},
		symbols.Field{Name: "ExitTime", Offset: offExited},
	)})
	t.AddStruct(symbols.StructType{Name: "_KPROCESS", Size: 0x1c8, Fields: keep("_KPROCESS",
		symbols.Field{Name: "DirectoryTableBase", Offset: offRoot},
		symbols.Field{Name: "ProcessListEntry", Offset: offKernelLink},
	)})
	t.AddStruct(symbols.StructType{Name: "_LIST_ENTRY", Size: 0x10, Fields: []symbols.Field{
		{Name: "Flink", Offset: 0}, {Name: "Blink", Offset: 8},
	}})
	t.AddSymbol(symbols.Symbol{Name: "PsActiveProcessHead", Address: activeHead})
	if !skip["KiProcessListHead"] {
		t.AddSymbol(symbols.Symbol{Name: "KiProcessListHead", Address: kernelHead})
	}
	return t
}

type proc struct {
	pid     uint64
	name    string
	exited  uint64
	root    uint64
	created uint64
	session bool
}

type image struct {
	k  kernel
	at []uint64

	src    sources
	pool   []processscan.Process
	owners []threadscan.Owned
	held   []uint64
}

func at(i int) uint64 { return firstProc + uint64(i)*stride }

func newImage(procs ...proc) *image {
	im := &image{k: kernel{s: store{}}}
	for i, p := range procs {
		a := at(i)
		im.at = append(im.at, a)
		var name [15]byte
		copy(name[:], p.name)
		im.k.put(a+offName, name[:])
		im.k.put64(a+offPID, p.pid)
		created := p.created
		if created == 0 {
			created = boot + uint64(i+1)*tick
		}
		im.k.put64(a+offCreated, created)
		im.k.put64(a+offExited, p.exited)
		im.k.put(a+offThreads, []byte{3, 0, 0, 0})
		root := p.root
		if root == 0 {
			root = 0x1aa000 + uint64(i)*0x1000
		}
		im.k.put64(a+offRoot, root)
		if p.session {
			im.k.put64(a+offSession, spaceAt)
		}
	}
	im.src = sources{
		list:    processlist.RunListing,
		pool:    func(tools.Context) ([]processscan.Process, error) { return im.pool, nil },
		owners:  func(tools.Context) ([]threadscan.Owned, error) { return im.owners, nil },
		handles: func(tools.Context, []processlist.Process) ([]uint64, error) { return im.held, nil },
	}
	return im
}

func (im *image) ring(head, member uint64, procs []uint64) {
	ring := []uint64{head}
	for _, p := range procs {
		ring = append(ring, p+member)
	}
	for i, e := range ring {
		im.k.put64(e, ring[(i+1)%len(ring)])
		im.k.put64(e+8, ring[(i+len(ring)-1)%len(ring)])
	}
}

// Links the active list, the kernel list and the session ring from the
// indexes given; a process off a list is linked into none of its rings.
func (im *image) link(active, kernelList, session []int) {
	pick := func(ix []int) []uint64 {
		out := []uint64{}
		for _, i := range ix {
			out = append(out, im.at[i])
		}
		return out
	}
	im.ring(activeHead, offLinks, pick(active))
	im.ring(kernelHead, offKernelLink, pick(kernelList))
	im.ring(spaceAt+0x10, offSessionLink, pick(session))
}

func (im *image) ctx(options map[string]any, omit ...string) (tools.Context, *[]string) {
	diags := []string{}
	opts := map[string]any{"diagnostics": &diags, tools.OptionPhysicalMemory: im.k.s}
	for k, v := range options {
		opts[k] = v
	}
	return tools.Context{Memory: im.k, Symbols: table(omit...), Profile: profiles.WindowsX64Profile{}, Options: opts}, &diags
}

func (im *image) run(t *testing.T, options map[string]any, omit ...string) ([]Row, []string) {
	t.Helper()
	ctx, diags := im.ctx(options, omit...)
	rows, err := run(ctx, im.src)
	if err != nil {
		t.Fatal(err)
	}
	return rows, *diags
}

func phys(va uint64) uint64 {
	pa, _ := translate(va)
	return pa
}

func rowFor(rows []Row, pid uint64) (Row, bool) {
	i := slices.IndexFunc(rows, func(r Row) bool { return r.PID == pid })
	if i < 0 {
		return Row{}, false
	}
	return rows[i], true
}

func said(diags []string, part string) bool {
	return slices.ContainsFunc(diags, func(d string) bool { return strings.Contains(d, part) })
}

func listedPlusOne() *image {
	return newImage(
		proc{pid: 4, name: "System"},
		proc{pid: 1300, name: "svchost.exe", session: true},
		proc{pid: 2400, name: "cmd.exe", session: true},
		proc{pid: 6000, name: "evil.exe", session: true},
	)
}

func TestEveryViewOnItsOwnFindsAHiddenProcess(t *testing.T) {
	for _, c := range []struct {
		view string
		set  func(im *image)
		in   func(Row) bool
	}{
		{"kernel list", func(im *image) { im.link([]int{0, 1, 2}, []int{0, 1, 2, 3}, []int{1, 2}) }, func(r Row) bool { return r.KernelList }},
		{"session ring", func(im *image) { im.link([]int{0, 1, 2}, []int{0, 1, 2}, []int{1, 2, 3}) }, func(r Row) bool { return r.SessionRing }},
		{"pool scan", func(im *image) {
			im.link([]int{0, 1, 2}, []int{0, 1, 2}, []int{1, 2})
			im.pool = []processscan.Process{{Offset: phys(im.at[3])}}
		}, func(r Row) bool { return r.PoolScan }},
		{"thread owner", func(im *image) {
			im.link([]int{0, 1, 2}, []int{0, 1, 2}, []int{1, 2})
			im.owners = []threadscan.Owned{{Process: im.at[3]}, {Process: im.at[3]}}
		}, func(r Row) bool { return r.ThreadOwner }},
		{"csrss handle", func(im *image) {
			im.link([]int{0, 1, 2}, []int{0, 1, 2}, []int{1, 2})
			im.held = []uint64{im.at[3]}
		}, func(r Row) bool { return r.CsrssHandle }},
	} {
		t.Run(c.view, func(t *testing.T) {
			im := listedPlusOne()
			c.set(im)
			rows, diags := im.run(t, nil)
			r, ok := rowFor(rows, 6000)
			if !ok || !c.in(r) || r.ActiveList || !r.Hidden || r.Verdict != VerdictHidden {
				t.Fatalf("evil.exe %+v (diagnostics %q)", r, diags)
			}
			if r.Physical != phys(im.at[3]) {
				t.Errorf("physical 0x%x", r.Physical)
			}
			if !said(diags, "pid 6000: hidden, held by") {
				t.Errorf("no hidden diagnostic: %q", diags)
			}
			for _, other := range rows {
				if other.PID != 6000 && (other.Verdict != VerdictListed || !other.ActiveList) {
					t.Errorf("row %+v", other)
				}
			}
		})
	}
}

func TestAViewThatFindsAListedProcessJoinsItsRow(t *testing.T) {
	im := listedPlusOne()
	im.link([]int{0, 1, 2, 3}, []int{0, 1, 2, 3}, []int{1, 2, 3})
	im.pool = []processscan.Process{{Offset: phys(im.at[1]), TypeIndexFailed: true}}
	im.owners = []threadscan.Owned{{Process: im.at[1]}}
	im.held = []uint64{im.at[1]}
	rows, _ := im.run(t, nil)
	if len(rows) != 4 {
		t.Fatalf("%d rows", len(rows))
	}
	r, _ := rowFor(rows, 1300)
	if !(r.ActiveList && r.KernelList && r.SessionRing && r.PoolScan && r.ThreadOwner && r.CsrssHandle && r.TypeIndexUnconfirmed) {
		t.Errorf("svchost %+v", r)
	}
	if r.Address != im.at[1] || r.Physical != phys(im.at[1]) || r.Verdict != VerdictListed {
		t.Errorf("svchost %+v", r)
	}
}

func TestTheSessionRingHeadIsNotARow(t *testing.T) {
	im := listedPlusOne()
	im.link([]int{0, 1, 2, 3}, []int{0, 1, 2, 3}, []int{1, 2, 3})
	rows, diags := im.run(t, nil)
	if len(rows) != 4 {
		t.Fatalf("rows %+v", rows)
	}
	if !said(diags, "session rings 3 (0 rejected") {
		t.Errorf("summary %q", diags)
	}
}

func TestVerdicts(t *testing.T) {
	exitAt := boot + 600*tick
	im := newImage(
		proc{pid: 4, name: "System"},
		proc{pid: 1300, name: "svchost.exe", root: 0x2000},
		proc{pid: 3000, name: "gone.exe", exited: exitAt},
		proc{pid: 1300, name: "svchost.exe", root: 0x2000, created: boot + 2*tick},
		proc{pid: 1300, name: "svchost.exe", root: 0x9000, created: boot + 2*tick},
	)
	im.link([]int{0, 1}, []int{0, 1}, nil)
	for _, i := range []int{2, 3, 4} {
		im.pool = append(im.pool, processscan.Process{Offset: phys(im.at[i])})
	}
	rows, diags := im.run(t, nil)
	want := map[uint64]Verdict{phys(im.at[0]): VerdictListed, phys(im.at[1]): VerdictListed,
		phys(im.at[2]): VerdictExited, phys(im.at[3]): VerdictCopy, phys(im.at[4]): VerdictHidden}
	for _, r := range rows {
		if r.Verdict != want[r.Physical] || r.Hidden != (r.Verdict == VerdictHidden) {
			t.Errorf("pid %d at 0x%x: %s hidden %v, want %s", r.PID, r.Physical, r.Verdict, r.Hidden, want[r.Physical])
		}
	}
	gone, _ := rowFor(rows, 3000)
	if !gone.ExitTimeRead || !gone.ExitTime.Equal(time.Date(2026, 5, 6, 8, 10, 0, 0, time.UTC)) {
		t.Errorf("exit time %v read %v", gone.ExitTime, gone.ExitTimeRead)
	}
	if !said(diags, "page-table root 0x2000, this one 0x9000") {
		t.Errorf("no root diagnostic: %q", diags)
	}
}

func TestARunningUnlistedProcessIsOnlyUnlistedWhenTheWalkDidNotClose(t *testing.T) {
	im := listedPlusOne()
	im.link([]int{0, 1, 2}, []int{0, 1, 2}, nil)
	im.pool = []processscan.Process{{Offset: phys(im.at[3])}}
	im.k.put64(im.at[1]+offLinks, 0xffff9e0500000000)
	im.k.put64(im.at[2]+offLinks+8, 0xffff9e0500000000)
	rows, diags := im.run(t, nil)
	r, _ := rowFor(rows, 6000)
	if r.Verdict != VerdictUnlisted || r.Hidden {
		t.Errorf("evil.exe %+v", r)
	}
	if !said(diags, "active list walk did not close: 1 running unlisted") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestACandidateThatFailsTheCheckIsCountedNotListed(t *testing.T) {
	im := listedPlusOne()
	im.link([]int{0, 1, 2, 3}, []int{0, 1, 2, 3}, nil)
	im.k.put64(at(7)+offPID, 7)
	im.owners = []threadscan.Owned{{Process: at(7)}, {Process: 0xffff9e0600000000}}
	rows, diags := im.run(t, nil)
	if len(rows) != 4 || !said(diags, "thread owners 0 (2 rejected by the process check)") {
		t.Errorf("%d rows, diagnostics %q", len(rows), diags)
	}
}

func TestAViewThatFailsIsLeftOut(t *testing.T) {
	im := listedPlusOne()
	im.link([]int{0, 1, 2, 3}, []int{0, 1, 2, 3}, []int{1, 2, 3})
	im.src.pool = func(tools.Context) ([]processscan.Process, error) { return nil, errors.New("sweep failed") }
	rows, diags := im.run(t, nil)
	if len(rows) != 4 || !said(diags, "pool scan: failed, left out: sweep failed") {
		t.Errorf("diagnostics %q", diags)
	}
	ctx, _ := im.ctx(map[string]any{"strict": true})
	if _, err := run(ctx, im.src); err == nil || !strings.Contains(err.Error(), "pool scan") {
		t.Errorf("strict: %v", err)
	}
	im.src.pool = func(tools.Context) ([]processscan.Process, error) { return nil, nil }
	ctx, diags2 := im.ctx(map[string]any{"strict": true}, "KiProcessListHead")
	if _, err := run(ctx, im.src); err != nil || !said(*diags2, "kernel process list: failed, left out") {
		t.Errorf("an unavailable view in strict mode: %v %q", err, *diags2)
	}
}

func TestWithoutTranslationRowsAreKeyedByVirtualAddress(t *testing.T) {
	im := listedPlusOne()
	im.link([]int{0, 1, 2, 3}, []int{0, 1, 2, 3}, nil)
	ctx, diags := im.ctx(nil)
	ctx.Memory = flatKernel{im.k}
	rows, err := run(ctx, im.src)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 || rows[1].Physical != 0 || rows[1].Address != im.at[1] || !said(*diags, ErrNoTranslation.Error()) {
		t.Errorf("rows %+v diagnostics %q", rows, *diags)
	}
}

func TestThePIDOptionAndTheOrder(t *testing.T) {
	im := newImage(
		proc{pid: 900, name: "evil.exe"},
		proc{pid: 100, name: "svchost.exe"},
		proc{pid: 100, name: "svchost.exe", created: boot + 2*tick, root: 0x9000},
	)
	im.link([]int{1}, []int{1}, nil)
	im.pool = []processscan.Process{{Offset: phys(im.at[2])}, {Offset: phys(im.at[0])}}
	rows, _ := im.run(t, nil)
	var got []uint64
	for _, r := range rows {
		got = append(got, r.Physical)
	}
	if want := []uint64{phys(im.at[1]), phys(im.at[2]), phys(im.at[0])}; !slices.Equal(got, want) {
		t.Errorf("order %x, want %x", got, want)
	}
	rows, _ = im.run(t, map[string]any{"pid": uint64(900)})
	if len(rows) != 1 || rows[0].PID != 900 {
		t.Errorf("pid 900: %+v", rows)
	}
}

func TestTheToolNeedsWindowsAndPhysicalMemory(t *testing.T) {
	im := listedPlusOne()
	im.link([]int{0, 1, 2, 3}, nil, nil)
	ctx, _ := im.ctx(nil)
	delete(ctx.Options, tools.OptionPhysicalMemory)
	if _, err := run(ctx, im.src); !errors.Is(err, ErrNoPhysicalMemory) {
		t.Errorf("no physical memory: %v", err)
	}
	ctx, _ = im.ctx(nil)
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); err == nil {
		t.Error("a Linux profile was accepted")
	}
}
