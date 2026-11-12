package threadorphaned

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/tools/windows/threadscan"
)

const (
	ethread    = uint64(0xffffd00000200000)
	driverBase = uint64(0xfffff80000100000)
)

var driver = modulelist.Module{Base: driverBase, Size: 0x10000, Name: "a.sys"}

// Each thread's _ETHREAD gets its own page so the physical-page rule can be
// tested against the start of the page.
func system(tid, start uint64) threadscan.Thread {
	return threadscan.Thread{Offset: 0x40000000 + tid*0x1000, VirtualOffset: ethread + tid*0x1000, PID: 4, TID: tid,
		Columns: threadscan.Columns{StartAddress: start, Win32StartAddress: start}}
}

type fixture struct {
	mem     testsupport.S51Memory
	threads []threadscan.Thread
	mods    []modulelist.Module
}

func newFixture(threads ...threadscan.Thread) *fixture {
	f := &fixture{mem: testsupport.S51Memory{}, threads: threads, mods: []modulelist.Module{driver}}
	for _, th := range threads {
		f.mem.Put32(th.VirtualOffset+testsupport.S51MiscFlags, 1<<testsupport.S51SystemBit)
		f.mem.Put32(th.VirtualOffset+testsupport.S51CrossFlags, 0)
	}
	return f
}

func (f *fixture) run(t *testing.T, strict bool, options map[string]any, omit ...string) ([]threadscan.Thread, string, error) {
	t.Helper()
	ctx, diags := testsupport.S51Context(f.mem, testsupport.S51Table(omit...), strict)
	for k, v := range options {
		ctx.Options[k] = v
	}
	rows, err := run(ctx, sources{
		modules: func(tools.Context) ([]modulelist.Module, error) { return f.mods, nil },
		threads: func(tools.Context) ([]threadscan.Thread, error) { return f.threads, nil },
	})
	return rows, strings.Join(*diags, "\n"), err
}

func TestASystemThreadStartingInNoModuleIsOrphaned(t *testing.T) {
	f := newFixture(system(16, driverBase+0x10), system(12, driverBase+0x20000), system(8, driverBase+0xffff))
	rows, diags, err := f.run(t, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].TID != 12 {
		t.Fatalf("rows %+v", rows)
	}
	if !strings.Contains(diags, "3 system threads: 0 terminated, 0 without a start address, 2 in a module, 1 in none") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestOnlyASystemThreadThatHasNotTerminatedIsJudged(t *testing.T) {
	user := system(8, 0x7ff600001000)
	user.PID = 1300
	done := system(12, 0x1000)
	f := newFixture(user, done, system(16, 0))
	f.mem.Put32(user.VirtualOffset+testsupport.S51MiscFlags, 0)
	testsupport.S51SetBit(f.mem, done.VirtualOffset+testsupport.S51CrossFlags, 0)
	rows, diags, err := f.run(t, false, nil)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if !strings.Contains(diags, "2 system threads: 1 terminated, 1 without a start address") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestADriverThreadOfAnotherProcessIsASystemThread(t *testing.T) {
	th := system(8, 0x5000)
	th.PID = 752
	rows, _, err := newFixture(th).run(t, false, nil)
	if err != nil || len(rows) != 1 {
		t.Errorf("rows %+v, %v", rows, err)
	}
}

func TestWithoutTheSystemThreadMemberProcess4IsTaken(t *testing.T) {
	other := system(8, 0x5000)
	other.PID = 752
	f := newFixture(system(12, 0x5000), other)
	rows, diags, err := f.run(t, false, nil, "_KTHREAD.SystemThread")
	if err != nil || len(rows) != 1 || rows[0].PID != 4 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if !strings.Contains(diags, "no _KTHREAD.SystemThread") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestAFlagThatDoesNotReadLeavesTheThreadUnexamined(t *testing.T) {
	lost := system(8, 0x5000)
	lost.VirtualOffset = 0
	lost.Offset = 0x40000ff0
	f := newFixture(system(12, 0x5000))
	f.threads = append(f.threads, lost)
	rows, diags, err := f.run(t, false, nil)
	if err != nil || len(rows) != 1 || rows[0].TID != 12 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if !strings.Contains(diags, "1 not examined") {
		t.Errorf("diagnostics %q", diags)
	}
	if _, _, err := f.run(t, true, nil); !errors.Is(err, ErrSystemFlagUnread) {
		t.Errorf("strict mode: %v", err)
	}
}

func TestThePIDOptionKeepsThatProcessThreads(t *testing.T) {
	other := system(8, 0x5000)
	other.PID = 752
	f := newFixture(system(12, 0x5000), other)
	rows, _, err := f.run(t, false, map[string]any{"pid": uint64(752)})
	if err != nil || len(rows) != 1 || rows[0].PID != 752 {
		t.Errorf("rows %+v, %v", rows, err)
	}
}

func TestNoModuleRangeMeansNoJudgement(t *testing.T) {
	f := newFixture(system(8, 0x5000))
	f.mods = []modulelist.Module{{Name: "a.sys", BaseUnreadable: true}}
	if _, _, err := f.run(t, false, nil); !errors.Is(err, ErrNoModuleRanges) {
		t.Errorf("err %v", err)
	}
}

func TestRowsAreInProcessThreadOrder(t *testing.T) {
	a, b := system(12, 0x5000), system(8, 0x6000)
	b.PID = 752
	rows, _, _ := newFixture(a, b).run(t, false, nil)
	if len(rows) != 2 || rows[0].PID != 4 || rows[1].PID != 752 {
		t.Errorf("rows %+v", rows)
	}
}
