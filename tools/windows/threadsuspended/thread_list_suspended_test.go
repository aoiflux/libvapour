package threadsuspended

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/pesymbols"
	"github.com/aoiflux/libvapour/tools/windows/threadaddress"
	"github.com/aoiflux/libvapour/tools/windows/threadlist"
	"github.com/aoiflux/libvapour/tools/windows/threadscan"
)

const (
	owner   = uint64(0xffffd00000100000)
	ethread = uint64(0xffffd00000200000)
	ntdll   = uint64(0x7ff800000000)
)

func thread(tid uint64, count int32) threadlist.Thread {
	return threadlist.Thread{PID: 1300, ProcessName: "explorer.exe", TID: tid, ETHREAD: ethread + tid*0x1000,
		StateName: "Waiting", SuspendCount: count,
		Columns: threadscan.Columns{StartAddress: ntdll + 0x100, StartPath: `\Windows\System32\ntdll.dll`,
			Win32StartAddress: 0x7ff900001000, Process: owner}}
}

type fixture struct {
	mem     testsupport.S51Memory
	threads []threadlist.Thread
	exports int
}

func (f *fixture) run(t *testing.T, strict bool, omit ...string) ([]Thread, []string, error) {
	t.Helper()
	ctx, diags := testsupport.S51Context(f.mem, testsupport.S51Table(omit...), strict)
	rows, err := run(ctx, sources{
		threads: func(tools.Context) ([]threadlist.Thread, error) { return f.threads, nil },
		spaces: func(ctx tools.Context) (*threadaddress.Spaces, error) {
			procs := []processlist.Process{{PID: 1300, Name: "explorer.exe", EPROCESS: owner}}
			return threadaddress.NewWith(ctx, procs, func(tools.Context, processlist.Process) ([]memoryranges.Mapping, error) {
				return []memoryranges.Mapping{{Start: ntdll, End: ntdll + 0xffff, Type: memoryranges.KindImage}}, nil
			}, func(tools.Context, pesymbols.Module) ([]pe.Export, error) {
				f.exports++
				return []pe.Export{{Name: "RtlUserThreadStart", RVA: 0x100}}, nil
			}), nil
		},
	})
	return rows, *diags, err
}

func newFixture(threads ...threadlist.Thread) *fixture {
	f := &fixture{mem: testsupport.S51Memory{}, threads: threads}
	for _, th := range threads {
		f.mem.Put32(th.ETHREAD+testsupport.S51ThreadFlags, 0)
	}
	return f
}

func TestAThreadIsListedWhenItsSuspendCountIsAboveZero(t *testing.T) {
	f := newFixture(thread(8, 0), thread(4, 2), thread(12, 1))
	rows, diags, err := f.run(t, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].TID != 4 || rows[1].TID != 12 || rows[0].SuspendCount != 2 {
		t.Fatalf("rows %+v", rows)
	}
	r := rows[0]
	if r.StartExport != "RtlUserThreadStart" || r.Win32StartExport != "" || r.StartPath == "" || r.State != "Waiting" {
		t.Errorf("row %+v", r)
	}
	if f.exports != 1 {
		t.Errorf("export table read %d times, want once", f.exports)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "3 threads, 2 suspended") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestTheFreezeFlagIsReportedNotSelected(t *testing.T) {
	frozen := thread(4, 0)
	f := newFixture(frozen, thread(8, 1))
	testsupport.S51SetBit(f.mem, frozen.ETHREAD+testsupport.S51ThreadFlags, testsupport.S51FreezeBit)
	testsupport.S51SetBit(f.mem, f.threads[1].ETHREAD+testsupport.S51ThreadFlags, testsupport.S51FreezeBit)
	rows, _, err := f.run(t, false)
	if err != nil || len(rows) != 1 || !rows[0].Frozen || rows[0].FrozenUnreadable {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	f.mem = testsupport.S51Memory{}
	rows, _, _ = f.run(t, false)
	if len(rows) != 1 || rows[0].Frozen || !rows[0].FrozenUnreadable {
		t.Errorf("unread flag: %+v", rows)
	}
	rows, _, _ = f.run(t, false, "_KTHREAD.FreezeCount")
	if len(rows) != 1 || rows[0].Frozen || rows[0].FrozenUnreadable {
		t.Errorf("table without the flag: %+v", rows)
	}
}

func TestANegativeOrUnreadCountIsCountedNotListed(t *testing.T) {
	unread := thread(8, 0)
	unread.SuspendCountUnreadable = true
	f := newFixture(thread(4, -3), unread)
	rows, diags, err := f.run(t, false)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "suspend count unread on 1, negative on 1") {
		t.Errorf("diagnostics %q", diags)
	}
	if _, _, err := f.run(t, true); !errors.Is(err, ErrSuspendCountUnread) {
		t.Errorf("strict mode: %v", err)
	}
}

func TestAStartInKernelSpaceOrOfAnUnlistedOwnerIsNotNamed(t *testing.T) {
	kernel := thread(4, 1)
	kernel.StartAddress = 0xfffff80000001000
	stray := thread(8, 1)
	stray.Process = owner + 0x1000
	f := newFixture(kernel, stray)
	rows, diags, err := f.run(t, false)
	if err != nil || len(rows) != 2 || rows[0].StartExport != "" || rows[1].StartExport != "" {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "2 addresses of an owner not listed") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestAFailedThreadListFailsTheTool(t *testing.T) {
	ctx, _ := testsupport.S51Context(testsupport.S51Memory{}, testsupport.S51Table(), false)
	_, err := run(ctx, sources{threads: func(tools.Context) ([]threadlist.Thread, error) { return nil, errors.New("no list") }})
	if err == nil || !strings.HasPrefix(err.Error(), Name+": thread list") {
		t.Errorf("err %v", err)
	}
}
