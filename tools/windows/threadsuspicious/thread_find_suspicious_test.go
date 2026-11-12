package threadsuspicious

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
	heap    = uint64(0x20000)
	mapped  = uint64(0x40000)
)

var ranges = []memoryranges.Mapping{
	{Start: heap, End: heap + 0xffff, Type: memoryranges.KindPrivate, Protection: "PAGE_EXECUTE_READWRITE"},
	{Start: mapped, End: mapped + 0xffff, Type: memoryranges.KindMapped, Protection: "PAGE_READONLY", Path: `\data.bin`},
	{Start: 0x60000, End: 0x6ffff, Type: memoryranges.KindUnknown},
	{Start: ntdll, End: ntdll + 0xffff, Type: memoryranges.KindImage, Protection: "PAGE_EXECUTE_WRITECOPY",
		Path: `\Windows\System32\ntdll.dll`},
}

func thread(tid, win32 uint64) threadlist.Thread {
	return threadlist.Thread{PID: 1300, ProcessName: "app.exe", TID: tid, ETHREAD: ethread + tid*0x1000, StateName: "Waiting",
		Columns: threadscan.Columns{StartAddress: ntdll + 0x100, Win32StartAddress: win32, Process: owner}}
}

type fixture struct {
	mem     testsupport.S51Memory
	threads []threadlist.Thread
	ranges  []memoryranges.Mapping
	walkErr error
}

func newFixture(threads ...threadlist.Thread) *fixture {
	f := &fixture{mem: testsupport.S51Memory{}, threads: threads, ranges: ranges}
	for _, th := range threads {
		f.mem.Put32(th.ETHREAD+testsupport.S51MiscFlags, 0)
	}
	f.mem.Put64(owner+testsupport.S51VadCount, uint64(len(ranges)))
	f.mem.Put64(owner+testsupport.S51SecureState, 0)
	return f
}

func (f *fixture) run(t *testing.T, strict bool) ([]Thread, string, error) {
	t.Helper()
	ctx, diags := testsupport.S51Context(f.mem, testsupport.S51Table(), strict)
	rows, err := run(ctx, sources{
		threads: func(tools.Context) ([]threadlist.Thread, error) { return f.threads, nil },
		spaces: func(ctx tools.Context) (*threadaddress.Spaces, error) {
			procs := []processlist.Process{{PID: 1300, Name: "app.exe", EPROCESS: owner}}
			return threadaddress.NewWith(ctx, procs, func(tools.Context, processlist.Process) ([]memoryranges.Mapping, error) {
				return f.ranges, f.walkErr
			}, func(tools.Context, pesymbols.Module) ([]pe.Export, error) { return nil, nil }), nil
		},
	})
	return rows, strings.Join(*diags, "\n"), err
}

func TestEachKindOfRangeGivesItsFinding(t *testing.T) {
	f := newFixture(thread(4, ntdll+0x200), thread(8, heap+0x10), thread(12, mapped), thread(16, 0x90000), thread(20, 0x60000))
	rows, diags, err := f.run(t, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		tid     uint64
		finding Finding
		typ     string
	}{{8, FindingStartPrivate, memoryranges.KindPrivate}, {12, FindingStartMappedFile, memoryranges.KindMapped},
		{16, FindingStartUnmapped, ""}}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v", rows)
	}
	for i, w := range want {
		r := rows[i]
		if r.TID != w.tid || r.Finding != w.finding || r.RangeType != w.typ || r.AddressKind != AddressWin32Start {
			t.Errorf("row %d = %+v, want tid %d %s", i, r, w.tid, w.finding)
		}
	}
	if rows[0].RangeStart != heap || rows[0].Protection != "PAGE_EXECUTE_READWRITE" || rows[1].Path != `\data.bin` {
		t.Errorf("range columns %+v %+v", rows[0], rows[1])
	}
	if !strings.Contains(diags, "1 in a range of unknown kind") || !strings.Contains(diags, "6 in an image") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestBothStartAddressesAreExaminedStartFirst(t *testing.T) {
	th := thread(4, heap)
	th.StartAddress = heap + 0x20
	rows, _, _ := newFixture(th).run(t, false)
	if len(rows) != 2 || rows[0].AddressKind != AddressStart || rows[1].AddressKind != AddressWin32Start {
		t.Errorf("rows %+v", rows)
	}
}

func TestAnAddressInNoRangeOfAShortWalkIsNotJudged(t *testing.T) {
	f := newFixture(thread(4, 0x90000))
	f.mem.Put64(owner+testsupport.S51VadCount, uint64(len(ranges))+1)
	rows, diags, _ := f.run(t, false)
	if len(rows) != 0 || !strings.Contains(diags, "in no range of a short walk") {
		t.Errorf("rows %+v, diagnostics %q", rows, diags)
	}
	f.mem.Put64(owner+testsupport.S51VadCount, uint64(len(ranges)))
	f.mem.Put64(owner+testsupport.S51SecureState, 1)
	if rows, _, _ := f.run(t, false); len(rows) != 0 {
		t.Errorf("secure process rows %+v", rows)
	}
}

func TestThreadsThatCannotBeJudgedAreCounted(t *testing.T) {
	sys := thread(4, heap)
	stray := thread(8, heap)
	stray.Process = owner + 0x1000
	kernel := thread(12, 0)
	kernel.StartAddress = 0xffff9d0169868300
	unread := thread(16, heap)
	unread.Win32StartAddressUnreadable = true
	unread.StartAddressUnreadable = true
	f := newFixture(sys, stray, kernel, unread)
	testsupport.S51SetBit(f.mem, sys.ETHREAD+testsupport.S51MiscFlags, testsupport.S51SystemBit)
	rows, diags, err := f.run(t, false)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	for _, want := range []string{"1 owner not listed", "1 system thread", "1 not a user address", "1 zero", "2 unread"} {
		if !strings.Contains(diags, want) {
			t.Errorf("diagnostics %q lack %q", diags, want)
		}
	}
}

func TestAnOwnerWithoutRangesOrAFailedWalkIsNotExamined(t *testing.T) {
	f := newFixture(thread(4, heap), thread(8, heap))
	f.ranges = nil
	rows, diags, _ := f.run(t, false)
	if len(rows) != 0 || !strings.Contains(diags, "2 owner has no ranges") {
		t.Errorf("rows %+v, diagnostics %q", rows, diags)
	}
	f.walkErr = errors.New("tree unread")
	rows, diags, _ = f.run(t, false)
	if len(rows) != 0 || strings.Count(diags, "range walk failed:") != 1 {
		t.Errorf("rows %+v, diagnostics %q", rows, diags)
	}
	if _, _, err := f.run(t, true); err == nil {
		t.Error("strict mode keeps going past a failed walk")
	}
}

func TestAFlagThatDoesNotReadIsAnErrorInStrictMode(t *testing.T) {
	f := newFixture(thread(4, heap))
	f.mem = testsupport.S51Memory{}
	if _, _, err := f.run(t, true); !errors.Is(err, ErrSystemFlagUnread) {
		t.Errorf("err %v", err)
	}
}
