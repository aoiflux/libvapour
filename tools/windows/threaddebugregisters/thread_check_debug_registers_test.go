package threaddebugregisters

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
	frames  = uint64(0xffffd00000800000)
	amsi    = uint64(0x7ff810000000)
)

type fixture struct {
	mem     testsupport.S51Memory
	threads []threadlist.Thread
	spaces  int
}

// A thread whose trap frame came from user mode with the given Dr7 and
// breakpoint addresses.
func (f *fixture) add(tid, dr7 uint64, addresses ...uint64) *threadlist.Thread {
	frame := frames + tid*0x1000
	f.mem.Put64(frame+testsupport.S51SegCs, testsupport.S51UserCodeSeg)
	f.mem.Put64(frame+testsupport.S51Rip, 0x7ff600001234)
	f.mem.Put64(frame+testsupport.S51Rsp, 0xa1f000)
	f.mem.Put64(frame+testsupport.S51Dr7, dr7)
	for i := range 4 {
		v := uint64(0)
		if i < len(addresses) {
			v = addresses[i]
		}
		f.mem.Put64(frame+testsupport.S51Dr0+8*uint64(i), v)
	}
	th := threadlist.Thread{PID: 1300, ProcessName: "app.exe", TID: tid, ETHREAD: ethread + tid*0x1000, StateName: "Waiting",
		TrapFrame: frame, Columns: threadscan.Columns{Process: owner}}
	f.mem.Put(th.ETHREAD, make([]byte, 8))
	f.threads = append(f.threads, th)
	return &f.threads[len(f.threads)-1]
}

func (f *fixture) run(t *testing.T, strict bool, omit ...string) ([]Thread, string, error) {
	t.Helper()
	ctx, diags := testsupport.S51Context(f.mem, testsupport.S51Table(omit...), strict)
	rows, err := run(ctx, sources{
		threads: func(tools.Context) ([]threadlist.Thread, error) { return f.threads, nil },
		spaces: func(ctx tools.Context) (*threadaddress.Spaces, error) {
			f.spaces++
			procs := []processlist.Process{{PID: 1300, Name: "app.exe", EPROCESS: owner}}
			return threadaddress.NewWith(ctx, procs, func(tools.Context, processlist.Process) ([]memoryranges.Mapping, error) {
				return []memoryranges.Mapping{{Start: amsi, End: amsi + 0xffff, Type: memoryranges.KindImage,
					Path: `\Windows\System32\amsi.dll`}}, nil
			}, func(tools.Context, pesymbols.Module) ([]pe.Export, error) {
				return []pe.Export{{Name: "AmsiScanBuffer", RVA: 0x2540}}, nil
			}), nil
		},
	})
	return rows, strings.Join(*diags, "\n"), err
}

func TestAnEnabledBreakpointIsPlacedAndNamed(t *testing.T) {
	f := &fixture{mem: testsupport.S51Memory{}}
	f.add(8, 1|1<<2, amsi+0x2540, 0xfffff80000001000)
	f.add(4, 0)
	rows, diags, err := f.run(t, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(rows[0].Breakpoints) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	b := rows[0].Breakpoints[0]
	if b.Index != 0 || b.Address != amsi+0x2540 || b.Export != "AmsiScanBuffer" || b.RangeType != memoryranges.KindImage ||
		b.Path != `\Windows\System32\amsi.dll` || b.Condition != ConditionExecute || b.Length != 1 || !b.Local {
		t.Errorf("breakpoint %+v", b)
	}
	if k := rows[0].Breakpoints[1]; k.Index != 1 || k.RangeType != "" || k.Export != "" {
		t.Errorf("kernel-address breakpoint %+v", k)
	}
	if rows[0].Dr7 != 5 || rows[0].DebugActive != 0 || rows[0].DebugActiveUnreadable {
		t.Errorf("row %+v", rows[0])
	}
	if !strings.Contains(diags, "1 breakpoint enabled") || !strings.Contains(diags, "1 no breakpoint enabled") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestStaleOrKernelFramesAreNotReported(t *testing.T) {
	f := &fixture{mem: testsupport.S51Memory{}}
	f.add(4, 0x6d121, 0x6d126)
	k := f.add(8, 1, amsi)
	f.mem.Put64(k.TrapFrame+testsupport.S51SegCs, testsupport.S51KernelCodeSeg)
	r := f.add(12, 1, amsi)
	f.mem.Put64(r.TrapFrame+testsupport.S51Rip, 0xfffff80000001000)
	f.threads = append(f.threads, threadlist.Thread{TID: 16}, threadlist.Thread{TID: 20, TrapFrameUnreadable: true})
	rows, diags, err := f.run(t, false)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	for _, want := range []string{"1 reserved bits set", "2 kernel-mode frame", "1 no trap frame", "1 trap frame pointer unread"} {
		if !strings.Contains(diags, want) {
			t.Errorf("diagnostics %q lack %q", diags, want)
		}
	}
	if f.spaces != 0 {
		t.Error("process ranges built with nothing to place")
	}
	if _, _, err := f.run(t, true); !errors.Is(err, ErrTrapFrameUnread) {
		t.Errorf("strict mode: %v", err)
	}
}

func TestAFrameThatDoesNotReadIsCounted(t *testing.T) {
	f := &fixture{mem: testsupport.S51Memory{}}
	f.threads = []threadlist.Thread{{TID: 4, TrapFrame: frames}}
	_, diags, err := f.run(t, false)
	if err != nil || !strings.Contains(diags, "1 trap frame unread") {
		t.Errorf("diagnostics %q, %v", diags, err)
	}
}

func TestTheDebugRegistersAreRequired(t *testing.T) {
	f := &fixture{mem: testsupport.S51Memory{}}
	for _, m := range []string{"_KTRAP_FRAME.Dr2", "_KTRAP_FRAME.Dr7", "_KTRAP_FRAME.SegCs"} {
		if _, _, err := f.run(t, false, m); !errors.Is(err, ErrLayout) {
			t.Errorf("without %s: %v", m, err)
		}
	}
}

func TestWithoutDebugActiveTheRowStillComes(t *testing.T) {
	f := &fixture{mem: testsupport.S51Memory{}}
	f.add(4, 1, amsi)
	rows, _, err := f.run(t, false, "_DISPATCHER_HEADER.DebugActive")
	if err != nil || len(rows) != 1 || rows[0].DebugActiveUnreadable {
		t.Errorf("rows %+v, %v", rows, err)
	}
}
