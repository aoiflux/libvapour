package processscan

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
)

type winWorld struct {
	f     *testsupport.ProcessFixture
	diags []string
}

func newWinWorld(procs ...testsupport.FixtureProcess) *winWorld {
	return &winWorld{f: testsupport.BuildPooledProcessFixture(procs)}
}

func (w *winWorld) ctx(options map[string]any) tools.Context {
	ctx := w.f.Context()
	ctx.Options["diagnostics"] = &w.diags
	for k, v := range options {
		ctx.Options[k] = v
	}
	return ctx
}

func said(diags []string, part string) bool {
	return slices.ContainsFunc(diags, func(d string) bool { return strings.Contains(d, part) })
}

func pooled() []testsupport.FixtureProcess {
	return []testsupport.FixtureProcess{
		{PID: 4, Name: "System", NoPeb: true},
		{PID: 1300, Name: "svchost.exe", NoPeb: true},
		{PID: 2400, Name: "hidden.exe", NoPeb: true, Unlinked: true},
	}
}

func TestThePoolScanFindsListedAndUnlinkedProcesses(t *testing.T) {
	w := newWinWorld(pooled()...)
	rows, err := Run(w.ctx(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows %+v diags %q", rows, w.diags)
	}
	for _, r := range rows {
		va, pa := w.f.EPROCESS(r.PID)
		if r.Offset != pa || r.VirtualOffset != va || r.OtherCopy != 0 || r.TypeIndexFailed {
			t.Errorf("pid %d: %+v, want physical 0x%x kernel 0x%x", r.PID, r, pa, va)
		}
	}
	if rows[2].Name != "hidden.exe" {
		t.Errorf("order: %+v", rows)
	}
	if !said(w.diags, "any.process.scan: 3 processes from 3 tag hits") ||
		!said(w.diags, "lacks _EPROCESS.Pcb.Header.Type") {
		t.Errorf("diags %q", w.diags)
	}
}

func TestABodyTheProcessCheckRefusesIsCounted(t *testing.T) {
	w := newWinWorld(testsupport.FixtureProcess{PID: 4, Name: "System", NoPeb: true},
		testsupport.FixtureProcess{PID: 6, Name: "odd.exe", NoPeb: true})
	rows, err := Run(w.ctx(nil))
	if err != nil || len(rows) != 1 || rows[0].PID != 4 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if !said(w.diags, "1 bodies refused by the process check: id is 0, not a multiple of 4, or wider than a dword 1") {
		t.Errorf("diags %q", w.diags)
	}
}

func TestThePIDSetNarrowsTheTool(t *testing.T) {
	w := newWinWorld(pooled()...)
	out, err := RunAny(w.ctx(map[string]any{"pid": "2400"}))
	rows, _ := out.([]Process)
	if err != nil || len(rows) != 1 || rows[0].PID != 2400 {
		t.Errorf("rows %+v err %v", rows, err)
	}
}

func TestTheScanNeedsPhysicalMemoryAndWindows(t *testing.T) {
	w := newWinWorld(pooled()...)
	ctx := w.ctx(nil)
	delete(ctx.Options, tools.OptionPhysicalMemory)
	if _, err := Run(ctx); !errors.Is(err, ErrNoPhysicalMemory) {
		t.Errorf("err %v", err)
	}
	ctx = w.ctx(nil)
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); err == nil {
		t.Error("Run took a linux profile")
	}
}

func TestProcessesAtAPhysicalOffset(t *testing.T) {
	w := newWinWorld(pooled()...)
	va, pa := w.f.EPROCESS(1300)
	procs, set, err := ProcessesAtOffset(w.ctx(map[string]any{"t.offset": pa}), "t", "t.offset")
	if err != nil || !set || len(procs) != 1 || procs[0].PID != 1300 || procs[0].EPROCESS != va {
		t.Fatalf("procs %+v set %v err %v", procs, set, err)
	}
	if !said(w.diags, "t: _EPROCESS at physical") {
		t.Errorf("diags %q", w.diags)
	}
	w.diags = nil
	if procs, set, _ := ProcessesAtOffset(w.ctx(map[string]any{"t.offset": pa, "pid": uint64(4)}), "t", "t.offset"); len(procs) != 0 || !set ||
		!said(w.diags, "pid 1300 (svchost.exe) is outside the pid set") {
		t.Errorf("pid set: %+v %q", procs, w.diags)
	}
	w.diags = nil
	if procs, set, _ := ProcessesAtOffset(w.ctx(map[string]any{"t.offset": uint64(0x123)}), "t", "t.offset"); len(procs) != 0 || !set ||
		!said(w.diags, "found no _EPROCESS at physical 0x123") {
		t.Errorf("no match: %+v %q", procs, w.diags)
	}
	w.diags = nil
	if _, set, _ := ProcessesAtOffset(w.ctx(map[string]any{"t.offset": uint64(0)}), "t", "t.offset"); set || !said(w.diags, "is 0") {
		t.Errorf("zero: %v %q", set, w.diags)
	}
	page, _ := w.f.Memory.ReadAt(pa&^0xfff, 0x1000)
	copyPA := w.f.Memory.AllocPage()
	w.f.Memory.WriteAt(copyPA, page)
	unmapped := copyPA + pa&0xfff
	w.f.Memory.WriteU64(unmapped+testsupport.FixturePIDOffset, 1304)
	w.diags = nil
	if procs, _, _ := ProcessesAtOffset(w.ctx(map[string]any{"t.offset": unmapped}), "t", "t.offset"); len(procs) != 0 ||
		!said(w.diags, "the kernel maps no address of it") {
		t.Errorf("unmapped: %+v %q", procs, w.diags)
	}
	if _, set, err := ProcessesAtOffset(w.ctx(nil), "t", "t.offset"); set || err != nil {
		t.Errorf("unset: %v %v", set, err)
	}
	if _, _, err := ProcessesAtOffset(w.ctx(map[string]any{"t.offset": "x"}), "t", "t.offset"); err == nil {
		t.Error("a wrong option type was taken")
	}
}
