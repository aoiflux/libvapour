package threadlist

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

const (
	userPID   = uint64(0x200)
	systemPID = uint64(4)
	vadStart  = uint64(0x00007ff700000000)
	vadEnd    = uint64(0x00007ff70000ffff)
	userTeb   = uint64(0x000000a000001000)
	tick      = uint64(10_000_000)
)

var (
	started = fileTime(time.Date(2026, 5, 6, 10, 0, 0, 0, time.UTC))
	exited  = fileTime(time.Date(2026, 5, 6, 11, 0, 0, 0, time.UTC))
)

func fileTime(t time.Time) uint64 {
	const secondsFrom1601To1970 = 11644473600
	return uint64(t.Unix()+secondsFrom1601To1970) * tick
}

type world struct {
	fx     *testsupport.ProcessFixture
	places []testsupport.S50Placement
	diags  *[]string
}

func (w world) ctx() tools.Context {
	ctx := w.fx.Context()
	ctx.Options["diagnostics"] = w.diags
	return ctx
}

func (w world) place(tid uint64) testsupport.S50Placement {
	for _, p := range w.places {
		if p.TID == tid {
			return p
		}
	}
	return testsupport.S50Placement{}
}

func standardThreads() []testsupport.S50Thread {
	module := testsupport.S50ModuleBase()
	return []testsupport.S50Thread{
		{TID: 8, Owner: systemPID, State: 5, WaitReason: 6, Priority: 13, Created: started,
			Start: module + 0x1000, Win32Start: module + 0x1000},
		{TID: 0x210, Owner: userPID, State: 5, WaitReason: 5, SuspendCount: 1, Priority: 8, Teb: userTeb,
			Created: started, Start: vadStart + 0x10, Win32Start: vadStart + 0x20,
			TrapFrame: &testsupport.S50TrapFrame{Rip: vadStart + 0x30, Rsp: 0x000000a000100000, SegCs: 0x33,
				SegSs: 0x2b, EFlags: 0x246, Rax: 7}},
		{TID: 0x214, Owner: userPID, State: 4, WaitReason: 22, Teb: userTeb + 0x2000, Created: started,
			Exited: exited, Start: 0xffffd00000123450, StartInvalid: true, Win32Start: vadStart + 0x40,
			TrapFrame: &testsupport.S50TrapFrame{Rip: 0xfffff80000400000, Rsp: 0xfffff80000500000, SegCs: 0x10}},
		{TID: 0x218, Owner: userPID, State: 5, Teb: userTeb + 0x4000, Created: started, Unlisted: true},
	}
}

func build(t testing.TB, threads []testsupport.S50Thread) world {
	t.Helper()
	fx := testsupport.BuildProcessFixture([]testsupport.FixtureProcess{
		{PID: systemPID, Name: "System", NoPeb: true},
		{PID: userPID, Name: "app.exe", NoPeb: true,
			VADs: []testsupport.FixtureVAD{{Start: vadStart, End: vadEnd, Path: `\Windows\System32\app.dll`}}},
	})
	places := fx.AddS50Threads(threads, `\SystemRoot\system32\ntoskrnl.exe`)
	return world{fx: fx, places: places, diags: &[]string{}}
}

func TestTheListGivesEachThreadOnItsProcessList(t *testing.T) {
	w := build(t, standardThreads())
	rows, err := Run(w.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("%d rows, want the 3 listed threads (diagnostics %q)", len(rows), *w.diags)
	}
	sys, user, gone := rows[0], rows[1], rows[2]
	sysEP, _ := w.fx.EPROCESS(systemPID)
	userEP, _ := w.fx.EPROCESS(userPID)

	if sys.PID != systemPID || sys.ProcessName != "System" || sys.TID != 8 || sys.ListEPROCESS != sysEP ||
		sys.ETHREAD != w.place(8).Virtual || sys.Process != sysEP {
		t.Errorf("system thread identity %+v", sys)
	}
	if sys.StartPath != `\SystemRoot\system32\ntoskrnl.exe` || sys.Win32StartPath != sys.StartPath {
		t.Errorf("a start address in system space names its module: %q, %q", sys.StartPath, sys.Win32StartPath)
	}
	if sys.Teb != 0 || sys.TebUnreadable || sys.TrapFrame != 0 || sys.TrapFrameUnreadable {
		t.Errorf("system thread Teb 0x%x TrapFrame 0x%x", sys.Teb, sys.TrapFrame)
	}

	if user.PID != userPID || user.TID != 0x210 || user.ListEPROCESS != userEP || user.Process != userEP {
		t.Errorf("user thread identity %+v", user)
	}
	if user.State != 5 || user.StateName != "Waiting" || user.WaitReason != 5 || user.WaitReasonName != "Suspended" {
		t.Errorf("state %d %q, wait reason %d %q", user.State, user.StateName, user.WaitReason, user.WaitReasonName)
	}
	if user.SuspendCount != 1 || user.Priority != 8 || user.Teb != userTeb || user.TrapFrame != w.place(0x210).TrapFrame {
		t.Errorf("suspend %d priority %d teb 0x%x frame 0x%x", user.SuspendCount, user.Priority, user.Teb, user.TrapFrame)
	}
	if user.StartPath != `\Windows\System32\app.dll` || user.Win32StartPath != user.StartPath {
		t.Errorf("a start address in a file VAD names its file: %q, %q", user.StartPath, user.Win32StartPath)
	}
	if want, _ := time.Parse(time.RFC3339, "2026-05-06T10:00:00Z"); !user.CreateTime.Equal(want) || user.CreateTimeUnreadable {
		t.Errorf("CreateTime %v", user.CreateTime)
	}
	if !user.ExitTime.IsZero() || user.ExitTimeUnreadable {
		t.Errorf("a live thread's ExitTime holds its own address, no time: %v unread %v", user.ExitTime, user.ExitTimeUnreadable)
	}

	if gone.State != 4 || gone.StateName != "Terminated" || gone.WaitReasonName != "WrTerminated" {
		t.Errorf("exited thread state %q wait %q", gone.StateName, gone.WaitReasonName)
	}
	if want, _ := time.Parse(time.RFC3339, "2026-05-06T11:00:00Z"); !gone.ExitTime.Equal(want) {
		t.Errorf("ExitTime %v", gone.ExitTime)
	}
	if gone.StartAddress != 0 || !gone.StartAddressInvalid || gone.StartAddressUnreadable || gone.StartPath != "" {
		t.Errorf("StartAddressInvalid set: address 0x%x invalid %v path %q", gone.StartAddress, gone.StartAddressInvalid, gone.StartPath)
	}
	if gone.Win32StartPath != `\Windows\System32\app.dll` {
		t.Errorf("Win32StartPath %q", gone.Win32StartPath)
	}
}

func TestThePIDOptionKeepsOnlyThatProcesssThreads(t *testing.T) {
	w := build(t, standardThreads())
	ctx := w.ctx()
	ctx.Options["pid"] = []uint64{systemPID}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].TID != 8 {
		t.Fatalf("rows %+v, want only TID 8", rows)
	}
}

func TestAValueOutsideTheEnumerationHasNoName(t *testing.T) {
	w := build(t, []testsupport.S50Thread{{TID: 8, Owner: systemPID, State: 7, WaitReason: 39, Created: started}})
	rows, err := Run(w.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].State != 7 || rows[0].StateName != "" || rows[0].WaitReason != 39 || rows[0].WaitReasonName != "" {
		t.Fatalf("rows %+v", rows)
	}
}

func TestANegativePriorityStaysNegative(t *testing.T) {
	w := build(t, []testsupport.S50Thread{{TID: 8, Owner: systemPID, Priority: -2, SuspendCount: -1, Created: started}})
	rows, err := Run(w.ctx())
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if rows[0].Priority != -2 || rows[0].SuspendCount != -1 {
		t.Errorf("priority %d suspend %d, want the signed values", rows[0].Priority, rows[0].SuspendCount)
	}
}

func breakList(w world) {
	place := w.place(0x210)
	w.fx.Memory.WriteU64(place.Physical+testsupport.S50ThreadListEntry, 0)
}

func TestABrokenThreadListIsReportedAndRecovered(t *testing.T) {
	w := build(t, standardThreads())
	breakList(w)
	rows, err := Run(w.ctx())
	if err != nil {
		t.Fatal(err)
	}
	tids := map[uint64]bool{}
	for _, r := range rows {
		tids[r.TID] = true
	}
	if !tids[0x210] || !tids[0x214] {
		t.Errorf("the walk from the Blink side recovers 0x214: %v", tids)
	}
	if !hasDiag(*w.diags, "list link is null") {
		t.Errorf("no diagnostic for the null link: %q", *w.diags)
	}
}

func TestStrictModeRefusesABrokenThreadList(t *testing.T) {
	w := build(t, standardThreads())
	breakList(w)
	ctx := w.ctx()
	ctx.Options["strict"] = true
	if _, err := Run(ctx); !errors.Is(err, winkernel.ErrListNull) {
		t.Fatalf("err %v, want ErrListNull", err)
	}
}

func TestAThreadTheCheckRejectsIsKeptAndReported(t *testing.T) {
	w := build(t, []testsupport.S50Thread{{TID: 8, Owner: systemPID, CidPID: 3, Created: started}})
	rows, err := Run(w.ctx())
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if !hasDiag(*w.diags, "thread check") {
		t.Errorf("no diagnostic: %q", *w.diags)
	}
}

func TestTheListMembersAreRequired(t *testing.T) {
	w := build(t, standardThreads())
	tab := w.fx.Table
	ethread, _ := tab.Struct("_ETHREAD")
	var kept []symbols.Field
	for _, f := range ethread.Fields {
		if f.Name != "ThreadListEntry" {
			kept = append(kept, f)
		}
	}
	ethread.Fields = kept
	tab.AddStruct(ethread)
	if _, err := Run(w.ctx()); !errors.Is(err, ErrNoListMember) {
		t.Fatalf("err %v, want ErrNoListMember", err)
	}
}

func TestATableWithoutTheEnumerationsLeavesNamesEmptyAndSaysSo(t *testing.T) {
	diags := []string{}
	ctx := tools.Context{Symbols: symbols.NewTable("bare", 8), Options: map[string]any{"diagnostics": &diags}}
	if names := enumNames(ctx, "_KTHREAD_STATE", "StateName"); len(names) != 0 {
		t.Errorf("names %v", names)
	}
	if !hasDiag(diags, "symbol table has no _KTHREAD_STATE") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestRunAnyReportsAColumnTheTableLacks(t *testing.T) {
	w := build(t, standardThreads())
	tab := w.fx.Table
	ethread, _ := tab.Struct("_ETHREAD")
	var kept []symbols.Field
	for _, f := range ethread.Fields {
		if f.Name != "CreateTime" {
			kept = append(kept, f)
		}
	}
	ethread.Fields = kept
	tab.AddStruct(ethread)
	out, err := RunAny(w.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if rows := out.([]Thread); len(rows) != 3 || !rows[0].CreateTimeUnreadable {
		t.Fatalf("rows %+v", rows)
	}
	if !hasDiag(*w.diags, "symbol table has no _ETHREAD.CreateTime") {
		t.Errorf("diagnostics %q", *w.diags)
	}
}

func hasDiag(diags []string, part string) bool {
	for _, d := range diags {
		if strings.Contains(d, part) {
			return true
		}
	}
	return false
}
