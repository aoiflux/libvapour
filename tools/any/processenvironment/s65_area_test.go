package processenvironment

import (
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const areaVA = uint64(0x7ffd00000000)

type linuxFixture struct {
	t     *testing.T
	k     *lt.Kernel
	us    *lt.UserSpaces
	tasks []uint64
}

func newLinuxFixture(t *testing.T) *linuxFixture {
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	return &linuxFixture{t: t, k: k, us: k.NewUserSpaces(16 << 20)}
}

// pages are the area's bytes per page; a nil page is left unmapped.
func (f *linuxFixture) task(pid int32, comm string, start, end uint64, pages ...[]byte) uint64 {
	pgd, as := f.us.New()
	for i, p := range pages {
		if p == nil {
			continue
		}
		pa := as.MapPage(areaVA + uint64(i)*0x1000)
		f.us.PM.WriteAt(pa, p)
	}
	mm := f.k.AddMM(lt.MM{PGD: pgd, EnvStart: start, EnvEnd: end})
	task := f.k.AddTask(lt.Task{PID: pid, TGID: pid, Comm: comm, MM: mm})
	f.tasks = append(f.tasks, task)
	f.k.LinkTasks(f.tasks...)
	return task
}

func (f *linuxFixture) run(options map[string]any) ([]LinuxEnvVar, []string, error) {
	ctx, diags := f.us.Context(options)
	rows, err := RunLinux(ctx)
	return rows, *diags, err
}

func keys(rows []LinuxEnvVar) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Key + "=" + r.Value
	}
	return out
}

func TestALinuxAreaGivesItsVariables(t *testing.T) {
	f := newLinuxFixture(t)
	area := []byte("HOME=/root\x00PATH=/usr/bin\x00A=b=c\x00")
	f.task(100, "bash", areaVA, areaVA+uint64(len(area)), area)
	rows, diags, err := f.run(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(keys(rows), []string{"HOME=/root", "PATH=/usr/bin", "A=b=c"}) || len(diags) != 0 {
		t.Fatalf("rows %q diags %q", keys(rows), diags)
	}
	if r := rows[0]; r.PID != 100 || r.Comm != "bash" || r.PPID != 0 {
		t.Errorf("row %+v", r)
	}
}

func TestATitleWrittenOverTheAreaIsSkipped(t *testing.T) {
	f := newLinuxFixture(t)
	area := []byte("daemon: running [host.local]\x00\x00\x00LANG=C\x00")
	f.task(200, "avahi-daemon", areaVA, areaVA+uint64(len(area)), area)
	rows, diags, _ := f.run(nil)
	if !slices.Equal(keys(rows), []string{"LANG=C"}) || !said(diags, "1 tasks with environment strings lacking a name, skipped") {
		t.Errorf("rows %q diags %q", keys(rows), diags)
	}
}

func TestAPartlyReadAreaDropsItsCutString(t *testing.T) {
	f := newLinuxFixture(t)
	first := make([]byte, 0x1000)
	copy(first, "A=1\x00")
	copy(first[0x1000-4:], "B=22")
	f.task(300, "app", areaVA, areaVA+0x1800, first, nil)
	rows, diags, _ := f.run(nil)
	if !slices.Equal(keys(rows), []string{"A=1"}) || !said(diags, "whose environment area reads only in part") {
		t.Errorf("rows %q diags %q", keys(rows), diags)
	}
}

func TestAreasThatGiveNothing(t *testing.T) {
	f := newLinuxFixture(t)
	f.task(400, "empty", areaVA, areaVA)
	f.task(401, "unread", areaVA, areaVA+0x10)
	f.task(402, "kernel-half", areaVA, 0xffff888000000000)
	rows, diags, err := f.run(nil)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %v err %v", rows, err)
	}
	for _, want := range []string{"1 tasks whose environment area does not read", "1 tasks with environment bounds outside user space"} {
		if !said(diags, want) {
			t.Errorf("missing %q in %q", want, diags)
		}
	}
}

func TestAnAreaOverTheBufferLimitIsCut(t *testing.T) {
	f := newLinuxFixture(t)
	area := []byte("A=1\x00B=2\x00")
	f.task(500, "big", areaVA, areaVA+1<<30, area)
	ctx, diags := f.us.Context(nil)
	ctx.Limits.MaxBufferBytes, ctx.Limits.MaxTextBytes, ctx.Limits.MaxNameBytes = 0x1000, 0x1000, 0x100
	rows, err := RunLinux(ctx)
	if err != nil || len(rows) != 2 || !said(*diags, "over MaxBufferBytes, cut") {
		t.Errorf("rows %q err %v diags %q", keys(rows), err, *diags)
	}
}

func TestThePIDSetNarrowsTheTasks(t *testing.T) {
	f := newLinuxFixture(t)
	area := []byte("A=1\x00")
	f.task(600, "a", areaVA, areaVA+uint64(len(area)), area)
	f.task(601, "b", areaVA, areaVA+uint64(len(area)), area)
	rows, _, _ := f.run(map[string]any{"pid": uint64(601)})
	if len(rows) != 1 || rows[0].PID != 601 {
		t.Errorf("rows %+v", rows)
	}
}

func TestRunRefusesLinuxAndRunLinuxWindows(t *testing.T) {
	f := newLinuxFixture(t)
	ctx, _ := f.us.Context(nil)
	if _, err := Run(ctx); err == nil {
		t.Error("Run took a linux profile")
	}
	if out, err := RunAny(ctx); err != nil {
		t.Errorf("RunAny: %v", err)
	} else if _, ok := out.([]LinuxEnvVar); !ok {
		t.Errorf("RunAny gave %T", out)
	}
	var w tools.Context
	w.Profile = nil
	if _, err := RunLinux(w); err == nil {
		t.Error("RunLinux took an empty context")
	}
}

func TestSplittingALinuxArea(t *testing.T) {
	a := splitLinuxArea([]byte("=x\x00\x00A=\x00B=\xff\x00tail"))
	if len(a.vars) != 2 || a.unnamed != 1 || a.vars[0].name != "A" || a.vars[1].value != "�" {
		t.Errorf("%+v", a)
	}
	if a := splitLinuxArea([]byte("NO=NUL")); len(a.vars) != 0 {
		t.Errorf("unterminated: %+v", a)
	}
}
