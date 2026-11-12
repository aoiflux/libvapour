package joblist

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

func fixture() *testsupport.S69Processes {
	return testsupport.NewS69Processes([]testsupport.FixtureProcess{
		{PID: 100, Name: "svchost.exe", Parent: 4},
		{PID: 200, Name: "worker.exe", Parent: 100},
		{PID: 300, Name: "alone.exe", Parent: 4},
		{PID: 400, Name: "other.exe", Parent: 4},
	})
}

func run(t *testing.T, ctx tools.Context) []Row {
	t.Helper()
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestEachJobIsListedOnceUnderItsFirstProcess(t *testing.T) {
	f := fixture()
	job := f.AddJob(5, 2, 1, 1, 100, 200)
	f.SetImagePath(100, `\Device\HarddiskVolume3\Windows\System32\svchost.exe`)
	f.SetImagePath(200, `\Device\HarddiskVolume3\w\worker.exe`)
	f.SetSession(100, 1)
	rows := run(t, f.Context())
	if len(rows) != 3 {
		t.Fatalf("rows = %+v, want the job's row and its two members", rows)
	}
	head := rows[0]
	if head.Depth != 0 || head.PID != 100 || head.Job != job || head.Process != OriginalProcessLabel || head.IsJobLink ||
		head.Total != 5 || head.Active != 2 || head.Terminated != 1 || head.JobSessionID != 1 ||
		head.TotalUnreadable || head.ActiveUnreadable || head.TerminatedUnreadable || head.JobSessionIDUnreadable ||
		head.SessionID != 1 || head.PPID != 4 || head.Name != "svchost.exe" {
		t.Errorf("job row = %+v", head)
	}
	for i, want := range []struct {
		pid  uint64
		path string
	}{{100, `\Device\HarddiskVolume3\Windows\System32\svchost.exe`}, {200, `\Device\HarddiskVolume3\w\worker.exe`}} {
		m := rows[i+1]
		if m.Depth != 1 || !m.IsJobLink || m.PID != want.pid || m.Process != want.path || m.ProcessUnreadable || m.Job != job {
			t.Errorf("member %d = %+v", i, m)
		}
	}
	if rows[2].PPID != 100 || rows[2].Name != "worker.exe" {
		t.Errorf("member 200 = %+v", rows[2])
	}
}

func TestThePIDOptionKeepsOnlyTheProcessesItNames(t *testing.T) {
	f := fixture()
	f.AddJob(2, 2, 0, 0, 100, 200)
	ctx := f.Context()
	ctx.Options["pid"] = "200"
	rows := run(t, ctx)
	if len(rows) != 2 || rows[0].PID != 200 || rows[0].Depth != 0 || rows[1].PID != 200 || rows[1].Depth != 1 {
		t.Errorf("rows = %+v, want process 200 heading the job and as its member", rows)
	}
}

func TestAListEntryOfAnotherJobIsNotAMember(t *testing.T) {
	f := fixture()
	f.AddJob(2, 2, 0, 0, 100, 300)
	f.AddJob(1, 1, 0, 0, 300)
	rows := run(t, f.Context())
	var members []uint64
	for _, r := range rows {
		if r.Depth == 1 {
			members = append(members, r.PID)
		}
	}
	if len(members) != 2 || members[0] != 100 || members[1] != 300 {
		t.Errorf("members %v, want 100 under the first job and 300 under its own", members)
	}
}

func TestAMemberWithoutAPathIsFlagged(t *testing.T) {
	f := fixture()
	f.AddJob(1, 1, 0, 0, 400)
	rows := run(t, f.Context())
	if len(rows) != 2 || !rows[1].ProcessUnreadable || rows[1].Process != "" {
		t.Errorf("rows = %+v", rows)
	}
}

func TestPhysicalPlacesEveryRow(t *testing.T) {
	f := fixture()
	f.AddJob(1, 1, 0, 0, 300)
	ctx := f.Context()
	ctx.Options[OptionPhysical] = true
	rows := run(t, ctx)
	_, pa := f.EPROCESS(300)
	for _, r := range rows {
		if r.Physical != pa || r.PhysicalUnknown {
			t.Errorf("row = %+v, want physical 0x%x", r, pa)
		}
	}
	ctx.Options[OptionPhysical] = "yes please"
	if _, err := Run(ctx); err == nil {
		t.Error("a physical option of the wrong form is accepted")
	}
}

func TestAMissingCounterIsMarkedOnTheJob(t *testing.T) {
	f := fixture()
	st, _ := f.Table.Struct("_EJOB")
	st.Fields = st.Fields[:1]
	f.Table.AddStruct(st)
	f.AddJob(1, 1, 0, 0, 300)
	rows := run(t, f.Context())
	if len(rows) != 2 || !rows[0].TotalUnreadable || !rows[0].ActiveUnreadable || !rows[0].TerminatedUnreadable ||
		!rows[0].JobSessionIDUnreadable {
		t.Errorf("rows = %+v", rows)
	}
}

func TestAJobThatDoesNotReadHasNoMembers(t *testing.T) {
	f := fixture()
	ep, _ := f.EPROCESS(300)
	_, pa := f.EPROCESS(300)
	f.Memory.WriteU64(pa+testsupport.S69ProcessJob, 0xfffff80000f00000)
	rows := run(t, f.Context())
	if len(rows) != 1 || rows[0].EPROCESS != ep || !rows[0].TotalUnreadable {
		t.Errorf("rows = %+v", rows)
	}
}

func TestATableWithoutJobMembersIsAnError(t *testing.T) {
	f := fixture()
	f.Table.AddStruct(symbols.StructType{Name: "_EJOB", Size: 0x100})
	if _, err := Run(f.Context()); !errors.Is(err, ErrNoJobType) {
		t.Errorf("err = %v", err)
	}
}
