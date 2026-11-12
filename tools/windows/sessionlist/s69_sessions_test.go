package sessionlist

import (
	"testing"
	"time"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/tools/any/processenvironment"
)

func TestProcessesComeInSessionOrderWithAbsentSessionsFirst(t *testing.T) {
	f := testsupport.NewS69Processes([]testsupport.FixtureProcess{
		{PID: 4, Name: "System"}, {PID: 600, Name: "winlogon.exe"}, {PID: 500, Name: "services.exe"},
		{PID: 700, Name: "explorer.exe"},
	})
	f.SetSession(600, 1)
	f.SetSession(500, 0)
	f.SetSession(700, 1)
	f.SetCreateTime(700, 133500000000000000)
	rows, err := Run(f.Context())
	if err != nil {
		t.Fatal(err)
	}
	var pids []uint64
	for _, r := range rows {
		pids = append(pids, r.PID)
	}
	want := []uint64{4, 500, 600, 700}
	if len(pids) != len(want) {
		t.Fatalf("pids %v, want %v", pids, want)
	}
	for i := range want {
		if pids[i] != want[i] {
			t.Fatalf("pids %v, want %v", pids, want)
		}
	}
	if rows[0].SessionID != SessionIDNotApplicable || rows[3].SessionID != 1 || rows[3].Process != "explorer.exe" {
		t.Errorf("rows = %+v", rows)
	}
	if !rows[3].CreateTime.Equal(time.Date(2024, time.January, 17, 21, 20, 0, 0, time.UTC)) {
		t.Errorf("CreateTime %v", rows[3].CreateTime)
	}
}

func TestThePIDOptionKeepsOnlyTheProcessesItNames(t *testing.T) {
	f := testsupport.NewS69Processes([]testsupport.FixtureProcess{{PID: 8, Name: "a"}, {PID: 12, Name: "b"}})
	ctx := f.Context()
	ctx.Options["pid"] = "12"
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || rows[0].PID != 12 {
		t.Errorf("rows %+v, err %v", rows, err)
	}
}

func TestTheFirstOfEachVariableNameWinsWhateverItsCase(t *testing.T) {
	got := variablesOf([]processenvironment.EnvVar{
		{PID: 8, Variable: "UserName", Value: "alice"}, {PID: 8, Variable: "USERNAME", Value: "mallory"},
		{PID: 8, Variable: "userdomain", Value: "CORP"}, {PID: 8, Variable: "SESSIONNAME", Value: "Console"},
		{PID: 8, Variable: "PATH", Value: `C:\x`}, {PID: 9, Variable: "USERNAME", Value: "SYSTEM$"},
	})
	if v := got[8]; v.user != "alice" || v.domain != "CORP" || v.session != "Console" {
		t.Errorf("pid 8 = %+v", v)
	}
	if v := got[9]; v.user != "SYSTEM$" || v.domain != "" {
		t.Errorf("pid 9 = %+v", v)
	}
}

func TestAccountName(t *testing.T) {
	for _, c := range []struct{ domain, user, want string }{
		{"CORP", "alice", `CORP\alice`}, {"", "alice", "alice"}, {"CORP", "", ""}, {"", "", ""},
	} {
		if got := accountName(c.domain, c.user); got != c.want {
			t.Errorf("accountName(%q, %q) = %q, want %q", c.domain, c.user, got, c.want)
		}
	}
}
