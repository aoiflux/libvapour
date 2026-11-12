package guidesktops

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/gui"
	"github.com/aoiflux/libvapour/tools/gui/guitest"
)

func TestOneRowPerThreadAndOneForAThreadlessDesktop(t *testing.T) {
	for _, l := range gui.Layouts() {
		f := guitest.Build(guitest.Typical(l))
		env, err := gui.OpenLayout(f.Ctx, Name, f.Layout)
		if err != nil {
			t.Fatal(err)
		}
		groups, err := byStation(env)
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 2 || groups[0].Station != f.Stations[0].Address || len(groups[0].Desktops) != 2 {
			t.Fatalf("%s: groups %+v", l.Name, groups)
		}
		rows := groups[0].Rows
		if len(rows) != 3 {
			t.Fatalf("%s: rows %+v", l.Name, rows)
		}
		want := []Desktop{
			{Address: f.Stations[0].Desktops[0].Address, SessionID: 1, Station: "WinSta0", Name: "Default",
				TID: 0x104, PID: 0x40, Process: "explorer.exe"},
			{Address: f.Stations[0].Desktops[0].Address, SessionID: 1, Station: "WinSta0", Name: "Default",
				TID: 0x208, PID: 0x80, Process: "notepad.exe"},
			{Address: f.Stations[0].Desktops[1].Address, SessionID: 1, Station: "WinSta0", Name: "Winlogon",
				Threadless: true},
		}
		for i := range want {
			if rows[i] != want[i] {
				t.Fatalf("%s: row %d %+v, want %+v", l.Name, i, rows[i], want[i])
			}
		}
		if g := groups[1]; len(g.Rows) != 1 || g.Rows[0].Station != "Service-0x0-3e7$" || g.Rows[0].SessionID != 0 {
			t.Fatalf("%s: service station %+v", l.Name, g)
		}
	}
}

func TestAnOwnerThatDoesNotReadIsFlagged(t *testing.T) {
	l := gui.Layouts()[0]
	f := guitest.Build(guitest.Typical(l))
	info := f.Stations[0].Desktops[0].Threads[0]
	f.PutU64(info+l.Thread.ProcessInfo, 0)
	env, err := gui.OpenLayout(f.Ctx, Name, f.Layout)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := byStation(env)
	if err != nil {
		t.Fatal(err)
	}
	r := groups[0].Rows[0]
	if !r.ProcessUnreadable || r.Process != "" || r.PID != 0 || r.TID != 0x104 {
		t.Fatalf("%+v", r)
	}
}

func TestRunNeedsWin32kBase(t *testing.T) {
	f := guitest.Build(guitest.Typical(gui.Layouts()[0]))
	if _, err := Run(f.Ctx); !errors.Is(err, gui.ErrNoWin32kBase) {
		t.Fatal(err)
	}
	if _, err := tools.Get(Name); err != nil {
		t.Fatal(err)
	}
}
