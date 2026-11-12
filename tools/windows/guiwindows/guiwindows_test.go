package guiwindows

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/gui"
	"github.com/aoiflux/libvapour/tools/gui/guitest"
)

func TestRowsFollowTheTreeWithOwnersTextAndProcedures(t *testing.T) {
	for _, l := range gui.Layouts() {
		f := guitest.Build(guitest.Typical(l))
		env, err := gui.OpenLayout(f.Ctx, Name, f.Layout)
		if err != nil {
			t.Fatal(err)
		}
		groups, err := byStation(f.Ctx, env)
		if err != nil {
			t.Fatal(err)
		}
		rows := groups[0].Rows
		if len(rows) != 5 || len(groups[1].Rows) != 0 {
			t.Fatalf("%s: %+v", l.Name, groups)
		}
		d := f.Stations[0].Desktops[0]
		notepad := rows[3]
		want := Window{Address: d.Windows[3].Address, SessionID: 1, Station: "WinSta0", Desktop: "Default",
			DesktopAddress: d.Address, Parent: d.Windows[0].Address, Depth: 1, Text: "Untitled - Notepad",
			Procedure: 0x7ff698760000, TID: 0x208, PID: 0x80, Process: "notepad.exe"}
		if notepad != want {
			t.Fatalf("%s: %+v, want %+v", l.Name, notepad, want)
		}
		if r := rows[4]; !r.ProcessUnreadable || r.TID != 0 || r.Text != "" || r.TextUnreadable {
			t.Fatalf("%s: ownerless %+v", l.Name, r)
		}
	}
}

func TestRejectedWindowsAreReported(t *testing.T) {
	l := gui.Layouts()[1]
	f := guitest.Build(guitest.Typical(l))
	w := f.Stations[0].Desktops[0].Windows[1]
	f.PutU64(w.Address+l.Window.Desktop, 0)
	var sink []string
	f.Ctx.Options["diagnostics"] = &sink
	env, err := gui.OpenLayout(f.Ctx, Name, f.Layout)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := byStation(f.Ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups[0].Rows) != 1 {
		t.Fatalf("%+v", groups[0].Rows)
	}
	if !strings.Contains(strings.Join(sink, "\n"), "windows left out with their subtrees: gui: object names another desktop 1") {
		t.Fatalf("%q", sink)
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
