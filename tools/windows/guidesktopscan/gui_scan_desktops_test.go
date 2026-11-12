package guidesktopscan

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/gui"
	"github.com/aoiflux/libvapour/tools/gui/guitest"
)

func TestEveryDesktopWithAStationIsFound(t *testing.T) {
	l := gui.Layouts()[2]
	f := guitest.Build(guitest.Typical(l))
	env, err := gui.OpenLayout(f.Ctx, Name, f.Layout)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rows(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("%+v", got)
	}
	counts := map[string]int{}
	for _, r := range got {
		counts[r.Station+"/"+r.Name]++
		if r.Address == 0 {
			t.Fatalf("unplaced %+v", r)
		}
	}
	if counts["WinSta0/Default"] != 2 || counts["WinSta0/Winlogon"] != 1 || counts["Service-0x0-3e7$/Default"] != 1 {
		t.Fatalf("%v", counts)
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
