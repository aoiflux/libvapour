package guistations

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/gui"
	"github.com/aoiflux/libvapour/tools/gui/guitest"
)

func fixture() *guitest.Fixture {
	return guitest.Build(guitest.Spec{Layout: gui.Layouts()[1], Stations: []guitest.StationSpec{
		{Name: "WinSta0", Session: 2},
		{Name: "Service-0x0-3e5$", Session: 0},
	}})
}

func TestRowsCarryNameSessionAndBothAddresses(t *testing.T) {
	f := fixture()
	env, err := gui.OpenLayout(f.Ctx, Name, f.Layout)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rows(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	for i, want := range []struct {
		name    string
		session uint32
	}{{"WinSta0", 2}, {"Service-0x0-3e5$", 0}} {
		s := got[i]
		if s.Name != want.name || s.SessionID != want.session || s.Address != f.Stations[i].Address ||
			s.Physical != f.Stations[i].Physical || s.OtherCopy != 0 {
			t.Fatalf("row %d: %+v", i, s)
		}
	}
}

func TestRunRefusesAnotherOSAndAMissingWin32kBase(t *testing.T) {
	f := fixture()
	if _, err := Run(f.Ctx); !errors.Is(err, gui.ErrNoWin32kBase) {
		t.Fatal(err)
	}
	f.Ctx.Profile = linux{f.Ctx.Profile}
	if _, err := Run(f.Ctx); err == nil || !strings.Contains(err.Error(), Name+": unsupported profile os") {
		t.Fatal(err)
	}
	if _, err := Run(tools.Context{}); err == nil {
		t.Fatal("empty context accepted")
	}
}

func TestTheToolIsRegistered(t *testing.T) {
	if _, err := tools.Get(Name); err != nil {
		t.Fatal("not registered")
	}
}

type linux struct{ profiles.Profile }

func (linux) OS() string { return "linux" }
