package gui_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/gui"
	"github.com/aoiflux/libvapour/tools/gui/guitest"
)

const tool = "windows.gui.test"

func spec(l gui.Layout) guitest.Spec { return guitest.Typical(l) }

func open(t *testing.T, f *guitest.Fixture) *gui.Env {
	t.Helper()
	env, err := gui.OpenLayout(f.Ctx, tool, f.Layout)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func diagnostics(ctx *tools.Context) *[]string {
	var sink []string
	ctx.Options["diagnostics"] = &sink
	return &sink
}

func TestEveryLayoutReadsTheWholeFixture(t *testing.T) {
	for _, l := range gui.Layouts() {
		t.Run(l.Name, func(t *testing.T) {
			f := guitest.Build(spec(l))
			env := open(t, f)
			stations, err := env.ScanStations()
			if err != nil {
				t.Fatal(err)
			}
			if len(stations) != 2 {
				t.Fatalf("stations %+v", stations)
			}
			byName := map[string]gui.Station{}
			for _, s := range stations {
				byName[s.Name] = s
				if s.Address == 0 || s.Physical != f.Physical(s.Address) {
					t.Fatalf("station %q placed at 0x%x, physical 0x%x", s.Name, s.Address, s.Physical)
				}
			}
			st := byName["WinSta0"]
			if st.SessionID != 1 || st.Address != f.Stations[0].Address {
				t.Fatalf("WinSta0 %+v", st)
			}
			desktops, err := env.Desktops(&st)
			if err != nil || len(desktops) != 2 || desktops[0].Name != "Default" || desktops[1].Name != "Winlogon" {
				t.Fatalf("desktops %+v %v", desktops, err)
			}
			if desktops[0].StationName != "WinSta0" || desktops[0].SessionID != 1 {
				t.Fatalf("desktop %+v", desktops[0])
			}
			threads, err := env.Threads(desktops[0])
			if err != nil || len(threads) != 2 {
				t.Fatalf("threads %+v %v", threads, err)
			}
			if threads[1].TID != 0x208 || threads[1].Owner.PID != 0x80 || threads[1].Owner.Process != "notepad.exe" {
				t.Fatalf("thread %+v", threads[1])
			}
			walk, err := env.Windows(desktops[0])
			if err != nil || len(walk.Rejected) != 0 {
				t.Fatalf("windows %+v %v", walk, err)
			}
			var got []string
			for _, w := range walk.Windows {
				got = append(got, w.Text)
			}
			if strings.Join(got, "|") != "|Program Manager|SHELLDLL_DefView|Untitled - Notepad|" {
				t.Fatalf("window order %q", got)
			}
			w := walk.Windows[2]
			if w.Depth != 2 || w.Parent != walk.Windows[1].Address || w.Procedure != 0x7ff612341000 ||
				!w.ProcedureReadable || !w.TextReadable || w.Thread.Owner.Process != "explorer.exe" {
				t.Fatalf("window %+v", w)
			}
			if last := walk.Windows[4]; last.Thread.TID != 0 || last.Thread.Owner.ProcessReadable {
				t.Fatalf("ownerless window %+v", last)
			}
		})
	}
}

func TestDesktopScanKeepsOnlyDesktopsWhoseStationReads(t *testing.T) {
	l := gui.Layouts()[1]
	f := guitest.Build(spec(l))
	lost := f.Stations[1].Desktops[0]
	f.PutU64(lost.Address+l.Desktop.Station, 0)
	env := open(t, f)
	found, err := env.ScanDesktops()
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("desktops %+v", found)
	}
	for _, d := range found {
		if d.StationName != "WinSta0" || d.SessionID != 1 || d.Address == 0 {
			t.Fatalf("desktop %+v", d)
		}
	}
}

func TestStationScanRefusesNamesAnAPICannotCreate(t *testing.T) {
	for _, name := range []string{"", `Win\Sta0`, "Win\x01Sta"} {
		if gui.ValidObjectName(name) {
			t.Fatalf("%q accepted", name)
		}
	}
	if !gui.ValidObjectName("Service-0x0-3e7$") {
		t.Fatal("service station refused")
	}
}

func TestStationWithAPointerOutsideSystemSpaceIsNotAStation(t *testing.T) {
	l := gui.Layouts()[2]
	f := guitest.Build(spec(l))
	f.PutU64(f.Stations[1].Address+l.Station.Desktops, 0x00007ff600000000)
	stations, err := open(t, f).ScanStations()
	if err != nil {
		t.Fatal(err)
	}
	if len(stations) != 1 || stations[0].Name != "WinSta0" {
		t.Fatalf("stations %+v", stations)
	}
}

func firstStation(t *testing.T, env *gui.Env, name string) gui.Station {
	t.Helper()
	stations, err := env.ScanStations()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stations {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no station %q", name)
	return gui.Station{}
}

func TestDesktopListStopsAtADesktopOfAnotherStation(t *testing.T) {
	l := gui.Layouts()[1]
	f := guitest.Build(spec(l))
	d := f.Stations[0].Desktops[1]
	f.PutU64(d.Address+l.Desktop.Station, f.Stations[1].Address)
	env := open(t, f)
	sink := diagnostics(&f.Ctx)
	st := firstStation(t, env, "WinSta0")
	desktops, err := env.Desktops(&st)
	if err != nil || len(desktops) != 1 {
		t.Fatalf("desktops %+v %v", desktops, err)
	}
	if !strings.Contains(strings.Join(*sink, "\n"), gui.ErrOtherStation.Error()) {
		t.Fatalf("diagnostics %q", *sink)
	}

	f.Ctx.Options["strict"] = true
	strictEnv := open(t, f)
	st = firstStation(t, strictEnv, "WinSta0")
	if _, err := strictEnv.Desktops(&st); !errors.Is(err, gui.ErrOtherStation) {
		t.Fatalf("strict: %v", err)
	}
}

func TestDesktopListLoopEnds(t *testing.T) {
	l := gui.Layouts()[0]
	f := guitest.Build(spec(l))
	ds := f.Stations[0].Desktops
	f.PutU64(ds[1].Address+l.Desktop.Next, ds[0].Address)
	env := open(t, f)
	st := firstStation(t, env, "WinSta0")
	desktops, err := env.Desktops(&st)
	if err != nil || len(desktops) != 2 {
		t.Fatalf("desktops %d %v", len(desktops), err)
	}
}

func TestDesktopListStopsAtMaxListEntries(t *testing.T) {
	l := gui.Layouts()[0]
	f := guitest.Build(spec(l))
	f.Ctx.Limits.MaxListEntries = 1
	env := open(t, f)
	st := firstStation(t, env, "WinSta0")
	desktops, err := env.Desktops(&st)
	if err != nil || len(desktops) != 1 {
		t.Fatalf("desktops %d %v", len(desktops), err)
	}
}

func TestAThreadOfAnotherDesktopIsLeftOut(t *testing.T) {
	l := gui.Layouts()[3]
	f := guitest.Build(spec(l))
	d := f.Stations[0].Desktops[0]
	f.PutU64(d.Threads[0]+l.Thread.Desktop, f.Stations[0].Desktops[1].Address)
	env := open(t, f)
	st := firstStation(t, env, "WinSta0")
	desktops, _ := env.Desktops(&st)
	threads, err := env.Threads(desktops[0])
	if err != nil || len(threads) != 1 || threads[0].TID != 0x208 {
		t.Fatalf("threads %+v %v", threads, err)
	}
}

func TestAThreadWhoseETHREADIsNoThreadIsLeftOut(t *testing.T) {
	l := gui.Layouts()[2]
	f := guitest.Build(spec(l))
	d := f.Stations[0].Desktops[0]
	f.PutU64(d.Threads[1]+l.Thread.EThread, d.Address)
	env := open(t, f)
	st := firstStation(t, env, "WinSta0")
	desktops, _ := env.Desktops(&st)
	threads, err := env.Threads(desktops[0])
	if err != nil || len(threads) != 1 || threads[0].TID != 0x104 {
		t.Fatalf("threads %+v %v", threads, err)
	}
}

func windowsOf(t *testing.T, f *guitest.Fixture) gui.WindowWalk {
	t.Helper()
	env := open(t, f)
	st := firstStation(t, env, "WinSta0")
	desktops, err := env.Desktops(&st)
	if err != nil {
		t.Fatal(err)
	}
	walk, err := env.Windows(desktops[0])
	if err != nil {
		t.Fatal(err)
	}
	return walk
}

func TestAWindowThatDoesNotNameItselfIsLeftOutWithItsSubtree(t *testing.T) {
	l := gui.Layouts()[1]
	f := guitest.Build(spec(l))
	w := f.Stations[0].Desktops[0].Windows[1]
	f.PutU64(w.Address+l.Window.Self, 0)
	walk := windowsOf(t, f)
	if len(walk.Windows) != 1 || walk.Rejected[gui.ErrNotSelf.Error()] != 1 {
		t.Fatalf("walk %+v", walk)
	}
}

func TestAChildNamingAnotherParentEndsItsSiblingChain(t *testing.T) {
	l := gui.Layouts()[0]
	f := guitest.Build(spec(l))
	ws := f.Stations[0].Desktops[0].Windows
	f.PutU64(ws[3].Address+l.Window.Parent, ws[1].Address)
	walk := windowsOf(t, f)
	if len(walk.Windows) != 3 || walk.Rejected[gui.ErrOtherParent.Error()] != 1 {
		t.Fatalf("walk %+v", walk)
	}
}

func TestASiblingLoopEnds(t *testing.T) {
	l := gui.Layouts()[1]
	f := guitest.Build(spec(l))
	ws := f.Stations[0].Desktops[0].Windows
	f.PutU64(ws[4].Address+l.Window.Next, ws[1].Address)
	walk := windowsOf(t, f)
	if len(walk.Windows) != 5 {
		t.Fatalf("walk %d", len(walk.Windows))
	}
}

func TestTheTreeStopsAtMaxRecursionDepth(t *testing.T) {
	l := gui.Layouts()[1]
	f := guitest.Build(spec(l))
	f.Ctx.Limits.MaxRecursionDepth = 1
	walk := windowsOf(t, f)
	if len(walk.Windows) != 4 {
		t.Fatalf("walk %d", len(walk.Windows))
	}
}

func TestTheTreeStopsAtMaxListEntries(t *testing.T) {
	l := gui.Layouts()[1]
	f := guitest.Build(spec(l))
	f.Ctx.Limits.MaxListEntries = 3
	walk := windowsOf(t, f)
	if len(walk.Windows) != 3 {
		t.Fatalf("walk %d", len(walk.Windows))
	}
}

func TestWindowTextRules(t *testing.T) {
	l := gui.Layouts()[2]
	at := func(f *guitest.Fixture, w guitest.Window, p gui.Place) uint64 {
		if p == gui.InShadow {
			return w.Shadow
		}
		return w.Address
	}
	cases := []struct {
		name  string
		write func(f *guitest.Fixture, w guitest.Window)
	}{
		{"odd length", func(f *guitest.Fixture, w guitest.Window) {
			f.PutU32(at(f, w, l.Window.TextLength)+l.Window.TextLengthAt, 3)
		}},
		{"length at the maximum", func(f *guitest.Fixture, w guitest.Window) {
			f.PutU32(at(f, w, l.Window.TextMaximum)+l.Window.TextMaximumAt, 30)
		}},
		{"buffer outside the heap", func(f *guitest.Fixture, w guitest.Window) {
			f.PutU64(w.Address+l.Window.TextBuffer, f.Stations[0].Address)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := guitest.Build(spec(l))
			w := f.Stations[0].Desktops[0].Windows[1]
			c.write(f, w)
			walk := windowsOf(t, f)
			got := walk.Windows[1]
			if got.TextReadable || got.Text != "" || !got.ProcedureReadable {
				t.Fatalf("window %+v", got)
			}
		})
	}
}

func TestAShadowOutsideTheHeapLeavesTextAndProcedureUnread(t *testing.T) {
	l := gui.Layouts()[1]
	f := guitest.Build(spec(l))
	w := f.Stations[0].Desktops[0].Windows[3]
	f.PutU64(w.Address+l.Window.ShadowOffset, 0x10)
	walk := windowsOf(t, f)
	got := walk.Windows[3]
	if got.TextReadable || got.ProcedureReadable || got.Address != w.Address {
		t.Fatalf("window %+v", got)
	}
}

func TestLayoutSelection(t *testing.T) {
	for _, l := range gui.Layouts() {
		got, err := gui.LayoutFor(fingerprint(strings.ToLower(l.GUID), l.Age))
		if err != nil || got.Name != l.Name {
			t.Fatalf("%s: %+v %v", l.Name, got.Name, err)
		}
	}
	if _, err := gui.LayoutFor(fingerprint("00000000000000000000000000000000", 1)); !errors.Is(err, gui.ErrUnsupportedVersion) {
		t.Fatal(err)
	}
}

func TestEveryLayoutIsDistinctAndInsideItsObjects(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range gui.Layouts() {
		if seen[l.GUID] {
			t.Fatalf("%s twice", l.GUID)
		}
		seen[l.GUID] = true
		w := l.Window
		if w.Next == w.Parent || w.Parent == w.Child || w.Self == w.Desktop || w.Thread == w.Desktop {
			t.Fatalf("%s: window members overlap", l.Name)
		}
		if l.Desktop.Threads <= l.Desktop.Station || l.Desktop.HeapSize != l.Desktop.HeapBase+8 {
			t.Fatalf("%s: desktop members", l.Name)
		}
	}
}

func TestOpenRefusesA32BitTable(t *testing.T) {
	f := guitest.Build(spec(gui.Layouts()[0]))
	f.Ctx.Symbols = thirtyTwo{f.Ctx.Symbols}
	if _, err := gui.OpenLayout(f.Ctx, tool, f.Layout); !errors.Is(err, gui.ErrNot64Bit) {
		t.Fatal(err)
	}
}

func TestOpenToolRefusesAnotherOS(t *testing.T) {
	f := guitest.Build(spec(gui.Layouts()[0]))
	f.Ctx.Profile = linuxProfile{f.Ctx.Profile}
	if _, err := gui.OpenTool(f.Ctx, tool); err == nil || !strings.Contains(err.Error(), "unsupported profile os") {
		t.Fatal(err)
	}
}

// The sizes are those of the measured 26100 server images (M9): without the
// debug record they must still not choose a layout.
func TestAWin32kBaseWithoutADebugRecordIsRefusedWhateverItsSizes(t *testing.T) {
	k := testsupport.NewS64Kernel()
	k.AddModule("win32kbase.sys", k.Skip(), 0x343000)
	k.AddModule("win32kfull.sys", k.Skip(), 0x402000)
	ctx := k.Context()
	sink := diagnostics(&ctx)
	if _, err := gui.Open(ctx, tool); !errors.Is(err, gui.ErrNoDebugRecord) {
		t.Fatalf("err %v, want the debug record refusal", err)
	}
	for _, d := range *sink {
		if strings.Contains(d, "chosen") {
			t.Errorf("a layout was chosen: %q", d)
		}
	}
}

func TestOpenWithoutWin32kBaseFails(t *testing.T) {
	f := guitest.Build(spec(gui.Layouts()[0]))
	if _, err := gui.Open(f.Ctx, tool); !errors.Is(err, gui.ErrNoWin32kBase) {
		t.Fatal(err)
	}
}
