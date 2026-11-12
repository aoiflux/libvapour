package consolelist

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

func layout19041Fixture(t *testing.T) (*fixture, *Layout) {
	t.Helper()
	l, err := LayoutFor(true, 10, 0, 19045)
	if err != nil {
		t.Fatal(err)
	}
	return newFixture(l), l
}

func TestAConsoleIsReadWhole(t *testing.T) {
	f, l := layout19041Fixture(t)
	spec := defaultConsole()
	spec.screens = []screenSpec{
		{rows: []string{"first", "", "third   "}, width: 12, first: 2},
		{rows: []string{"other"}, width: 8},
	}
	spec.active = 1
	f.console(fixtureConsole, spec)
	s, b := f.space(), limits.Default()

	if v := l.InspectConsole(s, fixtureConsole, b); !v.Accepted() {
		t.Fatalf("console rejected: %s: %v", v.Rule, v.Err)
	}
	c := l.ReadConsole(s, fixtureConsole, map[uint64]bool{4242: true}, b)
	if len(c.Incomplete) != 0 {
		t.Fatalf("incomplete: %v", c.Incomplete)
	}
	if c.Title != "Command Prompt" || c.OriginalTitle != `C:\Windows\system32\cmd.exe` {
		t.Errorf("titles %q %q", c.Title, c.OriginalTitle)
	}
	if c.ScreenBufferColumns != 120 || c.ScreenBufferRows != 9001 || c.HistoryBufferSize != 50 || c.NumberOfHistoryBuffers != 4 {
		t.Errorf("settings %d x %d, %d/%d", c.ScreenBufferColumns, c.ScreenBufferRows, c.HistoryBufferSize, c.NumberOfHistoryBuffers)
	}
	if len(c.AttachedProcesses) != 1 || c.AttachedProcesses[0].PID != 4242 || !c.AttachedProcesses[0].InProcessList {
		t.Errorf("attached %+v", c.AttachedProcesses)
	}
	if len(c.Histories) != 1 {
		t.Fatalf("histories %+v", c.Histories)
	}
	h := c.Histories[0]
	if h.Application != "cmd.exe" || h.BufferSize != 50 || h.RecallPosition != 1 || !h.OwnerPIDKnown || h.OwnerPID != 4242 {
		t.Errorf("history %+v", h)
	}
	if got := commandTexts(h); !reflect.DeepEqual(got, []string{"whoami", "net user /domain"}) {
		t.Errorf("commands %q", got)
	}
	want := []Alias{{Executable: "cmd.exe", Source: "ll", Target: "dir /a $*"}}
	for i := range c.Aliases {
		c.Aliases[i].Address = 0
	}
	if !reflect.DeepEqual(c.Aliases, want) {
		t.Errorf("aliases %+v", c.Aliases)
	}
	if len(c.Screens) != 2 || c.Screens[0].Active || !c.Screens[1].Active {
		t.Fatalf("screens %+v", c.Screens)
	}
	rows := c.Screens[0].Rows
	wantRows := []ScreenRow{{Row: 0, Text: "first"}, {Row: 2, Text: "third"}}
	if !reflect.DeepEqual(rows, wantRows) || c.Screens[0].Columns != 12 || c.Screens[0].RowCount != 3 {
		t.Errorf("screen rows %+v, columns %d", rows, c.Screens[0].Columns)
	}
}

func commandTexts(h History) []string {
	var out []string
	for _, c := range h.Commands {
		out = append(out, c.Text)
	}
	return out
}

func TestEachConsoleRuleRejectsWhatBreaksIt(t *testing.T) {
	cases := []struct {
		name   string
		rule   string
		err    error
		break_ func(f *fixture, l *Layout)
	}{
		{"zero columns", RuleScreenSize, ErrScreenBufferSize, func(f *fixture, l *Layout) {
			f.m.put(fixtureConsole+uint64(l.console.screenWidth.off), l.console.screenWidth, 0)
		}},
		{"negative rows", RuleScreenSize, ErrScreenBufferSize, func(f *fixture, l *Layout) {
			f.m.put(fixtureConsole+uint64(l.console.screenHeight.off), l.console.screenHeight, -3)
		}},
		{"process count off by one", RuleProcessList, ErrListCount, func(f *fixture, l *Layout) {
			f.m.u64(fixtureConsole+uint64(l.console.processCount.off), 2)
		}},
		{"process list outside the process", RuleProcessList, ErrOutside, func(f *fixture, l *Layout) {
			f.m.u64(fixtureConsole+uint64(l.console.processList), 0x10)
		}},
		{"history list link broken", RuleHistoryList, ErrListLink, func(f *fixture, l *Layout) {
			head, _ := f.space().pointer(fixtureConsole + uint64(l.console.historyList))
			first, _ := f.space().pointer(head)
			f.m.u64(first+pointerBytes, first)
		}},
		{"title longer than its capacity", RuleTitles, ErrStringShape, func(f *fixture, l *Layout) {
			f.m.u64(fixtureConsole+uint64(l.console.title+l.text.length.off), 99)
		}},
		{"more buffers than allowed", RuleBufferNumber, ErrTooManyBuffers, func(f *fixture, l *Layout) {
			f.m.put(fixtureConsole+uint64(l.console.historyMax.off), l.console.historyMax, 0)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, l := layout19041Fixture(t)
			f.console(fixtureConsole, defaultConsole())
			tc.break_(f, l)
			v := l.InspectConsole(f.space(), fixtureConsole, limits.Default())
			if v.Accepted() || v.Rule != tc.rule || !errors.Is(v.Err, tc.err) {
				t.Errorf("verdict %s: %v, want %s: %v", v.Rule, v.Err, tc.rule, tc.err)
			}
		})
	}
}

func TestAConsoleWithoutProcessesIsRejected(t *testing.T) {
	f, l := layout19041Fixture(t)
	spec := defaultConsole()
	spec.pids, spec.historyOwner = nil, []int{-1}
	f.console(fixtureConsole, spec)
	v := l.InspectConsole(f.space(), fixtureConsole, limits.Default())
	if v.Rule != RuleProcessList || !errors.Is(v.Err, ErrNoProcess) {
		t.Errorf("verdict %s: %v", v.Rule, v.Err)
	}
}

func TestAConsoleWhoseActiveScreenIsNotListedSaysSo(t *testing.T) {
	f, l := layout19041Fixture(t)
	spec := defaultConsole()
	spec.active = 5
	f.console(fixtureConsole, spec)
	c := l.ReadConsole(f.space(), fixtureConsole, nil, limits.Default())
	if len(c.Incomplete) != 1 || !strings.Contains(c.Incomplete[0], "screen buffers") {
		t.Errorf("incomplete %v", c.Incomplete)
	}
	if len(c.Screens) != 1 || c.Screens[0].Active {
		t.Errorf("screens %+v", c.Screens)
	}
}

func TestAnAttachedProcessNotListedByTheKernelIsMarked(t *testing.T) {
	f, l := layout19041Fixture(t)
	f.console(fixtureConsole, defaultConsole())
	c := l.ReadConsole(f.space(), fixtureConsole, map[uint64]bool{8: true}, limits.Default())
	if len(c.AttachedProcesses) != 1 || c.AttachedProcesses[0].PID != 4242 || c.AttachedProcesses[0].InProcessList {
		t.Errorf("attached %+v", c.AttachedProcesses)
	}
}

func TestARowThatDoesNotReadLeavesTheOthers(t *testing.T) {
	f, l := layout19041Fixture(t)
	f.console(fixtureConsole, defaultConsole())
	s := f.space()
	scr, _ := s.pointer(fixtureConsole + uint64(l.console.screenList))
	tb, _ := s.pointer(scr + uint64(l.console.screen.textBuffer))
	rowMap, _ := s.pointer(tb + uint64(l.console.textBuffer.rows))
	f.m.u64(rowMap, 0x30)
	c := l.ReadConsole(s, fixtureConsole, nil, limits.Default())
	sc := c.Screens[0]
	if !sc.Incomplete || len(sc.Rows) != 1 || sc.Rows[0] != (ScreenRow{Row: 2, Text: `C:\>whoami`}) {
		t.Errorf("screen %+v", sc)
	}
}

func TestRowsPastMaxRowsPerObjectRefuseTheScreen(t *testing.T) {
	f, l := layout19041Fixture(t)
	f.console(fixtureConsole, defaultConsole())
	b := limits.Default()
	b.MaxRowsPerObject = 2
	c := l.ReadConsole(f.space(), fixtureConsole, nil, b)
	if len(c.Screens) != 1 || len(c.Screens[0].Rows) != 0 || len(c.Incomplete) == 0 {
		t.Errorf("screens %+v, incomplete %v", c.Screens, c.Incomplete)
	}
}

func TestTheSearchFindsTheConsoleByItsSettingsPair(t *testing.T) {
	f, l := layout19041Fixture(t)
	f.console(fixtureConsole, defaultConsole())
	decoy := fixtureImage + 0x8000
	f.m.u32(decoy, 50)
	f.m.u32(decoy+4, 4)
	found, err := l.FindConsoles(f.space(), []uint64{50}, []uint64{4}, limits.Default())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(found.Accepted, []uint64{fixtureConsole}) || found.RejectedCount() != 1 {
		t.Errorf("accepted %x, rejected %v", found.Accepted, found.RejectedBy)
	}
	other, _ := l.FindConsoles(f.space(), []uint64{100}, []uint64{4}, limits.Default())
	if len(other.Accepted) != 0 {
		t.Errorf("found with the wrong history size: %x", other.Accepted)
	}
}

func TestTheConsoleReaderRefusesALayoutWithoutConsoleMembers(t *testing.T) {
	base, err := LayoutFor(true, 10, 0, 19041)
	if err != nil {
		t.Fatal(err)
	}
	historyOnly := *base
	historyOnly.console, historyOnly.noConsole = nil, "history members only"
	l := &historyOnly
	if l.HasConsole() || l.ConsoleGap() == "" {
		t.Fatal("history-only layout has console members")
	}
	if _, ok := l.SettingsPair(); ok {
		t.Error("history-only layout has a settings pair")
	}
	v := l.InspectConsole(Space{}, 0, limits.Default())
	if !errors.Is(v.Err, ErrUnsupportedVersion) {
		t.Errorf("verdict %v", v.Err)
	}
}
