package consolelist

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
)

const fixtureHostPID = 700

// A capture with one conhost.exe whose memory holds what f wrote, and one
// other process.
func runContext(t *testing.T, f *fixture, build uint16) tools.Context {
	t.Helper()
	pf := testsupport.BuildProcessFixture([]testsupport.FixtureProcess{
		{PID: 4242, Name: "cmd.exe"},
		{PID: fixtureHostPID, Name: "conhost.exe", VADs: []testsupport.FixtureVAD{
			{Start: fixtureHeap, End: fixtureHeap + fixtureHeapBytes - 1},
			{Start: fixtureImage, End: fixtureImage + fixtureImageSize - 1},
		}},
	})
	space := pf.Space(fixtureHostPID)
	for page, data := range f.m.pages {
		space.MapData(page, data)
	}
	ctx := pf.Context()
	ctx.Symbols, ctx.Memory = testsupport.WithWindowsVersion(ctx.Symbols, ctx.Memory, 10, 0, build)
	ctx.Options["diagnostics"] = &[]string{}
	return ctx
}

func diagnostics(ctx tools.Context) []string { return *ctx.Options["diagnostics"].(*[]string) }

func TestRunReadsTheConsoleOfEachHost(t *testing.T) {
	f, _ := layout19041Fixture(t)
	f.console(fixtureConsole, defaultConsole())
	ctx := runContext(t, f, 19045)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows %+v, diagnostics %q", rows, diagnostics(ctx))
	}
	c := rows[0]
	if c.PID != fixtureHostPID || c.Process != "conhost.exe" || c.Address != fixtureConsole || c.Title != "Command Prompt" {
		t.Errorf("console %+v", c)
	}
	if len(c.AttachedProcesses) != 1 || !c.AttachedProcesses[0].InProcessList || len(c.Histories) != 1 || len(c.Screens) != 1 {
		t.Errorf("console parts %+v", c)
	}
}

func TestRunSaysWhenAHostHoldsNoConsole(t *testing.T) {
	f, _ := layout19041Fixture(t)
	ctx := runContext(t, f, 19045)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if !hasDiagnostic(ctx, "process 700 at 0x", "no console state found") {
		t.Errorf("diagnostics %q", diagnostics(ctx))
	}
}

func TestStrictModeFailsOnAConsoleThatDidNotReadWhole(t *testing.T) {
	f, _ := layout19041Fixture(t)
	spec := defaultConsole()
	spec.active = 3
	f.console(fixtureConsole, spec)
	ctx := runContext(t, f, 19045)
	ctx.Options["strict"] = true
	rows, err := Run(ctx)
	if !errors.Is(err, ErrIncomplete) || len(rows) != 1 {
		t.Errorf("rows %d, %v", len(rows), err)
	}
}

func TestRunRefusesBuildsWithoutConsoleMembers(t *testing.T) {
	for _, build := range []uint16{26100, 14393, 22631} {
		f, _ := layout19041Fixture(t)
		_, err := Run(runContext(t, f, build))
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("build %d: %v", build, err)
		}
	}
}

func TestRunNeedsAWindowsProfile(t *testing.T) {
	f, _ := layout19041Fixture(t)
	ctx := runContext(t, f, 19045)
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "unsupported profile os") {
		t.Errorf("err %v", err)
	}
}

func TestOptionsOfTheWrongTypeOrRangeAreErrors(t *testing.T) {
	for _, tc := range []struct {
		key   string
		value any
	}{
		{OptionNoRegistry, 7},
		{OptionMaxHistory, "fifty"},
		{OptionMaxHistory, []uint64{0}},
		{OptionMaxBuffers, []uint64{1 << 32}},
	} {
		f, _ := layout19041Fixture(t)
		ctx := runContext(t, f, 19045)
		ctx.Options[tc.key] = tc.value
		if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) {
			t.Errorf("%s = %v: %v", tc.key, tc.value, err)
		}
	}
}

func TestAnOptionReplacesTheDefaultSize(t *testing.T) {
	f, _ := layout19041Fixture(t)
	spec := defaultConsole()
	spec.historySize = 999
	f.console(fixtureConsole, spec)
	ctx := runContext(t, f, 19045)
	if rows, _ := Run(ctx); len(rows) != 0 {
		t.Fatalf("found with the default size: %+v", rows)
	}
	ctx = runContext(t, f, 19045)
	ctx.Options[OptionMaxHistory] = []uint64{999}
	ctx.Options[OptionNoRegistry] = true
	if rows, err := Run(ctx); err != nil || len(rows) != 1 {
		t.Errorf("rows %d, %v", len(rows), err)
	}
}

func hasDiagnostic(ctx tools.Context, parts ...string) bool {
	for _, d := range diagnostics(ctx) {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(d, p)
		}
		if all {
			return true
		}
	}
	return false
}

func TestTheSizesSearchedAreTheOptionOrDefaultAndTheRegistry(t *testing.T) {
	settings := []Setting{
		{HistoryBufferSize: DWORDValue{Value: 100, Set: true}},
		{NumberOfHistoryBuffers: DWORDValue{Value: 4, Set: true}},
	}
	z := gatherSizes(settings, nil, nil)
	if !equalU64(z.historyBufferSizes, []uint64{50, 100}) || !equalU64(z.numberOfHistoryBuffers, []uint64{4}) {
		t.Errorf("sizes %+v", z)
	}
	z = gatherSizes(nil, []uint64{30, 30}, []uint64{8})
	if !equalU64(z.historyBufferSizes, []uint64{30}) || !equalU64(z.numberOfHistoryBuffers, []uint64{8}) {
		t.Errorf("sizes %+v", z)
	}
}

func equalU64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestLayoutsServeTheirMeasuredBuildsOnly(t *testing.T) {
	for _, tc := range []struct {
		is64                bool
		major, minor, build uint64
		ok, console         bool
	}{
		{true, 10, 0, 19041, true, true},
		{true, 10, 0, 19045, true, true},
		{true, 10, 0, 26100, false, false},
		{true, 10, 0, 14393, false, false},
		{true, 6, 3, 19041, false, false},
		{false, 10, 0, 19041, false, false},
		{true, 10, 0, 1 << 40, false, false},
	} {
		l, err := LayoutFor(tc.is64, tc.major, tc.minor, tc.build)
		if tc.ok != (err == nil) || err != nil && !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("%+v: %v", tc, err)
			continue
		}
		if err == nil && l.HasConsole() != tc.console {
			t.Errorf("%+v: console members %v", tc, l.HasConsole())
		}
	}
}

func TestEveryMemberIsListedForMeasurement(t *testing.T) {
	l, _ := LayoutFor(true, 10, 0, 19041)
	seen := map[string]bool{}
	for _, m := range l.Members() {
		if seen[m.Name] {
			t.Errorf("%s twice", m.Name)
		}
		seen[m.Name] = true
	}
	if !seen["console.historySize"] || !seen["row.width"] || !seen["history.lastDisplayed"] {
		t.Errorf("members %v", seen)
	}
}
