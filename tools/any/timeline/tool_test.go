package timeline

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
)

func testContext(osName string, options map[string]any) (tools.Context, *[]string) {
	diags := []string{}
	if options == nil {
		options = map[string]any{}
	}
	options["diagnostics"] = &diags
	ctx := tools.Context{Memory: testsupport.NewPagedMemory(4096), Symbols: testsupport.UnicodeStringSymbols(), Options: options}
	ctx.Profile = profiles.WindowsX64Profile{}
	if osName == linux {
		ctx.Profile = profiles.LinuxX64Profile{}
	}
	return ctx, &diags
}

func TestOptionsOfTheWrongTypeAreErrors(t *testing.T) {
	for key, v := range map[string]any{OptionToolFilter: 5, OptionCreateBodyfile: "x", OptionRecordConfig: "x"} {
		ctx, _ := testContext(windows, map[string]any{key: v})
		if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) {
			t.Errorf("%s = %v: error %v", key, v, err)
		}
		if _, err := Collect(ctx); !errors.Is(err, tools.ErrOptionType) {
			t.Errorf("Collect with %s = %v: error %v", key, v, err)
		}
	}
}

func TestRefusalsComeBeforeAnySourceRuns(t *testing.T) {
	ctx, diags := testContext(windows, map[string]any{OptionRecordConfig: true})
	if _, err := Run(ctx); !errors.Is(err, ErrRecordConfig) {
		t.Errorf("record_config: %v", err)
	}
	ctx, _ = testContext(windows, map[string]any{OptionCreateBodyfile: true})
	if _, err := Run(ctx); !errors.Is(err, ErrNoOutputDir) {
		t.Errorf("body file without a directory: %v", err)
	}
	for _, words := range [][]string{{"no.such.tool"}, {"thread", "linux.boot"}} {
		ctx, _ = testContext(windows, map[string]any{OptionToolFilter: words})
		if _, err := Run(ctx); !errors.Is(err, ErrToolFilter) {
			t.Errorf("filter %q: %v", words, err)
		}
	}
	ctx, _ = testContext(windows, nil)
	ctx.Profile = otherProfile{}
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), `unsupported profile os "plan9"`) {
		t.Errorf("other os: %v", err)
	}
	if len(*diags) != 0 {
		t.Errorf("diagnostics %q", *diags)
	}
}

type otherProfile struct{}

func (otherProfile) Name() string       { return "other" }
func (otherProfile) OS() string         { return "plan9" }
func (otherProfile) PointerSize() uint8 { return 8 }

func TestFilterWordsPickSourcesByPartOfTheirName(t *testing.T) {
	got, err := choose(windows, []string{"thread", "network.list"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range got {
		names = append(names, s.tool)
	}
	if !slices.Equal(names, []string{"windows.thread.list", "windows.thread.scan", "windows.thread.find_orphaned", "windows.network.list"}) {
		t.Errorf("chose %q", names)
	}
	if _, err := choose(windows, []string{""}); !errors.Is(err, ErrToolFilter) {
		t.Errorf("an empty word: %v", err)
	}
	all, _ := choose(linux, nil)
	if len(all) != len(Sources(linux)) {
		t.Errorf("no words chose %d of %d", len(all), len(Sources(linux)))
	}
}

func fakeSource(name string, entries []Entry, err error) source {
	return source{tool: name, os: windows, read: func(ctx tools.Context, r *recorder) error {
		for _, e := range entries {
			r.row()
			r.stamp(object{subject: e.Subject, address: e.Address}, e.Event, e.Field, e.Time, true)
		}
		return err
	}}
}

func TestGatherSortsAcrossSourcesAndKeepsRowsOfAFailedOne(t *testing.T) {
	ctx, diags := testContext(windows, nil)
	failure := errors.New("cut short")
	res, err := gather(ctx, []source{
		fakeSource("b", []Entry{{Time: t2, Event: Created, Field: "F", Subject: "late"}}, nil),
		fakeSource("a", []Entry{{Time: t1, Event: Created, Field: "F", Subject: "early"}}, failure),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 2 || res.Entries[0].Subject != "early" || res.Entries[1].Tool != "b" {
		t.Errorf("entries %+v", res.Entries)
	}
	if len(res.Sources) != 2 || res.Sources[1].Failure != failure || res.Sources[0].Failure != nil {
		t.Errorf("summaries %+v", res.Sources)
	}
	if len(*diags) != 1 || !strings.Contains((*diags)[0], "any.timeline.list: source a: run failed, 1 rows kept: cut short") {
		t.Errorf("diagnostics %q", *diags)
	}

	ctx, _ = testContext(windows, map[string]any{"strict": true})
	if _, err := gather(ctx, []source{fakeSource("a", nil, failure)}); !errors.Is(err, failure) {
		t.Errorf("strict: %v", err)
	}
}

func TestSourcesSeeNeitherTheTimelineOptionsNorThePIDFilter(t *testing.T) {
	ctx, _ := testContext(windows, map[string]any{OptionToolFilter: []string{"x"}, OptionCreateBodyfile: true,
		"pid": []uint64{4}, "other": 1})
	var seen map[string]any
	read := func(ctx tools.Context, r *recorder) error {
		seen = ctx.Options
		return nil
	}
	src := source{tool: "a", os: windows, read: read, overrides: map[string]any{"added": true}}
	if _, err := gather(ctx, []source{src}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{OptionToolFilter, OptionCreateBodyfile, "pid"} {
		if _, ok := seen[k]; ok {
			t.Errorf("source saw %s", k)
		}
	}
	if seen["other"] != 1 || seen["added"] != true || seen["diagnostics"] == nil {
		t.Errorf("source options %v", seen)
	}
	if _, ok := ctx.Options["added"]; ok {
		t.Error("an override reached the caller's options")
	}
}

func TestRunOnAnEmptyImageGivesNoEntriesAndADiagnosticPerFailedSource(t *testing.T) {
	for _, osName := range []string{windows, linux} {
		ctx, diags := testContext(osName, nil)
		entries, err := Run(ctx)
		if err != nil {
			t.Fatalf("%s: %v", osName, err)
		}
		if len(entries) != 0 {
			t.Errorf("%s: %d entries", osName, len(entries))
		}
		for _, d := range *diags {
			if !strings.HasPrefix(d, Name+": ") && !strings.Contains(d, ": ") {
				t.Errorf("%s: diagnostic %q", osName, d)
			}
		}
	}
}

func TestRunWritesTheBodyFileInTimeOrder(t *testing.T) {
	dir := t.TempDir()
	ctx, diags := testContext(linux, map[string]any{OptionCreateBodyfile: true, tools.OptionOutputDir: dir,
		OptionToolFilter: []string{"linux.boot"}})
	if _, err := Run(ctx); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range *diags {
		found = found || strings.HasPrefix(d, "any.timeline.list: body file timeline.body in ")
	}
	if !found {
		t.Errorf("no body file diagnostic in %q", *diags)
	}
}
