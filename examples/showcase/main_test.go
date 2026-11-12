package main

import (
	"bytes"
	"flag"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/internal/ownerfile"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/timeline"
	"github.com/aoiflux/libvapour/tools/linux/kernelsymbols"
	"github.com/aoiflux/libvapour/tools/windows/credentialcached"
	"github.com/aoiflux/libvapour/tools/windows/credentiallocal"
	"github.com/aoiflux/libvapour/tools/windows/credentiallsasecrets"
	"github.com/aoiflux/libvapour/tools/windows/credentialtruecrypt"
)

const module = "github.com/aoiflux/libvapour/"

func reflectValue(v any) reflect.Value { return reflect.ValueOf(v) }

func parse(t *testing.T, args ...string) (settings, string, error) {
	t.Helper()
	fs := flag.NewFlagSet("showcase", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return parseArgs(fs, args)
}

func TestDefaults(t *testing.T) {
	s, image, err := parse(t, "memory.raw")
	if err != nil {
		t.Fatal(err)
	}
	if image != "memory.raw" || s.osName != "windows" || s.out != defaultReport || !s.summary || !s.timings ||
		s.maxRows != 0 || s.revealSecrets || !s.config.CollectDiagnostics || s.named != nil || s.pidGiven() {
		t.Fatalf("defaults %+v image %q", s, image)
	}
}

func TestFlagsReachTheSessionConfig(t *testing.T) {
	s, _, err := parse(t, "-os", "linux", "-symbols", "k.vsym", "-cr3", "0x1aa000", "-strict", "-offline",
		"-pid", "4", "-process-list-sanity", "-process-list-active-only", "-process-list-cross-check-csv", "p.csv",
		"-network-scan-include-corrupt", "-pagefiles", " pagefile.sys, ,swapfile.sys ", "-tools", "a.b.c, d.e.f",
		"-opt", " windows.registry.read_key.hive = SOFTWARE ", "-opt", "pid=0,8", "-max-rows", "50",
		"-out", "r.txt", "-summary=false", "-summary-out", "s.txt", "-timings=false", "-reveal-secrets", "image")
	if err != nil {
		t.Fatal(err)
	}
	c := s.config
	if c.SymbolsPath != "k.vsym" || c.KernelCR3 != 0x1aa000 || !c.Strict || !c.OfflineOnly || c.PID != 4 ||
		!c.ProcessListSanityFilter || !c.ProcessListActiveOnly || c.ProcessListCrossCheckCSV != "p.csv" ||
		!c.NetworkScanIncludeCorrupt || !slices.Equal(c.PagefilePaths, []string{"pagefile.sys", "swapfile.sys"}) {
		t.Fatalf("config %+v", c)
	}
	if c.ToolOptions["windows.registry.read_key.hive"] != "SOFTWARE" || c.ToolOptions["pid"] != "0,8" {
		t.Fatalf("options %v", c.ToolOptions)
	}
	if s.osName != "linux" || !slices.Equal(s.named, []string{"a.b.c", "d.e.f"}) || s.maxRows != 50 || s.out != "r.txt" ||
		s.summary || s.summaryOut != "s.txt" || s.timings || !s.revealSecrets {
		t.Fatalf("settings %+v", s)
	}
}

func TestAPIDOptionCountsAsAPID(t *testing.T) {
	s, _, err := parse(t, "-opt", "pid=0", "image")
	if err != nil || !s.pidGiven() {
		t.Fatalf("pid=0 option not seen as a PID: %v", err)
	}
}

func TestBadCommandLinesAreRefused(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"a", "b"},
		{"-opt", "novalue", "image"},
		{"-opt", "=v", "image"},
		{"-max-rows", "-1", "image"},
		{"image", "-strict"},
	} {
		if _, _, err := parse(t, args...); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
}

func TestTheDefaultSelectionIsTheImagesPlatform(t *testing.T) {
	specs := []tools.Spec{{Name: "any.a.list"}, {Name: memoryranges.Name}, {Name: timeline.Name}, {Name: kernelsymbols.Name},
		{Name: "linux.b.list"}, {Name: "windows.c.list"}}
	cases := []struct {
		os       string
		named    []string
		pid      bool
		selected []string
		skipped  []string
	}{
		{"windows", nil, false, []string{"any.a.list", "windows.c.list"}, []string{memoryranges.Name, timeline.Name}},
		{" Linux ", nil, false, []string{"any.a.list", "linux.b.list"}, []string{memoryranges.Name, timeline.Name, kernelsymbols.Name}},
		{"linux", nil, true, []string{"any.a.list", memoryranges.Name, "linux.b.list"}, []string{timeline.Name, kernelsymbols.Name}},
		{"windows", []string{"linux.b.list", memoryranges.Name, timeline.Name}, false, []string{"linux.b.list", memoryranges.Name, timeline.Name}, nil},
	}
	for _, c := range cases {
		selected, skipped := selectTools(c.os, specs, c.named, c.pid)
		if !slices.Equal(selected, c.selected) || !slices.Equal(skipped, c.skipped) {
			t.Errorf("%q %q pid=%t: selected %q skipped %q", c.os, c.named, c.pid, selected, skipped)
		}
	}
}

func TestEveryRegisteredToolBelongsToAPlatform(t *testing.T) {
	specs := tools.List()
	if len(specs) == 0 {
		t.Fatal("no tools registered")
	}
	for _, spec := range specs {
		owner, _, _ := strings.Cut(spec.Name, ".")
		if owner != anyPlatform && owner != "windows" && owner != "linux" {
			t.Errorf("%s would never be selected by default", spec.Name)
		}
	}
	for name := range skippedByDefault {
		if _, err := tools.Get(name); err != nil {
			t.Errorf("the skipped tool is not registered: %v", err)
		}
	}
}

func TestEveryPackageThatRegistersAToolIsLinked(t *testing.T) {
	registering := map[string]bool{}
	err := filepath.WalkDir(filepath.Join("..", "..", "tools"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(src, []byte("tools.MustRegister(")) || bytes.Contains(src, []byte("tools.Register(")) {
			rel, err := filepath.Rel(filepath.Join("..", ".."), filepath.Dir(path))
			if err != nil {
				return err
			}
			registering[module+filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "tools.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	linked := map[string]bool{}
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		linked[p] = true
	}
	for p := range registering {
		if !linked[p] {
			t.Errorf("%s registers a tool but tools.go does not import it", p)
		}
	}
	for p := range linked {
		if !registering[p] {
			t.Errorf("tools.go imports %s, which registers no tool", p)
		}
	}
}

func TestCredentialsAreRedactedByDefault(t *testing.T) {
	const secret = "s3cr3tvalue"
	rows := map[string]any{
		credentiallocal.Name:      []credentiallocal.Entry{{User: "Administrator", RID: 500, LMHash: secret, NTHash: secret}},
		credentialcached.Name:     []credentialcached.Entry{{EffectiveName: "user", Verifier: []byte(secret)}},
		credentiallsasecrets.Name: []credentiallsasecrets.Entry{{Name: "DPAPI_SYSTEM", CurrentValue: []byte(secret), OldValue: []byte(secret)}},
		credentialtruecrypt.Name:  []credentialtruecrypt.Passphrase{{Offset: 0x10, Length: uint64(len(secret)), Password: secret}},
	}
	if len(rows) != len(secretFields) {
		t.Fatalf("%d credential tools have secret fields, %d tested", len(secretFields), len(rows))
	}
	for name, result := range rows {
		tb := tabulate(result, secretsFor(name, false))
		if !slices.Equal(slices.Sorted(slices.Values(tb.hidden)), slices.Sorted(slices.Values(secretFields[name]))) {
			t.Errorf("%s: hidden %q, want %q: a field was renamed", name, tb.hidden, secretFields[name])
		}
		var out bytes.Buffer
		writeTable(&out, tb, 0)
		if strings.Contains(out.String(), secret) || strings.Contains(out.String(), "73336372") || strings.Contains(out.String(), "11 bytes") {
			t.Errorf("%s: secret printed:\n%s", name, out.String())
		}
		if revealed := tabulate(result, secretsFor(name, true)); len(revealed.hidden) != 0 {
			t.Errorf("%s: -reveal-secrets still hides %q", name, revealed.hidden)
		}
	}
}

func TestATableIsCutOnlyWhereAskedAndSaysSo(t *testing.T) {
	tb := table{header: []string{"A"}, rows: [][]string{{"1"}, {"2"}, {"3"}}, hidden: []string{"A"}}
	var cut, whole bytes.Buffer
	writeTable(&cut, tb, 2)
	writeTable(&whole, tb, 0)
	if !strings.Contains(cut.String(), "(1 more rows in the report file)") || strings.Contains(cut.String(), "\n3\n") {
		t.Errorf("cut table:\n%s", cut.String())
	}
	if strings.Contains(whole.String(), "more rows") || !strings.Contains(whole.String(), "\n3\n") ||
		!strings.Contains(whole.String(), "rows: 3\nhidden: A (pass -reveal-secrets to show them)\n") {
		t.Errorf("whole table:\n%s", whole.String())
	}
}

func TestAnOutcomeShowsItsErrorAndDiagnostics(t *testing.T) {
	var out bytes.Buffer
	writeOutcome(&out, outcome{name: "any.x.list", description: "List x", err: os.ErrNotExist,
		diagnostics: []string{"any.x.list: at 0x10: bad\x1b"}, duration: 1500 * time.Microsecond}, 0)
	want := "\n[any.x.list]\nList x\ntime: 2ms\nerror: file does not exist\ndiagnostics: 1\n- any.x.list: at 0x10: bad\\x1b\n"
	if out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}

func TestTheSummaryCountsEveryTool(t *testing.T) {
	r := &run{
		settings: settings{osName: "windows"},
		image:    "m.raw",
		selected: []string{"any.a.list", "windows.b.list"},
		skipped:  []string{memoryranges.Name},
		session:  []string{"one"},
		outcomes: []outcome{
			{name: "any.a.list", rows: 3, diagnostics: []string{"d"}},
			{name: "windows.b.list", err: os.ErrInvalid},
		},
	}
	var out bytes.Buffer
	writeSummary(&out, r)
	for _, want := range []string{
		"libvapour showcase summary\n", "tools: 2 (every any and windows tool)\n", "skipped: " + memoryranges.Name,
		"status: ok=1 error=1\n", "session diagnostics: 1\n", "any.a.list      ok      3     1",
		"windows.b.list  error   -     0", "[errors]\n- windows.b.list: invalid argument\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, out.String())
		}
	}
}

func TestTheSummarySitsBesideTheReport(t *testing.T) {
	cases := [][3]string{
		{"showcase_report.txt", "", "showcase_report_summary.txt"},
		{filepath.Join("out", "r"), "", filepath.Join("out", "r_summary")},
		{"r.txt", " s.txt ", "s.txt"},
	}
	for _, c := range cases {
		if got := summaryPath(c[0], c[1]); got != c[2] {
			t.Errorf("summaryPath(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestAnImageThatDoesNotOpenIsReportedInPrivateFiles(t *testing.T) {
	dir := t.TempDir()
	s, image, err := parse(t, "-out", filepath.Join(dir, "new", "report.txt"), filepath.Join(dir, "missing.raw"))
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := showcase(s, image, &stdout); err == nil {
		t.Fatal("a missing image gave no error")
	}
	data, err := os.ReadFile(s.out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "libvapour showcase report\n") || !strings.Contains(string(data), "\nerror: ") {
		t.Errorf("report:\n%s", data)
	}
	if private, err := ownerfile.IsPrivate(s.out); err != nil || !private {
		t.Errorf("report not private: %t %v", private, err)
	}
}

func FuzzOptionFlag(f *testing.F) {
	for _, seed := range []string{"pid=4", " a = b ", "=x", "noequals", "k==v", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, arg string) {
		o := optionFlag{}
		err := o.Set(arg)
		key, value, ok := strings.Cut(arg, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			if err == nil {
				t.Fatalf("%q accepted", arg)
			}
			return
		}
		if err != nil || len(o) != 1 || o[key] != strings.TrimSpace(value) {
			t.Fatalf("%q: %v %v", arg, o, err)
		}
	})
}
