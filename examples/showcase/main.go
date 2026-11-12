package main

import (
	"bufio"
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	libvapour "github.com/aoiflux/libvapour"
	"github.com/aoiflux/libvapour/examples/internal/cli"
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

const (
	defaultReport = "showcase_report.txt"
	summaryMark   = "_summary"
	pidOption     = "pid"
	anyPlatform   = "any"
	rule          = "================================================================================"
)

type skipRule struct {
	reason      string
	pidIncludes bool
}

// These three gave most of the report's bytes (S78 M2, M3); a pid filter
// makes only the page listing small.
var skippedByDefault = map[string]skipRule{
	memoryranges.Name:  {"across every process it gives millions of page runs; name it with -tools, or give -pid or -opt pid=", true},
	timeline.Name:      {"it repeats the timed rows of the other tools, about half the report; name it with -tools", false},
	kernelsymbols.Name: {"it lists every kernel symbol, hundreds of thousands of rows; name it with -tools", false},
}

// Lengths are secret too: a password's length narrows a search for it.
var secretFields = map[string][]string{
	credentiallocal.Name:      {"LMHash", "NTHash"},
	credentialcached.Name:     {"Verifier"},
	credentiallsasecrets.Name: {"CurrentValue", "OldValue"},
	credentialtruecrypt.Name:  {"Password", "Length"},
}

type settings struct {
	osName        string
	config        libvapour.OpenConfig
	named         []string
	maxRows       int
	out           string
	summary       bool
	summaryOut    string
	timings       bool
	revealSecrets bool
}

type optionFlag map[string]any

func (o optionFlag) String() string { return "" }

func (o optionFlag) Set(v string) error {
	key, value, ok := strings.Cut(v, "=")
	key = strings.TrimSpace(key)
	if !ok || key == "" {
		return fmt.Errorf("showcase: -opt wants key=value, got %q", v)
	}
	o[key] = strings.TrimSpace(value)
	return nil
}

type outcome struct {
	name        string
	description string
	table       table
	rows        int
	diagnostics []string
	err         error
	duration    time.Duration
}

type run struct {
	settings settings
	image    string
	selected []string
	skipped  []string
	started  time.Time
	session  []string
	outcomes []outcome
	total    time.Duration
}

func main() {
	log.SetFlags(0)
	s, image, err := parseArgs(flag.CommandLine, os.Args[1:])
	if err != nil {
		os.Exit(2)
	}
	if err := showcase(s, image, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func parseArgs(fs *flag.FlagSet, args []string) (settings, string, error) {
	var s settings
	var cfg libvapour.OpenConfig
	var toolList, pagefiles string
	options := optionFlag{}
	fs.StringVar(&s.osName, "os", "windows", "operating system of the image: windows or linux")
	fs.StringVar(&cfg.SymbolsPath, "symbols", "", "kernel .vsym symbol table (found when omitted: from the symbol server or its cache on windows, from the image on linux)")
	fs.Uint64Var(&cfg.KernelCR3, "cr3", 0, "the kernel's page-table root; the session finds it, and a different value fails the open (hex such as 0x1aa000 is accepted)")
	fs.BoolVar(&cfg.Strict, "strict", false, "make a tool stop with an error where it would otherwise report a diagnostic")
	fs.Uint64Var(&cfg.PID, "pid", 0, "run per-process tools on this PID only (0 = every process; -opt pid=0 names PID 0, -opt pid=4,8 a set)")
	fs.BoolVar(&cfg.ProcessListSanityFilter, "process-list-sanity", false, "any.process.list: drop rows whose fields fail the plausibility checks")
	fs.BoolVar(&cfg.ProcessListActiveOnly, "process-list-active-only", false, "any.process.list: keep only processes that are running")
	fs.StringVar(&cfg.ProcessListCrossCheckCSV, "process-list-cross-check-csv", "", "any.process.list: CSV of processes recorded by other means, compared with the list")
	fs.BoolVar(&cfg.NetworkScanIncludeCorrupt, "network-scan-include-corrupt", false, "windows.network.scan: keep rows that decoded only in part")
	fs.BoolVar(&cfg.OfflineOnly, "offline", false, "windows only: download no symbols; use the symbol cache or -symbols")
	fs.StringVar(&pagefiles, "pagefiles", "", "pagefile copies, comma-separated, in pagefile-number order (for example pagefile.sys,swapfile.sys)")
	fs.BoolVar(&s.timings, "timings", true, "end the report with each tool's run time, slowest first")
	fs.StringVar(&toolList, "tools", "", "tools to run, comma-separated (default: every tool for -os, without "+memoryranges.Name+" unless -pid is given)")
	fs.IntVar(&s.maxRows, "max-rows", 0, "print at most this many rows of each table on stdout (0 = all); the report file always holds every row")
	fs.StringVar(&s.out, "out", defaultReport, "report file to write, readable by you alone (mode 0600; on windows an ACL for you and SYSTEM)")
	fs.BoolVar(&s.summary, "summary", true, "also write a summary file")
	fs.StringVar(&s.summaryOut, "summary-out", "", "summary file to write (default: the -out name with "+summaryMark+" before its extension)")
	fs.BoolVar(&s.revealSecrets, "reveal-secrets", false, "print password hashes, cached-logon verifiers, LSA secrets and found passphrases instead of "+redactedCell)
	fs.Var(options, "opt", "tool option as key=value, repeatable (for example -opt windows.registry.read_key.hive=SOFTWARE)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: showcase [flags] <memory image>\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return settings{}, "", err
	}
	image, err := cli.Image(fs)
	if err != nil {
		fmt.Fprintln(fs.Output(), err)
		fs.Usage()
		return settings{}, "", err
	}
	if s.maxRows < 0 {
		err := fmt.Errorf("showcase: -max-rows must be 0 or more, got %d", s.maxRows)
		fmt.Fprintln(fs.Output(), err)
		return settings{}, "", err
	}
	cfg.PagefilePaths = splitList(pagefiles)
	cfg.CollectDiagnostics = true
	cfg.ToolOptions = options
	s.config = cfg
	s.named = splitList(toolList)
	return s, image, nil
}

func splitList(s string) []string {
	var out []string
	for item := range strings.SplitSeq(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func (s settings) pidGiven() bool {
	_, ok := s.config.ToolOptions[pidOption]
	return s.config.PID != 0 || ok
}

func selectTools(osName string, specs []tools.Spec, named []string, pidGiven bool) (selected, skipped []string) {
	if len(named) > 0 {
		return named, nil
	}
	platform := strings.ToLower(strings.TrimSpace(osName))
	for _, spec := range specs {
		owner, _, _ := strings.Cut(spec.Name, ".")
		switch {
		case owner != anyPlatform && owner != platform:
		case skips(spec.Name, pidGiven):
			skipped = append(skipped, spec.Name)
		default:
			selected = append(selected, spec.Name)
		}
	}
	return selected, skipped
}

func skips(name string, pidGiven bool) bool {
	r, ok := skippedByDefault[name]
	return ok && !(r.pidIncludes && pidGiven)
}

func showcase(s settings, image string, stdout io.Writer) error {
	reportPath := s.out
	if strings.TrimSpace(reportPath) == "" {
		reportPath = defaultReport
	}
	report, err := createPrivate(reportPath)
	if err != nil {
		return err
	}
	defer report.Close()
	file := bufio.NewWriter(report)

	r := &run{settings: s, image: image, started: time.Now()}
	r.selected, r.skipped = selectTools(s.osName, tools.List(), s.named, s.pidGiven())
	both := io.MultiWriter(file, stdout)
	writeHeader(both, "report", r)

	session, err := libvapour.OpenMemory(image, s.osName, s.config)
	if err != nil {
		fmt.Fprintf(both, "\nerror: %s\n", cli.Text(err.Error()))
		_ = file.Flush()
		return fmt.Errorf("showcase: open image: %w", err)
	}
	r.session = session.Diagnostics()
	writeDiagnostics(both, "\n[session]\n", r.session)

	for _, name := range r.selected {
		o := execute(session, name, secretsFor(name, s.revealSecrets))
		if s.maxRows == 0 {
			writeOutcome(both, o, 0)
		} else {
			writeOutcome(file, o, 0)
			writeOutcome(stdout, o, s.maxRows)
		}
		// Tables are written as each tool ends, so only one is held at a time.
		o.table = table{}
		r.outcomes = append(r.outcomes, o)
	}
	r.total = time.Since(r.started)
	closeErr := session.Close()

	if s.timings {
		writeTimings(both, r)
	}
	if err := file.Flush(); err != nil {
		return fmt.Errorf("showcase: write report: %w", err)
	}
	if err := report.Close(); err != nil {
		return fmt.Errorf("showcase: write report: %w", err)
	}
	fmt.Fprintf(stdout, "\nreport saved: %s\n", cli.Text(reportPath))

	if s.summary {
		path := summaryPath(reportPath, s.summaryOut)
		if err := writeSummaryFile(path, r); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "summary saved: %s\n", cli.Text(path))
	}
	if closeErr != nil {
		return fmt.Errorf("showcase: close image: %w", closeErr)
	}
	return nil
}

func secretsFor(name string, reveal bool) []string {
	if reveal {
		return nil
	}
	return secretFields[name]
}

func execute(session *libvapour.Session, name string, secrets []string) outcome {
	o := outcome{name: name}
	if t, err := tools.Get(name); err == nil {
		o.description = t.Spec.Description
	}
	before := len(session.Diagnostics())
	start := time.Now()
	result, err := session.Execute(name)
	o.duration = time.Since(start)
	o.err = err
	if all := session.Diagnostics(); len(all) > before {
		o.diagnostics = all[before:]
	}
	if err == nil {
		o.table = tabulate(result, secrets)
		o.rows = len(o.table.rows)
	}
	return o
}

func createPrivate(path string) (*os.File, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := ownerfile.MkdirAll(dir); err != nil {
			return nil, fmt.Errorf("showcase: make directory for %s: %w", path, err)
		}
	}
	f, err := ownerfile.Create(path)
	if err != nil {
		return nil, fmt.Errorf("showcase: create %s: %w", path, err)
	}
	return f, nil
}

func summaryPath(report, override string) string {
	if v := strings.TrimSpace(override); v != "" {
		return v
	}
	ext := filepath.Ext(report)
	return strings.TrimSuffix(report, ext) + summaryMark + ext
}

func writeHeader(w io.Writer, kind string, r *run) {
	fmt.Fprintf(w, "libvapour showcase %s\n", kind)
	fmt.Fprintf(w, "generated: %s\n", r.started.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "image: %s\n", cli.Text(r.image))
	fmt.Fprintf(w, "os: %s\n", cli.Text(r.settings.osName))
	if len(r.settings.named) > 0 {
		fmt.Fprintf(w, "tools: %d named by -tools\n", len(r.selected))
	} else {
		fmt.Fprintf(w, "tools: %d (every %s and %s tool)\n", len(r.selected), anyPlatform, cli.Text(strings.ToLower(r.settings.osName)))
	}
	for _, name := range r.skipped {
		fmt.Fprintf(w, "skipped: %s (%s)\n", name, skippedByDefault[name].reason)
	}
	fmt.Fprintln(w, rule)
}

func writeDiagnostics(w io.Writer, heading string, diagnostics []string) {
	if len(diagnostics) == 0 {
		return
	}
	fmt.Fprint(w, heading)
	fmt.Fprintf(w, "diagnostics: %d\n", len(diagnostics))
	for _, d := range diagnostics {
		fmt.Fprintf(w, "- %s\n", cli.Text(d))
	}
}

func writeOutcome(w io.Writer, o outcome, maxRows int) {
	fmt.Fprintf(w, "\n[%s]\n", cli.Text(o.name))
	if o.description != "" {
		fmt.Fprintf(w, "%s\n", cli.Text(o.description))
	}
	fmt.Fprintf(w, "time: %s\n", o.duration.Round(time.Millisecond))
	if o.err != nil {
		fmt.Fprintf(w, "error: %s\n", cli.Text(o.err.Error()))
	} else {
		writeTable(w, o.table, maxRows)
	}
	writeDiagnostics(w, "", o.diagnostics)
}

func writeTable(w io.Writer, t table, maxRows int) {
	fmt.Fprintf(w, "rows: %d\n", len(t.rows))
	if len(t.hidden) > 0 {
		fmt.Fprintf(w, "hidden: %s (pass -reveal-secrets to show them)\n", strings.Join(t.hidden, ", "))
	}
	if len(t.rows) == 0 {
		return
	}
	shown := t.rows
	if maxRows > 0 && len(shown) > maxRows {
		shown = shown[:maxRows]
	}
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, strings.Join(t.header, "\t"))
	for _, row := range shown {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	_ = tw.Flush()
	if more := len(t.rows) - len(shown); more > 0 {
		fmt.Fprintf(w, "(%d more rows in the report file)\n", more)
	}
}

func status(o outcome) string {
	if o.err != nil {
		return "error"
	}
	return "ok"
}

func writeTimings(w io.Writer, r *run) {
	fmt.Fprintf(w, "\n[timings]\ntotal: %s\n", r.total.Round(time.Millisecond))
	byTime := slices.Clone(r.outcomes)
	slices.SortStableFunc(byTime, func(a, b outcome) int { return cmp.Compare(b.duration, a.duration) })
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "Tool\tStatus\tTime")
	for _, o := range byTime {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", cli.Text(o.name), status(o), o.duration.Round(time.Millisecond))
	}
	_ = tw.Flush()
}

func writeSummary(w io.Writer, r *run) {
	writeHeader(w, "summary", r)
	ok, failed := 0, 0
	for _, o := range r.outcomes {
		if o.err != nil {
			failed++
		} else {
			ok++
		}
	}
	fmt.Fprintf(w, "status: ok=%d error=%d\n", ok, failed)
	fmt.Fprintf(w, "total: %s\n", r.total.Round(time.Millisecond))
	fmt.Fprintf(w, "session diagnostics: %d\n\n", len(r.session))
	tw := cli.NewTable(w)
	fmt.Fprintln(tw, "Tool\tStatus\tRows\tDiagnostics\tTime")
	for _, o := range r.outcomes {
		rows := "-"
		if o.err == nil {
			rows = fmt.Sprint(o.rows)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", cli.Text(o.name), status(o), rows, len(o.diagnostics), o.duration.Round(time.Millisecond))
	}
	_ = tw.Flush()
	if failed > 0 {
		fmt.Fprint(w, "\n[errors]\n")
		for _, o := range r.outcomes {
			if o.err != nil {
				fmt.Fprintf(w, "- %s: %s\n", cli.Text(o.name), cli.Text(o.err.Error()))
			}
		}
	}
}

func writeSummaryFile(path string, r *run) error {
	f, err := createPrivate(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	writeSummary(w, r)
	err = errors.Join(w.Flush(), f.Close())
	if err != nil {
		return fmt.Errorf("showcase: write summary: %w", err)
	}
	return nil
}
