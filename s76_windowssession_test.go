package libvapour

import (
	"encoding/binary"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
	toolprocesslist "github.com/aoiflux/libvapour/tools/any/processlist"
)

type refuseRequests struct{ asked *[]string }

func (r refuseRequests) RoundTrip(req *http.Request) (*http.Response, error) {
	*r.asked = append(*r.asked, req.URL.String())
	return nil, errors.New("s76 test: no network")
}

func noDownloads(t *testing.T) *[]string {
	t.Helper()
	var asked []string
	saved := http.DefaultTransport
	http.DefaultTransport = refuseRequests{asked: &asked}
	t.Cleanup(func() { http.DefaultTransport = saved })
	return &asked
}

func hasNote(notes []string, parts ...string) bool {
	return slices.ContainsFunc(notes, func(n string) bool {
		for _, p := range parts {
			if !strings.Contains(n, p) {
				return false
			}
		}
		return true
	})
}

func openWithTable(t *testing.T, k *winKernel, d symbols.Declaration, cfg OpenConfig) (*Session, error) {
	t.Helper()
	cfg.SymbolsPath = writeTable(t, d)
	cfg.OfflineOnly = true
	s, err := OpenWindowsMemory(k.write(t), cfg)
	if err == nil {
		t.Cleanup(func() { _ = s.Close() })
	}
	return s, err
}

func TestAWindowsSessionWithItsOwnTableFindsRootAndBase(t *testing.T) {
	k := newWinKernel(fxGUID)
	build := fxBuild(fxGUID)
	s, err := openWithTable(t, k, winDeclaration(&build, noPTELayout, false), OpenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := s.Context()
	if root, ok := ctx.KernelDTB(); !ok || root != k.root {
		t.Errorf("kernel root = 0x%x, %v; want 0x%x", root, ok, k.root)
	}
	if base, ok := ctx.KernelBase(); !ok || base != fxKernelBase {
		t.Errorf("kernel base = 0x%x, %v", base, ok)
	}
	if ctx.PagingMode() != layers.ModeX64.Name() {
		t.Errorf("paging mode %q", ctx.PagingMode())
	}
	if ctx.PhysicalMemory() == nil || ctx.LoadPDB == nil || ctx.ProcessMemory == nil {
		t.Error("context lacks a physical reader, PDB loader or process spaces")
	}
	head, err := ctx.Symbols.LookupSymbol("PsActiveProcessHead")
	if err != nil || head.Address != k.headVA {
		t.Fatalf("PsActiveProcessHead = 0x%x, %v", head.Address, err)
	}
	flink, err := ctx.Symbols.ReadPointer(ctx.Memory, head.Address)
	if err != nil || flink != k.linksVA {
		t.Errorf("head Flink through the kernel space = 0x%x, %v", flink, err)
	}
	if v, ok := ctx.Options[optionStartFlink]; !ok || v != k.headVA {
		t.Errorf("start entry = %#x, %v; the System scan ran, so the System entry's Flink is known", v, ok)
	}
	notes := s.Diagnostics()
	for _, want := range [][]string{
		{"from the System process"},
		{"kernel base 0x", "the System process's list Blink", "confirmed"},
		{"names ntkrnlmp.pdb", "could not confirm"},
		{"windows.network.scan", "no layout"},
	} {
		if !hasNote(notes, want...) {
			t.Errorf("no note with %q in %q", want, notes)
		}
	}
	if err := ctx.Validate(); err != nil {
		t.Errorf("context does not validate: %v", err)
	}
}

func TestAWindowsSessionFromTheStartPageNeedsNoSystemScan(t *testing.T) {
	asked := noDownloads(t)
	k := newWinKernel(fxGUID)
	k.addStartPage()
	build := fxBuild(fxGUID)
	cache := t.TempDir()
	seedCache(t, cache, fxFingerprint(fxGUID), winDeclaration(&build, noPTELayout, false))

	s, err := OpenWindowsMemory(k.write(t), OpenConfig{OfflineOnly: true, CollectDiagnostics: true,
		SymbolLoad: autoload.LoadOptions{CacheDir: cache}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := s.Context()
	if root, _ := ctx.KernelDTB(); root != k.root {
		t.Errorf("kernel root 0x%x", root)
	}
	if base, _ := ctx.KernelBase(); base != fxKernelBase {
		t.Errorf("kernel base 0x%x", base)
	}
	if _, ok := ctx.Options[optionStartFlink]; ok {
		t.Error("start entry set, so the System scan ran though the start page gave root and base")
	}
	notes := s.Diagnostics()
	if !hasNote(notes, "root", "from the processor start page") || !hasNote(notes, "kernel base", "processor start page", "confirmed") {
		t.Errorf("notes %q", notes)
	}
	if len(*asked) != 0 {
		t.Errorf("offline session asked the network: %q", *asked)
	}
}

func TestATableForAnotherBuildIsRefused(t *testing.T) {
	other := fxGUID
	other[0] ^= 0xff
	build := fxBuild(other)

	_, err := openWithTable(t, newWinKernel(fxGUID), winDeclaration(&build, noPTELayout, false), OpenConfig{})
	if !errors.Is(err, errOtherKernelBuild) {
		t.Errorf("image of another build at the base: %v", err)
	}

	k := newWinKernel(fxGUID)
	k.addStartPage()
	if _, err := openWithTable(t, k, winDeclaration(&build, noPTELayout, false), OpenConfig{}); !errors.Is(err, errOtherKernelBuild) ||
		!strings.Contains(err.Error(), "processor start page") {
		t.Errorf("running kernel of another build: %v", err)
	}
}

func TestATableNamingNoBuildFollowsTheRunningKernel(t *testing.T) {
	k := newWinKernel(fxGUID)
	k.addStartPage()
	s, err := openWithTable(t, k, winDeclaration(nil, noPTELayout, false), OpenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if base, _ := s.Context().KernelBase(); base != fxKernelBase {
		t.Errorf("kernel base 0x%x", base)
	}
	if !hasNote(s.Diagnostics(), "names no kernel build", "not checked") {
		t.Errorf("notes %q", s.Diagnostics())
	}

	s, err = openWithTable(t, newWinKernel(fxGUID), winDeclaration(nil, noPTELayout, false), OpenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Context().KernelBase(); ok {
		t.Error("a base was set with nothing to confirm it against")
	}
	if head, _ := s.Context().Symbols.LookupSymbol("PsActiveProcessHead"); head.Address != fxHeadRVA {
		t.Errorf("head moved to 0x%x", head.Address)
	}
}

func TestAGivenKernelRootMustBeTheCapturesRoot(t *testing.T) {
	k := newWinKernel(fxGUID)
	build := fxBuild(fxGUID)
	d := winDeclaration(&build, noPTELayout, false)
	if _, err := openWithTable(t, k, d, OpenConfig{KernelCR3: k.root | 0x5}); err != nil {
		t.Errorf("root with flag bits: %v", err)
	}
	if _, err := openWithTable(t, k, d, OpenConfig{KernelCR3: k.root + fxPage}); err == nil || !strings.Contains(err.Error(), "was given") {
		t.Errorf("another root: %v", err)
	}
}

const pagedOutVA = fxKernelBase + 0x10000

func pagefileKernel(t *testing.T) (*winKernel, string) {
	t.Helper()
	k := newWinKernel(fxGUID)
	k.setEntry(pagedOutVA, 2<<32|0<<1)
	data := make([]byte, 3*fxPage)
	copy(data[2*fxPage:], "paged out")
	path := filepath.Join(t.TempDir(), "pagefile.sys")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return k, path
}

func TestPagefilesAreReadOnlyInTheLayoutTheyAreDecodedIn(t *testing.T) {
	build := fxBuild(fxGUID)
	k, path := pagefileKernel(t)
	s, err := openWithTable(t, k, winDeclaration(&build, pte14393, false), OpenConfig{PagefilePaths: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Context().Memory.ReadAt(pagedOutVA, 9); err != nil || string(got) != "paged out" {
		t.Errorf("paged-out page = %q, %v", got, err)
	}
	if _, err := openWithTable(t, k, winDeclaration(&build, pte14393, false),
		OpenConfig{PagefilePaths: []string{filepath.Join(t.TempDir(), "absent.sys")}}); err == nil {
		t.Error("a pagefile that does not open was ignored")
	}

	s, err = openWithTable(t, k, winDeclaration(&build, pte19045, false),
		OpenConfig{PagefilePaths: []string{filepath.Join(t.TempDir(), "absent.sys")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Context().Memory.ReadAt(pagedOutVA, 9); !errors.Is(err, layers.ErrPageInPagefile) {
		t.Errorf("read through a refused layout: %v", err)
	}
	if !hasNote(s.Diagnostics(), "pagefiles not read", "PageFileLow") {
		t.Errorf("notes %q", s.Diagnostics())
	}
}

func TestTheKernelBuildPicksTheNetworkLayout(t *testing.T) {
	k := newWinKernel(fxGUID)
	k.addBuildNumber(fxNtBuildNumber)
	build := fxBuild(fxGUID)
	s, err := openWithTable(t, k, winDeclaration(&build, noPTELayout, true), OpenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := s.Context()
	if got := ctx.NetworkScanLayout(); got != "tcpip-26100" {
		t.Fatalf("layout %q, notes %q", got, s.Diagnostics())
	}
	if _, err := ctx.Symbols.Struct("tcpEndpoint"); err != nil {
		t.Errorf("layout types not reachable: %v", err)
	}
	if _, err := ctx.Symbols.Struct("_EPROCESS"); err != nil {
		t.Errorf("kernel types hidden: %v", err)
	}
	if head, err := ctx.Symbols.LookupSymbol("PsActiveProcessHead"); err != nil || head.Address != k.headVA {
		t.Errorf("kernel symbol through the layered table: 0x%x, %v", head.Address, err)
	}
}

func TestOpenOptionsComeFromTheConfigOverTheMap(t *testing.T) {
	build := fxBuild(fxGUID)
	d := winDeclaration(&build, noPTELayout, false)
	csv := filepath.Join(t.TempDir(), "snapshot.csv")
	if err := os.WriteFile(csv, []byte("pid,name\n4,System\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mine := map[string]any{"pid": uint64(9), "own.key": "kept"}
	rows := make([]toolprocesslist.SnapshotProcess, 1, 4)
	rows[0] = toolprocesslist.SnapshotProcess{PID: 8, Name: "given"}
	s, err := openWithTable(t, newWinKernel(fxGUID), d, OpenConfig{
		PID: 7, Strict: true, ToolOptions: mine, ProcessListSanityFilter: true, ProcessListActiveOnly: true,
		ProcessListCrossCheckCSV: csv, ProcessListCrossCheck: rows, NetworkScanIncludeCorrupt: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	o := s.Context().Options
	for key, want := range map[string]any{optionPID: uint64(7), "own.key": "kept", optionStrict: true,
		optionProcessListSanity: true, optionProcessListActive: true, optionNetworkScanCorrupt: true} {
		if o[key] != want {
			t.Errorf("option %s = %v, want %v", key, o[key], want)
		}
	}
	if _, ok := o[optionProcessListCross]; !ok {
		t.Error("no cross-checker from the file")
	}
	if mine["pid"] != uint64(9) || len(mine) != 2 {
		t.Errorf("caller's map changed: %v", mine)
	}
	if spare := rows[:cap(rows)]; spare[1] != (toolprocesslist.SnapshotProcess{}) {
		t.Errorf("file rows written into the caller's slice: %+v", spare)
	}
	if _, err := openWithTable(t, newWinKernel(fxGUID), d, OpenConfig{ProcessListCrossCheckCSV: csv + ".absent"}); err == nil {
		t.Error("a cross-check file that does not read was ignored")
	}
}

func TestDiagnosticsGoToTheSinkWhenCollected(t *testing.T) {
	build := fxBuild(fxGUID)
	d := winDeclaration(&build, noPTELayout, false)
	s, err := openWithTable(t, newWinKernel(fxGUID), d, OpenConfig{CollectDiagnostics: true})
	if err != nil {
		t.Fatal(err)
	}
	sink := diagnosticSink(s.Context().Options)
	if sink == nil || len(*sink) == 0 || !slices.Equal(*sink, s.Diagnostics()) {
		t.Fatalf("sink %v, diagnostics %q", sink, s.Diagnostics())
	}
	s.Context().AddDiagnostic("s76 test: %s", "a tool's line")
	if got := s.Diagnostics(); got[len(got)-1] != "s76 test: a tool's line" || !strings.HasPrefix(got[0], "memory: ") {
		t.Errorf("diagnostics in order: %q", got)
	}
	got := s.Diagnostics()
	got[0] = "changed"
	if s.Diagnostics()[0] == "changed" {
		t.Error("Diagnostics returned the session's own slice")
	}
}

func TestRunsGiveOneRowPerToolAskedFor(t *testing.T) {
	build := fxBuild(fxGUID)
	s, err := openWithTable(t, newWinKernel(fxGUID), winDeclaration(&build, noPTELayout, false), OpenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	report := s.ExecuteSelected([]string{"no.such.tool", "any.process.list"})
	if len(report.Tools) != 2 || report.Tools[0].Spec.Name != "no.such.tool" || report.Tools[0].Error == nil ||
		report.Tools[1].Spec.Description == "" {
		t.Errorf("selected rows %+v", report.Tools)
	}
	if _, err := s.Execute("no.such.tool"); err == nil {
		t.Error("unknown tool ran")
	}
	all := s.ExecuteAll()
	names := make([]string, len(all.Tools))
	for i, r := range all.Tools {
		names[i] = r.Spec.Name
	}
	want := make([]string, 0, len(tools.List()))
	for _, spec := range tools.List() {
		want = append(want, spec.Name)
	}
	if !slices.Equal(names, want) || !slices.Contains(names, "windows.module.list") {
		t.Errorf("ExecuteAll ran %q", names)
	}
}

func TestClosingTwiceIsHarmless(t *testing.T) {
	build := fxBuild(fxGUID)
	k := newWinKernel(fxGUID)
	path := k.write(t)
	s, err := OpenWindowsMemory(path, OpenConfig{SymbolsPath: writeTable(t, winDeclaration(&build, noPTELayout, false))})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}

func TestAnalyzeMemoryRunsAndCloses(t *testing.T) {
	build := fxBuild(fxGUID)
	k := newWinKernel(fxGUID)
	report, err := AnalyzeMemory(k.write(t), " Windows ", OpenConfig{
		SymbolsPath: writeTable(t, winDeclaration(&build, noPTELayout, false)), OfflineOnly: true},
		[]string{"no.such.tool"})
	if err != nil || len(report.Tools) != 1 || len(report.Diagnostics) == 0 {
		t.Errorf("report %+v, %v", report, err)
	}
}

func TestStrictModeRefusesAKernelBaseNothingConfirmed(t *testing.T) {
	build := fxBuild(fxGUID)
	named := winDeclaration(&build, noPTELayout, false)
	if _, err := openWithTable(t, newWinKernel(fxGUID), named, OpenConfig{Strict: true}); err != nil {
		t.Errorf("confirmed base, strict: %v", err)
	}

	blank := newWinKernel(fxGUID)
	blank.mapPage(fxKernelBase)
	s, err := openWithTable(t, blank, named, OpenConfig{})
	if err != nil {
		t.Fatalf("no base: %v", err)
	}
	if _, ok := s.Context().KernelBase(); ok || !hasNote(s.Diagnostics(), "no kernel base found") {
		t.Errorf("no base, notes %q", s.Diagnostics())
	}
	if _, err := openWithTable(t, blank, named, OpenConfig{Strict: true}); !errors.Is(err, errStrictKernelBase) ||
		!strings.Contains(err.Error(), "no kernel base found") {
		t.Errorf("no base, strict: %v", err)
	}

	unread := newWinKernel(fxGUID)
	header := peWithCodeView(`x\ntkrnlmp.pdb`, fxGUID, 1)
	binary.LittleEndian.PutUint32(header[0x200+20:], 0x5000)
	copy(unread.buf[unread.mapPage(fxKernelBase):], header)
	s, err = openWithTable(t, unread, named, OpenConfig{})
	if err != nil {
		t.Fatalf("unconfirmed base: %v", err)
	}
	if base, _ := s.Context().KernelBase(); base != fxKernelBase || !hasNote(s.Diagnostics(), "is unconfirmed") {
		t.Errorf("unconfirmed base 0x%x, notes %q", base, s.Diagnostics())
	}
	if _, err := openWithTable(t, unread, named, OpenConfig{Strict: true}); !errors.Is(err, errStrictKernelBase) ||
		!strings.Contains(err.Error(), "the System process's list Blink") {
		t.Errorf("unconfirmed base, strict: %v", err)
	}

	if _, err := openWithTable(t, newWinKernel(fxGUID), winDeclaration(nil, noPTELayout, false), OpenConfig{Strict: true}); !errors.Is(err, errStrictKernelBase) {
		t.Errorf("no build to check against, strict: %v", err)
	}

	table := lookupTable(t, symbols.Declaration{PointerWidth: 8, WindowsPDB: &build,
		Addresses: []symbols.Address{{Name: "PsActiveProcessHead", Address: fxHeadRVA}}})
	id := &autoload.KernelIdentity{Fingerprint: fxFingerprint(fxGUID), Method: methodTableOwnBuild}
	none := kernelBase{tried: []string{"the debugger data block scan: not found"}}
	lenient := &opening{}
	if got, base, err := lenient.acceptKernelBase(table, id, none); err != nil || base != 0 || got != symbols.SymbolTable(table) ||
		!hasNote(lenient.notes, "no kernel base found") {
		t.Errorf("no base: 0x%x %v, notes %q", base, err, lenient.notes)
	}
	strict := &opening{cfg: OpenConfig{Strict: true}}
	if _, _, err := strict.acceptKernelBase(table, id, none); !errors.Is(err, errStrictKernelBase) || !strings.Contains(err.Error(), "not found") {
		t.Errorf("no base, strict: %v", err)
	}
}

func TestOptionsOfTheWrongFormFailTheOpen(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent.raw")
	for key, value := range map[string]any{
		"pid":                         "four",
		"strict":                      "maybe",
		tools.OptionMaxDumpSize:       -1,
		optionProcessListSanity:       "sometimes",
		optionProcessListActive:       3,
		optionNetworkScanCorrupt:      []string{"yes"},
		optionStartFlink:              "head",
		optionProcessListCross:        5,
		optionDiagnostics:             []string{},
		tools.OptionPhysicalMemory:    "capture",
		tools.OptionNetworkScanLayout: 26100,
	} {
		_, err := OpenWindowsMemory(absent, OpenConfig{ToolOptions: map[string]any{key: value}})
		if !errors.Is(err, tools.ErrOptionType) || !strings.Contains(err.Error(), "open config") || !strings.Contains(err.Error(), key) {
			t.Errorf("%s = %v: %v", key, value, err)
		}
	}
	_, err := OpenLinuxMemory(absent, OpenConfig{ToolOptions: map[string]any{"pid": "four", optionProcessListActive: 3}})
	if !errors.Is(err, tools.ErrOptionType) || !strings.Contains(err.Error(), "pid") || !strings.Contains(err.Error(), optionProcessListActive) {
		t.Errorf("every bad option named: %v", err)
	}
	k := newWinKernel(fxGUID)
	build := fxBuild(fxGUID)
	if _, err := openWithTable(t, k, winDeclaration(&build, noPTELayout, false), OpenConfig{ToolOptions: map[string]any{
		"pid": "4, 0x8", optionProcessListSanity: "yes", "own.tool.key": struct{}{}}}); err != nil {
		t.Errorf("good options: %v", err)
	}
}
