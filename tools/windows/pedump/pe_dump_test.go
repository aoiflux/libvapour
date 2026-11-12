package pedump

import (
	"debug/pe"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	userBase   = testsupport.S55UserBase
	kernelBase = testsupport.S55KernelBase
	driverBase = testsupport.S55DriverBase
	unmapped   = testsupport.S55Unmapped
)

type world struct {
	f     *testsupport.ProcessFixture
	ctx   tools.Context
	diags *[]string
}

func build(t *testing.T, procs []testsupport.FixtureProcess, sessions map[uint64]uint32, mods []testsupport.S55KernelModule) world {
	t.Helper()
	w, err := testsupport.BuildS55World(procs, sessions, mods)
	if err != nil {
		t.Fatal(err)
	}
	return world{f: w.ProcessFixture, ctx: w.Ctx, diags: w.Diags}
}

func explorer() []testsupport.FixtureProcess { return testsupport.S55Explorer() }

func standardModules() []testsupport.S55KernelModule { return testsupport.S55StandardModules() }

func (w world) run(t *testing.T, opts map[string]any) ([]Artifact, string, error) {
	t.Helper()
	dir := t.TempDir()
	w.ctx.Options[tools.OptionOutputDir] = dir
	for k, v := range opts {
		w.ctx.Options[k] = v
	}
	out, err := RunAny(w.ctx)
	if err != nil {
		return nil, dir, err
	}
	return out.([]Artifact), dir, nil
}

func parsed(t *testing.T, dir string, a Artifact) *pe.File {
	t.Helper()
	f, err := pe.Open(filepath.Join(dir, a.FileName))
	if err != nil {
		t.Fatalf("%s: %v", a.FileName, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestEveryLoadedImageIsWrittenAsAPEFile(t *testing.T) {
	w := build(t, explorer(), nil, standardModules())
	arts, dir, err := w.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 3 {
		t.Fatalf("%d rows, want explorer.exe's module then two kernel modules: %+v", len(arts), arts)
	}
	proc := arts[0]
	if proc.Source != SourceProcess || proc.PID != 1200 || proc.Process != "explorer.exe" || proc.Base != userBase ||
		proc.Path != `C:\Windows\explorer.exe` {
		t.Errorf("process row %+v", proc)
	}
	if !strings.HasPrefix(proc.FileName, "module.pid1200.0x00007ff600000000.0x") || !strings.HasSuffix(proc.FileName, ".explorer.exe.pe") {
		t.Errorf("process name %q", proc.FileName)
	}
	kern, kd := arts[1], arts[2]
	if kern.Source != SourceKernel || kern.Name != "ntoskrnl.exe" || kd.Path != `\SystemRoot\system32\kd.dll` {
		t.Errorf("kernel rows %+v, %+v", kern, kd)
	}
	for _, a := range arts {
		if !a.Complete() || a.Size != testsupport.MappedPESize || a.Captured != uint64(testsupport.MappedPESize) || a.Sections != 2 {
			t.Errorf("%s: %+v, want a complete image of every section", a.FileName, a)
			continue
		}
		f := parsed(t, dir, a)
		if got := f.OptionalHeader.(*pe.OptionalHeader64).ImageBase; got != a.Base || !a.ImageBaseFixed {
			t.Errorf("%s: ImageBase 0x%x, want the load address 0x%x", a.FileName, got, a.Base)
		}
	}
	entry := testsupport.S55ModuleEntries + 0x1000
	if want := "module.kernel.0xfffff80002000000.0x" + hexPad(entry) + ".kd.dll.pe"; kd.FileName != want {
		t.Errorf("kernel name %q, want %q: the label is the path's file", kd.FileName, want)
	}
}

func hexPad(v uint64) string { return fmt.Sprintf("%016x", v) }

func TestAnImageThatCannotBeWrittenIsSkippedWithItsReason(t *testing.T) {
	mods := standardModules()
	mods = append(mods, testsupport.S55KernelModule{Name: "gone.sys", Path: `\SystemRoot\gone.sys`, Base: unmapped,
		Image: testsupport.BuildMappedPE(0x1c0000000)})
	w := build(t, explorer()[:1], nil, mods)
	arts, _, err := w.run(t, map[string]any{"pid": uint64(4)})
	if err != nil {
		t.Fatal(err)
	}
	gone := arts[len(arts)-1]
	if gone.Written() || !strings.Contains(gone.Skipped, "not readable") {
		t.Errorf("gone.sys %+v, want skipped as unreadable headers", gone)
	}
	want := "windows.pe.dump: kernel gone.sys at 0xfffff80003000000: " + gone.Skipped
	if !contains(*w.diags, want) {
		t.Errorf("no diagnostic %q in %q", want, *w.diags)
	}
}

func contains(diags []string, want string) bool {
	for _, d := range diags {
		if d == want {
			return true
		}
	}
	return false
}

func TestAnImageOverTheArtifactCapIsNotRead(t *testing.T) {
	w := build(t, explorer()[:1], nil, standardModules())
	w.ctx.Limits.MaxArtifactBytes = int64(testsupport.MappedPESize) - 1
	arts, dir, err := w.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range arts {
		if a.Written() || !strings.Contains(a.Skipped, "over MaxArtifactBytes") {
			t.Errorf("%+v, want skipped over the cap", a)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("%d files written past the cap", len(entries))
	}
}

func TestAnExistingFileIsNeverReplaced(t *testing.T) {
	w := build(t, explorer()[:1], nil, standardModules()[:1])
	dir := t.TempDir()
	w.ctx.Options[tools.OptionOutputDir] = dir
	first, err := Run(w.ctx)
	if err != nil || len(first) != 1 || !first[0].Written() {
		t.Fatalf("first run %+v, %v", first, err)
	}
	second, err := Run(w.ctx)
	if err != nil || len(second) != 1 || second[0].Written() {
		t.Fatalf("second run %+v, %v; want the row skipped", second, err)
	}
}

func TestASessionDriverIsReadThroughAProcessOfItsSession(t *testing.T) {
	mods := standardModules()
	mods = append(mods, testsupport.S55KernelModule{Name: "win32k.sys", Path: `\SystemRoot\System32\win32k.sys`, Base: unmapped,
		Image: testsupport.BuildMappedPE(0x1c0000000), InSession: []uint64{1200}})
	w := build(t, explorer(), map[uint64]uint32{1200: 1}, mods)
	arts, dir, err := w.run(t, map[string]any{"pid": uint64(4)})
	if err != nil {
		t.Fatal(err)
	}
	win32k := arts[len(arts)-1]
	if !win32k.Complete() {
		t.Fatalf("win32k.sys %+v, want it read through session 1", win32k)
	}
	parsed(t, dir, win32k)
}

type fixed struct {
	at   uint64
	data []byte
}

func (f *fixed) Size() uint64 { return ^uint64(0) }
func (f *fixed) ReadAt(off, n uint64) ([]byte, error) {
	if off < f.at || off+n > f.at+uint64(len(f.data)) {
		return nil, memory.ErrOutOfBounds
	}
	return f.data[off-f.at : off-f.at+n], nil
}

func TestTheFirstReaderWhoseHeadersParseIsChosen(t *testing.T) {
	empty := &fixed{}
	image := &fixed{at: driverBase, data: testsupport.BuildMappedPE(0x180000000)}
	if r := ReaderForModule([]memory.MemoryReader{empty, image}, driverBase); r != memory.MemoryReader(image) {
		t.Error("the reader that maps the headers was passed over")
	}
	if r := ReaderForModule([]memory.MemoryReader{empty, image}, kernelBase); r != memory.MemoryReader(empty) {
		t.Error("with no reader mapping the headers, the kernel reader is not the one used")
	}
	if ReaderForModule(nil, kernelBase) != nil {
		t.Error("no readers gave a reader")
	}
}

func TestTheBaseOptionRules(t *testing.T) {
	w := build(t, explorer(), nil, standardModules())
	for _, tc := range []struct {
		opts map[string]any
		want error
	}{
		{map[string]any{OptionKernelModule: true}, ErrNoBase},
		{map[string]any{OptionKernelModule: true, OptionBase: kernelBase, "pid": uint64(4)}, ErrKernelModuleAndPID},
		{map[string]any{OptionBase: kernelBase}, ErrNoDumpTarget},
		{map[string]any{OptionBase: "nonsense", "pid": uint64(4)}, tools.ErrOptionType},
		{map[string]any{OptionKernelModule: "yes please"}, tools.ErrOptionType},
	} {
		w.ctx.Options = map[string]any{}
		if _, _, err := w.run(t, tc.opts); !errors.Is(err, tc.want) {
			t.Errorf("%v: %v, want %v", tc.opts, err, tc.want)
		}
	}
}

func TestAKernelImageAtAGivenBaseIsFiledUnderTheSystemProcess(t *testing.T) {
	w := build(t, explorer(), nil, standardModules())
	arts, dir, err := w.run(t, map[string]any{OptionBase: kernelBase & (1<<48 - 1), OptionKernelModule: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 1 {
		t.Fatalf("rows %+v", arts)
	}
	a := arts[0]
	if a.PID != 4 || a.Process != "System" || a.Base != kernelBase || a.FileName != "image.kernel.0xfffff80001000000.pe" || !a.Complete() {
		t.Errorf("row %+v", a)
	}
	parsed(t, dir, a)
}

func TestAProcessImageAtAGivenBaseIsReadInEachChosenProcess(t *testing.T) {
	w := build(t, explorer(), nil, standardModules())
	arts, _, err := w.run(t, map[string]any{OptionBase: userBase, "pid": uint64(1200)})
	if err != nil {
		t.Fatal(err)
	}
	ep, _ := w.f.EPROCESS(1200)
	want := "image.pid1200.0x00007ff600000000.0x" + hexPad(ep) + ".pe"
	if len(arts) != 1 || arts[0].FileName != want || !arts[0].Complete() || arts[0].Source != SourceProcess {
		t.Errorf("rows %+v, want one complete %s", arts, want)
	}
	w.ctx.Options = map[string]any{"diagnostics": w.diags}
	arts, _, err = w.run(t, map[string]any{OptionBase: userBase, "pid": uint64(77)})
	if err != nil || len(arts) != 0 {
		t.Fatalf("no such PID: %+v, %v", arts, err)
	}
	if !contains(*w.diags, "windows.pe.dump: no listed process has a PID the pid option names: nothing read at 0x7ff600000000") {
		t.Errorf("diagnostics %q", *w.diags)
	}
}

func TestTheDumpNeedsWindowsAndAnOutputDirectory(t *testing.T) {
	w := build(t, explorer(), nil, standardModules())
	if _, err := Run(w.ctx); !errors.Is(err, ErrNoOutputDir) {
		t.Errorf("no output_dir: %v", err)
	}
	w.ctx.Profile = profiles.LinuxX64Profile{}
	w.ctx.Options[tools.OptionOutputDir] = t.TempDir()
	if _, err := Run(w.ctx); !errors.Is(err, ErrNotWindows) {
		t.Errorf("linux profile: %v", err)
	}
}

func TestStrictModeFailsWhenAListFails(t *testing.T) {
	w := build(t, explorer(), nil, standardModules())
	w.ctx.Symbols = hidden{w.ctx.Symbols, "PsLoadedModuleList"}
	_, _, err := w.run(t, map[string]any{"strict": true})
	if err == nil || !strings.Contains(err.Error(), " modules not listed: ") {
		t.Errorf("strict: %v", err)
	}
	w.ctx.Options = map[string]any{"diagnostics": w.diags}
	arts, _, err := w.run(t, nil)
	if err != nil || len(arts) != 1 || arts[0].Source != SourceProcess {
		t.Errorf("not strict: %+v, %v; want explorer.exe's module only", arts, err)
	}
	if !contains(*w.diags, "windows.pe.dump: kernel modules not listed, none dumped: windows.module.list: modulelist: symbol table has no PsLoadedModuleList: hidden") {
		t.Errorf("diagnostics %q", *w.diags)
	}
}

type hidden struct {
	symbols.SymbolTable
	name string
}

func (h hidden) LookupSymbol(name string) (symbols.Symbol, error) {
	if name == h.name {
		return symbols.Symbol{}, errors.New("hidden")
	}
	return h.SymbolTable.LookupSymbol(name)
}
