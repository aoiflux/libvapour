package pesymbols

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
)

const (
	firstBase  = uint64(0x7ff810000000)
	secondBase = uint64(0x7ff820000000)

	debugDirRVA  = uint32(0x3000)
	codeViewRVA  = uint32(0x3100)
	debugDirSlot = 0x98 + 112 + 6*8
)

var testGUID = [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 1, 2, 3, 4, 5, 6, 7, 8}

// withCodeView adds a debug directory with one CodeView entry to an image
// from testsupport.BuildExportingPE (optional header at 0x98, PE32+).
func withCodeView(img []byte, path string) []byte {
	out := slices.Clone(img)
	binary.LittleEndian.PutUint32(out[debugDirSlot:], debugDirRVA)
	binary.LittleEndian.PutUint32(out[debugDirSlot+4:], 28)
	e := out[debugDirRVA:]
	rec := append([]byte("RSDS"), testGUID[:]...)
	rec = binary.LittleEndian.AppendUint32(rec, 3)
	rec = append(append(rec, path...), 0)
	binary.LittleEndian.PutUint32(e[12:], 2)
	binary.LittleEndian.PutUint32(e[16:], uint32(len(rec)))
	binary.LittleEndian.PutUint32(e[20:], codeViewRVA)
	copy(out[codeViewRVA:], rec)
	return out
}

func exportsOf(names ...string) []testsupport.FixtureExport {
	out := make([]testsupport.FixtureExport, len(names))
	for i, n := range names {
		out[i] = testsupport.FixtureExport{Name: n, Body: []byte{0xC3}}
	}
	return out
}

func viewFixture(procs ...testsupport.FixtureProcess) *testsupport.ProcessFixture {
	return testsupport.BuildProcessFixture(procs)
}

func view(base uint64, path string) testsupport.FixtureVAD {
	return testsupport.FixtureVAD{Start: base, End: base + uint64(testsupport.ExportImageSize) - 1, Path: path}
}

func twoProcesses(first, second []byte) *testsupport.ProcessFixture {
	f := viewFixture(
		testsupport.FixtureProcess{PID: 100, Name: "a.exe", VADs: []testsupport.FixtureVAD{view(firstBase, `\Windows\System32\ntdll.dll`)}},
		testsupport.FixtureProcess{PID: 200, Name: "b.exe", VADs: []testsupport.FixtureVAD{view(firstBase, `\Windows\System32\ntdll.dll`)}},
	)
	f.Space(100).MapImage(firstBase, first)
	f.Space(200).MapImage(firstBase, second)
	return f
}

func pdbLoader(t *symbols.Table, calls *int) func(autoload.Fingerprint) (symbols.SymbolTable, error) {
	return func(fp autoload.Fingerprint) (symbols.SymbolTable, error) {
		*calls++
		if fp.PDBName != "ntdll.pdb" || fp.Age != 3 || fp.GUID != autoload.FormatGUID(testGUID[:]) {
			return nil, errors.New("no such pdb")
		}
		return t, nil
	}
}

func TestNamesAreAnsweredInTheAskOrderWithRepeatsAndMissingOnce(t *testing.T) {
	img := testsupport.BuildExportingPE(firstBase, exportsOf("A", "B", "C"))
	ctx := twoProcesses(img, img).Context()
	found, missing, err := Resolve(ctx, SourceProcesses, map[string][]string{"NTDLL.DLL ": {"C", "Z", "A", "C", "Z"}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range found["ntdll.dll"] {
		got = append(got, s.Name)
	}
	if !slices.Equal(got, []string{"C", "A", "C"}) {
		t.Errorf("found %v, want [C A C]", got)
	}
	if !slices.Equal(missing["ntdll.dll"], []string{"Z"}) {
		t.Errorf("missing %v, want [Z]", missing["ntdll.dll"])
	}
	if s := found["ntdll.dll"][0]; s.Address != firstBase+uint64(testsupport.ExportRVA(2)) || s.FoundInPID != 100 {
		t.Errorf("C = %+v, want the first process's export at RVA 0x%x", s, testsupport.ExportRVA(2))
	}
}

func TestASecondMappingAnswersWhatTheFirstCouldNotRead(t *testing.T) {
	img := testsupport.BuildExportingPE(firstBase, exportsOf("A"))
	f := twoProcesses(img, img)
	ctx := withDiagnostics(f.Context())
	testsupport.HoleInProcess(&ctx, f.DirectoryTableBase(100), firstBase+uint64(testsupport.ExportDirRVA), firstBase+0x3000)
	found, _, err := Resolve(ctx, SourceProcesses, map[string][]string{"ntdll.dll": {"A"}})
	if err != nil {
		t.Fatal(err)
	}
	if s := found["ntdll.dll"]; len(s) != 1 || s[0].FoundInPID != 200 {
		t.Fatalf("A = %+v, want pid 200's copy", s)
	}
	if !hasDiagnostic(ctx, "exports do not read in 1 of 2 mappings tried") {
		t.Errorf("no count of the unread mapping: %v", diagnostics(ctx))
	}
}

func TestThePDBAnswersFirstAndNamesWhatIsNotExported(t *testing.T) {
	img := withCodeView(testsupport.BuildExportingPE(firstBase, exportsOf("A")), `d:\build\ntdll.pdb`)
	f := twoProcesses(img, img)
	ctx := f.Context()
	pdb := symbols.NewTable("ntdll", 8)
	pdb.AddSymbol(symbols.Symbol{Name: "A", Address: 0x1800})
	pdb.AddSymbol(symbols.Symbol{Name: "Private", Address: 0x1900})
	calls := 0
	ctx.LoadPDB = pdbLoader(pdb, &calls)
	found, missing, err := Resolve(ctx, SourceProcesses, map[string][]string{"ntdll.dll": {"A", "Private"}})
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing %v, err %v", missing, err)
	}
	got := found["ntdll.dll"]
	if got[0].Address != firstBase+0x1800 || got[1].Address != firstBase+0x1900 || got[0].FoundInPID != 100 {
		t.Errorf("found %+v, want base+PDB RVA from pid 100", got)
	}
	if calls != 1 {
		t.Errorf("LoadPDB called %d times, want 1: the first mapping answered everything", calls)
	}
}

func TestAPDBThatDoesNotLoadIsReportedOnceAndTheExportsAnswer(t *testing.T) {
	img := withCodeView(testsupport.BuildExportingPE(firstBase, exportsOf("A")), "other.pdb")
	ctx := withDiagnostics(twoProcesses(img, img).Context())
	calls := 0
	ctx.LoadPDB = pdbLoader(symbols.NewTable("x", 8), &calls)
	found, _, _ := Resolve(ctx, SourceProcesses, map[string][]string{"ntdll.dll": {"A", "Absent"}})
	if s := found["ntdll.dll"]; len(s) != 1 || s[0].Address != firstBase+uint64(testsupport.ExportRVA(0)) {
		t.Fatalf("A = %+v, want the export", s)
	}
	if calls != 1 {
		t.Errorf("LoadPDB called %d times for one fingerprint, want 1", calls)
	}
	if n := countDiagnostics(ctx, "not loaded, exports used"); n != 1 {
		t.Errorf("%d not-loaded diagnostics, want 1", n)
	}
}

func TestAForwarderIsGivenAsOne(t *testing.T) {
	img := testsupport.BuildExportingPE(firstBase, []testsupport.FixtureExport{{Name: "HeapAlloc", Forwarder: "NTDLL.RtlAllocateHeap"}})
	ctx := twoProcesses(img, img).Context()
	found, _, _ := Resolve(ctx, SourceProcesses, map[string][]string{"ntdll.dll": {"HeapAlloc"}})
	if s := found["ntdll.dll"]; len(s) != 1 || s[0].Forwarder != "NTDLL.RtlAllocateHeap" {
		t.Errorf("HeapAlloc = %+v, want the forwarder", s)
	}
}

func TestAddressesAreNamedByThePDBsFirstNameInsideTheMappingThenByExports(t *testing.T) {
	img := withCodeView(testsupport.BuildExportingPE(firstBase, exportsOf("A", "B")), "ntdll.pdb")
	ctx := twoProcesses(img, img).Context()
	pdb := symbols.NewTable("ntdll", 8)
	pdb.AddSymbol(symbols.Symbol{Name: "Zeta", Address: uint64(testsupport.ExportRVA(0))})
	pdb.AddSymbol(symbols.Symbol{Name: "Alpha", Address: uint64(testsupport.ExportRVA(0))})
	pdb.AddSymbol(symbols.Symbol{Name: "Far", Address: 0x100000})
	calls := 0
	ctx.LoadPDB = pdbLoader(pdb, &calls)
	a0 := firstBase + uint64(testsupport.ExportRVA(0))
	a1 := firstBase + uint64(testsupport.ExportRVA(1))
	far := firstBase + 0x100000
	found, missing, err := ResolveAddresses(ctx, SourceProcesses, map[string][]uint64{"ntdll.dll": {a0, a1, far}})
	if err != nil {
		t.Fatal(err)
	}
	got := found["ntdll.dll"]
	if len(got) != 2 || got[0].Name != "Alpha" || got[1].Name != "B" {
		t.Errorf("found %+v, want Alpha from the PDB and B from the exports", got)
	}
	if !slices.Equal(missing["ntdll.dll"], []uint64{far}) {
		t.Errorf("missing %v, want the address outside the mapping", missing["ntdll.dll"])
	}
}

func TestTheKernelImageIsAnsweredFromTheKernelTable(t *testing.T) {
	f := viewFixture(testsupport.FixtureProcess{PID: 4, Name: "System", NoPeb: true})
	f.Table.AddSymbol(symbols.Symbol{Name: "PsActiveProcessHead", Address: 0xfffff80000123450})
	ctx := f.Context()
	found, _, err := Resolve(ctx, SourceKernel, map[string][]string{KernelModuleName: {"PsActiveProcessHead"}})
	if err != nil || len(found[KernelModuleName]) != 1 || found[KernelModuleName][0].Address != 0xfffff80000123450 {
		t.Fatalf("found %+v, err %v", found, err)
	}
	back, _, err := ResolveAddresses(ctx, SourceKernel, map[string][]uint64{KernelModuleName: {0xfffff80000123450}})
	if err != nil || len(back[KernelModuleName]) != 1 || back[KernelModuleName][0].Name != "PsActiveProcessHead" {
		t.Fatalf("back %+v, err %v", back, err)
	}
}

func TestTheProcessSpaceIsTheOnlyReaderOfAProcessMapping(t *testing.T) {
	img := testsupport.BuildExportingPE(firstBase, exportsOf("A"))
	f := twoProcesses(img, img)
	f.Kernel.MapImage(firstBase, img)
	ctx, _ := testsupport.RefuseProcessSpace(f.Context(), f.DirectoryTableBase(100))
	if _, err := Exports(ctx, Module{PID: 100, DirectoryTableBase: f.DirectoryTableBase(100), Base: firstBase}); err == nil {
		t.Fatal("exports read although the process space did not open")
	}
}

func TestViewsAndLoaderListsGiveTheInstancesWhateverThePIDOption(t *testing.T) {
	img := testsupport.BuildExportingPE(secondBase, exportsOf("A"))
	f := viewFixture(
		testsupport.FixtureProcess{PID: 100, Name: "a.exe",
			Modules: []testsupport.FixtureModule{{Name: "Kernel32.DLL", Base: secondBase, Image: img}},
			VADs:    []testsupport.FixtureVAD{view(secondBase, `\Windows\System32\KERNEL32.DLL`), view(firstBase, "nopath")}},
		testsupport.FixtureProcess{PID: 200, Name: "b.exe"},
	)
	ctx := f.Context()
	ctx.Options["pid"] = uint64(200)
	views, err := CollectModules(ctx, SourceProcesses, []string{"kernel32.dll", "nopath"})
	if err != nil {
		t.Fatal(err)
	}
	if v := views["kernel32.dll"]; len(v) != 1 || v[0].PID != 100 || v[0].Size != uint64(testsupport.ExportImageSize) {
		t.Errorf("views %+v, want pid 100's view of the image", views)
	}
	if len(views["nopath"]) != 0 {
		t.Errorf("a path without a separator named a module: %+v", views["nopath"])
	}
	ctx.Options[OptionLoaderList] = true
	listed, err := CollectModules(ctx, SourceProcesses, []string{"KERNEL32.dll"})
	if err != nil {
		t.Fatal(err)
	}
	if l := listed["kernel32.dll"]; len(l) != 1 || l[0].Base != secondBase || l[0].ProcessName != "a.exe" {
		t.Errorf("loader instances %+v", listed)
	}
	ctx.Options[OptionLoaderList] = "maybe"
	if _, err := CollectModules(ctx, SourceProcesses, []string{"x.dll"}); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("loader_list of the wrong type: %v", err)
	}
}

func TestCopyExportsIsTheUnionInAddressOrderWithoutForwarders(t *testing.T) {
	first := testsupport.BuildExportingPE(firstBase, []testsupport.FixtureExport{
		{Name: "EtwB", Body: []byte{0xC3}}, {Name: "EtwA", Body: []byte{0xC3}}, {Name: "EtwF", Forwarder: "X.Y"}, {Name: "Other", Body: []byte{0xC3}}})
	f := twoProcesses(first, first)
	ctx := f.Context()
	testsupport.HoleInProcess(&ctx, f.DirectoryTableBase(200), firstBase, firstBase+0x1000)
	inst, err := CollectModules(ctx, SourceProcesses, []string{"ntdll.dll"})
	if err != nil {
		t.Fatal(err)
	}
	syms, unread := CopyExports(ctx, inst["ntdll.dll"], func(n string) bool { return strings.HasPrefix(n, "Etw") })
	var names []string
	for _, s := range syms {
		names = append(names, s.Name)
	}
	if !slices.Equal(names, []string{"EtwB", "EtwA"}) || unread != 1 {
		t.Errorf("names %v unread %d, want [EtwB EtwA] in address order and 1 unread", names, unread)
	}
}

func TestReadRVAAtBoundsTheImageAndRefusesShortReads(t *testing.T) {
	r := shortReader{size: 0x2000}
	read := ReadRVAAt(r, 0x1000, 0x1000)
	if _, err := read(0xFF0, 0x20); !errors.Is(err, errOutside) {
		t.Errorf("read past the image: %v", err)
	}
	if _, err := read(0, -1); err == nil {
		t.Error("negative length accepted")
	}
	if _, err := ReadRVAAt(r, 0x1F00, 0)(0, 0x200); err == nil {
		t.Error("short read accepted")
	}
	if b, err := ReadRVAAt(r, 0, 0)(0x10, 4); err != nil || len(b) != 4 {
		t.Errorf("unbounded read: %v", err)
	}
}

func TestRunChecksItsOptions(t *testing.T) {
	f := viewFixture(testsupport.FixtureProcess{PID: 4, Name: "System", NoPeb: true})
	cases := []struct {
		opts map[string]any
		want error
	}{
		{map[string]any{}, ErrNoModuleRequested},
		{map[string]any{OptionModule: "x.dll"}, ErrNoSymbolsRequested},
		{map[string]any{OptionModule: "x.dll", OptionSymbols: []string{"A"}, OptionAddresses: []uint64{1}}, ErrNamesAndAddresses},
		{map[string]any{OptionModule: "x.dll", OptionSymbols: []string{"A"}, OptionSource: "disk"}, ErrUnknownSource},
	}
	for _, c := range cases {
		ctx := f.Context()
		for k, v := range c.opts {
			ctx.Options[k] = v
		}
		if _, err := Run(ctx); !errors.Is(err, c.want) {
			t.Errorf("options %v: %v, want %v", c.opts, err, c.want)
		}
	}
	ctx := f.Context()
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); !errors.Is(err, ErrNotWindows) {
		t.Errorf("linux profile: %v", err)
	}
}

func TestRunResolvesTheModuleOption(t *testing.T) {
	img := testsupport.BuildExportingPE(firstBase, exportsOf("A"))
	ctx := twoProcesses(img, img).Context()
	ctx.Options[OptionModule] = "NtDll.Dll"
	ctx.Options[OptionSymbols] = []string{"A", "Q"}
	res, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Module != "ntdll.dll" || res.Source != SourceProcesses || len(res.Symbols) != 1 || !slices.Equal(res.Missing, []string{"Q"}) {
		t.Errorf("result %+v", res)
	}
}

func TestTheToolIsRegistered(t *testing.T) {
	if _, err := tools.Get(Name); err != nil {
		t.Fatalf("%s is not registered", Name)
	}
}

func TestFindPDBRecordAcrossPagesAndAfterAHole(t *testing.T) {
	rec := append([]byte("RSDS"), testGUID[:]...)
	rec = binary.LittleEndian.AppendUint32(rec, 7)
	rec = append(rec, `C:\b\Tcpip.PDB`+"\x00"...)
	mem := make(pages, 4)
	mem[0] = make([]byte, 0x1000)
	copy(mem[0][0x1000-10:], rec)
	mem[1] = make([]byte, 0x1000)
	copy(mem[1], rec[10:])
	fp, ok := FindPDBRecord(mem, 0, 0x4000, "tcpip.pdb")
	if !ok || fp.Age != 7 || fp.GUID != autoload.FormatGUID(testGUID[:]) || fp.PDBName != "tcpip.pdb" {
		t.Fatalf("across pages: %+v %v", fp, ok)
	}
	mem[0], mem[1] = nil, nil
	mem[3] = make([]byte, 0x1000)
	copy(mem[3][0x20:], rec)
	if _, ok := FindPDBRecord(mem, 0, 0x4000, "tcpip.pdb"); !ok {
		t.Error("record after a hole not found")
	}
	if _, ok := FindPDBRecord(mem, 0, 0x4000, "ntdll.pdb"); ok {
		t.Error("record of another PDB taken")
	}
	if _, ok := FindPDBRecord(mem, 0x3000, 0x20, "tcpip.pdb"); ok {
		t.Error("record outside the range taken")
	}
}

func FuzzFindPDBRecord(f *testing.F) {
	rec := append([]byte("RSDS"), testGUID[:]...)
	rec = binary.LittleEndian.AppendUint32(rec, 1)
	f.Add(append(rec, "a.pdb\x00"...), "a.pdb")
	f.Add([]byte("RSDSRSDS"), "")
	f.Fuzz(func(t *testing.T, data []byte, name string) {
		mem := pages{data}
		fp, ok := FindPDBRecord(mem, 0, uint64(len(data)), name)
		if ok && (fp.PDBName != name || len(fp.GUID) != 32) {
			t.Fatalf("found %+v for %q in data without it", fp, name)
		}
	})
}

type pages [][]byte

func (p pages) Size() uint64 { return uint64(len(p)) * 0x1000 }

func (p pages) ReadAt(off, n uint64) ([]byte, error) {
	out := make([]byte, 0, n)
	for at := off; at < off+n; {
		i := at / 0x1000
		if i >= uint64(len(p)) || p[i] == nil {
			return nil, memory.ErrOutOfBounds
		}
		pageEnd := (i + 1) * 0x1000
		take := min(off+n, pageEnd) - at
		lo := at - i*0x1000
		if lo+take > uint64(len(p[i])) {
			return nil, memory.ErrOutOfBounds
		}
		out = append(out, p[i][lo:lo+take]...)
		at += take
	}
	return out, nil
}

type shortReader struct{ size uint64 }

func (s shortReader) Size() uint64 { return s.size }

func (s shortReader) ReadAt(off, n uint64) ([]byte, error) {
	if off >= s.size {
		return nil, memory.ErrOutOfBounds
	}
	return make([]byte, min(n, s.size-off)), nil
}

var errOutside = pe.ErrOutsideImage

func withDiagnostics(ctx tools.Context) tools.Context {
	sink := []string{}
	ctx.Options["diagnostics"] = &sink
	return ctx
}

func diagnostics(ctx tools.Context) []string {
	if sink, ok := ctx.Options["diagnostics"].(*[]string); ok {
		return *sink
	}
	return nil
}

func countDiagnostics(ctx tools.Context, part string) int {
	n := 0
	for _, d := range diagnostics(ctx) {
		if strings.Contains(d, part) {
			n++
		}
	}
	return n
}

func hasDiagnostic(ctx tools.Context, part string) bool { return countDiagnostics(ctx, part) > 0 }
