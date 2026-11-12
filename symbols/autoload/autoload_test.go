package autoload

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
)

func convertible() pdbFixture {
	f := newFixture()
	f.types = [][]byte{
		memberList(memberSpec{"Flink", 0x1002, 0}, memberSpec{"Blink", 0x1002, 8}),
		structRecord(lfStructure, "_LIST_ENTRY", 16, 0x1000, 0),
		pointerRecord(0x1001, 8),
	}
	f.publics = []publicSpec{{kind: sPub32, name: "PsActiveProcessHead", segment: 2, offset: 0x30}}
	return f
}

func serve(t *testing.T, f pdbFixture, calls *[]string) symbolFetcher {
	t.Helper()
	data := f.file()
	return func(location string) ([]byte, error) {
		*calls = append(*calls, location)
		return data, nil
	}
}

func TestATableIsConvertedFetchedAndCached(t *testing.T) {
	f := convertible()
	dir := t.TempDir()
	var calls []string
	opts := LoadOptions{CacheDir: dir, ServerURL: "https://symbols.example/store/", fetch: serve(t, f, &calls)}
	table, err := LoadWithOptions(f.fingerprint(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if off, err := table.(*symbols.Table).OffsetOf("_LIST_ENTRY", "Blink"); err != nil || off != 8 {
		t.Fatalf("_LIST_ENTRY.Blink at %d (%v)", off, err)
	}
	if sym, err := table.LookupSymbol("PsActiveProcessHead"); err != nil || sym.Address != 0x5030 {
		t.Fatalf("PsActiveProcessHead %+v (%v)", sym, err)
	}
	want := "https://symbols.example/store/fixture.pdb/" + f.fingerprint().GUID + "3/fixture.pdb"
	if len(calls) != 1 || calls[0] != want {
		t.Fatalf("fetched %v, want %s", calls, want)
	}
	path := filepath.Join(dir, BuilderVersion, "fixture-"+f.fingerprint().GUID+"-3.vsym")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("no cache file at %s", path)
	}
	if build, ok := table.(*symbols.Table).WindowsPDB(); !ok || build.GUID != f.fingerprint().GUID || build.Age != 3 {
		t.Fatalf("table names build %+v", build)
	}
	if _, err := LoadWithOptions(f.fingerprint(), LoadOptions{CacheDir: dir, OfflineOnly: true}); err != nil {
		t.Fatalf("the cached table does not load offline: %v", err)
	}
}

func TestTheSymbolServerPathWritesTheAgeInHex(t *testing.T) {
	fp := &Fingerprint{PDBName: "mfc100.amd64.pdb", GUID: "e6ab77ce50004aa289714029b5704885", Age: 23}
	if got := symbolServerPath(fp); got != "mfc100.amd64.pdb/E6AB77CE50004AA289714029B570488517/mfc100.amd64.pdb" {
		t.Fatalf("path %s", got)
	}
	if got := fp.String(); got != "mfc100.amd64.pdb/e6ab77ce50004aa289714029b5704885-23" {
		t.Fatalf("fingerprint %s", got)
	}
}

func TestAPDBForAnotherBuildIsNotCached(t *testing.T) {
	f := convertible()
	other := convertible()
	other.age = 4
	dir := t.TempDir()
	var calls []string
	_, err := LoadWithOptions(other.fingerprint(), LoadOptions{CacheDir: dir, fetch: serve(t, f, &calls)})
	if err == nil || !strings.Contains(err.Error(), "not the one requested") {
		t.Fatalf("a PDB of age 3 answered for age 4: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, BuilderVersion)); len(entries) != 0 {
		t.Fatalf("cache holds %d files", len(entries))
	}
}

func TestOfflineLoadingNeverFetches(t *testing.T) {
	f := convertible()
	dir := t.TempDir()
	fail := func(string) ([]byte, error) { t.Fatal("fetched offline"); return nil, nil }
	_, err := LoadWithOptions(f.fingerprint(), LoadOptions{CacheDir: dir, OfflineOnly: true, fetch: fail})
	if !errors.Is(err, ErrSymbolsUnavailableOffline) || !strings.Contains(err.Error(), "no cached table") {
		t.Fatalf("offline without a table: %v", err)
	}

	path, _ := CachePath(dir, f.fingerprint())
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadWithOptions(f.fingerprint(), LoadOptions{CacheDir: dir, OfflineOnly: true, fetch: fail})
	if !errors.Is(err, ErrSymbolsUnavailableOffline) || !strings.Contains(err.Error(), "cannot be used") {
		t.Fatalf("offline with an unusable table: %v", err)
	}
}

func TestARejectedCacheFileIsRebuiltAndNamedWhenTheRebuildFails(t *testing.T) {
	f := convertible()
	dir := t.TempDir()
	path, _ := CachePath(dir, f.fingerprint())
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a table"), 0o600); err != nil {
		t.Fatal(err)
	}
	down := func(string) ([]byte, error) { return nil, errors.New("server unreachable") }
	_, err := LoadWithOptions(f.fingerprint(), LoadOptions{CacheDir: dir, fetch: down})
	if err == nil || !strings.Contains(err.Error(), "server unreachable") || !strings.Contains(err.Error(), "cannot be used") {
		t.Fatalf("failed rebuild: %v", err)
	}
	var calls []string
	if _, err := LoadWithOptions(f.fingerprint(), LoadOptions{CacheDir: dir, fetch: serve(t, f, &calls)}); err != nil || len(calls) != 1 {
		t.Fatalf("rebuild: %v after %d fetches", err, len(calls))
	}
}

func TestAFingerprintThatCannotNameAFileIsRefused(t *testing.T) {
	for _, fp := range []*Fingerprint{
		nil,
		{PDBName: "../evil.pdb", GUID: strings.Repeat("A", 32), Age: 1},
		{PDBName: "a/b.pdb", GUID: strings.Repeat("A", 32), Age: 1},
		{PDBName: "..", GUID: strings.Repeat("A", 32), Age: 1},
		{PDBName: "ok.pdb", GUID: strings.Repeat("G", 32), Age: 1},
		{PDBName: "ok.pdb", GUID: "ABC", Age: 1},
	} {
		if _, err := CachePath(t.TempDir(), fp); err == nil {
			t.Errorf("CachePath(%+v) accepted", fp)
		}
	}
	got, err := CachePath("d", &Fingerprint{PDBName: "ntkrnlmp.PDB", GUID: strings.Repeat("a", 32), Age: 26})
	if err != nil || got != filepath.Join("d", BuilderVersion, "ntkrnlmp-"+strings.Repeat("A", 32)+"-26.vsym") {
		t.Fatalf("CachePath = %s (%v)", got, err)
	}
}

func TestLoadOptionsResolveDefaultsAndRefuseWhatTheyCannotTake(t *testing.T) {
	o, err := LoadOptions{}.Resolved()
	if err != nil || o.ServerURL != DefaultServerURL || o.HTTPTimeout != DefaultHTTPTimeout || o.MaxDownload != DefaultMaxDownload {
		t.Fatalf("defaults %+v (%v)", o, err)
	}
	if o, _ := (LoadOptions{ServerURL: "https://host/path///"}).Resolved(); o.ServerURL != "https://host/path" {
		t.Fatalf("trailing slashes kept: %s", o.ServerURL)
	}
	for name, bad := range map[string]LoadOptions{
		"ServerURL":         {ServerURL: "file:///symbols"},
		"ServerURL ":        {ServerURL: "https://user@host/"},
		"ServerURL  ":       {ServerURL: "https://host/?q=1"},
		"HTTPTimeout":       {HTTPTimeout: 25 * time.Hour},
		"HTTPTimeout ":      {HTTPTimeout: -time.Second},
		"MaxDownload":       {MaxDownload: ceilingDownload + 1},
		"MaxDownload ":      {MaxDownload: -1},
		"MaxRecursionDepth": {Limits: limits.Limits{MaxRecursionDepth: limits.CeilingRecursionDepth + 1}},
	} {
		if _, err := bad.Resolved(); err == nil || !strings.Contains(err.Error(), strings.TrimSpace(name)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTheConversionTakesThePointerWidthAndRefusesWhatCannotBePlaced(t *testing.T) {
	f := convertible()
	f.machine = machineI386
	d, err := pdbToDeclaration(f.file(), f.fingerprint(), 0)
	if err != nil || d.PointerWidth != 4 {
		t.Fatalf("x86 PDB: width %d (%v)", d.PointerWidth, err)
	}
	f.machine = 0x1c0
	if _, err := pdbToDeclaration(f.file(), f.fingerprint(), 0); err == nil {
		t.Error("a PDB for a machine of unknown pointer width converted")
	}
	f = convertible()
	f.sections = nil
	if _, err := pdbToDeclaration(f.file(), f.fingerprint(), 0); err == nil {
		t.Error("a PDB with no section headers converted")
	}
	f = convertible()
	f.publics = []publicSpec{{kind: sPub32, name: "Nowhere", segment: 9}}
	if _, err := pdbToDeclaration(f.file(), f.fingerprint(), 0); err == nil {
		t.Error("a PDB with no placeable symbol converted")
	}
	if _, err := pdbToDeclaration([]byte("not a pdb"), f.fingerprint(), 0); !errors.Is(err, errNotMSF) {
		t.Errorf("not a PDB: %v", err)
	}
}

func TestKernelPDBNamesAreTheFourKernelImages(t *testing.T) {
	for _, name := range []string{"ntoskrnl.pdb", "NTKRNLMP.PDB", "ntkrnlpa.pdb", "ntkrpamp.pdb"} {
		if !IsKernelPDB(name) {
			t.Errorf("%s is not a kernel PDB", name)
		}
	}
	for _, name := range []string{"hal.pdb", "ntdll.pdb", "ntkrnlmp", ""} {
		if IsKernelPDB(name) {
			t.Errorf("%s is a kernel PDB", name)
		}
	}
	guid := []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8}
	if got := FormatGUID(guid); got != "123456789ABCDEF00102030405060708" {
		t.Fatalf("FormatGUID = %s", got)
	}
}
