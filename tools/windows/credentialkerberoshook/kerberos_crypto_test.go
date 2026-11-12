package credentialkerberoshook

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
)

func twoClean() []fxEntry { return []fxEntry{cleanEntry(18), cleanEntry(23)} }

func mustRun(t *testing.T, r fxRun) []Row {
	t.Helper()
	rows, err := Run(r.ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rows
}

func hasDiagnostic(r fxRun, target error) bool {
	for _, d := range *r.diags {
		if strings.Contains(d, target.Error()) {
			return true
		}
	}
	return false
}

func TestTableFromSymbolsGivesOneCleanRowPerEntry(t *testing.T) {
	r := fxCapture{image: fxImage{count: 2, entries: twoClean()}, symbols: true}.run()
	rows := mustRun(t, r)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2; diagnostics %v", len(rows), *r.diags)
	}
	for i, row := range rows {
		if row.TableSource != SourceSymbols || row.TableAddress != fxBase+uint64(fxTableRVA) || row.Index != i {
			t.Errorf("row %d: source %s table 0x%x index %d", i, row.TableSource, row.TableAddress, row.Index)
		}
		if row.EntryAddress != row.TableAddress+uint64(i)*entrySize {
			t.Errorf("row %d: entry 0x%x", i, row.EntryAddress)
		}
		if row.Redirected || row.RegisteredBy != tableModule || row.PID != fxLSASS || row.Process != lsassImage {
			t.Errorf("row %d: %+v", i, row)
		}
		if row.NameUnreadable || row.Name != "Kerberos AES256-CTS-HMAC-SHA1-96" {
			t.Errorf("row %d: name %q unreadable %v", i, row.Name, row.NameUnreadable)
		}
		if len(row.Routines) != 9 {
			t.Errorf("row %d: %d routines, want 9", i, len(row.Routines))
		}
		for _, rt := range row.Routines {
			if rt.Redirected || rt.Module != tableModule || rt.Kind == "" {
				t.Errorf("row %d: routine %+v", i, rt)
			}
		}
	}
	if rows[0].EncryptionTypeName != "aes256-cts-hmac-sha1-96" || rows[1].EncryptionTypeName != "rc4-hmac" {
		t.Errorf("type names %q %q", rows[0].EncryptionTypeName, rows[1].EncryptionTypeName)
	}
}

func TestTableFromCodeWhenThereIsNoPDB(t *testing.T) {
	for _, c := range []fxCapture{
		{image: fxImage{count: 2, entries: twoClean(), export: true}},
		{image: fxImage{count: 2, entries: twoClean(), export: true, noDebug: true}, symbols: true},
	} {
		r := c.run()
		rows := mustRun(t, r)
		if len(rows) != 2 || rows[0].TableSource != SourceCode || rows[0].TableAddress != fxBase+uint64(fxTableRVA) {
			t.Fatalf("rows %+v, diagnostics %v", rows, *r.diags)
		}
	}
}

func TestNoRouteLeavesADiagnosticAndNoRows(t *testing.T) {
	r := fxCapture{image: fxImage{count: 2, entries: twoClean()}}.run()
	rows := mustRun(t, r)
	if len(rows) != 0 || !hasDiagnostic(r, ErrTableNotFound) {
		t.Fatalf("rows %d, diagnostics %v", len(rows), *r.diags)
	}
	d := (*r.diags)[0]
	if !strings.HasPrefix(d, Name+": process 916 cryptdll.dll at 0x7ff907100000: ") {
		t.Errorf("diagnostic form: %s", d)
	}
}

func TestRoutineOutsideItsHomeIsRedirected(t *testing.T) {
	cases := []struct {
		name   string
		target uint64
		module string
		kind   string
	}{
		{"private memory", fxPrivate + 0x40, "", "private"},
		{"another module", fxOther + 0x80, "extra.dll", "mapped"},
		{"no view", 0x7ff9_0900_0000, "", ""},
	}
	for _, c := range cases {
		e := cleanEntry(23)
		e.routines[0x28] = c.target
		e.routines[0x38] = c.target + 0x10
		r := fxCapture{image: fxImage{count: 2, entries: []fxEntry{cleanEntry(18), e}}, symbols: true}.run()
		rows := mustRun(t, r)
		if len(rows) != 2 {
			t.Fatalf("%s: %d rows", c.name, len(rows))
		}
		if rows[0].Redirected {
			t.Errorf("%s: the untouched entry is redirected", c.name)
		}
		if !rows[1].Redirected {
			t.Fatalf("%s: the overwritten entry is not redirected", c.name)
		}
		redirected := map[Slot]Routine{}
		for _, rt := range rows[1].Routines {
			if rt.Redirected {
				redirected[rt.Slot] = rt
			}
		}
		if len(redirected) != 2 {
			t.Fatalf("%s: redirected %v", c.name, redirected)
		}
		got := redirected[SlotInitialise]
		if got.Address != c.target || got.Module != c.module || got.Kind != c.kind {
			t.Errorf("%s: initialise %+v", c.name, got)
		}
		if _, ok := redirected[SlotDecrypt]; !ok {
			t.Errorf("%s: decrypt not redirected", c.name)
		}
	}
}

func TestNameInAnotherModuleMovesTheHome(t *testing.T) {
	e := fxEntry{etype: -200, name: fxOther, routines: map[int]uint64{0x28: fxOther + 0x100, 0x30: fxBase + 0x1100}}
	r := fxCapture{image: fxImage{count: 1, entries: []fxEntry{e}}, symbols: true, otherName: "Extra Cipher"}.run()
	rows := mustRun(t, r)
	if len(rows) != 1 {
		t.Fatalf("%d rows; %v", len(rows), *r.diags)
	}
	row := rows[0]
	if row.RegisteredBy != "extra.dll" || row.Name != "Extra Cipher" || row.EncryptionTypeName != "" {
		t.Fatalf("%+v", row)
	}
	if row.Routines[0].Redirected || !row.Routines[1].Redirected || !row.Redirected {
		t.Errorf("routines %+v", row.Routines)
	}
}

func TestCountChecks(t *testing.T) {
	for _, c := range []struct {
		count uint32
		want  error
	}{
		{maxEntries + 1, ErrCountRange},
		{0xffffffff, ErrCountRange},
	} {
		r := fxCapture{image: fxImage{count: c.count, entries: twoClean()}, symbols: true}.run()
		if rows := mustRun(t, r); len(rows) != 0 || !hasDiagnostic(r, c.want) {
			t.Errorf("count %d: rows %d, diagnostics %v", c.count, len(rows), *r.diags)
		}
	}
	r := fxCapture{image: fxImage{count: maxEntries, entries: twoClean()}, symbols: true}.run()
	if rows := mustRun(t, r); len(rows) != maxEntries {
		t.Errorf("count %d: %d rows", maxEntries, len(rows))
	}
	r = fxCapture{image: fxImage{count: 0, entries: twoClean()}, symbols: true}.run()
	if rows := mustRun(t, r); len(rows) != 0 || len(*r.diags) != 0 {
		t.Errorf("count 0: rows %d, diagnostics %v", len(rows), *r.diags)
	}
}

func TestTableOutsideTheViewIsRefused(t *testing.T) {
	r := fxCapture{image: fxImage{count: 2, entries: twoClean()}, symbols: true}.run()
	r.ctx.LoadPDB = func(autoload.Fingerprint) (symbols.SymbolTable, error) {
		t := symbols.NewTable("far", 8)
		t.AddSymbol(symbols.Symbol{Name: symbolTable, Address: 0x7f80})
		t.AddSymbol(symbols.Symbol{Name: symbolCount, Address: uint64(fxCountRVA)})
		return t, nil
	}
	if rows := mustRun(t, r); len(rows) != 0 || !hasDiagnostic(r, ErrHeadOutsideView) {
		t.Errorf("rows %d, diagnostics %v", len(rows), *r.diags)
	}
}

func TestUnreadEntryIsReportedAndTheOthersKept(t *testing.T) {
	r := fxCapture{image: fxImage{count: 3, entries: []fxEntry{cleanEntry(18), cleanEntry(17), cleanEntry(23)}}, symbols: true}.run()
	second := fxBase + uint64(fxTableRVA) + entrySize
	testsupport.HoleInProcess(&r.ctx, r.fixture.DirectoryTableBase(fxLSASS), second, second+entrySize)
	rows := mustRun(t, r)
	if len(rows) != 2 || rows[0].Index != 0 || rows[1].Index != 2 || !hasDiagnostic(r, ErrEntryUnread) {
		t.Errorf("rows %+v, diagnostics %v", rows, *r.diags)
	}
}

func TestMissingProcessesAndModules(t *testing.T) {
	r := fxCapture{image: fxImage{count: 2, entries: twoClean()}, symbols: true, noCryptdll: true}.run()
	if rows := mustRun(t, r); len(rows) != 0 || !hasDiagnostic(r, ErrNoTableModule) {
		t.Errorf("no cryptdll: rows %d, diagnostics %v", len(rows), *r.diags)
	}
	r = fxCapture{image: fxImage{count: 2, entries: twoClean()}, symbols: true, process: "svchost.exe"}.run()
	if rows := mustRun(t, r); len(rows) != 0 || !hasDiagnostic(r, ErrNoLSASS) {
		t.Errorf("no lsass: rows %d, diagnostics %v", len(rows), *r.diags)
	}
	r = fxCapture{image: fxImage{count: 2, entries: twoClean()}, symbols: true}.run()
	r.ctx.Options["pid"] = uint64(4)
	if rows := mustRun(t, r); len(rows) != 0 || len(*r.diags) != 0 {
		t.Errorf("pid 4: rows %d, diagnostics %v", len(rows), *r.diags)
	}
}

func TestStrictModeEndsOnTheFirstFailure(t *testing.T) {
	r := fxCapture{image: fxImage{count: maxEntries + 1, entries: twoClean()}, symbols: true}.run()
	r.ctx.Options["strict"] = true
	if _, err := Run(r.ctx); !errors.Is(err, ErrCountRange) {
		t.Errorf("err %v", err)
	}
	r = fxCapture{image: fxImage{count: 2, entries: twoClean()}, symbols: true, process: "svchost.exe"}.run()
	r.ctx.Options["strict"] = true
	if _, err := Run(r.ctx); !errors.Is(err, ErrNoLSASS) {
		t.Errorf("err %v", err)
	}
}

func TestUnsupportedTables(t *testing.T) {
	r := fxCapture{image: fxImage{count: 2, entries: twoClean()}, symbols: true}.run()
	ctx := r.ctx
	ctx.Symbols = symbols.NewTable("x86", 4)
	if _, err := Run(ctx); !errors.Is(err, ErrPointerSize) {
		t.Errorf("4-byte pointers: %v", err)
	}
	ctx = r.ctx
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); err == nil {
		t.Error("linux profile accepted")
	}
}

func TestRegisteredUnderItsName(t *testing.T) {
	if _, err := tools.Get(Name); err != nil {
		t.Fatalf("%s is not registered", Name)
	}
}
