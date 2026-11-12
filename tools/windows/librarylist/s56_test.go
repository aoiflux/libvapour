package librarylist

import (
	"errors"
	"strings"
	"testing"

	ts "github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/tools/winkernel"
	"github.com/aoiflux/libvapour/util"
)

const filetime2026 = uint64(134_000_000_000_000_000)

func lib(name string, base uint64) ts.S56Library {
	return ts.S56Library{Base: base, Size: 0x10000, Name: name, FullPath: `C:\Windows\System32\` + name, LoadCount: 1, LoadTime: filetime2026}
}

func runRows(t *testing.T, img *ts.S56Image) []DLL {
	t.Helper()
	rows, err := RunAny(img.Context())
	if err != nil {
		t.Fatalf("RunAny: %v", err)
	}
	return rows.([]DLL)
}

func names(rows []DLL) string {
	var out []string
	for _, d := range rows {
		out = append(out, d.Name)
	}
	return strings.Join(out, ",")
}

func hasDiagnostic(img *ts.S56Image, part string) bool {
	for _, d := range img.Diagnostics {
		if strings.Contains(d, part) {
			return true
		}
	}
	return false
}

func TestRowsFollowTheLoadOrderListAndCarryTheRecordFields(t *testing.T) {
	img := ts.BuildS56Image([]ts.S56Process{{PID: 100, Name: "app.exe", CreateTime: filetime2026 - 1,
		Libraries: []ts.S56Library{
			{Base: 0x7ff700000000, Size: 0x20000, Name: "app.exe", FullPath: `C:\app.exe`, LoadCount: 0xffffffff, LoadTime: filetime2026, NotInInit: true},
			lib("ntdll.dll", 0x7ffa00000000),
			lib("kernel32.dll", 0x7ffa10000000),
		}}})
	rows := runRows(t, img)
	if got := names(rows); got != "app.exe,ntdll.dll,kernel32.dll" {
		t.Fatalf("rows %s", got)
	}
	d := rows[0]
	p := img.Process(100)
	if d.PID != 100 || d.ProcName != "app.exe" || d.EPROCESS != p.EPROCESS || d.DirectoryTableBase != p.DirectoryTableBase ||
		d.Entry != p.Records[0] || d.Base != 0x7ff700000000 || d.Size != 0x20000 || d.FullPath != `C:\app.exe` ||
		d.LoadCount != 0xffffffff || d.LoadCountUnreadable || d.LoadTimeUnreadable || d.Wow64 {
		t.Errorf("row %+v", d)
	}
	if want, _ := util.FiletimeToTime(filetime2026); !d.LoadTime.Equal(want) || d.LoadTime.IsZero() {
		t.Errorf("LoadTime %v, want %v", d.LoadTime, want)
	}
	if !d.InLoadOrder || !d.InMemoryOrder || d.InInitializationOrder {
		t.Errorf("process image lists %v %v %v, want load and memory only", d.InLoadOrder, d.InMemoryOrder, d.InInitializationOrder)
	}
	if !rows[1].InInitializationOrder {
		t.Errorf("ntdll not in initialization order")
	}
}

func TestARecordCutFromTheLoadOrderListStillShowsFromTheOtherLists(t *testing.T) {
	cut := lib("hidden.dll", 0x7ffa20000000)
	cut.NotInLoad = true
	initOnly := lib("late.dll", 0x7ffa30000000)
	initOnly.NotInLoad, initOnly.NotInMemory = true, true
	img := ts.BuildS56Image([]ts.S56Process{{PID: 8, Name: "a.exe", Libraries: []ts.S56Library{
		lib("a.exe", 0x7ff700000000), initOnly, cut, lib("ntdll.dll", 0x7ffa00000000)}}})
	rows := runRows(t, img)
	if got := names(rows); got != "a.exe,ntdll.dll,hidden.dll,late.dll" {
		t.Fatalf("rows %s, want load order then memory-only then init-only", got)
	}
	if rows[2].InLoadOrder || !rows[2].InMemoryOrder || !rows[2].InInitializationOrder {
		t.Errorf("hidden.dll lists %+v", rows[2])
	}
	if rows[3].InLoadOrder || rows[3].InMemoryOrder || !rows[3].InInitializationOrder {
		t.Errorf("late.dll lists %+v", rows[3])
	}
}

func TestABrokenLinkIsReportedAndTheBackwardWalkRecoversTheRest(t *testing.T) {
	img := ts.BuildS56Image([]ts.S56Process{{PID: 8, Name: "a.exe", Libraries: []ts.S56Library{
		lib("a.dll", 0x10000000), lib("b.dll", 0x20000000), lib("c.dll", 0x30000000)}}})
	user := img.UserOf(8)
	records := img.Process(8).Records
	for _, link := range []uint64{0, 0x10, 0x20} {
		user.WriteU64(records[0]+link, 0)
	}
	rows := runRows(t, img)
	if got := names(rows); got != "a.dll,c.dll,b.dll" {
		t.Fatalf("rows %s, want the forward part then the backward part", got)
	}
	if !hasDiagnostic(img, "list link is null") {
		t.Errorf("no break diagnostic in %q", img.Diagnostics)
	}
	img.Options["strict"] = true
	if _, err := RunAny(img.Context()); !errors.Is(err, winkernel.ErrListNull) {
		t.Errorf("strict error %v, want the list break", err)
	}
}

func TestARecordWhoseDllBaseDoesNotReadIsFlaggedAndCounted(t *testing.T) {
	straddling := lib("b.dll", 0x20000000)
	straddling.RecordAt = ts.S56RecordVA + 0x20000 - ts.S56RecordDllBase
	img := ts.BuildS56Image([]ts.S56Process{{PID: 8, Name: "a.exe", Libraries: []ts.S56Library{
		lib("a.dll", 0x10000000), straddling}}})
	img.UserOf(8).Unmap(ts.S56RecordVA + 0x20000)
	rows := runRows(t, img)
	if len(rows) != 2 || rows[0].Name != "a.dll" || rows[0].BaseUnreadable {
		t.Fatalf("rows %+v", rows)
	}
	if f := rows[1]; !f.BaseUnreadable || f.Base != 0 || f.Entry != straddling.RecordAt || !f.NameUnreadable || !f.InLoadOrder {
		t.Fatalf("flagged row %+v", f)
	}
	if !hasDiagnostic(img, "process 8 at 0x") || !hasDiagnostic(img, "1 loader records flagged: librarylist: DllBase does not read") {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
	img.Options["strict"] = true
	if _, err := RunAny(img.Context()); !errors.Is(err, ErrBaseUnread) {
		t.Errorf("strict error %v", err)
	}
}

func TestUnreadableNamesAreFlaggedNotDropped(t *testing.T) {
	img := ts.BuildS56Image([]ts.S56Process{{PID: 8, Name: "a.exe", Libraries: []ts.S56Library{lib("a.dll", 0x10000000)}}})
	user := img.UserOf(8)
	r := img.Process(8).Records[0]
	user.WriteU64(r+ts.S56RecordBaseName+8, 0x6000_0000_0000)
	user.WriteU64(r+ts.S56RecordFullName+8, 0x6000_0000_0000)
	rows := runRows(t, img)
	if len(rows) != 1 || !rows[0].NameUnreadable || !rows[0].FullPathUnreadable || rows[0].Base != 0x10000000 {
		t.Fatalf("rows %+v", rows)
	}
	if !hasDiagnostic(img, "BaseDllName does not read for 1 and FullDllName for 1 of 1") {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
}

func TestLoadCountComesFromTheDependencyNode(t *testing.T) {
	noNode := lib("b.dll", 0x20000000)
	noNode.NoDdag = true
	counted := lib("a.dll", 0x10000000)
	counted.LoadCount = 7
	img := ts.BuildS56Image([]ts.S56Process{{PID: 8, Name: "a.exe", Libraries: []ts.S56Library{counted, noNode}}})
	rows := runRows(t, img)
	if rows[0].LoadCount != 7 || rows[0].LoadCountUnreadable || rows[1].LoadCount != 0 || !rows[1].LoadCountUnreadable {
		t.Errorf("load counts %+v %+v", rows[0], rows[1])
	}
}

func TestAZeroLoadTimeIsNoTime(t *testing.T) {
	zero := lib("a.dll", 0x10000000)
	zero.LoadTime = 0
	img := ts.BuildS56Image([]ts.S56Process{{PID: 8, Name: "a.exe", Libraries: []ts.S56Library{zero}}})
	rows := runRows(t, img)
	if !rows[0].LoadTime.IsZero() || rows[0].LoadTimeUnreadable {
		t.Errorf("row %+v", rows[0])
	}
}

func TestATableWithoutTheDependencyNodeGivesNoLoadCounts(t *testing.T) {
	img := ts.BuildS56Image([]ts.S56Process{{PID: 8, Name: "a.exe", Libraries: []ts.S56Library{lib("a.dll", 0x10000000)}}})
	img.Table = ts.S56TableWithout("_LDR_DATA_TABLE_ENTRY.DdagNode")
	rows := runRows(t, img)
	if !rows[0].LoadCountUnreadable || !hasDiagnostic(img, "no load counts") {
		t.Errorf("row %+v diagnostics %q", rows[0], img.Diagnostics)
	}
}

func TestAWow64ProcessListsBothLoaders(t *testing.T) {
	img := ts.BuildS56Image([]ts.S56Process{{PID: 8, Name: "old.exe",
		Libraries: []ts.S56Library{lib("old.exe", 0x400000), lib("ntdll.dll", 0x7ffa00000000), lib("wow64.dll", 0x7ffa10000000)},
		Wow64:     []ts.S56Library{lib("old.exe", 0x400000), lib("ntdll.dll", 0x77000000), lib("kernel32.dll", 0x76000000)}}})
	rows := runRows(t, img)
	if got := names(rows); got != "old.exe,ntdll.dll,wow64.dll,old.exe,ntdll.dll,kernel32.dll" {
		t.Fatalf("rows %s", got)
	}
	w := rows[5]
	if !w.Wow64 || w.Base != 0x76000000 || w.Size != 0x10000 || w.FullPath != `C:\Windows\System32\kernel32.dll` ||
		!w.LoadCountUnreadable || !w.LoadTimeUnreadable || w.Entry != img.Process(8).Records32[2] || !w.InInitializationOrder {
		t.Errorf("32-bit row %+v", w)
	}
	if rows[1].Wow64 {
		t.Errorf("native row marked WoW64")
	}
}

func TestProcessesWithoutLoaderDataGiveNoRows(t *testing.T) {
	img := ts.BuildS56Image([]ts.S56Process{
		{PID: 4, Name: "System", NoPeb: true},
		{PID: 8, Name: "starting.exe", LdrZero: true},
		{PID: 12, Name: "paged.exe", Libraries: []ts.S56Library{lib("a.dll", 0x10000000)}},
		{PID: 16, Name: "ok.exe", Libraries: []ts.S56Library{lib("b.dll", 0x20000000)}},
	})
	img.UserOf(12).Unmap(ts.S56PebVA)
	rows := runRows(t, img)
	if got := names(rows); got != "b.dll" {
		t.Fatalf("rows %s", got)
	}
	if !hasDiagnostic(img, "loader data pointer is 0") || !hasDiagnostic(img, "loader data does not read") {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
	if hasDiagnostic(img, "process 4 ") {
		t.Errorf("a process without a PEB was reported: %q", img.Diagnostics)
	}
}

func TestBaseAndNameFiltersKeepMatchingRows(t *testing.T) {
	img := ts.BuildS56Image([]ts.S56Process{{PID: 8, Name: "a.exe", Libraries: []ts.S56Library{
		lib("Alpha.dll", 0x10000000), lib("beta.dll", 0x20000000), lib("gamma.dll", 0x30000000)}}})
	img.Options[OptionBase] = uint64(0x20000000)
	if got := names(runRows(t, img)); got != "beta.dll" {
		t.Errorf("base filter rows %s", got)
	}
	delete(img.Options, OptionBase)
	img.Options[OptionName] = "^alpha"
	if got := names(runRows(t, img)); got != "" {
		t.Errorf("case-sensitive name filter rows %s", got)
	}
	img.Options[OptionIgnoreCase] = true
	if got := names(runRows(t, img)); got != "Alpha.dll" {
		t.Errorf("case-folded name filter rows %s", got)
	}
	img.Options[OptionName] = `System32\\gamma`
	if got := names(runRows(t, img)); got != "gamma.dll" {
		t.Errorf("full-path match rows %s", got)
	}
}

func TestIgnoreCaseWithoutANameIsReported(t *testing.T) {
	img := ts.BuildS56Image([]ts.S56Process{{PID: 8, Name: "a.exe", Libraries: []ts.S56Library{lib("a.dll", 0x10000000)}}})
	img.Options[OptionIgnoreCase] = true
	runRows(t, img)
	if !hasDiagnostic(img, "changes nothing") {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
}

func TestAWrongOptionTypeIsAnError(t *testing.T) {
	img := ts.BuildS56Image(nil)
	img.Options[OptionIgnoreCase] = "yes please"
	if _, err := RunAny(img.Context()); err == nil {
		t.Errorf("no error for a string boolean")
	}
}

func TestThePIDSetNarrowsTheProcesses(t *testing.T) {
	img := ts.BuildS56Image([]ts.S56Process{
		{PID: 8, Name: "a.exe", Libraries: []ts.S56Library{lib("a.dll", 0x10000000)}},
		{PID: 12, Name: "b.exe", Libraries: []ts.S56Library{lib("b.dll", 0x20000000)}},
	})
	img.Options["pid"] = []uint64{12}
	if got := names(runRows(t, img)); got != "b.dll" {
		t.Errorf("rows %s", got)
	}
}

func TestATableWithoutTheLoaderTypesIsAnError(t *testing.T) {
	img := ts.BuildS56Image(nil)
	img.Table = ts.S56TableWithout("_LDR_DATA_TABLE_ENTRY.InLoadOrderLinks")
	if _, err := Run(img.Context()); !errors.Is(err, ErrLoaderLayout) {
		t.Errorf("error %v", err)
	}
}

func TestATableWithOnlyTheLoadOrderListWalksIt(t *testing.T) {
	img := ts.BuildS56Image([]ts.S56Process{{PID: 8, Name: "a.exe", Libraries: []ts.S56Library{lib("a.dll", 0x10000000)}}})
	img.Table = ts.S56TableWithout("_PEB_LDR_DATA.InMemoryOrderModuleList", "_LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks")
	rows := runRows(t, img)
	if len(rows) != 1 || !rows[0].InLoadOrder || rows[0].InMemoryOrder || rows[0].InInitializationOrder {
		t.Fatalf("rows %+v", rows)
	}
	if !hasDiagnostic(img, "only the lists it describes are walked") {
		t.Errorf("diagnostics %q", img.Diagnostics)
	}
}
