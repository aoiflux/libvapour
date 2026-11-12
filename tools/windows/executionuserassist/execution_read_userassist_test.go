package executionuserassist

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

const userPath = `\??\C:\Users\u\ntuser.dat`

func run(t *testing.T, strict, wide bool, hives ...assistFixture) ([]CountValue, []string, error) {
	t.Helper()
	var diags []string
	ctx := tools.Context{Options: map[string]any{"diagnostics": &diags, "strict": strict}}
	users := make([]userHive, len(hives))
	for i, h := range hives {
		users[i] = userHive{layer: h.hive, id: hiveIdentity{path: userPath, address: 0xffff800000001000 + uint64(i)<<12}}
	}
	rows, err := readUserHives(ctx, wide, users)
	return rows, diags, err
}

func mentions(diags []string, parts ...string) bool {
	for _, d := range diags {
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

func TestEveryCountValueGivesOneRow(t *testing.T) {
	f := newAssistHive()
	launched := time.Date(2026, 1, 30, 8, 14, 0, 250_000_000, time.UTC)
	written := time.Date(2026, 1, 30, 8, 27, 0, 0, time.UTC)
	_, programs := f.subkey(programsGUID, measuredVersion,
		countValue(systemPrefix+`\WindowsPowerShell\v1.0\powershell.exe`, countData(25, 204, 12905353, filetime(launched))),
		countValue(systemPrefix+`\ServerManager.exe`, countData(0, 10, 228238, 0)),
		countValue("UEME_CTLSESSION", sessionData()))
	programs.LastWrite = filetime(written)
	f.subkey(shortcutsGUID, measuredVersion,
		countValue(programsMenu+`\Windows PowerShell\Windows PowerShell.lnk`, countData(17, 0, 17, filetime(launched))))
	f.subkey(emptyGUID, measuredVersion)

	rows, diags, err := run(t, true, true, f)
	if err != nil || len(diags) != 0 {
		t.Fatalf("err %v, diagnostics %q", err, diags)
	}
	if len(rows) != 4 {
		t.Fatalf("%d rows, want 4: %+v", len(rows), rows)
	}
	ps := rows[2]
	if ps.GUID != programsGUID || ps.Name != systemPrefix+`\WindowsPowerShell\v1.0\powershell.exe` ||
		ps.KnownFolder != "FOLDERID_System" || ps.KnownFolderPath != `%windir%\system32` ||
		ps.ExpandedName != `%windir%\system32\WindowsPowerShell\v1.0\powershell.exe` ||
		ps.DataState != DataDecoded || ps.LaunchCount != 25 || !ps.LastLaunch.Equal(launched) ||
		!ps.CountKeyLastWrite.Equal(written) || ps.Version != 5 || !ps.VersionKnown ||
		ps.Key != assistKey+`\`+programsGUID+`\Count` || ps.HivePath != userPath || ps.DataLength != 72 {
		t.Errorf("program row: %+v", ps)
	}
	if never := rows[1]; never.Name != systemPrefix+`\ServerManager.exe` || never.LaunchCount != 0 ||
		!never.LastLaunch.IsZero() || never.DataState != DataDecoded {
		t.Errorf("never-launched row: %+v", never)
	}
	if s := rows[0]; s.Name != "UEME_CTLSESSION" || s.DataState != DataUnmeasured || s.LaunchCount != 0 ||
		len(s.Data) != 1612 || s.ExpandedName != "UEME_CTLSESSION" {
		t.Errorf("session row: %+v", s)
	}
	if lnk := rows[3]; lnk.GUID != shortcutsGUID || lnk.KnownFolder != "FOLDERID_Programs" ||
		lnk.ExpandedName != `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk` ||
		lnk.LaunchCount != 17 {
		t.Errorf("shortcut row: %+v", lnk)
	}
}

func TestA64BitKernelGivesTheRemarksPathsOfThe32BitFolders(t *testing.T) {
	name := systemX86 + `\WindowsPowerShell\v1.0\powershell.exe`
	for _, tc := range []struct {
		wide bool
		want string
	}{
		{false, `%windir%\system32\WindowsPowerShell\v1.0\powershell.exe`},
		{true, `%windir%\syswow64\WindowsPowerShell\v1.0\powershell.exe`},
	} {
		f := newAssistHive()
		f.subkey(programsGUID, measuredVersion, countValue(name, countData(1, 1, 13657, 1)))
		rows, _, _ := run(t, false, tc.wide, f)
		if len(rows) != 1 || rows[0].ExpandedName != tc.want || rows[0].KnownFolder != "FOLDERID_SystemX86" {
			t.Errorf("wide %v: %+v", tc.wide, rows)
		}
	}
}

func TestNamesWithoutAKnownFolderStayAsDecoded(t *testing.T) {
	f := newAssistHive()
	for _, name := range []string{
		`{00000000-0000-0000-0000-000000000000}\x.exe`,
		`C:\Users\Administrator\Desktop\demo.bat`,
		`Microsoft.Windows.Explorer`,
		`MicrosoftWindows.Client.CBS_cw5n1h2txyewy!CortanaUI`,
		systemPrefix + `x.exe`,
	} {
		f.hive.Values[f.hive.Path(assistKey+`\`+programsGUID+`\Count`)] = append(
			f.hive.Values[f.hive.Path(assistKey+`\`+programsGUID+`\Count`)], countValue(name, countData(1, 0, 0, 1)))
	}
	rows, _, _ := run(t, false, true, f)
	if len(rows) != 5 {
		t.Fatalf("%d rows, want 5", len(rows))
	}
	for _, r := range rows {
		if r.KnownFolder != "" || r.KnownFolderPath != "" || r.ExpandedName != r.Name {
			t.Errorf("%q: folder %q path %q expanded %q", r.Name, r.KnownFolder, r.KnownFolderPath, r.ExpandedName)
		}
	}
}

func TestAVirtualFolderKeepsTheName(t *testing.T) {
	f := newAssistHive()
	name := `{1E87508D-89C2-42F0-8A7E-645A0F50CA58}\App`
	f.subkey(programsGUID, measuredVersion, countValue(name, countData(1, 0, 0, 1)))
	rows, _, _ := run(t, false, true, f)
	if len(rows) != 1 || rows[0].KnownFolder != "FOLDERID_AppsFolder" || rows[0].KnownFolderPath != "" ||
		rows[0].ExpandedName != name {
		t.Errorf("%+v", rows)
	}
}

func TestAnUnreadableNameSortsLastAndIsNotDecoded(t *testing.T) {
	f := newAssistHive()
	unnamed := registryhive.Value{NameUnreadable: true, Type: 3, Raw: countData(2, 0, 0, 1), Length: 72}
	f.subkey(programsGUID, measuredVersion, unnamed, countValue("b.exe", countData(1, 0, 0, 1)),
		countValue("a.exe", countData(1, 0, 0, 1)))
	rows, _, _ := run(t, false, true, f)
	if len(rows) != 3 || rows[0].Name != "a.exe" || rows[1].Name != "b.exe" || !rows[2].NameUnreadable ||
		rows[2].Name != "" || rows[2].LaunchCount != 2 {
		t.Errorf("%+v", rows)
	}
}

func TestCutDataIsUnreadableAndReported(t *testing.T) {
	f := newAssistHive()
	cut := countValue("x.exe", countData(3, 0, 0, 1)[:40])
	cut.Length = 72
	f.subkey(programsGUID, measuredVersion, cut)
	rows, diags, err := run(t, false, true, f)
	if err != nil || len(rows) != 1 || rows[0].DataState != DataUnreadable || rows[0].LaunchCount != 0 ||
		len(rows[0].Data) != 40 || rows[0].DataLength != 72 {
		t.Fatalf("err %v rows %+v", err, rows)
	}
	if !mentions(diags, Name+": Count key of "+programsGUID, "1 values not read in full", ErrIncomplete.Error()) {
		t.Errorf("diagnostics %q", diags)
	}
	if _, _, err := run(t, true, true, f); !errors.Is(err, ErrIncomplete) {
		t.Errorf("strict: %v, want ErrIncomplete", err)
	}
}

func TestAnUnmeasuredVersionLeavesTheValuesUndecoded(t *testing.T) {
	f := newAssistHive()
	f.subkey(programsGUID, 6, countValue("x.exe", countData(3, 0, 0, 1)))
	f.subkey(emptyGUID, 6)
	rows, diags, err := run(t, false, true, f)
	if err != nil || len(rows) != 1 || rows[0].DataState != DataUnmeasured || rows[0].Version != 6 {
		t.Fatalf("err %v rows %+v", err, rows)
	}
	if len(diags) != 1 || !mentions(diags, "subkey "+programsGUID, "values not decoded", ErrVersion.Error()) {
		t.Errorf("diagnostics %q", diags)
	}
	if _, _, err := run(t, true, true, f); !errors.Is(err, ErrVersion) {
		t.Errorf("strict: %v, want ErrVersion", err)
	}
}

func TestAVersionThatDidNotReadStillDecodes(t *testing.T) {
	f := newAssistHive()
	g, _ := f.subkey(programsGUID, measuredVersion, countValue("x.exe", countData(3, 0, 0, 1)))
	f.hive.Values[g] = nil
	f.hive.ValuesIncomplete[g] = true
	rows, diags, err := run(t, true, true, f)
	if err != nil || len(diags) != 0 || len(rows) != 1 || rows[0].VersionKnown || rows[0].DataState != DataDecoded ||
		rows[0].LaunchCount != 3 {
		t.Errorf("err %v diagnostics %q rows %+v", err, diags, rows)
	}
}

func TestIncompleteListsAreReported(t *testing.T) {
	t.Run("subkeys of the UserAssist key", func(t *testing.T) {
		f := newAssistHive()
		f.subkey(programsGUID, measuredVersion, countValue("x.exe", countData(1, 0, 0, 1)))
		f.hive.SubkeysIncomplete[f.root] = true
		rows, diags, err := run(t, true, true, f)
		if len(rows) != 1 || !errors.Is(err, ErrIncomplete) ||
			!mentions(diags, "UserAssist key at 0x", "subkey list not read in full") {
			t.Errorf("rows %d err %v diagnostics %q", len(rows), err, diags)
		}
	})
	t.Run("Count key not found for certain", func(t *testing.T) {
		f := newAssistHive()
		g := f.hive.Key(f.root, programsGUID)
		f.hive.SubkeysIncomplete[g] = true
		rows, diags, err := run(t, true, true, f)
		if len(rows) != 0 || !errors.Is(err, ErrIncomplete) ||
			!mentions(diags, "subkey "+programsGUID+" at 0x", "Count key not read") {
			t.Errorf("rows %d err %v diagnostics %q", len(rows), err, diags)
		}
	})
	t.Run("values of a Count key", func(t *testing.T) {
		f := newAssistHive()
		_, count := f.subkey(programsGUID, measuredVersion, countValue("x.exe", countData(1, 0, 0, 1)))
		f.hive.ValuesIncomplete[count] = true
		rows, diags, err := run(t, true, true, f)
		if len(rows) != 1 || !errors.Is(err, ErrIncomplete) ||
			!mentions(diags, "Count key of "+programsGUID+" at 0x", "value list not read in full") {
			t.Errorf("rows %d err %v diagnostics %q", len(rows), err, diags)
		}
	})
	t.Run("not strict", func(t *testing.T) {
		f := newAssistHive()
		_, count := f.subkey(programsGUID, measuredVersion, countValue("x.exe", countData(1, 0, 0, 1)))
		f.hive.ValuesIncomplete[count] = true
		if rows, _, err := run(t, false, true, f); err != nil || len(rows) != 1 {
			t.Errorf("rows %d err %v", len(rows), err)
		}
	})
}

func TestALaunchTimeOutsideTheFiletimeRangeIsAbsent(t *testing.T) {
	f := newAssistHive()
	f.subkey(programsGUID, measuredVersion, countValue("x.exe", countData(1, 0, 0, 1<<63)))
	rows, diags, err := run(t, false, true, f)
	if err != nil || len(rows) != 1 || !rows[0].LastLaunch.IsZero() || rows[0].LaunchCount != 1 ||
		rows[0].DataState != DataDecoded || !mentions(diags, "value \"x.exe\"", ErrTime.Error()) {
		t.Errorf("err %v diagnostics %q rows %+v", err, diags, rows)
	}
	if _, _, err := run(t, true, true, f); !errors.Is(err, ErrTime) {
		t.Errorf("strict: %v, want ErrTime", err)
	}
}

func TestAHiveWithoutTheKeyGivesNothing(t *testing.T) {
	f := newAssistHive()
	f.hive.Subkeys[f.hive.Root] = nil
	rows, diags, err := run(t, true, true, f)
	if err != nil || len(rows) != 0 || len(diags) != 0 {
		t.Errorf("err %v diagnostics %q rows %+v", err, diags, rows)
	}
}

func TestAnUnreadableKeyIsReported(t *testing.T) {
	f := newAssistHive()
	f.hive.Root = nil
	rows, diags, err := run(t, false, true, f)
	if err != nil || len(rows) != 0 || !mentions(diags, "hive "+userPath+" at 0x", "UserAssist key not read") {
		t.Errorf("err %v diagnostics %q", err, diags)
	}
	if _, _, err := run(t, true, true, f); !errors.Is(err, ErrIncomplete) {
		t.Errorf("strict: %v, want ErrIncomplete", err)
	}
}

func TestNoUserHiveIsReported(t *testing.T) {
	rows, diags, err := run(t, true, true)
	if err != nil || len(rows) != 0 || !mentions(diags, "no NTUSER.DAT hive opens") {
		t.Errorf("err %v diagnostics %q", err, diags)
	}
}

func TestStrictModeKeepsEveryRowAndTheFirstError(t *testing.T) {
	f := newAssistHive()
	f.subkey(programsGUID, 6, countValue("x.exe", countData(1, 0, 0, 1)))
	_, count := f.subkey(shortcutsGUID, measuredVersion, countValue("y.lnk", countData(1, 0, 1, 1)))
	f.hive.ValuesIncomplete[count] = true
	rows, _, err := run(t, true, true, f)
	if len(rows) != 2 || !errors.Is(err, ErrVersion) {
		t.Errorf("rows %d err %v", len(rows), err)
	}
}

func TestRowsSortByHiveSubkeyAndName(t *testing.T) {
	a, b := newAssistHive(), newAssistHive()
	a.subkey(shortcutsGUID, measuredVersion, countValue("z.lnk", countData(1, 0, 1, 1)))
	a.subkey(strings.ToLower(programsGUID), measuredVersion, countValue("y.exe", countData(1, 0, 0, 1)),
		countValue("x.exe", countData(1, 0, 0, 1)))
	b.subkey(programsGUID, measuredVersion, countValue("w.exe", countData(1, 0, 0, 1)))
	rows, _, _ := run(t, false, true, b, a)
	var got []string
	for _, r := range rows {
		got = append(got, r.Name)
	}
	if strings.Join(got, " ") != "w.exe x.exe y.exe z.lnk" {
		t.Errorf("order %q", got)
	}
}

func TestOnlyNTUSERHivesAreUserHives(t *testing.T) {
	for _, tc := range []struct {
		hive registryhive.Hive
		want bool
	}{
		{registryhive.Hive{FileFullPath: `\??\C:\Users\u\ntuser.dat`}, true},
		{registryhive.Hive{FileFullPath: `\??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT`}, true},
		{registryhive.Hive{Name: "NTUSER.DAT"}, true},
		{registryhive.Hive{FileFullPath: `\??\C:\Users\u\AppData\Local\Microsoft\Windows\UsrClass.dat`}, false},
		{registryhive.Hive{FileFullPath: `\SystemRoot\System32\Config\SOFTWARE`}, false},
		{registryhive.Hive{FileFullPath: `\??\C:\Users\ntuser.dat.old\x.dat`}, false},
		{registryhive.Hive{}, false},
	} {
		if got := isUserHive(tc.hive); got != tc.want {
			t.Errorf("%+v: %v, want %v", tc.hive, got, tc.want)
		}
	}
}

func TestDataIsKeptAsStored(t *testing.T) {
	f := newAssistHive()
	data := countData(4, 5, 6, 7)
	f.subkey(programsGUID, measuredVersion, countValue("x.exe", data))
	rows, _, _ := run(t, false, true, f)
	if len(rows) != 1 || !bytes.Equal(rows[0].Data, data) {
		t.Errorf("%+v", rows)
	}
}
