package registryautostart

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

type fixture struct {
	diagnostics []string
	options     map[string]any
}

func (f *fixture) ctx() tools.Context {
	f.diagnostics = nil
	opts := map[string]any{"diagnostics": &f.diagnostics}
	for k, v := range f.options {
		opts[k] = v
	}
	return tools.Context{Profile: profiles.WindowsX64Profile{}, Options: opts}
}

func (f *fixture) said(part string) bool {
	for _, d := range f.diagnostics {
		if strings.Contains(d, part) {
			return true
		}
	}
	return false
}

func software(h *registrytest.FakeHive) openedHive {
	return openedHive{kind: softwareHive, path: `\REGISTRY\MACHINE\SOFTWARE`, file: `\SystemRoot\System32\Config\SOFTWARE`, reader: h}
}

func user(h *registrytest.FakeHive, sid string) openedHive {
	return openedHive{kind: userHive, path: `\REGISTRY\USER\` + sid, file: `\??\C:\Users\x\ntuser.dat`, reader: h}
}

func system(h *registrytest.FakeHive, set string, ok bool) openedHive {
	return openedHive{kind: systemHive, path: `\REGISTRY\MACHINE\SYSTEM`, reader: h,
		controlSet: func() (string, bool) { return set, ok }}
}

func run(t *testing.T, f *fixture, hives ...openedHive) []Entry {
	t.Helper()
	rows, err := listAutostart(f.ctx(), hives)
	if err != nil {
		t.Fatalf("listAutostart: %v", err)
	}
	return rows
}

func TestEveryValueOfARunKeyIsARowInStoredOrder(t *testing.T) {
	h := registrytest.NewFakeHive("SOFTWARE")
	run32 := h.Path(`Microsoft\Windows\CurrentVersion\Run`)
	run32.LastWrite = 134_000_000_000_000_000
	h.Values[run32] = []registryhive.Value{registrytest.SZ("Zeta", `C:\z.exe`), registrytest.SZ("Alpha", `C:\a.exe -q`)}
	f := &fixture{}
	rows := run(t, f, software(h))
	if len(rows) != 2 || rows[0].ValueName != "Zeta" || rows[1].Data != `C:\a.exe -q` {
		t.Fatalf("rows %+v", rows)
	}
	r := rows[0]
	if r.Location != LocationRun || r.Wow64View || r.User || r.Hive != `\REGISTRY\MACHINE\SOFTWARE` ||
		r.Key != `Microsoft\Windows\CurrentVersion\Run` || r.ValueType != 1 || r.KeyLastWrite.IsZero() || r.DataUnreadable {
		t.Errorf("row %+v", r)
	}
}

func TestRunOncePrefixesAreFlagsAndTheNameIsKept(t *testing.T) {
	h := registrytest.NewFakeHive("SOFTWARE")
	k := h.Path(`Microsoft\Windows\CurrentVersion\RunOnce`)
	h.Values[k] = []registryhive.Value{registrytest.SZ("!Later", "a"), registrytest.SZ("*Safe", "b"),
		registrytest.SZ("!*Both", "c"), registrytest.SZ("Plain!", "d")}
	rows := run(t, &fixture{}, software(h))
	want := [][2]bool{{true, false}, {false, true}, {true, true}, {false, false}}
	for i, r := range rows {
		if r.DeferredDeletion != want[i][0] || r.RunInSafeMode != want[i][1] {
			t.Errorf("%q: deferred %v safe %v", r.ValueName, r.DeferredDeletion, r.RunInSafeMode)
		}
	}
	if rows[0].ValueName != "!Later" {
		t.Errorf("name %q", rows[0].ValueName)
	}
}

func TestRunKeyPrefixesAreNotRunOnceFlags(t *testing.T) {
	h := registrytest.NewFakeHive("SOFTWARE")
	h.Values[h.Path(`Microsoft\Windows\CurrentVersion\Run`)] = []registryhive.Value{registrytest.SZ("!x", "a")}
	if rows := run(t, &fixture{}, software(h)); rows[0].DeferredDeletion {
		t.Errorf("a Run value took a RunOnce flag")
	}
}

func TestTheThirtyTwoBitViewAndNamedValues(t *testing.T) {
	h := registrytest.NewFakeHive("SOFTWARE")
	h.Values[h.Path(`Wow6432Node\Microsoft\Windows\CurrentVersion\Run`)] = []registryhive.Value{registrytest.SZ("Old", "o.exe")}
	h.Values[h.Path(`Microsoft\Windows NT\CurrentVersion\Winlogon`)] = []registryhive.Value{
		registrytest.SZ("Shell", "explorer.exe"), registrytest.SZ("Userinit", `C:\Windows\system32\userinit.exe,`),
		registrytest.SZ("DefaultUserName", "x")}
	h.Values[h.Path(`Microsoft\Windows NT\CurrentVersion\Windows`)] = []registryhive.Value{
		registrytest.SZ("AppInit_DLLs", ""), registrytest.DWORD("LoadAppInit_DLLs", 0)}
	rows := run(t, &fixture{}, software(h))
	got := []string{}
	for _, r := range rows {
		got = append(got, string(r.Location)+":"+r.ValueName)
	}
	if strings.Join(got, ",") != "Run:Old,Winlogon:Shell,Winlogon:Userinit,AppInit:AppInit_DLLs,AppInit:LoadAppInit_DLLs" {
		t.Fatalf("rows %v", got)
	}
	if !rows[0].Wow64View || rows[1].Wow64View {
		t.Errorf("views %v %v", rows[0].Wow64View, rows[1].Wow64View)
	}
	if rows[4].ValueType != 4 || rows[4].Data != "0x0" {
		t.Errorf("dword row %+v", rows[4])
	}
}

func TestImageDebuggersAreOneRowPerImageWithADebugger(t *testing.T) {
	h := registrytest.NewFakeHive("SOFTWARE")
	h.Values[h.Path(imageOptions+`\sethc.exe`)] = []registryhive.Value{registrytest.SZ("Debugger", `C:\cmd.exe`)}
	h.Values[h.Path(imageOptions+`\notepad.exe`)] = []registryhive.Value{registrytest.DWORD("GlobalFlag", 2)}
	rows := run(t, &fixture{}, software(h))
	if len(rows) != 1 || rows[0].Location != LocationImageDebugger || rows[0].Image != "sethc.exe" ||
		rows[0].Key != imageOptions+`\sethc.exe` || rows[0].Data != `C:\cmd.exe` {
		t.Fatalf("rows %+v", rows)
	}
}

func TestUserHivesGiveUserRows(t *testing.T) {
	h := registrytest.NewFakeHive("ntuser.dat")
	h.Values[h.Path(`Software\Microsoft\Windows\CurrentVersion\Run`)] = []registryhive.Value{registrytest.SZ("Sync", "s.exe")}
	h.Values[h.Path(`Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`)] = []registryhive.Value{registrytest.SZ("1", "p.exe")}
	f := &fixture{}
	rows := run(t, f, user(h, "S-1-5-21-1-2-3-1001"))
	if len(rows) != 2 || !rows[0].User || rows[0].Hive != `\REGISTRY\USER\S-1-5-21-1-2-3-1001` || rows[1].Location != LocationPolicyRun {
		t.Fatalf("rows %+v", rows)
	}
	if !f.said("no SOFTWARE hive") || f.said("no user hive") {
		t.Errorf("diagnostics %q", f.diagnostics)
	}
}

func TestHivesArePickedByRegistryPathThenFileName(t *testing.T) {
	for _, c := range []struct {
		hive registryhive.Hive
		want hiveKind
	}{
		{registryhive.Hive{RegistryPath: `\REGISTRY\MACHINE\SOFTWARE`}, softwareHive},
		{registryhive.Hive{RegistryPath: `\REGISTRY\MACHINE\SYSTEM`, FileFullPath: `\REGISTRY\MACHINE\SYSTEM`}, systemHive},
		{registryhive.Hive{RegistryPath: `\REGISTRY\USER\.DEFAULT`, FileFullPath: `\SystemRoot\System32\Config\DEFAULT`}, userHive},
		{registryhive.Hive{RegistryPath: `\REGISTRY\USER\S-1-5-19`}, userHive},
		{registryhive.Hive{RegistryPath: `\REGISTRY\USER\S-1-5-21-1-2-3-500_Classes`}, otherHive},
		{registryhive.Hive{RegistryPath: `\REGISTRY\A\{718a0353}`, FileFullPath: `\SystemRoot\System32\Config\BBI`}, otherHive},
		{registryhive.Hive{RegistryPath: `\REGISTRY\MACHINE\SAM`, FileFullPath: `SOFTWARE`}, otherHive},
		{registryhive.Hive{FileFullPath: `\SystemRoot\System32\Config\SOFTWARE`}, softwareHive},
		{registryhive.Hive{FileFullPath: `\??\C:\Users\x\NTUSER.DAT`}, userHive},
		{registryhive.Hive{FileFullPath: `\SystemRoot\System32\Config\DEFAULT`}, userHive},
		{registryhive.Hive{FileFullPath: `\??\C:\Users\x\UsrClass.dat`}, otherHive},
	} {
		if got := kindOf(c.hive); got != c.want {
			t.Errorf("%+v: kind %d, want %d", c.hive, got, c.want)
		}
	}
}

func TestBootExecuteComesFromTheCurrentControlSet(t *testing.T) {
	h := registrytest.NewFakeHive("SYSTEM")
	v := registryhive.Value{Name: "BootExecute", Type: 7, Data: "autocheck autochk *\nother", Raw: []byte{1, 0}, Length: 2}
	h.Values[h.Path(`ControlSet002\Control\Session Manager`)] = []registryhive.Value{v}
	h.Values[h.Path(`ControlSet001\Control\Session Manager`)] = []registryhive.Value{registrytest.SZ("BootExecute", "wrong")}
	rows := run(t, &fixture{}, system(h, "ControlSet002", true))
	if len(rows) != 1 || rows[0].Location != LocationBootExecute || rows[0].Data != "autocheck autochk *\nother" ||
		rows[0].Key != `ControlSet002\Control\Session Manager` {
		t.Fatalf("rows %+v", rows)
	}
	f := &fixture{}
	if rows := run(t, f, system(h, "ControlSet001", false)); len(rows) != 0 || !f.said("value Current does not read") {
		t.Errorf("rows %+v diagnostics %q", rows, f.diagnostics)
	}
}

func TestUnreadableLocationsAreReportedAndStrictModeReturnsTheFirst(t *testing.T) {
	h := registrytest.NewFakeHive("SOFTWARE")
	k := h.Path(`Microsoft\Windows\CurrentVersion\Run`)
	h.Values[k] = []registryhive.Value{registrytest.SZ("Kept", "k.exe")}
	h.ValuesIncomplete[k] = true
	wl := h.Path(`Microsoft\Windows NT\CurrentVersion\Winlogon`)
	h.Values[wl] = []registryhive.Value{{NameUnreadable: true}}
	h.ValuesIncomplete[wl] = true
	ifeo := h.Path(imageOptions)
	h.SubkeysIncomplete[ifeo] = true
	f := &fixture{}
	rows := run(t, f, software(h))
	if len(rows) != 1 || rows[0].ValueName != "Kept" {
		t.Fatalf("rows %+v", rows)
	}
	for _, want := range []string{`key Microsoft\Windows\CurrentVersion\Run: value list does not read`,
		"value Shell does not read", "subkey list does not read"} {
		if !f.said(want) {
			t.Errorf("no %q in %q", want, f.diagnostics)
		}
	}
	f.options = map[string]any{"strict": true}
	rows, err := listAutostart(f.ctx(), []openedHive{software(h)})
	if !errors.Is(err, ErrIncomplete) || len(rows) != 1 {
		t.Errorf("strict: %d rows, error %v", len(rows), err)
	}
}

func TestASecondSoftwareHiveIsNotRead(t *testing.T) {
	a, b := registrytest.NewFakeHive("SOFTWARE"), registrytest.NewFakeHive("SOFTWARE")
	b.Values[b.Path(`Microsoft\Windows\CurrentVersion\Run`)] = []registryhive.Value{registrytest.SZ("Late", "l.exe")}
	second := software(b)
	second.path = ""
	f := &fixture{}
	if rows := run(t, f, software(a), second); len(rows) != 0 || !f.said("a second SOFTWARE hive") {
		t.Errorf("rows %+v diagnostics %q", rows, f.diagnostics)
	}
}

func TestNoHivesAreReported(t *testing.T) {
	f := &fixture{}
	run(t, f)
	for _, want := range []string{"no SOFTWARE hive", "no SYSTEM hive", "no user hive"} {
		if !f.said(want) {
			t.Errorf("no %q in %q", want, f.diagnostics)
		}
	}
}

func FuzzRunOncePrefixes(f *testing.F) {
	for _, s := range []string{"", "!", "*", "!*x", "x!"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		deferred, safe := runOncePrefixes(name)
		if deferred && !strings.ContainsRune(name, '!') || safe && !strings.ContainsRune(name, '*') {
			t.Fatalf("%q: flags %v %v without the prefix", name, deferred, safe)
		}
		if len(name) > 0 && name[0] != '!' && name[0] != '*' && (deferred || safe) {
			t.Fatalf("%q: a flag from a character past the prefix", name)
		}
	})
}
