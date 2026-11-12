package softwarelist

import (
	"errors"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

func entryHive(key string, entries map[string][]registryhive.Value) *registrytest.FakeHive {
	h := registrytest.NewFakeHive("ROOT")
	root := h.Path(key)
	for name, values := range entries {
		h.Values[h.Key(root, name)] = values
	}
	return h
}

func TestEntriesFromEveryViewAreSortedByName(t *testing.T) {
	sw := entryHive(machineUninstall, map[string][]registryhive.Value{
		"{P1}": {registrytest.SZ("DisplayName", "zeta"), registrytest.SZ("DisplayVersion", "1.0"),
			registrytest.SZ("InstallDate", "20250319")},
		"KB1": nil,
	})
	wowRoot := sw.Path(wowUninstall)
	sw.Values[sw.Key(wowRoot, "{P2}")] = []registryhive.Value{registrytest.SZ("DisplayName", "Alpha"),
		registrytest.SZ("Publisher", "Pub")}
	user := entryHive(userUninstall, map[string][]registryhive.Value{"u": {registrytest.SZ("DisplayName", "Mid")}})
	var diags []string
	out, err := list(tools.Context{Options: map[string]any{"diagnostics": &diags}}, []source{
		{hive: sw, path: "SOFTWARE", address: 1, key: machineUninstall, view: ViewNative},
		{hive: sw, path: "SOFTWARE", address: 1, key: wowUninstall, view: ViewWOW64},
		{hive: user, path: `C:\Users\a\ntuser.dat`, address: 2, key: userUninstall, view: ViewUser},
	})
	if err != nil || len(out) != 4 {
		t.Fatalf("%v %+v", err, out)
	}
	got := []string{out[0].Key, out[1].Key, out[2].Key, out[3].Key}
	if !slices.Equal(got, []string{"KB1", "{P2}", "u", "{P1}"}) {
		t.Errorf("order %v", got)
	}
	if out[0].DisplayName != "" {
		t.Error("a key without DisplayName keeps it empty")
	}
	p := out[3]
	if p.View != ViewNative || p.DisplayVersion != "1.0" || p.InstallDate != "20250319" || p.HivePath != "SOFTWARE" {
		t.Errorf("%+v", p)
	}
	if out[1].View != ViewWOW64 || out[1].Publisher != "Pub" || out[2].View != ViewUser || out[2].HiveAddress != 2 {
		t.Errorf("%+v %+v", out[1], out[2])
	}
}

func TestUnreadValuesAndKeysAreReported(t *testing.T) {
	h := entryHive(machineUninstall, map[string][]registryhive.Value{"x": {{Name: "DisplayName", Type: 1, Length: 10}}})
	missing := registrytest.NewFakeHive("ROOT")
	missing.SubkeysIncomplete[missing.Root] = true
	var diags []string
	out, err := list(tools.Context{Options: map[string]any{"diagnostics": &diags, "strict": true}}, []source{
		{hive: h, key: machineUninstall, view: ViewNative},
		{hive: h, key: wowUninstall, view: ViewWOW64},
		{hive: missing, key: userUninstall, view: ViewUser},
	})
	if !errors.Is(err, ErrIncomplete) || len(out) != 1 || !slices.Equal(out[0].Unread, []string{"DisplayName"}) {
		t.Fatalf("%v %+v", err, out)
	}
	if len(diags) != 2 {
		t.Errorf("an absent WOW64 key is not reported; the others are: %q", diags)
	}
}

func TestTheFirstSoftwareHiveAndEveryUserHiveAreRead(t *testing.T) {
	opened := []registryhive.OpenedHive{
		{Hive: registryhive.Hive{Address: 1, FileFullPath: `\REGISTRY\MACHINE\SYSTEM`}},
		{Hive: registryhive.Hive{Address: 2, FileFullPath: `\SystemRoot\System32\Config\SOFTWARE`}},
		{Hive: registryhive.Hive{Address: 3, FileFullPath: `\??\C:\Users\a\ntuser.dat`}},
		{Hive: registryhive.Hive{Address: 4, Name: "software"}},
	}
	got, err := sourcesOf(opened)
	if err != nil || len(got) != 3 || got[0].address != 2 || got[1].view != ViewWOW64 || got[2].address != 3 {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := sourcesOf(opened[:1]); !errors.Is(err, ErrNoHive) {
		t.Errorf("err %v", err)
	}
}
