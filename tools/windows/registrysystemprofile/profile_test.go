package registrysystemprofile

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

func newReader(strict bool) (*reader, *[]string) {
	var diags []string
	return &reader{ctx: tools.Context{Options: map[string]any{"diagnostics": &diags, "strict": strict}}}, &diags
}

func qword(name string, v uint64) registryhive.Value {
	return registryhive.Value{Name: name, Type: regQWORD, Raw: binary.LittleEndian.AppendUint64(nil, v), Length: 8}
}

func filetime(t time.Time) uint64 {
	return uint64(t.Unix()+11644473600)*10_000_000 + uint64(t.Nanosecond()/100)
}

func find(t *testing.T, out []Setting, name string) Setting {
	t.Helper()
	for _, s := range out {
		if s.ValueName == name {
			return s
		}
	}
	t.Fatalf("no %s in %+v", name, out)
	return Setting{}
}

func TestVersionValuesAreReadAsStoredWithTheirTimes(t *testing.T) {
	installed := time.Date(2025, 3, 19, 20, 59, 35, 0, time.UTC)
	h := registrytest.NewFakeHive("ROOT")
	cv := h.Path(versionKey)
	h.Values[cv] = []registryhive.Value{
		registrytest.SZ("ProductName", "Windows Server 2016 Standard Evaluation"),
		registrytest.SZ("CurrentBuild", "14393"),
		registrytest.DWORD("UBR", 693),
		registrytest.DWORD("InstallDate", uint32(installed.Unix())),
		qword("InstallTime", filetime(installed.Add(711*time.Millisecond))),
		registrytest.SZ("Unlisted", "x"),
	}
	r, diags := newReader(false)
	r.readKey(h, HiveSoftware, versionKey, versionValues)
	if len(r.out) != 5 || len(*diags) != 0 {
		t.Fatalf("settings %+v diagnostics %q", r.out, *diags)
	}
	if s := find(t, r.out, "CurrentBuild"); s.Text != "14393" || s.Hive != HiveSoftware || s.Key != versionKey {
		t.Errorf("CurrentBuild %+v", s)
	}
	if s := find(t, r.out, "UBR"); s.Text != "693" {
		t.Errorf("UBR %+v", s)
	}
	if s := find(t, r.out, "InstallDate"); !s.Time.Equal(installed) {
		t.Errorf("InstallDate %+v", s)
	}
	if s := find(t, r.out, "InstallTime"); !s.Time.Equal(installed.Add(711 * time.Millisecond)) {
		t.Errorf("InstallTime %+v", s)
	}
}

func TestBiasesGiveSignedMinutesAndTheLocalOffset(t *testing.T) {
	for _, tc := range []struct {
		bias int32
		text string
		utc  string
	}{
		{-330, "-330", "UTC+05:30"},
		{480, "480", "UTC-08:00"},
		{0, "0", "UTC+00:00"},
	} {
		s := Setting{ValueName: "Bias"}
		if !decode(&s, registrytest.DWORD("Bias", uint32(tc.bias))) || s.Text != tc.text || s.UTCOffset != tc.utc {
			t.Errorf("bias %d gives %+v", tc.bias, s)
		}
	}
}

func TestTheSystemValuesComeFromTheCurrentControlSet(t *testing.T) {
	h := registrytest.NewFakeHive("ROOT")
	h.Values[h.Path(`ControlSet002\Control\ComputerName\ComputerName`)] = []registryhive.Value{registrytest.SZ("ComputerName", "LAB")}
	h.Values[h.Path(`ControlSet002\Control\TimeZoneInformation`)] = []registryhive.Value{
		registrytest.SZ("TimeZoneKeyName", "India Standard Time"), registrytest.DWORD("ActiveTimeBias", 0xfffffeb6)}
	r, _ := newReader(false)
	r.readSystem(h, "ControlSet002", true)
	if s := find(t, r.out, "Current"); s.Text != "ControlSet002" || s.Unreadable {
		t.Errorf("Select\\Current %+v", s)
	}
	if s := find(t, r.out, "ComputerName"); s.Text != "LAB" || !strings.HasPrefix(s.Key, "ControlSet002") {
		t.Errorf("ComputerName %+v", s)
	}
	if s := find(t, r.out, "ActiveTimeBias"); s.UTCOffset != "UTC+05:30" {
		t.Errorf("ActiveTimeBias %+v", s)
	}
}

func TestUnreadValuesAndKeysAreReported(t *testing.T) {
	h := registrytest.NewFakeHive("ROOT")
	cv := h.Path(versionKey)
	h.Values[cv] = []registryhive.Value{{Name: "ProductName", Type: 1, Length: 40}, {Name: "UBR", Type: 4, Raw: []byte{1, 2}, Length: 2}}
	h.ValuesIncomplete[cv] = true
	r, diags := newReader(true)
	r.readKey(h, HiveSoftware, versionKey, versionValues)
	if len(r.out) != len(versionValues) {
		t.Fatalf("%d settings, want one per value the incomplete list may hold", len(r.out))
	}
	for _, s := range r.out {
		if !s.Unreadable {
			t.Errorf("%+v read from an incomplete list", s)
		}
	}
	if !errors.Is(r.firstErr, ErrIncomplete) || len(*diags) != len(versionValues) {
		t.Errorf("err %v, %d diagnostics", r.firstErr, len(*diags))
	}
	h.SubkeysIncomplete[h.Root] = true
	r, diags = newReader(false)
	r.readKey(h, HiveSystem, `Missing`, []string{"x"})
	if len(r.out) != 0 || len(*diags) != 1 {
		t.Errorf("an unreadable key gives %+v %q", r.out, *diags)
	}
	r, _ = newReader(false)
	r.readSystem(registrytest.NewFakeHive("ROOT"), "ControlSet001", false)
	if s := find(t, r.out, "Current"); !s.Unreadable || !errors.Is(r.firstErr, ErrIncomplete) {
		t.Errorf("an unread Select\\Current gives %+v", s)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("Bias", uint32(4), []byte{0xb6, 0xfe, 0xff, 0xff})
	f.Add("InstallTime", uint32(11), []byte{1, 2, 3, 4, 5, 6, 7, 8})
	f.Fuzz(func(t *testing.T, name string, typ uint32, raw []byte) {
		s := Setting{ValueName: name}
		ok := decode(&s, registryhive.Value{Name: name, Type: typ, Raw: raw, Length: uint32(len(raw))})
		if ok && (typ == regDWORD && len(raw) != 4 || typ == regQWORD && len(raw) != 8) {
			t.Fatalf("a %d-byte value of type %d decoded", len(raw), typ)
		}
	})
}
