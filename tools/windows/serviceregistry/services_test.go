package serviceregistry

import (
	"errors"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

const servicesPath = `ControlSet001\Services`

func ctxOf(strict bool) (tools.Context, *[]string) {
	var diags []string
	return tools.Context{Options: map[string]any{"diagnostics": &diags, "strict": strict}}, &diags
}

func TestAServiceKeyGivesItsDocumentedValues(t *testing.T) {
	s := Decode("Tcpip", []registryhive.Value{
		registrytest.DWORD("Type", 1), registrytest.DWORD("Start", 0), registrytest.DWORD("ErrorControl", 3),
		registrytest.DWORD("Tag", 4),
		{Name: "ImagePath", Type: regExpandSZ, Data: `System32\drivers\tcpip.sys`, Raw: []byte{1, 0}, Length: 2},
		registrytest.SZ("DisplayName", "TCP/IP"), registrytest.SZ("Group", "PNP_TDI"),
	}, true)
	if !slices.Equal(s.TypeNames, []string{"kernel_driver"}) || s.StartName != "boot" || s.ErrorControlName != "critical" ||
		s.Tag != 4 || s.ImagePath != `System32\drivers\tcpip.sys` || s.DisplayName != "TCP/IP" || s.Group != "PNP_TDI" {
		t.Errorf("%+v", s)
	}
	if !slices.Equal(s.Absent, []string{"ObjectName"}) || len(s.Unread) != 0 {
		t.Errorf("absent %v unread %v", s.Absent, s.Unread)
	}
}

func TestValuesOfTheWrongKindOrNotReadAreUnread(t *testing.T) {
	s := Decode("x", []registryhive.Value{
		registrytest.SZ("Type", "1"), {Name: "Start", Type: 4, Raw: []byte{1}, Length: 4}, registrytest.DWORD("ImagePath", 1),
	}, false)
	for _, name := range []string{"Type", "Start", "ImagePath", "ErrorControl", "Tag", "DisplayName", "ObjectName", "Group"} {
		if !slices.Contains(s.Unread, name) {
			t.Errorf("%s not unread in an incomplete list: %v", name, s.Unread)
		}
	}
	if len(s.Absent) != 0 || s.TypeNames != nil || s.StartName != "" {
		t.Errorf("%+v", s)
	}
}

func TestTypeBitsAreNamedAndTheRestWrittenInHex(t *testing.T) {
	for typ, want := range map[uint32][]string{
		0x10:  {"win32_own_process"},
		0x60:  {"win32_share_process", "user_service"},
		0xe0:  {"win32_share_process", "user_service", "0x80"},
		0x110: {"win32_own_process", "interactive_process"},
		0:     nil,
	} {
		if got := TypeNames(typ); !slices.Equal(got, want) {
			t.Errorf("TypeNames(0x%x) = %v, want %v", typ, got, want)
		}
	}
	if lookupName(startNames, 7) != "0x7" || lookupName(errorControlNames, 1) != "normal" {
		t.Error("start or error control names")
	}
}

func TestServicesAreSortedByNameAndIncompleteListsReported(t *testing.T) {
	h := registrytest.NewFakeHive("ROOT")
	root := h.Path(servicesPath)
	h.Key(root, "b")
	h.Key(root, "A")
	h.UnnamedKey(root)
	h.SubkeysIncomplete[root] = true
	ctx, diags := ctxOf(true)
	out, err := readServices(ctx, h, servicesPath)
	if !errors.Is(err, ErrIncomplete) || len(out) != 3 {
		t.Fatalf("%v %+v", err, out)
	}
	if out[0].Name != "A" || out[1].Name != "b" || !out[2].NameUnreadable {
		t.Errorf("order %+v", out)
	}
	if len(*diags) != 1 {
		t.Errorf("diagnostics %q", *diags)
	}
	if _, err := readServices(ctx, h, `ControlSet009\Services`); !errors.Is(err, ErrServicesUnread) {
		t.Errorf("missing Services key: %v", err)
	}
}

func FuzzTypeNames(f *testing.F) {
	f.Add(uint32(0xe0))
	f.Fuzz(func(t *testing.T, typ uint32) {
		names := TypeNames(typ)
		if (typ == 0) != (len(names) == 0) {
			t.Fatalf("type 0x%x gives %v", typ, names)
		}
	})
}
