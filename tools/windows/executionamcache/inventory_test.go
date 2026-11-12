package executionamcache

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

// Keys and values follow S63 M26 to M28.
const (
	fileID  = "0000" + "0123456789abcdef0123456789abcdef01234567"
	program = "0000" + "fedcba9876543210fedcba9876543210fedcba98"
)

var id = hiveID{path: `\??\C:\Windows\AppCompat\Programs\Amcache.hve`, address: 0x5000}

func ctxOf(strict bool) (tools.Context, *[]string) {
	var diags []string
	return tools.Context{Options: map[string]any{"diagnostics": &diags, "strict": strict}}, &diags
}

func hiveWith() *registrytest.FakeHive {
	h := registrytest.NewFakeHive("ROOT")
	f := h.Key(h.Path(`Root\InventoryApplicationFile`), "notepad.exe|0123456789abcdef")
	h.Values[f] = []registryhive.Value{
		registrytest.SZ("LowerCaseLongPath", `c:\windows\notepad.exe`), registrytest.SZ("Name", "notepad.exe"),
		registrytest.SZ("FileId", fileID), registrytest.SZ("ProgramId", program), registrytest.SZ("Publisher", "Microsoft"),
		registrytest.SZ("ProductName", "Windows"), registrytest.SZ("Version", "10.0"),
		registrytest.SZ("LinkDate", "05/06/2026 18:00:00"),
	}
	a := h.Key(h.Path(`Root\InventoryApplication`), program)
	h.Values[a] = []registryhive.Value{registrytest.SZ("Name", "Notepad"), registrytest.SZ("ProgramId", program),
		registrytest.SZ("RootDirPath", `C:\Windows`), registrytest.SZ("InstallDate", "")}
	d := h.Key(h.Path(`Root\InventoryDriverBinary`), "c:/windows/system32/drivers/x.sys")
	h.Values[d] = []registryhive.Value{registrytest.SZ("DriverId", fileID), registrytest.SZ("DriverName", "x.sys"),
		registrytest.DWORD("DriverTimeStamp", 0x6a000000), registrytest.SZ("Service", "x")}
	return h
}

func TestTheThreeInventoriesAreRead(t *testing.T) {
	ctx, diags := ctxOf(false)
	out, err := read(ctx, hiveWith(), id)
	if err != nil || len(out) != 3 || len(*diags) != 0 {
		t.Fatalf("%v %+v %q", err, out, *diags)
	}
	f, a, d := out[0], out[1], out[2]
	if f.Category != ApplicationFile || f.Path != `c:\windows\notepad.exe` || f.FileIDHash != fileID[4:] || f.ProgramID != program ||
		f.LinkDate != "05/06/2026 18:00:00" || f.Product != "Windows" || f.HivePath != id.path || f.HiveAddress != id.address {
		t.Errorf("file %+v", f)
	}
	if a.Category != Application || a.Name != "Notepad" || a.Path != `C:\Windows` || a.ProgramID != program || a.FileID != "" {
		t.Errorf("application %+v", a)
	}
	if d.Category != DriverBinary || d.Path != "c:/windows/system32/drivers/x.sys" || d.FileID != fileID ||
		!d.LinkTime.Equal(time.Unix(0x6a000000, 0).UTC()) || d.Service != "x" {
		t.Errorf("driver %+v", d)
	}
}

func TestADriverKeyWithoutASlashIsItsIdentifier(t *testing.T) {
	r := Decode(DriverBinary, &registryhive.KeyNode{Name: fileID}, []registryhive.Value{registrytest.SZ("DriverName", "a.sys")}, true)
	if r.Path != "" || r.FileID != fileID || r.FileIDHash == "" || r.Name != "a.sys" || len(r.Unread) != 0 {
		t.Errorf("%+v", r)
	}
}

func TestUnreadValuesAndKeysAreReported(t *testing.T) {
	h := hiveWith()
	files := h.Path(`Root\InventoryApplicationFile`)
	k := h.Subkeys[files][0]
	h.Values[k] = []registryhive.Value{{Name: "FileId", Type: 1, Length: 90}}
	h.ValuesIncomplete[k] = true
	h.SubkeysIncomplete[h.Path(`Root\InventoryApplication`)] = true
	h.Path(`Root\File`)
	ctx, diags := ctxOf(true)
	out, err := read(ctx, h, id)
	if !errors.Is(err, ErrIncomplete) || len(out) != 3 {
		t.Fatalf("%v %+v", err, out)
	}
	if !slices.Contains(out[0].Unread, "FileId") || !slices.Contains(out[0].Unread, "LowerCaseLongPath") {
		t.Errorf("unread %v", out[0].Unread)
	}
	joined := strings.Join(*diags, "\n")
	if !strings.Contains(joined, "Root\\File present and not decoded") || strings.Count(joined, ErrIncomplete.Error()) != 2 {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestATimeStampOfAnotherKindIsUnread(t *testing.T) {
	v := registryhive.Value{Name: "DriverTimeStamp", Type: 11, Raw: binary.LittleEndian.AppendUint64(nil, 1), Length: 8}
	r := Decode(DriverBinary, &registryhive.KeyNode{Name: "x"}, []registryhive.Value{v}, true)
	if !r.LinkTime.IsZero() || !slices.Equal(r.Unread, []string{"DriverTimeStamp"}) {
		t.Errorf("%+v", r)
	}
}

func FuzzInventoryValues(f *testing.F) {
	f.Add("FileId", fileID, uint32(1))
	f.Add("DriverTimeStamp", "", uint32(4))
	f.Fuzz(func(t *testing.T, name, data string, typ uint32) {
		v := registryhive.Value{Name: name, Type: typ, Data: data, Raw: []byte(data), Length: uint32(len(data))}
		for _, c := range []Category{ApplicationFile, Application, DriverBinary} {
			r := Decode(c, &registryhive.KeyNode{Name: data}, []registryhive.Value{v}, true)
			if r.FileIDHash != "" && (len(r.FileIDHash) != idHashDigits || !strings.HasSuffix(r.FileID, r.FileIDHash)) {
				t.Fatalf("%+v", r)
			}
			if len(r.Unread) > 1 {
				t.Fatalf("one value unread %d times: %v", len(r.Unread), r.Unread)
			}
		}
	})
}
