package registrymounteddevices

import (
	"encoding/binary"
	"errors"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

func utf16le(s string) []byte {
	units := append(utf16.Encode([]rune(s)), 0)
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}

func dmio(guid [16]byte) []byte { return append([]byte(dmioPrefix), guid[:]...) }

func binaryValue(name string, raw []byte) registryhive.Value {
	return registryhive.Value{Name: name, Type: 3, Raw: raw, Length: uint32(len(raw))}
}

var guidBytesFixture = [16]byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8}

func TestNamesAreSortedByKindAndShareTheirVolumes(t *testing.T) {
	path := `\??\SCSI#Disk&Ven_Msft#5&1#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`
	values := []registryhive.Value{
		binaryValue(`\??\Volume{0acf4ffd-0576-11f0-b3ac-806e6f6e6963}`, utf16le(path)),
		binaryValue(`\DosDevices\D:`, utf16le(path)),
		binaryValue(`\DosDevices\C:`, dmio(guidBytesFixture)),
		binaryValue(`\DosDevices\C:\mnt`, []byte{1, 2, 3}),
		binaryValue(`#{x}`, []byte{}),
	}
	var diags []string
	out, err := names(tools.Context{Options: map[string]any{"diagnostics": &diags}}, 0x1000, values, true)
	if err != nil || len(out) != 5 {
		t.Fatalf("%v %+v", err, out)
	}
	c, d, mnt, vol, other := out[0], out[1], out[2], out[3], out[4]
	if c.Name != `\DosDevices\C:` || c.Kind != DriveLetter || c.Form != FormDMIO ||
		c.Identifier != "{12345678-9abc-def0-0102-030405060708}" || len(c.Volumes) != 0 {
		t.Errorf("C: %+v", c)
	}
	if d.Kind != DriveLetter || d.Form != FormDevicePath || d.Identifier != path || len(d.Volumes) != 1 || d.Volumes[0] != vol.Name {
		t.Errorf("D: %+v", d)
	}
	if mnt.Kind != MountPoint || mnt.Form != FormOther || mnt.Identifier != "010203" {
		t.Errorf("mount point %+v", mnt)
	}
	if vol.Kind != VolumeName || len(vol.Volumes) != 0 {
		t.Errorf("volume %+v", vol)
	}
	if other.Kind != OtherName {
		t.Errorf("other %+v", other)
	}
}

func TestUnreadValuesAndListsAreReported(t *testing.T) {
	var diags []string
	values := []registryhive.Value{{Name: `\DosDevices\E:`, Type: 3, Length: 24}, {NameUnreadable: true, Raw: []byte{1}, Length: 1}}
	out, err := names(tools.Context{Options: map[string]any{"diagnostics": &diags, "strict": true}}, 0x1000, values, false)
	if !errors.Is(err, ErrIncomplete) || len(out) != 2 || len(diags) != 2 {
		t.Fatalf("%v %+v %q", err, out, diags)
	}
	if !out[0].DataUnreadable || out[0].UniqueID != nil || !out[1].NameUnreadable || out[1].Kind != OtherName {
		t.Errorf("%+v", out)
	}
}

func TestKindsFollowTheMountManagerForms(t *testing.T) {
	for name, want := range map[string]Kind{
		`\DosDevices\Z:`:       DriveLetter,
		`\DosDevices\1:`:       MountPoint,
		`\DosDevices\C:\x`:     MountPoint,
		`\??\Volume{abc}`:      VolumeName,
		`\??\Volume{abc`:       OtherName,
		`\DosDevices\`:         OtherName,
		`\GLOBAL??\Volume{ab}`: OtherName,
	} {
		if got := KindOf(name); got != want {
			t.Errorf("KindOf(%q) = %s, want %s", name, got, want)
		}
	}
}

func FuzzUniqueID(f *testing.F) {
	f.Add(dmio(guidBytesFixture))
	f.Add(utf16le(`\??\SCSI#x`))
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		form, text := DecodeUniqueID(raw)
		switch form {
		case FormDMIO:
			if len(raw) != len(dmioPrefix)+guidBytes || len(text) != 38 {
				t.Fatalf("dmio from %d bytes: %q", len(raw), text)
			}
		case FormDevicePath:
			if len(raw)%2 != 0 || text == "" || text[0] != '\\' {
				t.Fatalf("device path %q from %x", text, raw)
			}
		case FormOther:
			if len(text) != 2*len(raw) {
				t.Fatalf("hex %q from %d bytes", text, len(raw))
			}
		}
	})
}
