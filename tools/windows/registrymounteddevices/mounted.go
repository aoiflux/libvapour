package registrymounteddevices

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

const Name = "windows.registry.list_mounted_devices"

var (
	ErrUnreadable = errors.New("registrymounteddevices: MountedDevices key not read")
	ErrIncomplete = errors.New("registrymounteddevices: MountedDevices not read in full")
)

type Kind string

const (
	DriveLetter Kind = "drive_letter"
	MountPoint  Kind = "mount_point"
	VolumeName  Kind = "volume_name"
	OtherName   Kind = "other"
)

type Form string

const (
	FormDMIO       Form = "dmio_id"
	FormDevicePath Form = "device_path"
	FormOther      Form = "other"
)

type MountedName struct {
	Name           string
	NameUnreadable bool
	Kind           Kind
	UniqueID       []byte
	Form           Form
	Identifier     string
	Volumes        []string
	DataUnreadable bool
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the mount manager's persistent names in SYSTEM\\MountedDevices: drive letters, mount points and volume names, each with its unique ID and the volume names that share it",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]MountedName, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	hive, err := registryhive.OpenHive(ctx, "SYSTEM", nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", Name, ErrUnreadable, err)
	}
	key, err := hive.OpenKey("MountedDevices")
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", Name, ErrUnreadable, err)
	}
	values, complete := hive.ValuesChecked(key)
	return names(ctx, key.Address, values, complete)
}

func names(ctx tools.Context, key uint64, values []registryhive.Value, complete bool) ([]MountedName, error) {
	var firstErr error
	if !complete {
		ctx.AddDiagnostic("%s: key at 0x%x: value list not read in full: %v", Name, key, ErrIncomplete)
		firstErr = fmt.Errorf("%s: key at 0x%x: value list: %w", Name, key, ErrIncomplete)
	}
	out := make([]MountedName, 0, len(values))
	cut := 0
	for _, v := range values {
		m := MountedName{Name: v.Name, NameUnreadable: v.NameUnreadable, Kind: OtherName}
		if !v.NameUnreadable {
			m.Kind = KindOf(v.Name)
		}
		if v.Unreadable() {
			m.DataUnreadable = true
			cut++
		} else {
			m.UniqueID = v.Raw
			m.Form, m.Identifier = DecodeUniqueID(v.Raw)
		}
		out = append(out, m)
	}
	if cut > 0 {
		ctx.AddDiagnostic("%s: key at 0x%x: %d unique IDs not read: %v", Name, key, cut, ErrIncomplete)
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: key at 0x%x: unique IDs: %w", Name, key, ErrIncomplete)
		}
	}
	linkVolumes(out)
	sortNames(out)
	if firstErr != nil && ctx.StrictMode() {
		return out, firstErr
	}
	return out, nil
}

const dosDevices = `\DosDevices\`

// Learn names the three forms: \??\Volume{GUID}, \DosDevices\D: and
// \DosDevices\C:\mymount.
func KindOf(name string) Kind {
	switch {
	case len(name) == len(dosDevices)+2 && strings.HasPrefix(name, dosDevices) && isLetter(name[len(dosDevices)]) &&
		name[len(name)-1] == ':':
		return DriveLetter
	case len(name) > len(dosDevices) && strings.HasPrefix(name, dosDevices):
		return MountPoint
	case strings.HasPrefix(name, `\??\Volume{`) && strings.HasSuffix(name, "}"):
		return VolumeName
	}
	return OtherName
}

func isLetter(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }

const dmioPrefix = "DMIO:ID:"

const guidBytes = 16

func DecodeUniqueID(raw []byte) (Form, string) {
	if len(raw) == len(dmioPrefix)+guidBytes && bytes.HasPrefix(raw, []byte(dmioPrefix)) {
		return FormDMIO, guidText(raw[len(dmioPrefix):])
	}
	if s, ok := devicePath(raw); ok {
		return FormDevicePath, s
	}
	return FormOther, hex.EncodeToString(raw)
}

// [MS-DTYP] 2.3.4: Data1, Data2 and Data3 little-endian, then Data4 as stored.
func guidText(b []byte) string {
	return fmt.Sprintf("{%08x-%04x-%04x-%x-%x}", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]),
		binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
}

func devicePath(raw []byte) (string, bool) {
	if len(raw) < 2 || len(raw)%2 != 0 {
		return "", false
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	for len(units) > 0 && units[len(units)-1] == 0 {
		units = units[:len(units)-1]
	}
	if len(units) == 0 || units[0] != '\\' {
		return "", false
	}
	for _, u := range units {
		if u < 0x20 || u == 0x7f {
			return "", false
		}
	}
	return string(utf16.Decode(units)), true
}

func linkVolumes(out []MountedName) {
	byID := map[string][]string{}
	for _, m := range out {
		if m.Kind == VolumeName && !m.DataUnreadable {
			byID[string(m.UniqueID)] = append(byID[string(m.UniqueID)], m.Name)
		}
	}
	for i := range out {
		if out[i].DataUnreadable {
			continue
		}
		for _, v := range byID[string(out[i].UniqueID)] {
			if v != out[i].Name {
				out[i].Volumes = append(out[i].Volumes, v)
			}
		}
		sort.Strings(out[i].Volumes)
	}
}

var kindOrder = map[Kind]int{DriveLetter: 0, MountPoint: 1, VolumeName: 2, OtherName: 3}

func sortNames(out []MountedName) {
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if kindOrder[a.Kind] != kindOrder[b.Kind] {
			return kindOrder[a.Kind] < kindOrder[b.Kind]
		}
		if a.NameUnreadable != b.NameUnreadable {
			return !a.NameUnreadable
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
}
