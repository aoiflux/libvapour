package serviceregistry

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.service.read_registry"

var (
	ErrServicesUnread = errors.New("serviceregistry: Services key not read")
	ErrIncomplete     = errors.New("serviceregistry: services not read in full")
)

type ServiceKey struct {
	Name           string
	NameUnreadable bool
	LastWrite      time.Time

	Type             uint32
	TypeNames        []string
	Start            uint32
	StartName        string
	ErrorControl     uint32
	ErrorControlName string
	Tag              uint32

	ImagePath   string
	DisplayName string
	ObjectName  string
	Group       string

	Absent []string
	Unread []string
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the service keys of the SYSTEM hive's current control set: type, start type, error control, tag, image path, display name, account and group",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type serviceHive interface {
	OpenKey(path string) (*registryhive.KeyNode, error)
	SubkeysChecked(node *registryhive.KeyNode) ([]*registryhive.KeyNode, bool)
	ValuesChecked(node *registryhive.KeyNode) ([]registryhive.Value, bool)
}

func Run(ctx tools.Context) ([]ServiceKey, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	hive, err := registryhive.OpenHive(ctx, "SYSTEM", nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", Name, ErrServicesUnread, err)
	}
	return readServices(ctx, hive, registryhive.CurrentControlSet(hive)+`\Services`)
}

func readServices(ctx tools.Context, h serviceHive, path string) ([]ServiceKey, error) {
	root, err := h.OpenKey(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: %w: %w", Name, path, ErrServicesUnread, err)
	}
	var firstErr error
	fail := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	subs, complete := h.SubkeysChecked(root)
	if !complete {
		ctx.AddDiagnostic("%s: key at 0x%x: subkey list not read in full: %v", Name, root.Address, ErrIncomplete)
		fail(fmt.Errorf("%s: %s subkeys: %w", Name, path, ErrIncomplete))
	}
	out := make([]ServiceKey, 0, len(subs))
	for _, sk := range subs {
		values, vc := h.ValuesChecked(sk)
		s := Decode(sk.Name, values, vc)
		s.NameUnreadable = sk.NameUnreadable
		if !sk.LastWriteUnreadable {
			s.LastWrite, _ = util.FiletimeToTime(sk.LastWrite)
		}
		if !vc || len(s.Unread) > 0 {
			ctx.AddDiagnostic("%s: key at 0x%x: values not read in full: %v", Name, sk.Address, ErrIncomplete)
			fail(fmt.Errorf("%s: service %q: %w", Name, sk.Name, ErrIncomplete))
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].NameUnreadable != out[j].NameUnreadable {
			return !out[i].NameUnreadable
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	if firstErr != nil && ctx.StrictMode() {
		return out, firstErr
	}
	return out, nil
}

const (
	regSZ       = 1
	regExpandSZ = 2
	regDWORD    = 4
)

func Decode(name string, values []registryhive.Value, complete bool) ServiceKey {
	s := ServiceKey{Name: name}
	lookup := func(value string) (registryhive.Value, bool) {
		v, found, maybe := registryhive.FindValue(values, complete, value)
		switch {
		case found && !v.Unreadable() && !v.TypeUnreadable:
			return v, true
		case found || maybe:
			s.Unread = append(s.Unread, value)
		default:
			s.Absent = append(s.Absent, value)
		}
		return registryhive.Value{}, false
	}
	number := func(value string, dst *uint32) bool {
		v, ok := lookup(value)
		if !ok {
			return false
		}
		if v.Type != regDWORD || len(v.Raw) != 4 {
			s.Unread = append(s.Unread, value)
			return false
		}
		*dst = binary.LittleEndian.Uint32(v.Raw)
		return true
	}
	text := func(value string, dst *string) {
		v, ok := lookup(value)
		if !ok {
			return
		}
		if v.Type != regSZ && v.Type != regExpandSZ {
			s.Unread = append(s.Unread, value)
			return
		}
		*dst = v.Data
	}
	if number("Type", &s.Type) {
		s.TypeNames = TypeNames(s.Type)
	}
	if number("Start", &s.Start) {
		s.StartName = lookupName(startNames, s.Start)
	}
	if number("ErrorControl", &s.ErrorControl) {
		s.ErrorControlName = lookupName(errorControlNames, s.ErrorControl)
	}
	number("Tag", &s.Tag)
	text("ImagePath", &s.ImagePath)
	text("DisplayName", &s.DisplayName)
	text("ObjectName", &s.ObjectName)
	text("Group", &s.Group)
	return s
}

// The CreateService and per-user services pages name these bits.
var typeBits = []struct {
	bit  uint32
	name string
}{
	{0x1, "kernel_driver"},
	{0x2, "file_system_driver"},
	{0x4, "adapter"},
	{0x8, "recognizer_driver"},
	{0x10, "win32_own_process"},
	{0x20, "win32_share_process"},
	{0x40, "user_service"},
	{0x100, "interactive_process"},
}

func TypeNames(t uint32) []string {
	var out []string
	for _, b := range typeBits {
		if t&b.bit != 0 {
			out = append(out, b.name)
			t &^= b.bit
		}
	}
	for bit := uint32(1); bit != 0; bit <<= 1 {
		if t&bit != 0 {
			out = append(out, fmt.Sprintf("0x%x", bit))
		}
	}
	return out
}

var startNames = []string{"boot", "system", "auto", "demand", "disabled"}

var errorControlNames = []string{"ignore", "normal", "severe", "critical"}

func lookupName(names []string, n uint32) string {
	if int64(n) < int64(len(names)) {
		return names[n]
	}
	return fmt.Sprintf("0x%x", n)
}
