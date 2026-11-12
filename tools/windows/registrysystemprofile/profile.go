package registrysystemprofile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.registry.read_system_profile"

var (
	ErrNoHive     = errors.New("registrysystemprofile: neither SOFTWARE nor SYSTEM opens")
	ErrIncomplete = errors.New("registrysystemprofile: value not read")
)

const (
	HiveSoftware = "SOFTWARE"
	HiveSystem   = "SYSTEM"
)

const versionKey = `Microsoft\Windows NT\CurrentVersion`

var versionValues = []string{"ProductName", "EditionID", "DisplayVersion", "ReleaseId", "CurrentBuild",
	"CurrentBuildNumber", "UBR", "BuildLabEx", "InstallationType", "InstallDate", "InstallTime", "RegisteredOwner",
	"RegisteredOrganization", "ProductId"}

var timeZoneValues = []string{"TimeZoneKeyName", "StandardName", "DaylightName", "Bias", "ActiveTimeBias"}

type Setting struct {
	Hive       string
	Key        string
	ValueName  string
	Type       uint32
	Text       string
	Time       time.Time
	UTCOffset  string
	Unreadable bool
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Read the Windows product, build, install time, registered owner, computer name and time zone values from the SOFTWARE and SYSTEM hives",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type valueReader interface {
	OpenKey(path string) (*registryhive.KeyNode, error)
	ValuesChecked(node *registryhive.KeyNode) ([]registryhive.Value, bool)
}

func Run(ctx tools.Context) ([]Setting, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	cells := registryhive.CellReader(ctx)
	software, swErr := registryhive.OpenHive(ctx, HiveSoftware, cells)
	system, syErr := registryhive.OpenHive(ctx, HiveSystem, cells)
	if swErr != nil && syErr != nil {
		return nil, fmt.Errorf("%s: %w: %w", Name, ErrNoHive, errors.Join(swErr, syErr))
	}
	r := reader{ctx: ctx}
	if swErr != nil {
		ctx.AddDiagnostic("%s: %s hive not opened: %v", Name, HiveSoftware, swErr)
	} else {
		r.readKey(software, HiveSoftware, versionKey, versionValues)
	}
	if syErr != nil {
		ctx.AddDiagnostic("%s: %s hive not opened: %v", Name, HiveSystem, syErr)
	} else {
		set, read := registryhive.CurrentControlSetChecked(system)
		r.readSystem(system, set, read)
	}
	if r.firstErr != nil && ctx.StrictMode() {
		return r.out, r.firstErr
	}
	return r.out, nil
}

type reader struct {
	ctx      tools.Context
	out      []Setting
	firstErr error
}

func (r *reader) fail(err error) {
	if r.firstErr == nil {
		r.firstErr = err
	}
}

func (r *reader) readSystem(h valueReader, set string, read bool) {
	sel := Setting{Hive: HiveSystem, Key: "Select", ValueName: "Current", Type: regDWORD}
	if read {
		sel.Text = set
	} else {
		sel.Unreadable = true
		r.ctx.AddDiagnostic("%s: SYSTEM\\Select\\Current not read: values below come from %s: %v", Name, set, ErrIncomplete)
		r.fail(fmt.Errorf("%s: SYSTEM\\Select\\Current: %w", Name, ErrIncomplete))
	}
	r.out = append(r.out, sel)
	r.readKey(h, HiveSystem, set+`\Control\ComputerName\ComputerName`, []string{"ComputerName"})
	r.readKey(h, HiveSystem, set+`\Control\ComputerName\ActiveComputerName`, []string{"ComputerName"})
	r.readKey(h, HiveSystem, set+`\Control\TimeZoneInformation`, timeZoneValues)
}

func (r *reader) readKey(h valueReader, hive, path string, names []string) {
	k, err := h.OpenKey(path)
	switch {
	case errors.Is(err, registryhive.ErrKeyNotFound):
		return
	case err != nil:
		r.ctx.AddDiagnostic("%s: key %s\\%s not read: %v", Name, hive, path, err)
		r.fail(fmt.Errorf("%s: key %s\\%s: %w", Name, hive, path, ErrIncomplete))
		return
	}
	values, complete := h.ValuesChecked(k)
	for _, name := range names {
		v, found, maybe := registryhive.FindValue(values, complete, name)
		if !found && !maybe {
			continue
		}
		s := Setting{Hive: hive, Key: path, ValueName: name}
		if found && decode(&s, v) {
			r.out = append(r.out, s)
			continue
		}
		s.Unreadable = true
		r.ctx.AddDiagnostic("%s: value %s at 0x%x: %v", Name, name, k.Address, ErrIncomplete)
		r.fail(fmt.Errorf("%s: value %s\\%s\\%s: %w", Name, hive, path, name, ErrIncomplete))
		r.out = append(r.out, s)
	}
}

const (
	regDWORD = 4
	regQWORD = 11
)

func decode(s *Setting, v registryhive.Value) bool {
	if v.TypeUnreadable || v.Unreadable() {
		return false
	}
	s.Type = v.Type
	switch v.Type {
	case regDWORD:
		if len(v.Raw) != 4 {
			return false
		}
		n := binary.LittleEndian.Uint32(v.Raw)
		s.Text = strconv.FormatUint(uint64(n), 10)
		switch s.ValueName {
		case "InstallDate":
			if n != 0 {
				s.Time = time.Unix(int64(n), 0).UTC()
			}
		case "Bias", "ActiveTimeBias":
			s.Text = strconv.Itoa(int(int32(n)))
			s.UTCOffset = offsetOf(int32(n))
		}
	case regQWORD:
		if len(v.Raw) != 8 {
			return false
		}
		n := binary.LittleEndian.Uint64(v.Raw)
		s.Text = strconv.FormatUint(n, 10)
		if s.ValueName == "InstallTime" {
			s.Time, _ = util.FiletimeToTime(n)
		}
	default:
		s.Text = v.Data
	}
	return true
}

// Learn: UTC = local time + bias, so local time is UTC minus the bias.
func offsetOf(bias int32) string {
	minutes := -int64(bias)
	sign := "+"
	if minutes < 0 {
		sign, minutes = "-", -minutes
	}
	return fmt.Sprintf("UTC%s%02d:%02d", sign, minutes/60, minutes%60)
}
