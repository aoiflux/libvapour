package softwarelist

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.software.list"

var (
	ErrNoHive     = errors.New("softwarelist: SOFTWARE hive does not open")
	ErrIncomplete = errors.New("softwarelist: uninstall entries not read in full")
)

type View string

const (
	ViewNative View = "native"
	ViewWOW64  View = "wow64"
	ViewUser   View = "user"
)

const (
	machineUninstall = `Microsoft\Windows\CurrentVersion\Uninstall`
	wowUninstall     = `Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	userUninstall    = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	userHiveFile     = "NTUSER.DAT"
)

type Program struct {
	HivePath    string
	HiveAddress uint64
	View        View

	Key           string
	KeyUnreadable bool
	KeyLastWrite  time.Time

	DisplayName     string
	DisplayVersion  string
	Publisher       string
	InstallDate     string
	InstallLocation string
	UninstallString string

	Unread []string
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the programs registered for removal under the Uninstall keys of SOFTWARE (native and Wow6432Node) and of each NTUSER.DAT: name, version, publisher, install date, location and uninstall command",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type uninstallHive interface {
	OpenKey(path string) (*registryhive.KeyNode, error)
	SubkeysChecked(node *registryhive.KeyNode) ([]*registryhive.KeyNode, bool)
	ValuesChecked(node *registryhive.KeyNode) ([]registryhive.Value, bool)
}

type source struct {
	hive    uninstallHive
	path    string
	address uint64
	key     string
	view    View
}

func Run(ctx tools.Context) ([]Program, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	sources, err := sourcesOf(registryhive.OpenEveryHive(ctx, nil))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	return list(ctx, sources)
}

func hivePath(h registryhive.Hive) string {
	if h.FileFullPath != "" {
		return h.FileFullPath
	}
	return h.Name
}

func named(h registryhive.Hive, name string) bool {
	return strings.EqualFold(registryhive.LastPathComponent(h.FileFullPath), name) || strings.EqualFold(h.Name, name) ||
		strings.EqualFold(registryhive.LastPathComponent(h.RegistryPath), name)
}

// The first SOFTWARE in load order is the one the system booted with, as
// OpenHive picks it; user hives follow in load order.
func sourcesOf(opened []registryhive.OpenedHive) ([]source, error) {
	var machine, users []source
	for _, o := range opened {
		at := source{hive: o.Layer, path: hivePath(o.Hive), address: o.Hive.Address}
		switch {
		case machine == nil && named(o.Hive, "SOFTWARE"):
			native, wow := at, at
			native.key, native.view = machineUninstall, ViewNative
			wow.key, wow.view = wowUninstall, ViewWOW64
			machine = []source{native, wow}
		case strings.EqualFold(registryhive.LastPathComponent(hivePath(o.Hive)), userHiveFile):
			at.key, at.view = userUninstall, ViewUser
			users = append(users, at)
		}
	}
	if machine == nil {
		return nil, ErrNoHive
	}
	return append(machine, users...), nil
}

func list(ctx tools.Context, sources []source) ([]Program, error) {
	var out []Program
	var firstErr error
	fail := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, s := range sources {
		key, err := s.hive.OpenKey(s.key)
		switch {
		case errors.Is(err, registryhive.ErrKeyNotFound):
			continue
		case err != nil:
			ctx.AddDiagnostic("%s: hive at 0x%x: key %s not read: %v", Name, s.address, s.key, err)
			fail(fmt.Errorf("%s: hive %s: %s: %w", Name, s.path, s.key, ErrIncomplete))
			continue
		}
		subs, complete := s.hive.SubkeysChecked(key)
		if !complete {
			ctx.AddDiagnostic("%s: key at 0x%x: subkey list not read in full: %v", Name, key.Address, ErrIncomplete)
			fail(fmt.Errorf("%s: hive %s: %s subkeys: %w", Name, s.path, s.key, ErrIncomplete))
		}
		for _, sk := range subs {
			values, vc := s.hive.ValuesChecked(sk)
			p := ProgramFromKey(sk, values, vc)
			p.HivePath, p.HiveAddress, p.View = s.path, s.address, s.view
			if len(p.Unread) > 0 {
				ctx.AddDiagnostic("%s: key at 0x%x: values %s not read: %v", Name, sk.Address, strings.Join(p.Unread, ", "), ErrIncomplete)
				fail(fmt.Errorf("%s: entry %q: %w", Name, sk.Name, ErrIncomplete))
			}
			out = append(out, p)
		}
	}
	sortPrograms(out)
	if firstErr != nil && ctx.StrictMode() {
		return out, firstErr
	}
	return out, nil
}

var entryValues = []string{"DisplayName", "DisplayVersion", "Publisher", "InstallDate", "InstallLocation", "UninstallString"}

func ProgramFromKey(sk *registryhive.KeyNode, values []registryhive.Value, complete bool) Program {
	p := Program{Key: sk.Name, KeyUnreadable: sk.NameUnreadable}
	if !sk.LastWriteUnreadable {
		p.KeyLastWrite, _ = util.FiletimeToTime(sk.LastWrite)
	}
	dst := []*string{&p.DisplayName, &p.DisplayVersion, &p.Publisher, &p.InstallDate, &p.InstallLocation, &p.UninstallString}
	for i, name := range entryValues {
		v, found, maybe := registryhive.FindValue(values, complete, name)
		switch {
		case found && !v.Unreadable() && !v.TypeUnreadable:
			*dst[i] = v.Data
		case found || maybe:
			p.Unread = append(p.Unread, name)
		}
	}
	return p
}

var viewOrder = map[View]int{ViewNative: 0, ViewWOW64: 1, ViewUser: 2}

func sortPrograms(out []Program) {
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if x, y := strings.ToLower(a.DisplayName), strings.ToLower(b.DisplayName); x != y {
			return x < y
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		if a.View != b.View {
			return viewOrder[a.View] < viewOrder[b.View]
		}
		return a.HivePath < b.HivePath
	})
}
