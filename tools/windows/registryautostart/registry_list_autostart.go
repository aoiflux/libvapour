package registryautostart

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.registry.list_autostart"

var ErrIncomplete = errors.New("registryautostart: an autostart location did not read in full")

func init() {
	tools.MustRegister(
		tools.Spec{
			Name: Name,
			Description: "List the documented autostart locations of the SOFTWARE, SYSTEM and user hives: Run, RunOnce, " +
				"RunServicesOnce, policy Run lists, Winlogon Shell and Userinit, AppInit, image debuggers and BootExecute",
		},
		RunAny,
	)
}

type Location string

const (
	LocationRun             Location = "Run"
	LocationRunOnce         Location = "RunOnce"
	LocationRunServicesOnce Location = "RunServicesOnce"
	LocationPolicyRun       Location = "PolicyRun"
	LocationWinlogon        Location = "Winlogon"
	LocationAppInit         Location = "AppInit"
	LocationImageDebugger   Location = "ImageDebugger"
	LocationBootExecute     Location = "BootExecute"
)

type Entry struct {
	Location  Location
	Wow64View bool
	User      bool

	Hive         string
	HiveFile     string
	Key          string
	KeyLastWrite time.Time

	Image           string
	ImageUnreadable bool

	ValueName           string
	ValueNameUnreadable bool
	ValueType           uint32
	Data                string
	DataUnreadable      bool

	DeferredDeletion bool
	RunInSafeMode    bool
}

type place struct {
	location Location
	wow64    bool
	key      string
	values   []string
}

const imageOptions = `Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

var softwarePlaces = []place{
	{location: LocationRun, key: `Microsoft\Windows\CurrentVersion\Run`},
	{location: LocationRunOnce, key: `Microsoft\Windows\CurrentVersion\RunOnce`},
	{location: LocationRunServicesOnce, key: `Microsoft\Windows\CurrentVersion\RunServicesOnce`},
	{location: LocationRun, wow64: true, key: `Wow6432Node\Microsoft\Windows\CurrentVersion\Run`},
	{location: LocationRunOnce, wow64: true, key: `Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
	{location: LocationPolicyRun, key: `Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
	{location: LocationWinlogon, key: `Microsoft\Windows NT\CurrentVersion\Winlogon`, values: []string{"Shell", "Userinit"}},
	{location: LocationAppInit, key: `Microsoft\Windows NT\CurrentVersion\Windows`,
		values: []string{"AppInit_DLLs", "LoadAppInit_DLLs", "IconServiceLib"}},
	{location: LocationAppInit, wow64: true, key: `Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
		values: []string{"AppInit_DLLs", "LoadAppInit_DLLs"}},
	{location: LocationImageDebugger, key: imageOptions, values: []string{"Debugger"}},
}

var userPlaces = []place{
	{location: LocationRun, key: `Software\Microsoft\Windows\CurrentVersion\Run`},
	{location: LocationRunOnce, key: `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{location: LocationPolicyRun, key: `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
}

const sessionManager = `Control\Session Manager`

type hiveReader interface {
	OpenKey(path string) (*registryhive.KeyNode, error)
	SubkeysChecked(node *registryhive.KeyNode) ([]*registryhive.KeyNode, bool)
	ValuesChecked(node *registryhive.KeyNode) ([]registryhive.Value, bool)
}

type hiveKind int

const (
	otherHive hiveKind = iota
	softwareHive
	systemHive
	userHive
)

type openedHive struct {
	kind       hiveKind
	path, file string
	reader     hiveReader
	// The current control set needs the hive layer itself; nil leaves
	// BootExecute unread.
	controlSet func() (string, bool)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Entry, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	var hives []openedHive
	for _, o := range registryhive.OpenEveryHive(ctx, nil) {
		layer := o.Layer
		hives = append(hives, openedHive{kind: kindOf(o.Hive), path: o.Hive.RegistryPath, file: o.Hive.FileFullPath,
			reader: layer, controlSet: func() (string, bool) { return registryhive.CurrentControlSetChecked(layer) }})
	}
	return listAutostart(ctx, hives)
}

// The registry path names the key a hive is loaded at; the file name is the
// fallback for a hive whose path did not read (S56 4.2 step 1).
func kindOf(h registryhive.Hive) hiveKind {
	path := strings.ToUpper(h.RegistryPath)
	switch {
	case path == `\REGISTRY\MACHINE\SOFTWARE`:
		return softwareHive
	case path == `\REGISTRY\MACHINE\SYSTEM`:
		return systemHive
	case strings.HasPrefix(path, `\REGISTRY\USER\`) && !strings.HasSuffix(path, "_CLASSES"):
		return userHive
	case path != "":
		return otherHive
	}
	switch strings.ToUpper(registryhive.LastPathComponent(h.FileFullPath)) {
	case "SOFTWARE":
		return softwareHive
	case "SYSTEM":
		return systemHive
	case "NTUSER.DAT", "DEFAULT":
		return userHive
	}
	return otherHive
}

type collector struct {
	ctx      tools.Context
	rows     []Entry
	firstErr error
}

func (c *collector) incomplete(h openedHive, key, what string, err error) {
	if err == nil {
		err = ErrIncomplete
	}
	full := fmt.Errorf("%s: %s key %s: %s does not read: %w", Name, h.name(), key, what, err)
	c.ctx.AddDiagnostic("%v", full)
	if c.firstErr == nil {
		c.firstErr = full
	}
}

func (h openedHive) name() string {
	if h.path != "" {
		return h.path
	}
	return h.file
}

func listAutostart(ctx tools.Context, hives []openedHive) ([]Entry, error) {
	c := &collector{ctx: ctx}
	var software, system *openedHive
	users := 0
	for i := range hives {
		h := &hives[i]
		switch h.kind {
		case softwareHive:
			if software != nil {
				ctx.AddDiagnostic("%s: a second SOFTWARE hive %q is not read; %q is", Name, h.name(), software.name())
				continue
			}
			software = h
			c.places(*h, softwarePlaces, false)
		case systemHive:
			if system != nil {
				ctx.AddDiagnostic("%s: a second SYSTEM hive %q is not read; %q is", Name, h.name(), system.name())
				continue
			}
			system = h
			c.bootExecute(*h)
		case userHive:
			users++
			c.places(*h, userPlaces, true)
		}
	}
	if software == nil {
		ctx.AddDiagnostic("%s: no SOFTWARE hive is loaded; no machine locations read", Name)
	}
	if system == nil {
		ctx.AddDiagnostic("%s: no SYSTEM hive is loaded; BootExecute not read", Name)
	}
	if users == 0 {
		ctx.AddDiagnostic("%s: no user hive is loaded; no per-user locations read", Name)
	}
	if ctx.StrictMode() && c.firstErr != nil {
		return c.rows, c.firstErr
	}
	return c.rows, nil
}

func (c *collector) places(h openedHive, places []place, user bool) {
	for _, p := range places {
		node, ok := c.open(h, p.key)
		if !ok {
			continue
		}
		if p.location == LocationImageDebugger {
			c.imageDebuggers(h, node, p)
			continue
		}
		c.values(h, node, p, p.key, user, "", false)
	}
}

func (c *collector) open(h openedHive, key string) (*registryhive.KeyNode, bool) {
	node, err := h.reader.OpenKey(key)
	switch {
	case err == nil:
		return node, true
	case errors.Is(err, registryhive.ErrKeyNotFound):
	default:
		c.incomplete(h, key, "key", err)
	}
	return nil, false
}

func (c *collector) values(h openedHive, node *registryhive.KeyNode, p place, key string, user bool, image string, imageUnread bool) {
	values, complete := h.reader.ValuesChecked(node)
	if !complete {
		c.incomplete(h, key, "value list", nil)
	}
	emit := func(v registryhive.Value) {
		e := Entry{Location: p.location, Wow64View: p.wow64, User: user, Hive: h.path, HiveFile: h.file, Key: key,
			Image: image, ImageUnreadable: imageUnread, ValueName: v.Name, ValueNameUnreadable: v.NameUnreadable,
			ValueType: v.Type, Data: v.Data, DataUnreadable: v.Unreadable() || v.TypeUnreadable}
		if !node.LastWriteUnreadable {
			e.KeyLastWrite, _ = util.FiletimeToTime(node.LastWrite)
		}
		if p.location == LocationRunOnce && !v.NameUnreadable {
			e.DeferredDeletion, e.RunInSafeMode = runOncePrefixes(v.Name)
		}
		c.rows = append(c.rows, e)
	}
	if p.values == nil {
		for _, v := range values {
			emit(v)
		}
		return
	}
	for _, name := range p.values {
		v, found, maybe := registryhive.FindValue(values, complete, name)
		switch {
		case found:
			emit(v)
		case maybe:
			c.incomplete(h, key, "value "+name, nil)
		}
	}
}

// Learn names the two prefixes separately; a name may carry both.
func runOncePrefixes(name string) (deferred, safeMode bool) {
	for _, r := range name {
		switch r {
		case '!':
			deferred = true
		case '*':
			safeMode = true
		default:
			return deferred, safeMode
		}
	}
	return deferred, safeMode
}

func (c *collector) imageDebuggers(h openedHive, node *registryhive.KeyNode, p place) {
	subkeys, complete := h.reader.SubkeysChecked(node)
	if !complete {
		c.incomplete(h, p.key, "subkey list", nil)
	}
	for _, sk := range subkeys {
		values, valuesComplete := h.reader.ValuesChecked(sk)
		_, found, maybe := registryhive.FindValue(values, valuesComplete, p.values[0])
		key := p.key + `\` + sk.Name
		switch {
		case found:
			c.values(h, sk, p, key, false, sk.Name, sk.NameUnreadable)
		case maybe:
			c.incomplete(h, key, "value "+p.values[0], nil)
		}
	}
}

func (c *collector) bootExecute(h openedHive) {
	if h.controlSet == nil {
		return
	}
	set, ok := h.controlSet()
	if !ok {
		c.incomplete(h, "Select", "value Current", nil)
		return
	}
	key := set + `\` + sessionManager
	node, ok := c.open(h, key)
	if !ok {
		return
	}
	c.values(h, node, place{location: LocationBootExecute, key: key, values: []string{"BootExecute"}}, key, false, "", false)
}
