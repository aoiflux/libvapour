package executionuserassist

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

const Name = "windows.execution.read_userassist"

const assistKey = `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`

const userHiveFile = "NTUSER.DAT"

type DataState string

const (
	DataDecoded    DataState = "decoded"
	DataUnmeasured DataState = "unmeasured"
	DataUnreadable DataState = "unreadable"
)

type CountValue struct {
	HivePath    string
	HiveAddress uint64
	Key         string

	GUID              string
	GUIDUnreadable    bool
	Version           uint32
	VersionKnown      bool
	CountKeyLastWrite time.Time

	Name            string
	NameUnreadable  bool
	KnownFolder     string
	KnownFolderPath string
	ExpandedName    string

	DataState  DataState
	DataLength uint32
	Data       []byte

	LaunchCount uint32
	LastLaunch  time.Time
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List Explorer's per-user program launch counts from NTUSER.DAT hives: decoded name, known folder, launch count and last launch time",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]CountValue, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	var users []userHive
	for _, oh := range registryhive.OpenEveryHive(ctx, nil) {
		if isUserHive(oh.Hive) {
			users = append(users, userHive{layer: oh.Layer, id: hiveIdentity{path: hiveLabel(oh.Hive), address: oh.Hive.Address}})
		}
	}
	return readUserHives(ctx, ctx.Symbols.PointerSize() == 8, users)
}

type userHive struct {
	layer assistHive
	id    hiveIdentity
}

func readUserHives(ctx tools.Context, wide bool, users []userHive) ([]CountValue, error) {
	if len(users) == 0 {
		ctx.AddDiagnostic("%s: no %s hive opens", Name, userHiveFile)
	}
	r := reader{ctx: ctx, wide: wide}
	for _, u := range users {
		r.readHive(u.layer, u.id)
	}
	sortValues(r.out)
	if r.firstErr != nil && ctx.StrictMode() {
		return r.out, r.firstErr
	}
	return r.out, nil
}

func hiveLabel(h registryhive.Hive) string {
	if h.FileFullPath != "" {
		return h.FileFullPath
	}
	return h.Name
}

func isUserHive(h registryhive.Hive) bool {
	return strings.EqualFold(registryhive.LastPathComponent(hiveLabel(h)), userHiveFile)
}

type assistHive interface {
	OpenKey(path string) (*registryhive.KeyNode, error)
	SubkeysChecked(node *registryhive.KeyNode) ([]*registryhive.KeyNode, bool)
	ValuesChecked(node *registryhive.KeyNode) ([]registryhive.Value, bool)
}

type hiveIdentity struct {
	path    string
	address uint64
}

type reader struct {
	ctx      tools.Context
	wide     bool
	out      []CountValue
	firstErr error
}

func (r *reader) fail(err error) {
	if r.firstErr == nil {
		r.firstErr = err
	}
}

func (r *reader) readHive(h assistHive, id hiveIdentity) {
	root, err := h.OpenKey(assistKey)
	switch {
	case errors.Is(err, registryhive.ErrKeyNotFound):
		return
	case err != nil:
		r.ctx.AddDiagnostic("%s: hive %s at 0x%x: UserAssist key not read: %v", Name, id.path, id.address, err)
		r.fail(fmt.Errorf("%s: hive %s: UserAssist key: %w", Name, id.path, ErrIncomplete))
		return
	}
	subs, complete := h.SubkeysChecked(root)
	if !complete {
		r.ctx.AddDiagnostic("%s: UserAssist key at 0x%x: subkey list not read in full: %v", Name, root.Address, ErrIncomplete)
		r.fail(fmt.Errorf("%s: hive %s: UserAssist subkeys: %w", Name, id.path, ErrIncomplete))
	}
	for _, g := range subs {
		r.readSubkey(h, id, g)
	}
}

const regDWORD = 4

func (r *reader) readSubkey(h assistHive, id hiveIdentity, g *registryhive.KeyNode) {
	base := CountValue{HivePath: id.path, HiveAddress: id.address, GUID: g.Name, GUIDUnreadable: g.NameUnreadable}
	values, complete := h.ValuesChecked(g)
	if v, found, _ := registryhive.FindValue(values, complete, "Version"); found && !v.Unreadable() &&
		v.Type == regDWORD && len(v.Raw) == 4 {
		base.Version = binary.LittleEndian.Uint32(v.Raw)
		base.VersionKnown = true
	}
	subs, complete := h.SubkeysChecked(g)
	count, found, maybe := registryhive.FindSubkey(subs, complete, "Count")
	switch {
	case maybe:
		r.ctx.AddDiagnostic("%s: subkey %s at 0x%x: Count key not read: %v", Name, g.Name, g.Address, ErrIncomplete)
		r.fail(fmt.Errorf("%s: subkey %s: Count key: %w", Name, g.Name, ErrIncomplete))
		return
	case !found:
		return
	}
	base.Key = assistKey + `\` + g.Name + `\Count`
	if !count.LastWriteUnreadable {
		base.CountKeyLastWrite, _ = util.FiletimeToTime(count.LastWrite)
	}
	values, complete = h.ValuesChecked(count)
	decodable := !base.VersionKnown || base.Version == measuredVersion
	if !decodable && len(values) > 0 {
		r.ctx.AddDiagnostic("%s: subkey %s at 0x%x: values not decoded: %v", Name, g.Name, g.Address, ErrVersion)
		r.fail(fmt.Errorf("%s: subkey %s: version %d: %w", Name, g.Name, base.Version, ErrVersion))
	}
	if !complete {
		r.ctx.AddDiagnostic("%s: Count key of %s at 0x%x: value list not read in full: %v", Name, g.Name,
			count.Address, ErrIncomplete)
		r.fail(fmt.Errorf("%s: Count key of %s: values: %w", Name, g.Name, ErrIncomplete))
	}
	cut := 0
	for _, v := range values {
		row := r.valueRow(base, v, decodable, count.Address)
		if row.DataState == DataUnreadable {
			cut++
		}
		r.out = append(r.out, row)
	}
	if cut > 0 {
		r.ctx.AddDiagnostic("%s: Count key of %s at 0x%x: %d values not read in full: %v", Name, g.Name,
			count.Address, cut, ErrIncomplete)
		r.fail(fmt.Errorf("%s: Count key of %s: value data: %w", Name, g.Name, ErrIncomplete))
	}
}

func (r *reader) valueRow(row CountValue, v registryhive.Value, decodable bool, key uint64) CountValue {
	row.NameUnreadable = v.NameUnreadable
	if !v.NameUnreadable {
		d := decodeName(v.Name, r.wide)
		row.Name, row.ExpandedName = d.name, d.expanded
		if d.found {
			row.KnownFolder, row.KnownFolderPath = d.folder.ID, d.folder.Path
		}
	}
	row.DataLength = v.Length
	row.Data = v.Raw
	if v.Unreadable() {
		row.DataState = DataUnreadable
		return row
	}
	data, err := DecodeCountData(v.Raw)
	if err != nil || !decodable {
		row.DataState = DataUnmeasured
		return row
	}
	row.DataState = DataDecoded
	row.LaunchCount = data.LaunchCount
	if data.LastLaunch != 0 {
		t, ok := util.FiletimeToTime(data.LastLaunch)
		if !ok {
			r.ctx.AddDiagnostic("%s: Count key of %s at 0x%x: value %q: last launch 0x%x: %v", Name, row.GUID, key,
				row.Name, data.LastLaunch, ErrTime)
			r.fail(fmt.Errorf("%s: Count key of %s: value %q: %w", Name, row.GUID, row.Name, ErrTime))
		}
		row.LastLaunch = t
	}
	return row
}

func sortValues(rows []CountValue) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.HivePath != b.HivePath {
			return a.HivePath < b.HivePath
		}
		if a.HiveAddress != b.HiveAddress {
			return a.HiveAddress < b.HiveAddress
		}
		if ga, gb := strings.ToUpper(a.GUID), strings.ToUpper(b.GUID); ga != gb {
			return ga < gb
		}
		if a.NameUnreadable != b.NameUnreadable {
			return b.NameUnreadable
		}
		return a.Name < b.Name
	})
}
