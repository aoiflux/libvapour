package tasklist

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

const Name = "windows.task.list"

var (
	ErrTruncated  = errors.New("tasklist: value ends inside a field")
	ErrFormat     = errors.New("tasklist: format value not measured")
	ErrRecordKind = errors.New("tasklist: record kind not measured")
	ErrField      = errors.New("tasklist: field value outside the measured set")
	ErrLimit      = errors.New("tasklist: record limit reached")
	ErrIncomplete = errors.New("tasklist: task cache not read in full")
)

const cacheKey = `Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`

type ValueState string

const (
	StateDecoded    ValueState = "decoded"
	StateAbsent     ValueState = "absent"
	StateUnreadable ValueState = "unreadable"
	StatePartial    ValueState = "partial"
	StateUndecoded  ValueState = "undecoded"
)

type Task struct {
	GUID           string
	GUIDUnreadable bool
	KeyLastWrite   time.Time

	Path               string
	TreePath           string
	URI                string
	Author             string
	Description        string
	Date               string
	Source             string
	Version            string
	Documentation      string
	SecurityDescriptor string
	SchemaVersion      string

	Enabled   *bool
	Principal Principal
	Settings  Settings
	Triggers  []Trigger

	ActionContext string
	Actions       []Action

	LastRunTime    time.Time
	LastTaskResult uint32

	TriggersState    ValueState
	ActionsState     ValueState
	DynamicInfoState ValueState
	UnreadableValues []string
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List scheduled tasks from the SOFTWARE hive's task cache: registration text, principal, triggers, actions and last run",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Task, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	hive, err := registryhive.OpenHive(ctx, "SOFTWARE", nil)
	if err != nil {
		return nil, fmt.Errorf("%s: SOFTWARE hive: %w", Name, err)
	}
	return listTasks(ctx, hive)
}

type cacheHive interface {
	OpenKey(path string) (*registryhive.KeyNode, error)
	SubkeysChecked(node *registryhive.KeyNode) ([]*registryhive.KeyNode, bool)
	ValuesChecked(node *registryhive.KeyNode) ([]registryhive.Value, bool)
}

func listTasks(ctx tools.Context, h cacheHive) ([]Task, error) {
	tasksKey, err := h.OpenKey(cacheKey + `\Tasks`)
	if err != nil {
		return nil, fmt.Errorf("%s: task cache Tasks key: %w", Name, err)
	}
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	tree := treePaths{byGUID: map[string]string{}, complete: true}
	if treeKey, err := h.OpenKey(cacheKey + `\Tree`); err == nil {
		tree.walk(ctx, h, treeKey, "", 0, map[uint32]bool{})
	} else if !errors.Is(err, registryhive.ErrKeyNotFound) {
		tree.complete = false
	}
	if !tree.complete {
		ctx.AddDiagnostic("%s: task cache Tree key not read in full; some tasks have no tree path", Name)
		note(fmt.Errorf("%s: Tree key: %w", Name, ErrIncomplete))
	}
	keys, complete := h.SubkeysChecked(tasksKey)
	if !complete {
		ctx.AddDiagnostic("%s: task cache Tasks key at 0x%x: subkey list not read in full: %v", Name,
			tasksKey.Address, ErrIncomplete)
		note(fmt.Errorf("%s: Tasks key: %w", Name, ErrIncomplete))
	}
	limit := ctx.Bounds().MaxRowsPerObject
	out := make([]Task, 0, len(keys))
	for _, k := range keys {
		t := readTask(ctx, h, k, limit, note)
		if !t.GUIDUnreadable {
			t.TreePath = tree.byGUID[strings.ToUpper(t.GUID)]
		}
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].sortPath(), out[j].sortPath()
		if a != b {
			return a < b
		}
		return out[i].GUID < out[j].GUID
	})
	if firstErr != nil && ctx.StrictMode() {
		return out, firstErr
	}
	return out, nil
}

func (t Task) sortPath() string {
	if t.Path != "" {
		return strings.ToLower(t.Path)
	}
	return strings.ToLower(t.TreePath)
}

type treePaths struct {
	byGUID   map[string]string
	complete bool
}

func (tp *treePaths) walk(ctx tools.Context, h cacheHive, node *registryhive.KeyNode, path string, depth int,
	seen map[uint32]bool) {
	if seen[node.CellIndex] {
		return
	}
	seen[node.CellIndex] = true
	if depth > ctx.Bounds().MaxRecursionDepth {
		tp.complete = false
		return
	}
	values, complete := h.ValuesChecked(node)
	if !complete {
		tp.complete = false
	}
	if v, found, _ := registryhive.FindValue(values, complete, "Id"); found && !v.Unreadable() && v.Type == regSZ {
		tp.byGUID[strings.ToUpper(v.Data)] = path
	}
	subs, complete := h.SubkeysChecked(node)
	if !complete {
		tp.complete = false
	}
	for _, s := range subs {
		if s.NameUnreadable {
			tp.complete = false
			continue
		}
		tp.walk(ctx, h, s, path+`\`+s.Name, depth+1, seen)
	}
}

const (
	regSZ    = 1
	regDWORD = 4
)

func readTask(ctx tools.Context, h cacheHive, k *registryhive.KeyNode, limit int, note func(error)) Task {
	t := Task{GUID: k.Name, GUIDUnreadable: k.NameUnreadable}
	if !k.LastWriteUnreadable {
		t.KeyLastWrite, _ = util.FiletimeToTime(k.LastWrite)
	}
	values, complete := h.ValuesChecked(k)
	lookup := func(name string) (registryhive.Value, ValueState) {
		v, found, maybe := registryhive.FindValue(values, complete, name)
		switch {
		case found && v.Unreadable():
			t.UnreadableValues = append(t.UnreadableValues, name)
			return v, StateUnreadable
		case found:
			return v, StateDecoded
		case maybe:
			t.UnreadableValues = append(t.UnreadableValues, name)
			return v, StateUnreadable
		}
		return v, StateAbsent
	}
	for _, f := range []struct {
		name string
		dst  *string
	}{
		{"Path", &t.Path}, {"URI", &t.URI}, {"Author", &t.Author}, {"Description", &t.Description},
		{"Date", &t.Date}, {"Source", &t.Source}, {"Version", &t.Version},
		{"Documentation", &t.Documentation}, {"SecurityDescriptor", &t.SecurityDescriptor},
	} {
		if v, st := lookup(f.name); st == StateDecoded && v.Type == regSZ {
			*f.dst = util.CountedText(v.Data)
		}
	}
	if v, st := lookup("Schema"); st == StateDecoded && v.Type == regDWORD && len(v.Raw) == 4 {
		s := binary.LittleEndian.Uint32(v.Raw)
		t.SchemaVersion = fmt.Sprintf("%d.%d", s>>16, s&0xFFFF)
	}
	report := func(value string, st ValueState, err error) {
		if err == nil {
			return
		}
		what := "not decoded"
		if st == StatePartial {
			what = "decoded in part"
		}
		ctx.AddDiagnostic("%s: task key %s at 0x%x: %s value %s: %v", Name, t.GUID, k.Address, value, what, err)
		note(fmt.Errorf("%s: task key %s: %s value: %w", Name, t.GUID, value, err))
	}
	var v registryhive.Value
	if v, t.TriggersState = lookup("Triggers"); t.TriggersState == StateDecoded {
		set, err := DecodeTriggers(v.Raw, limit)
		t.TriggersState = decodeState(err)
		if t.TriggersState != StateUndecoded {
			enabled := set.Enabled
			t.Enabled, t.Principal, t.Settings, t.Triggers = &enabled, set.Principal, set.Settings, set.Triggers
		}
		report("Triggers", t.TriggersState, err)
	}
	if v, t.ActionsState = lookup("Actions"); t.ActionsState == StateDecoded {
		set, err := DecodeActions(v.Raw, limit)
		t.ActionsState = decodeState(err)
		t.ActionContext, t.Actions = set.Context, set.Actions
		report("Actions", t.ActionsState, err)
	}
	if v, t.DynamicInfoState = lookup("DynamicInfo"); t.DynamicInfoState == StateDecoded {
		rs, err := DecodeDynamicInfo(v.Raw)
		if err != nil {
			t.DynamicInfoState = StateUndecoded
		}
		t.LastRunTime, t.LastTaskResult = rs.LastRunTime, rs.LastTaskResult
		report("DynamicInfo", t.DynamicInfoState, err)
	}
	return t
}

// The fields before the first record decode on their own, so a failure
// inside a record leaves a partial value.
type recordError struct {
	what string
	at   int
	err  error
}

func (e *recordError) Error() string {
	return fmt.Sprintf("%s record at offset 0x%x: %v", e.what, e.at, e.err)
}

func (e *recordError) Unwrap() error { return e.err }

func decodeState(err error) ValueState {
	var re *recordError
	switch {
	case err == nil:
		return StateDecoded
	case errors.As(err, &re):
		return StatePartial
	}
	return StateUndecoded
}
