package tasklist

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

func binValue(name string, data []byte) registryhive.Value {
	return registryhive.Value{Name: name, Type: 3, Raw: data, Length: uint32(len(data))}
}

type cacheFixture struct {
	hive  *registrytest.FakeHive
	tasks *registryhive.KeyNode
	tree  *registryhive.KeyNode
}

func newCache() cacheFixture {
	h := registrytest.NewFakeHive("SOFTWARE")
	return cacheFixture{hive: h, tasks: h.Path(cacheKey + `\Tasks`), tree: h.Path(cacheKey + `\Tree`)}
}

func (c cacheFixture) task(guid string, values ...registryhive.Value) *registryhive.KeyNode {
	k := c.hive.Key(c.tasks, guid)
	c.hive.Values[k] = values
	return k
}

func (c cacheFixture) treeEntry(path, guid string) {
	k := c.hive.Path(cacheKey + `\Tree` + path)
	c.hive.Values[k] = append(c.hive.Values[k], registrytest.SZ("Id", guid))
}

func run(t *testing.T, h cacheHive, strict bool) ([]Task, []string, error) {
	t.Helper()
	var diags []string
	ctx := tools.Context{Options: map[string]any{"diagnostics": &diags, "strict": strict}}
	rows, err := listTasks(ctx, h)
	return rows, diags, err
}

func TestATaskKeyGivesOneRowWithEveryDecodedValue(t *testing.T) {
	c := newCache()
	lastRun := time.Date(2026, 5, 24, 21, 3, 18, 0, time.UTC)
	k := c.task("{A1}",
		registrytest.SZ("Path", `\Microsoft\Windows\Example`), registrytest.SZ("URI", `\Microsoft\Windows\Example`),
		registrytest.SZ("Author", "Microsoft"), registrytest.SZ("SecurityDescriptor", "D:(A;;GA;;;SY)"),
		registrytest.DWORD("Schema", 0x00010005),
		binValue("Triggers", fullTriggers()),
		binValue("Actions", actionsValue(actionFormatLate, "LocalSystem", execRecord(actionFormatLate, "", `C:\a.exe`, "-q", ""))),
		binValue("DynamicInfo", dynamicInfo(runStateFormat, 1, filetime(lastRun), 0, 0)))
	k.LastWrite = filetime(lastRun)
	c.treeEntry(`\Microsoft\Windows\Example`, "{a1}")
	rows, diags, err := run(t, c.hive, true)
	if err != nil || len(diags) != 0 || len(rows) != 1 {
		t.Fatalf("%d rows, %v, %q", len(rows), err, diags)
	}
	r := rows[0]
	if r.GUID != "{A1}" || r.Path != `\Microsoft\Windows\Example` || r.TreePath != `\Microsoft\Windows\Example` ||
		r.Author != "Microsoft" || r.SecurityDescriptor != "D:(A;;GA;;;SY)" || r.SchemaVersion != "1.5" {
		t.Errorf("registration: %+v", r)
	}
	if r.Enabled == nil || !*r.Enabled || r.Principal.ID != "LocalSystem" || len(r.Triggers) != 10 {
		t.Errorf("triggers: %+v", r)
	}
	if r.ActionContext != "LocalSystem" || len(r.Actions) != 1 || r.Actions[0].Arguments != "-q" {
		t.Errorf("actions: %+v", r.Actions)
	}
	if !r.LastRunTime.Equal(lastRun) || !r.KeyLastWrite.Equal(lastRun) {
		t.Errorf("times: %v %v", r.LastRunTime, r.KeyLastWrite)
	}
	if r.TriggersState != StateDecoded || r.ActionsState != StateDecoded || r.DynamicInfoState != StateDecoded {
		t.Errorf("states: %s %s %s", r.TriggersState, r.ActionsState, r.DynamicInfoState)
	}
}

func TestRowsAreOrderedByPathThenKey(t *testing.T) {
	c := newCache()
	c.task("{C}", registrytest.SZ("Path", `\b`))
	c.task("{B}", registrytest.SZ("Path", `\A`))
	c.task("{A}")
	c.treeEntry(`\a2`, "{A}")
	rows, _, _ := run(t, c.hive, false)
	var got []string
	for _, r := range rows {
		got = append(got, r.GUID)
	}
	if strings.Join(got, " ") != "{B} {A} {C}" {
		t.Errorf("order %v", got)
	}
}

func TestAValueThatDoesNotDecodeIsMarkedAndReported(t *testing.T) {
	c := newCache()
	bad := fullTriggers()
	bad[0] = 24
	k := c.task("{T}", binValue("Triggers", bad),
		binValue("Actions", actionsValue(actionFormatLate, "A", execRecord(actionFormatLate, "", "c", "", ""), []byte{0x99, 0x99})),
		binValue("DynamicInfo", []byte{3, 0, 0, 0}))
	k.Address = 0x5000
	rows, diags, err := run(t, c.hive, false)
	if err != nil {
		t.Fatal(err)
	}
	r := rows[0]
	if r.TriggersState != StateUndecoded || r.Enabled != nil || r.ActionsState != StatePartial || len(r.Actions) != 1 ||
		r.DynamicInfoState != StateUndecoded {
		t.Errorf("states: %+v", r)
	}
	want := []string{
		"windows.task.list: task key {T} at 0x5000: Triggers value not decoded: tasklist: format value not measured: Triggers format 24",
		"windows.task.list: task key {T} at 0x5000: Actions value decoded in part: action record at offset 0x1e: tasklist: record kind not measured: 0x9999",
		"windows.task.list: task key {T} at 0x5000: DynamicInfo value not decoded: tasklist: format value not measured: DynamicInfo of 4 bytes",
	}
	if len(diags) != len(want) {
		t.Fatalf("diagnostics %q", diags)
	}
	for i := range want {
		if !strings.HasPrefix(diags[i], want[i]) {
			t.Errorf("diagnostic %d:\n got %s\nwant %s", i, diags[i], want[i])
		}
	}
	if _, _, err := run(t, c.hive, true); !errors.Is(err, ErrFormat) {
		t.Errorf("strict: %v", err)
	}
}

func TestAValueCutShortOrMissingFromAnIncompleteListIsUnreadable(t *testing.T) {
	c := newCache()
	cut := binValue("Triggers", fullTriggers()[:40])
	cut.Length = 400
	k := c.task("{U}", cut, registrytest.SZ("Path", `\p`))
	c.hive.ValuesIncomplete[k] = true
	k2 := c.task("{V}")
	_ = k2
	rows, _, err := run(t, c.hive, false)
	if err != nil {
		t.Fatal(err)
	}
	byGUID := map[string]Task{}
	for _, r := range rows {
		byGUID[r.GUID] = r
	}
	u := byGUID["{U}"]
	if u.TriggersState != StateUnreadable || u.ActionsState != StateUnreadable || u.Path != `\p` ||
		strings.Join(u.UnreadableValues, ",") != "URI,Author,Description,Date,Source,Version,Documentation,SecurityDescriptor,Schema,Triggers,Actions,DynamicInfo" {
		t.Errorf("incomplete list: %+v", u)
	}
	v := byGUID["{V}"]
	if v.TriggersState != StateAbsent || v.ActionsState != StateAbsent || len(v.UnreadableValues) != 0 {
		t.Errorf("complete list: %+v", v)
	}
}

func TestAnIncompleteCacheIsReportedAndFailsStrictMode(t *testing.T) {
	c := newCache()
	c.task("{A}")
	c.hive.SubkeysIncomplete[c.tasks] = true
	c.hive.SubkeysIncomplete[c.tree] = true
	rows, diags, err := run(t, c.hive, false)
	if err != nil || len(rows) != 1 || len(diags) != 2 {
		t.Fatalf("%d rows, %v, %q", len(rows), err, diags)
	}
	if _, _, err := run(t, c.hive, true); !errors.Is(err, ErrIncomplete) {
		t.Errorf("strict: %v", err)
	}
}

func TestAMissingTasksKeyFailsTheRun(t *testing.T) {
	h := registrytest.NewFakeHive("SOFTWARE")
	if _, _, err := run(t, h, false); !errors.Is(err, registryhive.ErrKeyNotFound) {
		t.Errorf("got %v", err)
	}
}

func TestATreeWithoutTheTaskLeavesItsTreePathEmpty(t *testing.T) {
	c := newCache()
	c.task("{A}")
	c.treeEntry(`\x`, "{B}")
	cyclic := c.hive.Path(cacheKey + `\Tree\loop`)
	c.hive.Subkeys[cyclic] = append(c.hive.Subkeys[cyclic], cyclic)
	rows, diags, err := run(t, c.hive, false)
	if err != nil || len(diags) != 0 || rows[0].TreePath != "" {
		t.Fatalf("%+v %v %q", rows, err, diags)
	}
}
