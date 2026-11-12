package callbacklist

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
)

func run(t *testing.T, f *fixture, strict bool) ([]Entry, error) {
	t.Helper()
	return collect(f.ctx(strict), f.mods)
}

func TestEveryKindIsReadInOrder(t *testing.T) {
	f := newFixture()
	rows, err := run(t, f, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		kind    Kind
		routine uint64
		detail  string
	}{
		{KindProcessCreate, routine(1), "slot 3"},
		{KindThreadCreate, routine(2), "slot 0"},
		{KindImageLoad, routine(3), "slot 63"},
		{KindRegistry, routine(4), "altitude 321000"},
		{KindBugCheck, routine(5), "component probe"},
		{KindBugCheckReason, routine(6), "KbCallbackSecondaryDumpData component probedump"},
		{KindShutdown, routine(7), "device 0x" + hex(deviceObject) + ` driver \Driver\probe`},
		{KindShutdownLastChance, routine(7), "device 0x" + hex(deviceObject) + ` driver \Driver\probe`},
		{KindFileSystemChange, routine(8), `driver \Driver\probe`},
		{KindPowerSetting, routine(9), "setting {BA3E0F4D-B817-4094-A2D1-D56379E6A0F3}"},
		{KindObjectHandle, routine(10), "Process pre create,duplicate altitude 321000.5"},
		{KindObjectHandle, routine(11), "Process post create,duplicate altitude 321000.5"},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v (diagnostics %v)", len(rows), len(want), rows, f.diags)
	}
	for i, w := range want {
		r := rows[i]
		if r.Kind != w.kind || r.Routine != w.routine || r.Detail != w.detail || r.Damage != "" {
			t.Errorf("row %d = %+v, want kind %s routine 0x%x detail %q", i, r, w.kind, w.routine, w.detail)
		}
		if r.Module != "probe" {
			t.Errorf("row %d owner %q, want probe", i, r.Module)
		}
	}
	if len(f.diags) != 0 {
		t.Errorf("diagnostics on a clean fixture: %v", f.diags)
	}
}

func hex(v uint64) string { return fmt.Sprintf("%x", v) }

func TestARoutineOutsideEveryModuleHasNoOwner(t *testing.T) {
	f := newFixture()
	f.mem.u64(pool+0x1008, 0xFFFFF80099000000)
	rows, _ := run(t, f, false)
	if rows[0].Routine != 0xFFFFF80099000000 || rows[0].Module != "" || rows[0].Damage != "" {
		t.Errorf("unowned routine row = %+v", rows[0])
	}
}

func TestFastRefBitsComeFromTheTable(t *testing.T) {
	f := newFixture()
	f.table.AddStruct(symbols.StructType{Name: "_EX_FAST_REF", Size: 8, Fields: []symbols.Field{
		{Name: "RefCnt", Type: symbols.TypeRef{BitLength: 3}}}})
	f.mem.u64(pool+0x1008+8, routine(12))
	f.mem.u64(fixtureSymbols["PspCreateProcessNotifyRoutine"]+3*8, (pool+0x1008)|0x7)
	rows, _ := run(t, f, false)
	if rows[0].Record != pool+0x1008 || rows[0].Routine != routine(12) {
		t.Errorf("three-bit fast ref row = %+v", rows[0])
	}
}

func TestAnUnmeasuredBuildListsOnlyTheHeaderRecords(t *testing.T) {
	f := newFixture()
	f.setBuild(22621)
	rows, err := run(t, f, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Kind != KindBugCheck || rows[1].Kind != KindBugCheckReason {
		t.Errorf("rows on an unmeasured build: %+v", rows)
	}
	if len(f.diags) != 1 || !strings.Contains(f.diags[0], "build 22621") {
		t.Errorf("diagnostics: %v", f.diags)
	}
}

func TestTheSharedReleaseBuildsUseTheFirstBuildsLayout(t *testing.T) {
	for _, build := range []uint32{19041, 19045} {
		f := newFixture()
		f.setBuild(build)
		rows, _ := run(t, f, false)
		if len(rows) != 12 {
			t.Errorf("build %d: %d rows, want 12", build, len(rows))
		}
	}
	if _, err := privateLayoutFor(19046); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("19046: %v", err)
	}
}

func TestANonDeviceObjectIsDamageAndStrictModeFails(t *testing.T) {
	f := newFixture()
	f.mem.u16(deviceObject, 7)
	rows, err := run(t, f, false)
	if err != nil {
		t.Fatal(err)
	}
	var shutdown []Entry
	for _, r := range rows {
		if r.Kind == KindShutdown || r.Kind == KindShutdownLastChance {
			shutdown = append(shutdown, r)
		}
	}
	if len(shutdown) != 2 || shutdown[0].Routine != 0 || shutdown[0].Damage != "object is not a device object" {
		t.Errorf("shutdown rows = %+v", shutdown)
	}
	if _, err := run(t, newFixtureWith(func(f *fixture) { f.mem.u16(deviceObject, 7) }), true); !errors.Is(err, ErrNotDevice) {
		t.Errorf("strict: %v", err)
	}
}

func newFixtureWith(change func(*fixture)) *fixture {
	f := newFixture()
	change(f)
	return f
}

func TestAnObjectEntryForAnotherTypeIsDamage(t *testing.T) {
	f := newFixture()
	f.mem.u64(pool+0x8040+0x20, threadType)
	rows, _ := run(t, f, false)
	last := rows[len(rows)-1]
	if last.Kind != KindObjectHandle || last.Routine != 0 || last.Damage != "entry names another object type" {
		t.Errorf("last row = %+v", last)
	}
}

func TestAnUnreadComponentKeepsTheRoutine(t *testing.T) {
	f := newFixture()
	f.mem.u64(pool+0x3028, 0xFFFF9FFF00000000)
	rows, _ := run(t, f, false)
	r := rows[4]
	if r.Kind != KindBugCheck || r.Routine != routine(5) || r.Damage != "name string does not read" {
		t.Errorf("bug-check row = %+v", r)
	}
	if _, err := run(t, newFixtureWith(func(f *fixture) { f.mem.u64(pool+0x3028, 0xFFFF9FFF00000000) }), true); !errors.Is(err, ErrStringUnread) {
		t.Errorf("strict: %v", err)
	}
}

func TestAnUnreadableArrayIsADiagnosticOrTheStrictError(t *testing.T) {
	f := newFixture()
	delete(f.mem, fixtureSymbols["PspCreateProcessNotifyRoutine"]&^0xFFF)
	rows, err := run(t, f, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Kind == KindProcessCreate || r.Kind == KindThreadCreate || r.Kind == KindImageLoad {
			t.Errorf("array row from unreadable memory: %+v", r)
		}
	}
	if len(f.diags) != 3 {
		t.Errorf("diagnostics: %v", f.diags)
	}
	g := newFixture()
	delete(g.mem, fixtureSymbols["PspCreateProcessNotifyRoutine"]&^0xFFF)
	if _, err := run(t, g, true); !errors.Is(err, ErrRecordUnread) {
		t.Errorf("strict: %v", err)
	}
}

func TestAMissingSymbolDropsOnlyItsKind(t *testing.T) {
	f := newFixture()
	f.table = fixtureTable()
	t2 := symbols.NewTable("s27", 8)
	for _, st := range []string{"_LIST_ENTRY", "_KUSER_SHARED_DATA", "_EX_FAST_REF", "_UNICODE_STRING", "_DEVICE_OBJECT", "_DRIVER_OBJECT", "_OBJECT_TYPE"} {
		s, _ := f.table.Struct(st)
		t2.AddStruct(s)
	}
	for name, at := range fixtureSymbols {
		if name != "CallbackListHead" {
			t2.AddSymbol(symbols.Symbol{Name: name, Address: at})
		}
	}
	f.table = t2
	rows, err := run(t, f, true)
	if err != nil {
		t.Fatalf("a missing symbol failed strict mode: %v", err)
	}
	for _, r := range rows {
		if r.Kind == KindRegistry {
			t.Errorf("registry row without its list head: %+v", r)
		}
	}
	if len(rows) != 11 || len(f.diags) != 1 || !strings.Contains(f.diags[0], "CallbackListHead") {
		t.Errorf("%d rows, diagnostics %v", len(rows), f.diags)
	}
}

func TestATableRecordTypeWinsOverTheHeaderOffsets(t *testing.T) {
	f := newFixture()
	f.table.AddStruct(symbols.StructType{Name: "_KBUGCHECK_CALLBACK_RECORD", Size: 0x50, Fields: []symbols.Field{
		field("CallbackRoutine", 0x40), field("Component", 0x48)}})
	f.mem.u64(pool+0x3040, routine(13))
	f.mem.u64(pool+0x3048, 0)
	rows, _ := run(t, f, false)
	if rows[4].Kind != KindBugCheck || rows[4].Routine != routine(13) || rows[4].Detail != "" {
		t.Errorf("bug-check row = %+v", rows[4])
	}
}

func TestA32BitKernelIsRefused(t *testing.T) {
	f := newFixture()
	ctx := f.ctx(false)
	ctx.Symbols = symbols.NewTable("x86", 4)
	if _, err := Run(ctx); !errors.Is(err, ErrNot64Bit) {
		t.Errorf("32-bit: %v", err)
	}
}

func TestOperationNames(t *testing.T) {
	for ops, want := range map[uint32]string{0: "none", 1: "create", 2: "duplicate", 3: "create,duplicate", 0x13: "create,duplicate,0x10"} {
		if got := operationNames(ops); got != want {
			t.Errorf("operationNames(%d) = %q, want %q", ops, got, want)
		}
	}
}

func FuzzCollect(f *testing.F) {
	f.Add([]byte{}, uint16(0))
	f.Add(make([]byte, 0x200), uint16(0x30))
	f.Fuzz(func(t *testing.T, data []byte, at uint16) {
		fx := newFixture()
		for _, base := range []uint64{pool, pool + 0x2000, pool + 0x3000, pool + 0x5000, pool + 0x7000, pool + 0x8000} {
			fx.mem.write(base+uint64(at), data)
		}
		rows, err := collect(fx.ctx(false), fx.mods)
		if err != nil {
			t.Fatalf("non-strict collect failed: %v", err)
		}
		for _, r := range rows {
			switch r.Kind {
			case KindProcessCreate, KindThreadCreate, KindImageLoad, KindRegistry, KindBugCheck, KindBugCheckReason,
				KindShutdown, KindShutdownLastChance, KindFileSystemChange, KindPowerSetting, KindObjectHandle:
			default:
				t.Fatalf("row of unknown kind %q", r.Kind)
			}
			if r.Damage == "" && r.Routine == 0 {
				t.Fatalf("undamaged row without a routine: %+v", r)
			}
		}
	})
}
