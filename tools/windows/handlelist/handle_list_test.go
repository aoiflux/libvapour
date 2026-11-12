package handlelist

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

func (f *s66Fixture) said(parts ...string) bool {
	for _, d := range f.diags {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(d, p)
		}
		if all {
			return true
		}
	}
	return false
}

func TestALevelZeroTableListsItsEntriesInValueOrder(t *testing.T) {
	f := newS66Fixture(true)
	f.objectType(7, "Event")
	f.objectType(9, "Semaphore")
	leaf := f.leaf(0)
	a, b := uint64(fxObjects+0x1230), uint64(fxObjects+0x5670)
	f.object(a, 7)
	f.object(b, 9)
	f.entry(leaf, 1, a, 0x1f0003)
	f.entry(leaf, 3, b, 0x20019|1<<25)
	p := f.handleTable(fxEprocess, fxTable, leaf, 1024)
	rows, err := f.walk(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []Handle{
		{PID: 4, ProcessName: "System", HandleValue: 4, Object: a, GrantedAccess: 0x1f0003, TypeIndex: 7, TypeName: "Event"},
		{PID: 4, ProcessName: "System", HandleValue: 12, Object: b, GrantedAccess: 0x20019, TypeIndex: 9, TypeName: "Semaphore"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d %+v, want %+v", i, rows[i], want[i])
		}
	}
}

func TestThePagesFirstEntryIsNeverAHandle(t *testing.T) {
	f := newS66Fixture(true)
	f.objectType(7, "Event")
	leaf := f.leaf(0)
	f.object(fxObjects, 7)
	f.mem.write(leaf, encodeEntry(fxObjects, 1)[:8])
	rows, err := f.walk(f.handleTable(fxEprocess, fxTable, leaf, 1024))
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
}

func TestALevelOneTableNumbersEachPageFromItsPlace(t *testing.T) {
	f := newS66Fixture(true)
	f.objectType(7, "Event")
	top := f.newPage()
	first, second := f.leaf(0), f.leaf(2048)
	f.mem.u64(top, first)
	f.mem.u64(top+16, second)
	f.mem.u64(top+24, f.leaf(3072))
	f.object(fxObjects, 7)
	f.entry(first, 255, fxObjects, 1)
	f.entry(second, 1, fxObjects, 2)
	rows, err := f.walk(f.handleTable(fxEprocess, fxTable, top|1, 3072))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].HandleValue != 1020 || rows[1].HandleValue != 2052 {
		t.Fatalf("rows %+v", rows)
	}
	if !f.said("1 page pointers at or past NextHandleNeedingPool 0xc00 are not followed") {
		t.Errorf("no ceiling diagnostic: %q", f.diags)
	}
}

func TestALevelTwoTableSpansAPointerPagePerMiddlePage(t *testing.T) {
	f := newS66Fixture(true)
	f.objectType(7, "Event")
	top, middle := f.newPage(), f.newPage()
	span := uint64(512 * 1024)
	leaf := f.leaf(span + 1024)
	f.mem.u64(top+8, middle)
	f.mem.u64(middle+8, leaf)
	f.object(fxObjects, 7)
	f.entry(leaf, 2, fxObjects, 1)
	rows, err := f.walk(f.handleTable(fxEprocess, fxTable, top|2, uint32(span+2048)))
	if err != nil || len(rows) != 1 || rows[0].HandleValue != span+1024+8 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
}

func TestATableCodeThatCannotBeATableIsRefused(t *testing.T) {
	for _, c := range []struct {
		code uint64
		want string
	}{
		{fxPages | 3, errTableLevel.Error()},
		{fxPages | 0x808, errTableCodeMisplace.Error()},
	} {
		f := newS66Fixture(true)
		f.opts["strict"] = true
		rows, err := f.walk(f.handleTable(fxEprocess, fxTable, c.code, 1024))
		if len(rows) != 0 || !errors.Is(err, ErrTableIncomplete) || !f.said("handle table of process 4", c.want) {
			t.Errorf("code 0x%x: rows %d, err %v, diagnostics %q", c.code, len(rows), err, f.diags)
		}
	}
}

func TestANullObjectTableHasNoHandlesAndNoComplaint(t *testing.T) {
	f := newS66Fixture(true)
	f.opts["strict"] = true
	rows, err := f.walk(f.handleTable(fxEprocess, 0, 0, 0))
	if err != nil || len(rows) != 0 || len(f.diags) != 0 {
		t.Fatalf("rows %+v, err %v, diagnostics %q", rows, err, f.diags)
	}
}

func TestAPageThatDoesNotReadOrIsMisplacedCostsItsEntriesOnly(t *testing.T) {
	f := newS66Fixture(true)
	f.objectType(7, "Event")
	top := f.newPage()
	good, wrong := f.leaf(0), f.leaf(0)
	f.mem.u64(top, good)
	f.mem.u64(top+8, 0xffff9000deadb000)
	f.mem.u64(top+16, wrong)
	f.object(fxObjects, 7)
	f.entry(good, 1, fxObjects, 1)
	f.entry(wrong, 1, fxObjects, 1)
	rows, err := f.walk(f.handleTable(fxEprocess, fxTable, top|1, 3072))
	if err != nil || len(rows) != 1 || rows[0].HandleValue != 4 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
	if !f.said("1 of 3 entry pages and 0 of 1 pointer pages do not read") ||
		!f.said("1 of 3 entry pages do not start at the handle value of their place", "want 0x800") {
		t.Errorf("diagnostics %q", f.diags)
	}
}

func TestWithoutAUsableNextHandleNeedingPoolTheLimitBoundsTheWalk(t *testing.T) {
	f := newS66Fixture(true)
	f.objectType(7, "Event")
	f.opts = map[string]any{"diagnostics": &f.diags}
	leaf := f.leaf(0)
	f.object(fxObjects, 7)
	for i := 1; i < 8; i++ {
		f.entry(leaf, i, fxObjects, 1)
	}
	ctx := f.ctx()
	ctx.Limits = limits.Limits{MaxTableEntries: 4}
	w, err := NewWalker(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows := w.Process(f.handleTable(fxEprocess, fxTable, leaf, 1000))
	w.Finish()
	if len(rows) != 3 || !f.said("stopped at MaxTableEntries (4), its rows may be a prefix") {
		t.Fatalf("rows %d, diagnostics %q", len(rows), f.diags)
	}
}

func TestAnObjectWhoseTypeDoesNotResolveIsListedWithoutTypeOrName(t *testing.T) {
	f := newS66Fixture(true)
	f.objectType(7, "Event")
	f.mem.write(fxTypes+fxTypeSlot, []byte{8})
	f.objectType(9, "Key")
	leaf := f.leaf(0)
	f.object(fxObjects, 7)
	f.object(fxObjects+0x1000, 5)
	f.entry(leaf, 1, fxObjects, 1)
	f.entry(leaf, 2, fxObjects+0x1000, 1)
	f.entry(leaf, 3, 0xffffa000ffff0000, 1)
	rows, err := f.walk(f.handleTable(fxEprocess, fxTable, leaf, 1024))
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
	for _, r := range rows {
		if r.TypeName != "" || !r.NameUnreadable {
			t.Errorf("row %+v has a type or a name", r)
		}
	}
	if rows[0].TypeIndex != 7 || rows[2].TypeIndex != 0 {
		t.Errorf("type indexes %d, %d", rows[0].TypeIndex, rows[2].TypeIndex)
	}
	if !f.said("3 handles hold an object header whose type does not resolve") {
		t.Errorf("diagnostics %q", f.diags)
	}
}

func TestWithoutObHeaderCookieTheStoredByteIsTheSlot(t *testing.T) {
	f := newS66Fixture(false)
	f.objectType(7, "Event")
	leaf := f.leaf(0)
	f.object(fxObjects+0x4200, 7)
	f.entry(leaf, 1, fxObjects+0x4200, 1)
	rows, err := f.walk(f.handleTable(fxEprocess, fxTable, leaf, 1024))
	if err != nil || len(rows) != 1 || rows[0].TypeName != "Event" {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
}

func TestTheHeaderAddressIsTheStoredBitsInCanonicalForm(t *testing.T) {
	f := newS66Fixture(true)
	l, err := readEntryLayout(f.table)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []uint64{0xffffa00012345670, 0xffff800000000010, 0x00007fff00000000} {
		e, ok := l.decode(encodeEntry(header, 0x3fffffff))
		if !ok || e.header != header || e.access != 0x1ffffff {
			t.Errorf("header 0x%x: decoded %+v, %v", header, e, ok)
		}
	}
	if _, ok := l.decode(make([]byte, fxEntrySize)); ok {
		t.Error("an empty entry is in use")
	}
}

func TestATableTheSymbolsDoNotDescribeIsRefused(t *testing.T) {
	for _, drop := range []string{"ObjectTable", "TableCode", "ObjectPointerBits", "GrantedAccessBits", "bitless"} {
		f := newS66Fixture(true)
		switch drop {
		case "ObjectTable":
			f.table.AddStruct(mustStruct(t, f, "_EPROCESS", drop, false))
		case "TableCode":
			f.table.AddStruct(mustStruct(t, f, "_HANDLE_TABLE", drop, false))
		case "bitless":
			f.table.AddStruct(mustStruct(t, f, "_HANDLE_TABLE_ENTRY", "ObjectPointerBits", true))
		default:
			f.table.AddStruct(mustStruct(t, f, "_HANDLE_TABLE_ENTRY", drop, false))
		}
		if _, err := NewWalker(f.ctx()); !errors.Is(err, ErrNoHandleLayout) {
			t.Errorf("%s: %v", drop, err)
		}
	}
}

func mustStruct(t *testing.T, f *s66Fixture, typ, member string, clearBits bool) symbols.StructType {
	t.Helper()
	st, err := f.table.Struct(typ)
	if err != nil {
		t.Fatal(err)
	}
	kept := st.Fields[:0:0]
	for _, m := range st.Fields {
		switch {
		case m.Name != member:
			kept = append(kept, m)
		case clearBits:
			m.Type.BitOffset, m.Type.BitLength = 0, 0
			kept = append(kept, m)
		}
	}
	st.Fields = kept
	return st
}

func TestOnlyAWindowsProfileIsListed(t *testing.T) {
	f := newS66Fixture(true)
	ctx := f.ctx()
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); !errors.Is(err, ErrNotWindows) {
		t.Errorf("Run: %v", err)
	}
	if _, err := RunAny(ctx); !errors.Is(err, ErrNotWindows) {
		t.Errorf("RunAny: %v", err)
	}
}

func TestAStringKeepsItsEmbeddedNULVisible(t *testing.T) {
	f := newS66Fixture(true)
	f.mem.text(fxStrings-0x100, "a\x00b")
	got, err := readUnicodeStringAt(f.ctx(), fxStrings-0x100)
	if err != nil || got != "a␀b" {
		t.Fatalf("%q, %v", got, err)
	}
}

func TestTheToolIsRegisteredUnderItsName(t *testing.T) {
	p, err := tools.Get(Name)
	if err != nil || p.Spec.Name != "windows.handle.list" {
		t.Fatalf("%+v, %v", p, err)
	}
}
