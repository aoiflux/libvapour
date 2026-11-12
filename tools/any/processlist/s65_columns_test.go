package processlist

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	s65HandleTable = uint64(0xffff9e0400100000)
	s65HandleCount = uint64(0x48)
)

func s65ColumnContext(t *testing.T, omit ...string) (tools.Context, s25Image, *[]string) {
	t.Helper()
	p := running(1300, "svchost.exe")
	p.parent = 812
	p.threads = 9
	p.exited = 0
	im := newS25Image(p)
	at := s25At(0)
	im.mem.put64(at+s25ObjTable, s65HandleTable)
	im.mem.put(s65HandleTable+s65HandleCount, []byte{0x2a, 0, 0, 0})
	im.mem.put64(at+s25Wow64, 0xffff9e0400200000)
	ctx, diags := im.ctx(nil, omit...)
	table := ctx.Symbols.(*symbols.Table)
	if !contains(omit, "_HANDLE_TABLE.HandleCount") {
		table.AddStruct(symbols.StructType{Name: "_HANDLE_TABLE", Size: 0x80, Fields: []symbols.Field{
			{Name: "HandleCount", Offset: s65HandleCount, Type: symbols.TypeRef{Name: "long"}},
		}})
	}
	return ctx, im, diags
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestEachColumnComesFromItsMember(t *testing.T) {
	ctx, im, _ := s65ColumnContext(t)
	c := NewColumnReader(ctx).Read(ctx, ctx.Memory, s25At(0))
	created, _ := time.Parse(time.RFC3339, "2026-05-06T08:00:01Z")
	want := Columns{PPID: 812, Threads: 9, Handles: 42, SessionID: 1, Wow64: true, CreateTime: created}
	if c != want {
		t.Errorf("columns %+v, want %+v", c, want)
	}
	if !c.ExitTime.IsZero() || c.ExitTimeUnreadable {
		t.Errorf("an ExitTime of 0 is the zero time and read: %v %v", c.ExitTime, c.ExitTimeUnreadable)
	}
	im.mem.put64(s25At(0)+s25Exited, checkFileTime(created.Add(time.Hour)))
	if c := NewColumnReader(ctx).Read(ctx, ctx.Memory, s25At(0)); !c.ExitTime.Equal(created.Add(time.Hour)) {
		t.Errorf("exit time %v", c.ExitTime)
	}
}

func TestTheHandleCountNeedsItsTypeAndATable(t *testing.T) {
	ctx, im, _ := s65ColumnContext(t, "_HANDLE_TABLE.HandleCount")
	if c := NewColumnReader(ctx).Read(ctx, ctx.Memory, s25At(0)); !c.HandlesUnreadable || c.Handles != 0 {
		t.Errorf("untyped handle count read: %+v", c)
	}
	ctx, im, _ = s65ColumnContext(t)
	im.mem.put64(s25At(0)+s25ObjTable, 0)
	if c := NewColumnReader(ctx).Read(ctx, ctx.Memory, s25At(0)); !c.HandlesUnreadable {
		t.Errorf("null handle table read: %+v", c)
	}
	ctx, im, _ = s65ColumnContext(t)
	im.mem.put(s65HandleTable+s65HandleCount, []byte{0xff, 0xff, 0xff, 0xff})
	if c := NewColumnReader(ctx).Read(ctx, ctx.Memory, s25At(0)); c.Handles != -1 {
		t.Errorf("handle count %d, want the sign-extended -1", c.Handles)
	}
}

func TestTheObjectReaderHoldsTheProcessAndKernelMemoryTheRest(t *testing.T) {
	ctx, im, _ := s65ColumnContext(t)
	body := ckMemory{}
	raw, _ := im.mem.ReadAt(s25At(0), 0x840)
	const physical = uint64(0x7d4f080)
	body.put(physical, raw)
	c := NewColumnReader(ctx).Read(ctx, body, physical)
	if c.PPID != 812 || c.Handles != 42 || c.SessionID != 1 || c.HandlesUnreadable {
		t.Errorf("columns from a physical body: %+v", c)
	}
}

func TestTheOlderSpellingOfTheWow64MemberIsRead(t *testing.T) {
	ctx, im, _ := s65ColumnContext(t, "_EPROCESS.WoW64Process")
	table := ctx.Symbols.(*symbols.Table)
	table.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x840, Fields: append(eprocessFields(table),
		symbols.Field{Name: "Wow64Process", Offset: 0x700})})
	im.mem.put64(s25At(0)+0x700, 1)
	if c := NewColumnReader(ctx).Read(ctx, ctx.Memory, s25At(0)); !c.Wow64 || c.Wow64Unreadable {
		t.Errorf("Wow64Process not read: %+v", c)
	}
}

func eprocessFields(table *symbols.Table) []symbols.Field {
	st, _ := table.Struct("_EPROCESS")
	return st.Fields
}

func TestAnAbsentMemberIsReportedOnceAndMakesItsColumnUnreadable(t *testing.T) {
	ctx, _, diags := s65ColumnContext(t, "_EPROCESS.ActiveThreads", "_EPROCESS.CreateTime", "_EPROCESS.WoW64Process")
	r := NewColumnReader(ctx)
	r.ReportAbsent(ctx, "test")
	for _, want := range []string{
		"test: symbol table has no _EPROCESS.ActiveThreads: Threads unreadable for every process",
		"test: symbol table has no _EPROCESS.CreateTime: CreateTime unreadable for every process",
	} {
		if !saidSo(*diags, want) {
			t.Errorf("missing %q in %q", want, *diags)
		}
	}
	if len(*diags) != 2 {
		t.Errorf("diagnostics %q, want two", *diags)
	}
	c := r.Read(ctx, ctx.Memory, s25At(0))
	if !c.ThreadsUnreadable || !c.CreateTimeUnreadable || !c.Wow64Unreadable {
		t.Errorf("absent members read: %+v", c)
	}
	if err := r.ReportUnread(ctx, "test", 1300, "svchost.exe", s25At(0), c); err != nil || saidSo(*diags, "kept") {
		t.Errorf("an absent member is reported as unread: %v %q", err, *diags)
	}
}

func TestAnUnreadColumnKeepsTheRowAndFailsStrictMode(t *testing.T) {
	ctx, im, diags := s65ColumnContext(t)
	ctx.Memory = gapReader{MemoryReader: im.mem, gaps: []uint64{s25At(0) + s25Parent, s25At(0) + s25Created}}
	r := NewColumnReader(ctx)
	c := r.Read(ctx, ctx.Memory, s25At(0))
	if !c.PPIDUnreadable || !c.CreateTimeUnreadable || c.ThreadsUnreadable {
		t.Fatalf("columns %+v", c)
	}
	if err := r.ReportUnread(ctx, "test", 1300, "svchost.exe", s25At(0), c); err != nil {
		t.Fatal(err)
	}
	want := "test: _EPROCESS at 0xffff9e03f66a0040: pid 1300 svchost.exe: PPID, CreateTime do not read, kept"
	if !saidSo(*diags, want) {
		t.Errorf("diagnostics %q, want %q", *diags, want)
	}
	ctx.Options["strict"] = true
	err := r.ReportUnread(ctx, "test", 1300, "svchost.exe", s25At(0), c)
	if !errors.Is(err, ErrColumnUnread) || !strings.Contains(err.Error(), "PPID, CreateTime") {
		t.Errorf("strict: %v", err)
	}
	if err := r.ReportUnread(ctx, "test", 1300, "svchost.exe", s25At(0), Columns{}); err != nil {
		t.Errorf("nothing unread: %v", err)
	}
}

func TestAHoleInPagedMemoryMakesItsColumnUnreadable(t *testing.T) {
	ctx, im, _ := s65ColumnContext(t)
	raw, _ := im.mem.ReadAt(s25At(0), 0x840)
	pm := testsupport.NewPagedMemory(0x10000)
	pm.WriteAt(0x1000, raw)
	body := holeMemory{PagedMemory: pm, holes: []uint64{0x1000 + s25Threads}}
	c := NewColumnReader(ctx).Read(ctx, body, 0x1000)
	if !c.ThreadsUnreadable || c.PPIDUnreadable || c.PPID != 812 {
		t.Errorf("columns %+v", c)
	}
}
