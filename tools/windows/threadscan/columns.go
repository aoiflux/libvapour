package threadscan

import (
	"fmt"
	"time"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

type Columns struct {
	StartAddress                uint64
	StartAddressUnreadable      bool
	StartAddressInvalid         bool
	StartPath                   string
	Win32StartAddress           uint64
	Win32StartAddressUnreadable bool
	Win32StartPath              string
	CreateTime                  time.Time
	CreateTimeUnreadable        bool
	ExitTime                    time.Time
	ExitTimeUnreadable          bool
	Process                     uint64
	ProcessUnreadable           bool
}

// Member holds one _ETHREAD or _KTHREAD member at its width. A table that
// declares no width (a hand-built one) is read at the width S50 T1, T3 and T5
// measured for the member.
type Member struct {
	Field   symbols.IntField
	Present bool
}

func (m Member) Read(r memory.MemoryReader, ethread uint64) (uint64, error) {
	if !m.Present {
		return 0, fmt.Errorf("threadscan: member not in the symbol table")
	}
	return m.Field.Read(r, ethread)
}

func (m Member) Signed(v uint64) int64 {
	if m.Field.Width == 0 || m.Field.Width >= 8 {
		return int64(v)
	}
	shift := 64 - 8*m.Field.Width
	return int64(v<<shift) >> shift
}

func ResolveMember(t symbols.SymbolTable, typeName, fieldName string, width uint64) Member {
	if t == nil {
		return Member{}
	}
	f, err := t.Field(typeName, fieldName)
	if err != nil {
		return Member{}
	}
	m, err := symbols.ResolveIntField(t, typeName, fieldName)
	if err != nil {
		m = symbols.IntField{Offset: f.Offset, Width: width, BitOffset: f.Type.BitOffset, BitLength: f.Type.BitLength}
	}
	if typeName == "_KTHREAD" {
		m.Offset += TcbOffset(t)
	}
	return Member{Field: m, Present: true}
}

// _ETHREAD.Tcb is at 0 on every measured build (S50 T1).
func TcbOffset(t symbols.SymbolTable) uint64 {
	if f, err := t.Field("_ETHREAD", "Tcb"); err == nil {
		return f.Offset
	}
	return 0
}

type columnMembers struct {
	start, startInvalid, win32 Member
	created, exited, process   Member
}

func resolveColumnMembers(t symbols.SymbolTable) columnMembers {
	pointer := uint64(0)
	if t != nil {
		pointer = uint64(t.PointerSize())
	}
	return columnMembers{
		start:        ResolveMember(t, "_ETHREAD", "StartAddress", pointer),
		startInvalid: ResolveMember(t, "_ETHREAD", "StartAddressInvalid", 1),
		win32:        ResolveMember(t, "_ETHREAD", "Win32StartAddress", pointer),
		created:      ResolveMember(t, "_ETHREAD", "CreateTime", 8),
		exited:       ResolveMember(t, "_ETHREAD", "ExitTime", 8),
		process:      ResolveMember(t, "_KTHREAD", "Process", pointer),
	}
}

type ColumnReader struct {
	tool    string
	members columnMembers
	owners  *owners
}

func NewColumnReader(ctx tools.Context, tool string) *ColumnReader {
	return &ColumnReader{tool: tool, members: resolveColumnMembers(ctx.Symbols), owners: newOwners(tool)}
}

// The thread list has its processes already; a scan finds owners by address.
func (r *ColumnReader) KnowProcesses(procs []processlist.Process) {
	for _, p := range procs {
		r.owners.known[p.EPROCESS] = p
	}
}

func (r *ColumnReader) ReportAbsent(ctx tools.Context) {
	m := r.members
	for _, c := range []struct {
		member Member
		name   string
		column string
	}{
		{m.start, "_ETHREAD.StartAddress", "StartAddress"},
		{m.win32, "_ETHREAD.Win32StartAddress", "Win32StartAddress"},
		{m.created, "_ETHREAD.CreateTime", "CreateTime"},
		{m.exited, "_ETHREAD.ExitTime", "ExitTime"},
		{m.process, "_KTHREAD.Process", "Process"},
	} {
		if !c.member.Present {
			ctx.AddDiagnostic("%s: symbol table has no %s: %s unreadable on every thread", r.tool, c.name, c.column)
		}
	}
}

func (r *ColumnReader) Read(object memory.MemoryReader, ethread uint64) Columns {
	m := r.members
	var c Columns
	c.StartAddress, c.StartAddressUnreadable = readPointer(m.start, object, ethread)
	if !c.StartAddressUnreadable && m.startInvalid.Present {
		if v, err := m.startInvalid.Read(object, ethread); err == nil && v != 0 {
			c.StartAddress, c.StartAddressInvalid = 0, true
		}
	}
	c.Win32StartAddress, c.Win32StartAddressUnreadable = readPointer(m.win32, object, ethread)
	c.CreateTime, c.CreateTimeUnreadable = readTime(m.created, object, ethread)
	c.ExitTime, c.ExitTimeUnreadable = readTime(m.exited, object, ethread)
	c.Process, c.ProcessUnreadable = readPointer(m.process, object, ethread)
	return c
}

func readPointer(m Member, object memory.MemoryReader, ethread uint64) (uint64, bool) {
	v, err := m.Read(object, ethread)
	if err != nil {
		return 0, true
	}
	return v, false
}

// A value with bit 63 set is no FILETIME (S50 D4). For ExitTime it is the
// KeyedWaitChain that shares the storage until the thread exits (S50 T2, M4).
func readTime(m Member, object memory.MemoryReader, ethread uint64) (time.Time, bool) {
	v, err := m.Read(object, ethread)
	if err != nil {
		return time.Time{}, true
	}
	t, _ := util.FiletimeToTime(v)
	return t, false
}

func (r *ColumnReader) AddPaths(ctx tools.Context, c *Columns) {
	if !c.StartAddressUnreadable {
		c.StartPath = r.owners.path(ctx, c.Process, c.ProcessUnreadable, c.StartAddress)
	}
	if !c.Win32StartAddressUnreadable {
		c.Win32StartPath = r.owners.path(ctx, c.Process, c.ProcessUnreadable, c.Win32StartAddress)
	}
}

func (r *ColumnReader) Unread(c Columns) string {
	m := r.members
	for _, col := range []struct {
		present, unread bool
		name            string
	}{
		{m.start.Present, c.StartAddressUnreadable, "StartAddress"},
		{m.win32.Present, c.Win32StartAddressUnreadable, "Win32StartAddress"},
		{m.created.Present, c.CreateTimeUnreadable, "CreateTime"},
		{m.exited.Present, c.ExitTimeUnreadable, "ExitTime"},
		{m.process.Present, c.ProcessUnreadable, "Process"},
	} {
		if col.present && col.unread {
			return col.name
		}
	}
	return ""
}

func (r *ColumnReader) unreadError(pid, tid, ethread uint64, column string) error {
	return fmt.Errorf("%s: pid %d tid %d _ETHREAD at 0x%x: %s does not read", r.tool, pid, tid, ethread, column)
}

func (r *ColumnReader) ReportUnread(ctx tools.Context, pid, tid, ethread uint64, c Columns) error {
	column := r.Unread(c)
	if column == "" {
		return nil
	}
	err := r.unreadError(pid, tid, ethread, column)
	if ctx.StrictMode() {
		return err
	}
	ctx.AddDiagnostic("%v, kept", err)
	return nil
}

func (r *ColumnReader) KeepListed(ctx tools.Context, pid, tid, ethread uint64, c Columns) (bool, error) {
	column := r.Unread(c)
	if column == "" {
		return true, nil
	}
	err := r.unreadError(pid, tid, ethread, column)
	if ctx.StrictMode() {
		return false, err
	}
	ctx.AddDiagnostic("%v, skipped", err)
	return false, nil
}
