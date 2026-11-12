package processlist

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/util"
)

var ErrColumnUnread = errors.New("processlist: process column does not read")

type Columns struct {
	PPID                 uint64
	PPIDUnreadable       bool
	Threads              uint32
	ThreadsUnreadable    bool
	Handles              int64
	HandlesUnreadable    bool
	CreateTime           time.Time
	CreateTimeUnreadable bool
	ExitTime             time.Time
	ExitTimeUnreadable   bool
	SessionID            int64
	Wow64                bool
	Wow64Unreadable      bool
}

type columnMembers struct {
	parent      optionalField
	threads     optionalField
	handleTable optionalField
	handleCount optionalField
	wow64       optionalField
	created     optionalField
	exited      optionalField
}

type ColumnReader struct {
	members  columnMembers
	sessions *SessionResolver
}

func NewColumnReader(ctx tools.Context) *ColumnReader {
	wow64 := lookupOptionalField(ctx, "_EPROCESS", "WoW64Process")
	if !wow64.present {
		wow64 = lookupOptionalField(ctx, "_EPROCESS", "Wow64Process")
	}
	return &ColumnReader{
		members: columnMembers{
			parent:      lookupOptionalField(ctx, "_EPROCESS", "InheritedFromUniqueProcessId"),
			threads:     lookupOptionalField(ctx, "_EPROCESS", "ActiveThreads"),
			handleTable: lookupOptionalField(ctx, "_EPROCESS", "ObjectTable"),
			handleCount: lookupOptionalField(ctx, "_HANDLE_TABLE", "HandleCount"),
			wow64:       wow64,
			created:     lookupOptionalField(ctx, "_EPROCESS", "CreateTime"),
			exited:      lookupOptionalField(ctx, "_EPROCESS", "ExitTime"),
		},
		sessions: NewSessionResolver(ctx),
	}
}

// object holds the _EPROCESS, which a scan may read from physical memory; what
// it points to is always kernel memory.
func (r *ColumnReader) Read(ctx tools.Context, object memory.MemoryReader, eprocess uint64) Columns {
	m := r.members
	var c Columns
	c.PPID, c.PPIDUnreadable = readMember(m.parent, func(at uint64) (uint64, error) {
		return ctx.Symbols.ReadPointer(object, eprocess+at)
	})
	threads, unread := readMember(m.threads, func(at uint64) (uint64, error) {
		v, err := ctx.Symbols.ReadUint32(object, eprocess+at)
		return uint64(v), err
	})
	c.Threads, c.ThreadsUnreadable = uint32(threads), unread
	c.Handles, c.HandlesUnreadable = r.handleCount(ctx, object, eprocess)
	c.SessionID = r.sessions.SessionIDIn(ctx, object, eprocess)
	wow64, unread := readMember(m.wow64, func(at uint64) (uint64, error) {
		return ctx.Symbols.ReadPointer(object, eprocess+at)
	})
	c.Wow64, c.Wow64Unreadable = wow64 != 0, unread
	c.CreateTime, c.CreateTimeUnreadable = readFiletime(ctx, object, eprocess, m.created)
	c.ExitTime, c.ExitTimeUnreadable = readFiletime(ctx, object, eprocess, m.exited)
	return c
}

func readMember(f optionalField, read func(offset uint64) (uint64, error)) (uint64, bool) {
	if !f.present {
		return 0, true
	}
	v, err := read(f.offset)
	if err != nil {
		return 0, true
	}
	return v, false
}

func (r *ColumnReader) handleCount(ctx tools.Context, object memory.MemoryReader, eprocess uint64) (int64, bool) {
	if !r.members.handleTable.present || !r.members.handleCount.present {
		return 0, true
	}
	table, err := ctx.Symbols.ReadPointer(object, eprocess+r.members.handleTable.offset)
	if err != nil || table == 0 {
		return 0, true
	}
	n, err := ctx.Symbols.ReadUint32(ctx.Memory, table+r.members.handleCount.offset)
	if err != nil {
		return 0, true
	}
	return int64(int32(n)), false
}

// A zero FILETIME is a read value, the zero time: ExitTime is 0 until exit.
func readFiletime(ctx tools.Context, object memory.MemoryReader, eprocess uint64, f optionalField) (time.Time, bool) {
	if !f.present {
		return time.Time{}, true
	}
	raw, err := ctx.Symbols.ReadUint64(object, eprocess+f.offset)
	if err != nil {
		return time.Time{}, true
	}
	t, _ := util.FiletimeToTime(raw)
	return t, false
}

type reportedColumn struct {
	field  optionalField
	member string
	column string
}

func (r *ColumnReader) reported() []reportedColumn {
	m := r.members
	return []reportedColumn{
		{m.parent, "InheritedFromUniqueProcessId", "PPID"},
		{m.threads, "ActiveThreads", "Threads"},
		{m.wow64, "WoW64Process", "Wow64"},
		{m.created, "CreateTime", "CreateTime"},
		{m.exited, "ExitTime", "ExitTime"},
	}
}

func (r *ColumnReader) ReportAbsent(ctx tools.Context, tool string) {
	for _, col := range r.reported() {
		if !col.field.present && col.column != "Wow64" {
			ctx.AddDiagnostic("%s: symbol table has no _EPROCESS.%s: %s unreadable for every process", tool, col.member, col.column)
		}
	}
}

func (r *ColumnReader) unread(c Columns) []string {
	flags := map[string]bool{"PPID": c.PPIDUnreadable, "Threads": c.ThreadsUnreadable, "Wow64": c.Wow64Unreadable,
		"CreateTime": c.CreateTimeUnreadable, "ExitTime": c.ExitTimeUnreadable}
	var out []string
	for _, col := range r.reported() {
		if col.field.present && flags[col.column] {
			out = append(out, col.column)
		}
	}
	return out
}

func (r *ColumnReader) ReportUnread(ctx tools.Context, tool string, pid uint64, name string, eprocess uint64, c Columns) error {
	cols := r.unread(c)
	if len(cols) == 0 {
		return nil
	}
	list := strings.Join(cols, ", ")
	if ctx.StrictMode() {
		return fmt.Errorf("%s: _EPROCESS at 0x%x: pid %d: %w: %s", tool, eprocess, pid, ErrColumnUnread, list)
	}
	verb := "does"
	if len(cols) > 1 {
		verb = "do"
	}
	ctx.AddDiagnostic("%s: _EPROCESS at 0x%x: pid %d %s: %s %s not read, kept", tool, eprocess, pid, name, list, verb)
	return nil
}
