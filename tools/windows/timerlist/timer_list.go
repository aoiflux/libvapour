package timerlist

import (
	"errors"
	"fmt"
	"math/bits"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/cpulist"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

const Name = "windows.timer.list"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List each processor's kernel timers that queue a deferred procedure call, and the module holding its routine",
		},
		RunAny,
	)
}

var (
	ErrNoTimerTable = errors.New("timerlist: symbol table has no _KPRCB.TimerTable, _KTIMER_TABLE.TimerEntries or _KTIMER_TABLE_ENTRY.Entry")
	ErrNoTimerType  = errors.New("timerlist: symbol table has no _KTIMER member needed")
	ErrNoDpcType    = errors.New("timerlist: symbol table has no _KDPC.Type or _KDPC.DeferredRoutine")
)

// _KOBJECTS values in every measured table, used when a table has no enum.
const (
	timerNotification    = 8
	timerSynchronization = 9
	dpcObject            = 19
	threadedDpcObject    = 26
)

type Entry struct {
	Processor        int
	Offset           uint64
	DueTime          uint64
	Period           uint32
	Signaled         bool
	Dpc              uint64
	Routine          uint64
	Module           string
	ModuleUnreadable bool
	Unowned          bool
	Symbol           string
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

type layout struct {
	table, entries, entrySize, entryList uint64
	buckets                              uint64
	header, links, due, period, dpc      uint64
	signal, dpcType, routine             uint64
	timerTypes                           [2]int64
	dpcTypes                             [2]int64
}

func resolve(t symbols.SymbolTable) (layout, error) {
	var l layout
	tableField, err := t.Field("_KPRCB", "TimerTable")
	if err != nil {
		return l, ErrNoTimerTable
	}
	entries, err := t.Field("_KTIMER_TABLE", "TimerEntries")
	if err != nil {
		return l, ErrNoTimerTable
	}
	l.table, l.entries = tableField.Offset, entries.Offset
	l.buckets = 1
	ref := &entries.Type
	for ; ref != nil && ref.IsArray; ref = ref.Element {
		l.buckets *= ref.ArrayLength
	}
	if ref == nil || l.buckets == 0 || entries.Type.ArrayLength == 0 {
		return l, ErrNoTimerTable
	}
	st, err := t.Struct(ref.Name)
	if err != nil || st.Size == 0 {
		return l, ErrNoTimerTable
	}
	l.entrySize = st.Size
	list, err := t.Field(ref.Name, "Entry")
	if err != nil {
		return l, ErrNoTimerTable
	}
	l.entryList = list.Offset
	for _, m := range []struct {
		typ, member string
		at          *uint64
		err         error
	}{
		{"_KTIMER", "Header", &l.header, ErrNoTimerType},
		{"_KTIMER", "TimerListEntry", &l.links, ErrNoTimerType},
		{"_KTIMER", "DueTime", &l.due, ErrNoTimerType},
		{"_KTIMER", "Period", &l.period, ErrNoTimerType},
		{"_KTIMER", "Dpc", &l.dpc, ErrNoTimerType},
		{"_DISPATCHER_HEADER", "SignalState", &l.signal, ErrNoTimerType},
		{"_KDPC", "Type", &l.dpcType, ErrNoDpcType},
		{"_KDPC", "DeferredRoutine", &l.routine, ErrNoDpcType},
	} {
		f, ferr := t.Field(m.typ, m.member)
		if ferr != nil {
			return l, fmt.Errorf("%s.%s: %w", m.typ, m.member, m.err)
		}
		*m.at = f.Offset
	}
	l.timerTypes = [2]int64{enumOr(t, "TimerNotificationObject", timerNotification),
		enumOr(t, "TimerSynchronizationObject", timerSynchronization)}
	l.dpcTypes = [2]int64{enumOr(t, "DpcObject", dpcObject), enumOr(t, "ThreadedDpcObject", threadedDpcObject)}
	return l, nil
}

func enumOr(t symbols.SymbolTable, value string, fallback int64) int64 {
	if det, ok := t.(symbols.DeterministicLookup); ok {
		if v, err := det.EnumValue("_KOBJECTS", value); err == nil {
			return v
		}
	}
	return fallback
}

type counts struct {
	buckets, unreadHeads, broken, backward, entries, repeated    int
	notTimer, unread, noDpc, notDpc, unowned, damage, misaligned int
}

func Run(ctx tools.Context) ([]Entry, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	t := ctx.Symbols
	l, err := resolve(t)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	listLayout, err := winkernel.NativeListLayout(t)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	processors, err := cpulist.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: processors: %w", Name, err)
	}
	mods, err := modulelist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: loaded modules: %w", Name, err)
		}
		ctx.AddDiagnostic("%s: loaded modules not read, so no routine has an owner: %v", Name, err)
	}
	owners := modulelist.NewAttributor(ctx, modulelist.Placed(ctx, Name, mods))
	if !owners.SymbolModuleKnown() {
		ctx.AddDiagnostic("%s: the kernel image is not among the loaded modules: routines have no symbol names", Name)
	}
	key, keyed := dpcKey(ctx)
	var c counts
	walker := winkernel.ListWalker{Tool: Name, Memory: ctx.Memory, Layout: listLayout, Limit: ctx.Bounds().MaxListEntries,
		Report: func(string, ...any) { c.damage++ }}
	seen := map[uint64]bool{}
	width := uint64(t.PointerSize())
	var out []Entry
	for _, p := range processors {
		base := p.PRCB + l.table + l.entries
		for b := uint64(0); b < l.buckets; b++ {
			head := base + b*l.entrySize + l.entryList
			c.buckets++
			walk, err := walker.WalkRecovering(head, "timer list")
			if err != nil {
				if ctx.StrictMode() {
					return nil, fmt.Errorf("%s: processor %d timer list at 0x%x: %w", Name, p.Index, head, err)
				}
				c.unreadHeads++
				continue
			}
			if walk.Forward != nil {
				c.broken++
			}
			c.backward += walk.Backward
			for _, link := range walk.Entries {
				c.entries++
				// A timer holds pointers and is pointer-aligned; one misaligned
				// link on mem6 reached a DPC in no module (S64 T7).
				if link%width != 0 {
					c.misaligned++
					continue
				}
				timer, ok := winkernel.Container(link, l.links)
				if !ok {
					c.unread++
					continue
				}
				if seen[timer] {
					c.repeated++
					continue
				}
				seen[timer] = true
				e, state := l.decode(ctx, timer, key, keyed)
				switch state {
				case stateNotTimer:
					c.notTimer++
					continue
				case stateUnread:
					c.unread++
					continue
				case stateNoDpc:
					c.noDpc++
					continue
				case stateNotDpc:
					c.notDpc++
					continue
				}
				e.Processor = p.Index
				if at := owners.At(e.Routine); len(at) > 0 {
					e.Module, e.Symbol, e.ModuleUnreadable = at[0].Module, at[0].Symbol, at[0].ModuleUnreadable
				} else {
					e.Unowned = true
					c.unowned++
				}
				out = append(out, e)
			}
		}
	}
	ctx.AddDiagnostic("%s: %d timer lists on %d processors, %d unreadable, %d whose forward walk broke (%d entries found "+
		"through Blink, %d link reports); %d entries, %d reached again, %d misaligned; %d not timers, %d unread, %d without a DPC, "+
		"%d whose DPC is not a DPC object; %d timers listed, %d with a routine in no module",
		Name, c.buckets, len(processors), c.unreadHeads, c.broken, c.backward, c.damage, c.entries, c.repeated, c.misaligned, c.notTimer,
		c.unread, c.noDpc, c.notDpc, len(out), c.unowned)
	return out, nil
}

type state int

const (
	stateRow state = iota
	stateNotTimer
	stateUnread
	stateNoDpc
	stateNotDpc
)

func (l layout) decode(ctx tools.Context, timer uint64, key dpcKeys, keyed bool) (Entry, state) {
	t, m := ctx.Symbols, ctx.Memory
	head, err := m.ReadAt(timer+l.header, 1)
	if err != nil || len(head) != 1 {
		return Entry{}, stateUnread
	}
	if int64(head[0]) != l.timerTypes[0] && int64(head[0]) != l.timerTypes[1] {
		return Entry{}, stateNotTimer
	}
	due, err1 := t.ReadUint64(m, timer+l.due)
	period, err2 := t.ReadUint32(m, timer+l.period)
	signal, err3 := t.ReadUint32(m, timer+l.header+l.signal)
	stored, err4 := t.ReadPointer(m, timer+l.dpc)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return Entry{}, stateUnread
	}
	dpc := stored
	if keyed {
		dpc = key.decode(stored, timer)
	}
	if dpc == 0 {
		return Entry{}, stateNoDpc
	}
	kind, err := m.ReadAt(dpc+l.dpcType, 1)
	if err != nil || len(kind) != 1 || (int64(kind[0]) != l.dpcTypes[0] && int64(kind[0]) != l.dpcTypes[1]) {
		return Entry{}, stateNotDpc
	}
	routine, err := t.ReadPointer(m, dpc+l.routine)
	if err != nil {
		return Entry{}, stateUnread
	}
	return Entry{Offset: timer, DueTime: due, Period: period, Signaled: signal != 0, Dpc: dpc, Routine: routine}, stateRow
}

type dpcKeys struct{ never, always uint64 }

// The kernels of these captures store _KTIMER.Dpc transformed with the
// globals KiWaitNever and KiWaitAlways and the timer's own address; no
// stored value reads as a pointer, and every decoded nonzero value is a
// _KDPC of type DpcObject (S64 T5, T6).
func dpcKey(ctx tools.Context) (dpcKeys, bool) {
	t := ctx.Symbols
	never, err1 := t.LookupSymbol("KiWaitNever")
	always, err2 := t.LookupSymbol("KiWaitAlways")
	if err1 != nil || err2 != nil || t.PointerSize() != 8 {
		return dpcKeys{}, false
	}
	n, err1 := t.ReadUint64(ctx.Memory, never.Address)
	a, err2 := t.ReadUint64(ctx.Memory, always.Address)
	if err1 != nil || err2 != nil {
		ctx.AddDiagnostic("%s: KiWaitNever or KiWaitAlways does not read: DPC pointers are taken as stored", Name)
		return dpcKeys{}, false
	}
	return dpcKeys{never: n, always: a}, true
}

func (k dpcKeys) decode(stored, timer uint64) uint64 {
	v := bits.RotateLeft64(stored^k.never, int(k.never&0xFF))
	return bits.ReverseBytes64(v^timer) ^ k.always
}
