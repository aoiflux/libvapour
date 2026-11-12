package threaddebugregisters

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/threadaddress"
	"github.com/aoiflux/libvapour/tools/windows/threadlist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.thread.check_debug_registers"

var (
	ErrLayout          = errors.New("threaddebugregisters: symbol table lacks a _KTRAP_FRAME member the check needs")
	ErrTrapFrameUnread = errors.New("threaddebugregisters: trap frame does not read")
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name: Name,
			Description: "List threads whose saved user-mode debug registers enable a hardware breakpoint, " +
				"with the range, file and export of each breakpoint address",
		},
		RunAny,
	)
}

type Thread struct {
	PID                   uint64
	Process               string
	TID                   uint64
	ETHREAD               uint64
	State                 string
	TrapFrame             uint64
	Dr7                   uint64
	DebugActive           uint8
	DebugActiveUnreadable bool
	Breakpoints           []Breakpoint
}

type Breakpoint struct {
	Index             int
	Address           uint64
	AddressUnreadable bool
	Local             bool
	Global            bool
	Condition         Condition
	Length            uint64
	RangeType         string
	Path              string
	Export            string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type sources struct {
	threads func(tools.Context) ([]threadlist.Thread, error)
	spaces  func(tools.Context) (*threadaddress.Spaces, error)
}

var defaultSources = sources{threads: threadlist.Run, spaces: threadaddress.New}

func Run(ctx tools.Context) ([]Thread, error) { return run(ctx, defaultSources) }

type registers struct {
	address     [breakpointSlots]symbols.IntField
	control     symbols.IntField
	debugActive symbols.IntField
	haveActive  bool
}

func resolveRegisters(t symbols.SymbolTable) (registers, error) {
	var r registers
	for i := range breakpointSlots {
		f, err := symbols.ResolveIntField(t, "_KTRAP_FRAME", fmt.Sprintf("Dr%d", i))
		if err != nil {
			return registers{}, fmt.Errorf("%w: %w", ErrLayout, err)
		}
		r.address[i] = f
	}
	f, err := symbols.ResolveIntField(t, "_KTRAP_FRAME", "Dr7")
	if err != nil {
		return registers{}, fmt.Errorf("%w: %w", ErrLayout, err)
	}
	r.control = f
	// The shared trap-frame reader needs these too; checking them here makes a
	// table without them fail once, before any thread is read.
	for _, name := range []string{"SegCs", "Rip", "Rsp"} {
		if _, err := symbols.ResolveIntField(t, "_KTRAP_FRAME", name); err != nil {
			return registers{}, fmt.Errorf("%w: %w", ErrLayout, err)
		}
	}
	header, herr := t.Field("_KTHREAD", "Header")
	tcb, terr := t.Field("_ETHREAD", "Tcb")
	if active, err := symbols.ResolveIntField(t, "_DISPATCHER_HEADER", "DebugActive"); err == nil && herr == nil && terr == nil {
		active.Offset += header.Offset + tcb.Offset
		r.debugActive, r.haveActive = active, true
	}
	return r, nil
}

type tally map[string]int

func (t tally) String() string {
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", t[k], k))
	}
	return strings.Join(parts, ", ")
}

func run(ctx tools.Context, src sources) ([]Thread, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	regs, err := resolveRegisters(ctx.Symbols)
	if err != nil {
		return nil, err
	}
	threads, err := src.threads(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: thread list: %w", Name, err)
	}
	seen := tally{}
	p := &placer{src: src}
	var rows []Thread
	for _, th := range threads {
		switch {
		case th.TrapFrameUnreadable:
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: thread %d at 0x%x: %w", Name, th.TID, th.ETHREAD, ErrTrapFrameUnread)
			}
			seen["trap frame pointer unread"]++
			continue
		case th.TrapFrame == 0:
			seen["no trap frame"]++
			continue
		}
		if _, err := threadlist.ReadTrapFrame(ctx, th.TrapFrame); err != nil {
			switch {
			case errors.Is(err, threadlist.ErrKernelModeTrapFrame):
				seen["kernel-mode frame"]++
				continue
			case errors.Is(err, threadlist.ErrTrapFrameLayout):
				return nil, fmt.Errorf("%s: %w: %w", Name, ErrLayout, err)
			case ctx.StrictMode():
				return nil, fmt.Errorf("%s: trap frame at 0x%x: %w: %w", Name, th.TrapFrame, ErrTrapFrameUnread, err)
			}
			seen["trap frame unread"]++
			continue
		}
		dr7, err := regs.control.Read(ctx.Memory, th.TrapFrame)
		if err != nil {
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: trap frame at 0x%x: %w: %w", Name, th.TrapFrame, ErrTrapFrameUnread, err)
			}
			seen["Dr7 unread"]++
			continue
		}
		slots, saved := decodeDebugControl(dr7, regs.control.Width)
		if !saved {
			seen["reserved bits set"]++
			continue
		}
		if len(slots) == 0 {
			seen["no breakpoint enabled"]++
			continue
		}
		seen["breakpoint enabled"]++
		row := Thread{PID: th.PID, Process: util.ReplaceInvalidUTF8(th.ProcessName), TID: th.TID, ETHREAD: th.ETHREAD,
			State: th.StateName, TrapFrame: th.TrapFrame, Dr7: dr7}
		if regs.haveActive {
			v, err := regs.debugActive.Read(ctx.Memory, th.ETHREAD)
			row.DebugActive, row.DebugActiveUnreadable = uint8(v), err != nil
		}
		for _, s := range slots {
			b := Breakpoint{Index: s.index, Local: s.local, Global: s.global, Condition: s.condition, Length: s.length}
			b.Address, err = regs.address[s.index].Read(ctx.Memory, th.TrapFrame)
			b.AddressUnreadable = err != nil
			if !b.AddressUnreadable && !th.ProcessUnreadable {
				p.place(ctx, th.Process, &b)
			}
			row.Breakpoints = append(row.Breakpoints, b)
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].PID != rows[j].PID {
			return rows[i].PID < rows[j].PID
		}
		return rows[i].TID < rows[j].TID
	})
	ctx.AddDiagnostic("%s: %d threads: %s", Name, len(threads), seen)
	p.report(ctx)
	return rows, nil
}

type placer struct {
	src      sources
	spaces   *threadaddress.Spaces
	tried    bool
	failed   map[uint64]bool
	notOwned int
}

func (p *placer) place(ctx tools.Context, owner uint64, b *Breakpoint) {
	if !threadaddress.UserAddress(ctx.Symbols.PointerSize(), b.Address) {
		return
	}
	if !p.tried {
		p.tried, p.failed = true, map[uint64]bool{}
		s, err := p.src.spaces(ctx)
		if err != nil {
			ctx.AddDiagnostic("%s: process ranges not read, breakpoints not placed: %v", Name, err)
		}
		p.spaces = s
	}
	if p.spaces == nil {
		return
	}
	if _, ok := p.spaces.Owner(owner); !ok {
		p.notOwned++
		return
	}
	at, err := p.spaces.Place(ctx, owner, b.Address)
	if err != nil {
		if !p.failed[owner] {
			p.failed[owner] = true
			ctx.AddDiagnostic("%s: process at 0x%x: range walk failed: %v", Name, owner, err)
		}
		return
	}
	b.RangeType, b.Path, b.Export = at.Range.Type, at.Range.Path, at.Export
}

func (p *placer) report(ctx tools.Context) {
	if p.spaces != nil && (p.notOwned > 0 || p.spaces.ExportsUnread > 0) {
		ctx.AddDiagnostic("%s: breakpoints not placed: %d of an owner not listed; %d export tables unread",
			Name, p.notOwned, p.spaces.ExportsUnread)
	}
}
