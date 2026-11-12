package threadsuspended

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/threadaddress"
	"github.com/aoiflux/libvapour/tools/windows/threadlist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.thread.list_suspended"

var ErrSuspendCountUnread = errors.New("threadsuspended: suspend count does not read")

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List threads whose suspend count is above zero, with the file and export each start address lies in",
		},
		RunAny,
	)
}

type Thread struct {
	PID               uint64
	Process           string
	TID               uint64
	ETHREAD           uint64
	State             string
	SuspendCount      int32
	Frozen            bool
	FrozenUnreadable  bool
	StartAddress      uint64
	StartPath         string
	StartExport       string
	Win32StartAddress uint64
	Win32StartPath    string
	Win32StartExport  string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type sources struct {
	threads func(tools.Context) ([]threadlist.Thread, error)
	spaces  func(tools.Context) (*threadaddress.Spaces, error)
}

var defaultSources = sources{threads: threadlist.Run, spaces: threadaddress.New}

func Run(ctx tools.Context) ([]Thread, error) { return run(ctx, defaultSources) }

type counts struct {
	threads, suspended, unread, negative int
}

func run(ctx tools.Context, src sources) ([]Thread, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	threads, err := src.threads(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: thread list: %w", Name, err)
	}
	frozen := threadaddress.ResolveThreadFlag(ctx.Symbols, "_KTHREAD", "FreezeCount")
	var c counts
	var picked []threadlist.Thread
	for _, th := range threads {
		c.threads++
		switch {
		case th.SuspendCountUnreadable:
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: thread %d at 0x%x: %w", Name, th.TID, th.ETHREAD, ErrSuspendCountUnread)
			}
			c.unread++
		case th.SuspendCount < 0:
			c.negative++
		case th.SuspendCount > 0:
			picked = append(picked, th)
		}
	}
	c.suspended = len(picked)
	rows := make([]Thread, 0, len(picked))
	if len(picked) > 0 {
		names := newNamer(ctx, src)
		for _, th := range picked {
			row := Thread{PID: th.PID, Process: util.ReplaceInvalidUTF8(th.ProcessName), TID: th.TID, ETHREAD: th.ETHREAD,
				State: th.StateName, SuspendCount: th.SuspendCount,
				StartAddress: th.StartAddress, StartPath: th.StartPath,
				Win32StartAddress: th.Win32StartAddress, Win32StartPath: th.Win32StartPath}
			if frozen.Known() {
				set, err := frozen.Set(ctx.Memory, th.ETHREAD)
				row.Frozen, row.FrozenUnreadable = set && err == nil, err != nil
			}
			if !th.ProcessUnreadable {
				if !th.StartAddressUnreadable {
					row.StartExport = names.export(ctx, th.Process, th.StartAddress)
				}
				if !th.Win32StartAddressUnreadable {
					row.Win32StartExport = names.export(ctx, th.Process, th.Win32StartAddress)
				}
			}
			rows = append(rows, row)
		}
		names.report(ctx)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].PID != rows[j].PID {
			return rows[i].PID < rows[j].PID
		}
		return rows[i].TID < rows[j].TID
	})
	ctx.AddDiagnostic("%s: %d threads, %d suspended; suspend count unread on %d, negative on %d",
		Name, c.threads, c.suspended, c.unread, c.negative)
	return rows, nil
}

type namer struct {
	spaces   *threadaddress.Spaces
	failed   map[uint64]bool
	notOwned int
}

func newNamer(ctx tools.Context, src sources) *namer {
	s, err := src.spaces(ctx)
	if err != nil {
		ctx.AddDiagnostic("%s: process ranges not read, start exports not named: %v", Name, err)
		return &namer{}
	}
	return &namer{spaces: s, failed: map[uint64]bool{}}
}

func (n *namer) export(ctx tools.Context, owner, address uint64) string {
	if n.spaces == nil || address == 0 || !threadaddress.UserAddress(ctx.Symbols.PointerSize(), address) {
		return ""
	}
	if _, ok := n.spaces.Owner(owner); !ok {
		n.notOwned++
		return ""
	}
	p, err := n.spaces.Place(ctx, owner, address)
	if err != nil {
		if !n.failed[owner] {
			n.failed[owner] = true
			ctx.AddDiagnostic("%s: process at 0x%x: range walk failed: %v", Name, owner, err)
		}
		return ""
	}
	return p.Export
}

func (n *namer) report(ctx tools.Context) {
	if n.spaces == nil {
		return
	}
	if n.notOwned > 0 || n.spaces.ExportsUnread > 0 {
		ctx.AddDiagnostic("%s: start exports not named: %d addresses of an owner not listed, %d export tables unread",
			Name, n.notOwned, n.spaces.ExportsUnread)
	}
}
