package threadorphaned

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/tools/windows/threadaddress"
	"github.com/aoiflux/libvapour/tools/windows/threadscan"
)

const Name = "windows.thread.find_orphaned"

var (
	ErrNoModuleRanges   = errors.New("threadorphaned: no loaded module has a readable range")
	ErrSystemFlagUnread = errors.New("threadorphaned: system-thread flag does not read")
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List system threads, found by pool scan, that have not terminated and start outside every loaded kernel module",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type sources struct {
	modules func(tools.Context) ([]modulelist.Module, error)
	threads func(tools.Context) ([]threadscan.Thread, error)
}

var defaultSources = sources{modules: modulelist.Run, threads: threadscan.Run}

func Run(ctx tools.Context) ([]threadscan.Thread, error) { return run(ctx, defaultSources) }

type counts struct {
	scanned, system, terminated, unread, noStart, inModule int
}

type flags struct {
	system     threadaddress.ThreadFlag
	terminated threadaddress.ThreadFlag
}

func run(ctx tools.Context, src sources) ([]threadscan.Thread, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	mods, err := src.modules(ctx.WithoutPIDFilter())
	if err != nil {
		return nil, fmt.Errorf("%s: module list: %w", Name, err)
	}
	placed := modulelist.Placed(ctx, Name, mods)
	if len(placed) == 0 {
		return nil, ErrNoModuleRanges
	}
	scanned, err := src.threads(ctx.WithoutPIDFilter())
	if err != nil {
		return nil, fmt.Errorf("%s: thread scan: %w", Name, err)
	}
	f := flags{
		system:     threadaddress.ResolveSystemThread(ctx.Symbols),
		terminated: threadaddress.ResolveThreadFlag(ctx.Symbols, "_ETHREAD", "Terminated"),
	}
	if !f.system.Known() {
		ctx.AddDiagnostic("%s: symbol table has no _KTHREAD.SystemThread; threads of process 4 are taken as system threads", Name)
	}
	pids := ctx.PIDs()
	var c counts
	var out []threadscan.Thread
	for _, th := range scanned {
		if !pids.Keep(th.PID) {
			continue
		}
		c.scanned++
		keep, err := f.orphaned(ctx, th, placed, &c)
		if err != nil {
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: thread %d at 0x%x: %w", Name, th.TID, th.Offset, err)
			}
			c.unread++
			continue
		}
		if keep {
			out = append(out, th)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.PID != b.PID {
			return a.PID < b.PID
		}
		if a.TID != b.TID {
			return a.TID < b.TID
		}
		return a.Offset < b.Offset
	})
	ctx.AddDiagnostic("%s: %d threads scanned, %d system threads: %d terminated, %d without a start address, "+
		"%d in a module, %d in none; %d not examined, a flag did not read",
		Name, c.scanned, c.system, c.terminated, c.noStart, c.inModule, len(out), c.unread)
	return out, nil
}

func (f flags) orphaned(ctx tools.Context, th threadscan.Thread, mods []modulelist.Module, c *counts) (bool, error) {
	r, at, ok := reader(ctx, th, max(f.system.End(), f.terminated.End()))
	if f.system.Known() && !ok {
		return false, ErrSystemFlagUnread
	}
	system, err := threadaddress.IsSystemThread(f.system, r, at, th.PID)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrSystemFlagUnread, err)
	}
	if !system {
		return false, nil
	}
	c.system++
	if f.terminated.Known() && ok {
		if done, err := f.terminated.Set(r, at); err == nil && done {
			c.terminated++
			return false, nil
		}
	}
	if th.StartAddressUnreadable || th.StartAddress == 0 {
		c.noStart++
		return false, nil
	}
	if len(modulelist.Containing(mods, th.StartAddress)) > 0 {
		c.inModule++
		return false, nil
	}
	return true, nil
}

// The scan's kernel address reads members wherever they lie; its physical
// offset only reads inside the page, since the next frame belongs to
// something else.
func reader(ctx tools.Context, th threadscan.Thread, end uint64) (memory.MemoryReader, uint64, bool) {
	if th.VirtualOffset != 0 {
		return ctx.Memory, th.VirtualOffset, true
	}
	phys := ctx.PhysicalMemory()
	if phys == nil || th.Offset%tools.PageSize+end > tools.PageSize {
		return nil, 0, false
	}
	return phys, th.Offset, true
}
