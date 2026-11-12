package processlist

import (
	"errors"

	"github.com/aoiflux/libvapour/tools"
)

var (
	ErrSystemProcess = errors.New("processlist: process is the initial system process, which runs kernel threads only")
	ErrExited        = errors.New("processlist: process has an exit time")
	ErrNoThreads     = errors.New("processlist: process has no active threads")
)

// Stands in for PsInitialSystemProcess when the global does not read (S25 M2).
const systemPID = uint64(4)

type ActiveProcessFilter struct {
	check   ProcessCheck
	system  uint64
	known   bool
	exited  member
	threads member
}

func ResolveActiveProcessFilter(ctx tools.Context) ActiveProcessFilter {
	f := ActiveProcessFilter{check: NewProcessCheck(ctx)}
	if ctx.Symbols == nil {
		return f
	}
	if sym, err := ctx.Symbols.LookupSymbol("PsInitialSystemProcess"); err == nil && ctx.Memory != nil {
		if v, err := ctx.Symbols.ReadPointer(ctx.Memory, sym.Address); err == nil && v != 0 {
			f.system, f.known = v, true
		}
	}
	f.exited = memberOf(ctx.Symbols, "_EPROCESS", "ExitTime")
	f.exited.width = 8
	f.threads = memberOf(ctx.Symbols, "_EPROCESS", "ActiveThreads")
	f.threads.width = 4
	return f
}

func (f ActiveProcessFilter) Keep(ctx tools.Context, p Process) bool {
	return f.Why(ctx, p) == nil
}

func (f ActiveProcessFilter) Why(ctx tools.Context, p Process) error {
	id, err := f.check.Check(ctx.Memory, p.EPROCESS)
	if err != nil {
		return err
	}
	if f.known && p.EPROCESS == f.system || !f.known && id.PID == systemPID {
		return ErrSystemProcess
	}
	if f.exited.ok {
		v, err := f.exited.read(ctx.Memory, p.EPROCESS)
		if err != nil {
			return err
		}
		if v != 0 {
			return ErrExited
		}
	}
	if f.threads.ok {
		v, err := f.threads.read(ctx.Memory, p.EPROCESS)
		if err != nil {
			return err
		}
		if v == 0 {
			return ErrNoThreads
		}
	}
	return nil
}

func (f ActiveProcessFilter) Active(ctx tools.Context, procs []Process) []Process {
	out := make([]Process, 0, len(procs))
	for _, p := range procs {
		if f.Keep(ctx, p) {
			out = append(out, p)
		}
	}
	return out
}
