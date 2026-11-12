package processlist

import (
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

func runLinux(ctx tools.Context, opts runOptions) ([]Process, error) {
	k := linuxobj.New(ctx)
	walk, err := k.Walker().Tasks(false, k.PIDSkip(ctx.PIDs()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)
	strict := ctx.StrictMode()
	if strict && (len(walk.Invalid) > 0 || walk.Walks[0].Broken() || walk.Walks[1].Broken()) {
		return nil, fmt.Errorf("%s: strict mode: the process walk left tasks out", Name)
	}
	out := make([]Process, 0, len(walk.Tasks))
	for _, addr := range walk.Tasks {
		p, err := linuxProcess(k, addr)
		if err != nil {
			if strict {
				return nil, fmt.Errorf("%s: task at %#x: %w", Name, addr, err)
			}
			ctx.AddDiagnostic("%s: task at %#x: left out: %v", Name, addr, err)
			continue
		}
		if opts.crossChecker != nil {
			ok, err := opts.crossChecker.Confirm(p)
			switch {
			case err != nil && strict:
				return nil, fmt.Errorf("%s: task at %#x: cross-check: %w", Name, addr, err)
			case err != nil:
				ctx.AddDiagnostic("%s: task at %#x: cross-check does not run, row kept: %v", Name, addr, err)
			case !ok:
				ctx.AddDiagnostic("%s: task at %#x: process %d is not in the snapshot", Name, addr, p.PID)
				continue
			}
		}
		out = append(out, p)
	}
	return out, nil
}

func linuxProcess(k *linuxobj.Kernel, addr uint64) (Process, error) {
	t := linuxobj.Task{Addr: addr}
	tgid, err := k.TGID(t)
	if err != nil {
		return Process{}, fmt.Errorf("tgid does not read: %w", err)
	}
	if tgid < 0 {
		return Process{}, fmt.Errorf("tgid %d is negative", tgid)
	}
	comm, err := k.Comm(t)
	if err != nil {
		return Process{}, fmt.Errorf("comm does not read: %w", err)
	}
	return Process{PID: uint64(tgid), Name: comm, EPROCESS: addr}, nil
}
