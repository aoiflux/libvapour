package processscan

import (
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

func ProcessesAtOffset(ctx tools.Context, tool, key string) (procs []processlist.Process, set bool, err error) {
	offset, ok, err := ctx.UintOption(key)
	if err != nil || !ok {
		return nil, false, err
	}
	if offset == 0 {
		ctx.AddDiagnostic("%s: option %s is 0, which names no _EPROCESS; ignored", tool, key)
		return nil, false, nil
	}
	rows, err := Run(ctx)
	if err != nil {
		return nil, true, fmt.Errorf("%s: option %s: %w", tool, key, err)
	}
	pids := ctx.PIDs()
	matched := 0
	for _, r := range rows {
		if r.Offset != offset {
			continue
		}
		matched++
		if r.VirtualOffset == 0 {
			ctx.AddDiagnostic("%s: _EPROCESS at physical 0x%x: the kernel maps no address of it, so it cannot be read as a process; omitted", tool, offset)
			continue
		}
		p, err := processlist.ProcessAt(ctx, r.VirtualOffset)
		if err != nil {
			ctx.AddDiagnostic("%s: _EPROCESS at physical 0x%x: does not read at kernel 0x%x, omitted: %v", tool, offset, r.VirtualOffset, err)
			continue
		}
		if !pids.Keep(p.PID) {
			ctx.AddDiagnostic("%s: _EPROCESS at physical 0x%x: pid %d (%s) is outside the pid set, omitted", tool, offset, p.PID, p.Name)
			continue
		}
		ctx.AddDiagnostic("%s: _EPROCESS at physical 0x%x: pid %d (%s) at kernel 0x%x", tool, offset, p.PID, p.Name, p.EPROCESS)
		procs = append(procs, p)
	}
	if matched == 0 {
		ctx.AddDiagnostic("%s: the process scan found no _EPROCESS at physical 0x%x", tool, offset)
	}
	return procs, true, nil
}
