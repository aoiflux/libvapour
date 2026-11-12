package processscan

import (
	"errors"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

const Name = "any.process.scan"

var ErrNoPhysicalMemory = errors.New("processscan: no physical memory to scan")

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Find processes in physical memory, including those no kernel list holds",
		},
		RunAny,
	)
}

type Process struct {
	PID             uint64
	Name            string
	Offset          uint64
	VirtualOffset   uint64
	OtherCopy       uint64
	TypeIndexFailed bool
	processlist.Columns
}

func RunAny(ctx tools.Context) (any, error) {
	if ctx.Profile != nil && strings.EqualFold(ctx.Profile.OS(), "linux") {
		return RunLinux(ctx)
	}
	rows, err := Run(ctx)
	if err != nil {
		return nil, err
	}
	pids := ctx.PIDs()
	columns := processlist.NewColumnReader(ctx)
	columns.ReportAbsent(ctx, Name)
	kept := make([]Process, 0, len(rows))
	for _, p := range rows {
		if !pids.Keep(p.PID) {
			continue
		}
		if err := columns.ReportUnread(ctx, Name, p.PID, p.Name, p.Offset, p.Columns); err != nil {
			return nil, err
		}
		kept = append(kept, p)
	}
	return kept, nil
}
