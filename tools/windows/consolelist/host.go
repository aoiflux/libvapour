package consolelist

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

// conhost.exe serves the console APIs, so it holds the consoles' state
// (S33 F1).
const HostImage = "conhost.exe"

type Host struct {
	Process processlist.Process
	Space   Space
}

// Hosts kept by the pid option, and every listed process, whatever the
// option says: an attached process is checked against all of them.
func FindHosts(ctx tools.Context, tool string) ([]Host, []processlist.Process, error) {
	procs, err := processlist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		return nil, nil, fmt.Errorf("%s: process list: %w", tool, err)
	}
	keep := ctx.PIDs()
	lister, listerErr := memoryranges.NewPageLister(ctx)
	var hosts []Host
	for _, p := range procs {
		if !strings.EqualFold(p.Name, HostImage) || !keep.Keep(p.PID) {
			continue
		}
		mem, err := ctx.ProcessSpace(p.DirectoryTableBase)
		if err != nil {
			ctx.AddDiagnostic("%s: process %d at 0x%x: address space not built: %v", tool, p.PID, p.EPROCESS, err)
			continue
		}
		vads, err := memoryranges.ProcessVADs(ctx, p)
		if err != nil {
			ctx.AddDiagnostic("%s: process %d at 0x%x: VADs not read: %v", tool, p.PID, p.EPROCESS, err)
			continue
		}
		regions := make([]Region, 0, len(vads))
		for _, v := range vads {
			if v.End >= v.Start && v.End+1 > v.End {
				regions = append(regions, Region{Start: v.Start, End: v.End + 1})
			}
		}
		sp := NewSpace(mem, regions)
		if listerErr == nil {
			var runs []Region
			_, err := lister.Pages(ctx, p, func(r memoryranges.PageRun) error {
				if r.Virtual+r.Size > r.Virtual {
					runs = append(runs, Region{Start: r.Virtual, End: r.Virtual + r.Size})
				}
				return nil
			})
			if err == nil {
				sp = sp.WithSearch(runs)
			} else {
				ctx.AddDiagnostic("%s: process %d at 0x%x: present pages not listed, every VAD is searched: %v", tool, p.PID, p.EPROCESS, err)
			}
		}
		hosts = append(hosts, Host{Process: p, Space: sp})
	}
	return hosts, procs, nil
}
