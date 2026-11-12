package processscan

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

var checkSentinels = []error{
	processlist.ErrCheckUnusable, processlist.ErrMemberUnread, processlist.ErrNoImageName, processlist.ErrBadID,
	processlist.ErrCreateTime, processlist.ErrExitTime, processlist.ErrPageTableRoot, processlist.ErrThreadLinks,
}

func Run(ctx tools.Context) ([]Process, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q (linux has RunLinux)", Name, ctx.Profile.OS())
	}
	phys := ctx.PhysicalMemory()
	if phys == nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPhysicalMemory)
	}
	tag := scan.ResolveTypeTag(ctx.Symbols, scan.ProcessObject,
		scan.Member{Struct: "_EPROCESS", Field: "Pcb"},
		scan.Member{Struct: "_KPROCESS", Field: "Header"},
		scan.Member{Struct: "_DISPATCHER_HEADER", Field: "Type"})
	if !tag.Resolved {
		ctx.AddDiagnostic("%s: symbol table lacks _EPROCESS.Pcb.Header.Type: bodies are not tested for the process type", Name)
	}
	layout, identity, err := ctx.ExecutiveScan(Name, scan.ProcessFilter, tag)
	if err != nil {
		return nil, err
	}
	identity.KeepIndexMismatch = true

	check := processlist.NewProcessCheck(ctx)
	columns := processlist.NewColumnReader(ctx)
	refused := map[uint64]error{}
	placed, stats, err := scan.FindExecutiveObjectsPlaced(phys, scan.ProcessFilter, layout, identity, func(body uint64) (Process, bool) {
		id, err := check.Check(phys, body)
		if err != nil {
			refused[body] = err
			return Process{}, false
		}
		delete(refused, body)
		return Process{PID: id.PID, Name: id.Name, Offset: body, Columns: columns.Read(ctx, phys, body)}, true
	}, ctx.Bounds().Workers)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	out := make([]Process, len(placed))
	for i, p := range placed {
		out[i] = p.Row
		out[i].VirtualOffset = p.Place.BodyAddress()
		out[i].OtherCopy = p.OtherMappedBody()
		out[i].TypeIndexFailed = p.TypeIndexFailed
	}
	ctx.AddDiagnostic("%s: %d processes from %d tag hits (%s)", Name, len(out), stats.TagHits, stats.Describe())
	if len(refused) > 0 {
		ctx.AddDiagnostic("%s: %d bodies refused by the process check: %s", Name, len(refused), refusals(refused))
	}
	if stats.TypeIndexFailed > 0 {
		ctx.AddDiagnostic("%s: %d processes kept with a header TypeIndex of another type", Name, stats.TypeIndexFailed)
	}
	return out, nil
}

func refusals(refused map[uint64]error) string {
	counts := map[string]int{}
	for _, err := range refused {
		key := err.Error()
		for _, s := range checkSentinels {
			if errors.Is(err, s) {
				key = strings.TrimPrefix(s.Error(), "processlist: ")
				break
			}
		}
		counts[key]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, counts[k])
	}
	return strings.Join(parts, ", ")
}
