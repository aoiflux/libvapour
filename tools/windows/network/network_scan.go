package network

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/tools"
)

const Name = "windows.network.scan"

const optionIncludeCorrupt = "windows.network.scan.include_corrupt"

const OptionIncludeCorrupt = optionIncludeCorrupt

// The pool tags of the allocations that hold the objects the tables list,
// read from their pool headers on every capture (M11).
var poolTags = []struct {
	tag  string
	body string
	kind EndpointKind
}{
	{"TcpE", typeTCPEndpoint, KindConnection},
	{"TTcb", typeTCPEndpoint, KindConnection},
	{"TcpL", typeTCPListener, KindListener},
	{"UdpA", typeUDPEndpoint, KindDatagram},
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Find TCP connections, TCP listeners and UDP endpoints in physical memory by pool tag",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

func Run(ctx tools.Context) ([]Endpoint, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	include, err := ctx.BoolOption(optionIncludeCorrupt)
	if err != nil {
		return nil, err
	}
	l, err := resolveLayout(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	phys := ctx.PhysicalMemory()
	if phys == nil {
		return nil, fmt.Errorf("%s: %w: no physical memory", Name, ErrObjectUnread)
	}
	filters := make([]scan.PoolFilter, len(poolTags))
	kinds := map[string]EndpointKind{}
	for i, p := range poolTags {
		filters[i] = scan.PoolFilter{Tag: p.tag, Body: p.body, PageType: scan.NonPagedPool | scan.FreePool}
		kinds[p.tag] = p.kind
	}
	header, err := ctx.StructureScan(Name, filters...)
	if err != nil {
		return nil, err
	}
	d := newDecoder(ctx, l)
	rejected := map[string]int{}
	decode := func(f scan.PoolFilter, at uint64, _ scan.PoolHeader) (Endpoint, bool) {
		var e Endpoint
		var err error
		if k := kinds[f.Tag]; k == KindConnection {
			e, err = d.connection(phys, at)
		} else {
			e, err = d.bound(phys, k, at)
		}
		e.PoolTag = f.Tag
		if err != nil {
			rejected[err.Error()]++
			if !include {
				return e, false
			}
			e.Rejected = err.Error()
		}
		return e, true
	}
	placed, stats, err := scan.FindFilteredStructsPlaced(phys, header, filters, decode, ctx.Bounds().Workers)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	rows := make([]Endpoint, len(placed))
	for i, p := range placed {
		e := p.Row
		e.ObjectAddress = p.Place.BodyAddress()
		e.ObjectPhysical = p.Place.Body
		e.OtherCopyPhysical = p.OtherMappedBody()
		rows[i] = e
	}
	reportScan(ctx, stats, rejected, include)
	return keepPIDs(ctx, rows), nil
}

func reportScan(ctx tools.Context, stats scan.ScanStats, rejected map[string]int, include bool) {
	reasons := make([]string, 0, len(rejected))
	total := 0
	for r, n := range rejected {
		reasons = append(reasons, fmt.Sprintf("%d %s", n, strings.TrimPrefix(r, "network: ")))
		total += n
	}
	sort.Strings(reasons)
	msg := fmt.Sprintf("%s: %d pool tag hits, %d passed the pool header checks, %d rows, %d failed the endpoint checks",
		Name, stats.TagHits, stats.Passed, stats.Accepted, total)
	if include {
		msg += " and are listed with Rejected set"
	}
	if len(reasons) > 0 {
		msg += ": " + strings.Join(reasons, "; ")
	}
	ctx.AddDiagnostic("%s", msg)
}
