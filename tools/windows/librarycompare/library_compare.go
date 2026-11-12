package librarycompare

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/librarylist"
)

const Name = "windows.library.compare"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Check each image view of a process against the three loader lists of its PEB",
		},
		RunAny,
	)
}

var ErrNotWindows = errors.New("librarycompare: profile is not windows")

// LoaderListsEmpty means no loader list of the process gave a record, so the
// three In flags say nothing about this image.
type Module struct {
	PID                  uint64
	Process              string
	Base                 uint64
	InLoad               bool
	InInit               bool
	InMem                bool
	Wow64                bool
	MappedPath           string
	MappedPathUnreadable bool
	LoaderListsEmpty     bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Module, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %q: %w", Name, ctx.Profile.OS(), ErrNotWindows)
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	dlls, err := librarylist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: loader lists: %w", Name, err)
	}
	decoder, err := memoryranges.NewDecoder(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: VAD layout: %w", Name, err)
	}
	records := indexRecords(dlls)
	pids := ctx.PIDs()
	var rows []Module
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		got, err := compareProcess(ctx, decoder, p, records[p.EPROCESS])
		if err != nil {
			return nil, err
		}
		rows = append(rows, got...)
	}
	return rows, nil
}

type membership struct {
	load, mem, init, wow bool
}

type processRecords struct {
	bases map[uint64]membership
	wow   int
}

func indexRecords(dlls []librarylist.DLL) map[uint64]*processRecords {
	out := map[uint64]*processRecords{}
	for _, d := range dlls {
		if d.BaseUnreadable {
			continue
		}
		r := out[d.EPROCESS]
		if r == nil {
			r = &processRecords{bases: map[uint64]membership{}}
			out[d.EPROCESS] = r
		}
		m := r.bases[d.Base]
		m.load = m.load || d.InLoadOrder
		m.mem = m.mem || d.InMemoryOrder
		m.init = m.init || d.InInitializationOrder
		m.wow = m.wow || d.Wow64
		r.bases[d.Base] = m
		if d.Wow64 {
			r.wow++
		}
	}
	return out
}

func compareProcess(ctx tools.Context, decoder memoryranges.Decoder, p processlist.Process, recs *processRecords) ([]Module, error) {
	where := fmt.Sprintf("%s: process %d at 0x%x", Name, p.PID, p.EPROCESS)
	maps, err := decoder.Mappings(ctx, p)
	if err != nil {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: VADs do not read: %w", where, err)
		}
		ctx.AddDiagnostic("%s: VADs do not read, process not compared: %v", where, err)
		return nil, nil
	}
	if recs == nil {
		recs = &processRecords{}
	}
	var rows []Module
	seen := map[uint64]bool{}
	repeated, unknown := 0, 0
	for _, m := range maps {
		if m.Type == memoryranges.KindUnknown {
			unknown++
			continue
		}
		if m.Type != memoryranges.KindImage {
			continue
		}
		if seen[m.Start] {
			repeated++
			continue
		}
		seen[m.Start] = true
		in := recs.bases[m.Start]
		rows = append(rows, Module{
			PID: p.PID, Process: p.Name, Base: m.Start,
			InLoad: in.load, InInit: in.init, InMem: in.mem, Wow64: in.wow,
			MappedPath: m.Path, MappedPathUnreadable: m.PathUnreadable,
			LoaderListsEmpty: len(recs.bases) == 0,
		})
	}
	slices.SortStableFunc(rows, func(a, b Module) int {
		switch {
		case a.Base < b.Base:
			return -1
		case a.Base > b.Base:
			return 1
		}
		return 0
	})
	if repeated > 0 {
		ctx.AddDiagnostic("%s: %d image views start where an earlier one starts: the first is kept", where, repeated)
	}
	if unknown > 0 {
		ctx.AddDiagnostic("%s: %d VADs of unknown kind are not compared: their flags do not read", where, unknown)
	}
	if len(rows) > 0 && len(recs.bases) == 0 {
		ctx.AddDiagnostic("%s: no loader list gave a record: its %d image views are on no list", where, len(rows))
	}
	if p.Wow64 && recs.wow == 0 && len(recs.bases) > 0 {
		ctx.AddDiagnostic("%s: WoW64 process whose 32-bit loader lists gave no record: its 32-bit images are on no list", where)
	}
	reportViewless(ctx, where, recs, seen)
	return rows, nil
}

// A record whose base starts no image view describes memory the loader did not
// map from an image section, which is worth an examiner's look.
func reportViewless(ctx tools.Context, where string, recs *processRecords, starts map[uint64]bool) {
	var bases []uint64
	for base := range recs.bases {
		if !starts[base] {
			bases = append(bases, base)
		}
	}
	if len(bases) == 0 {
		return
	}
	slices.Sort(bases)
	ctx.AddDiagnostic("%s: %d loader records have no image view at their DllBase, the lowest at 0x%x", where, len(bases), bases[0])
}
