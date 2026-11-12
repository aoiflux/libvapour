package memorypattern

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/kernelpattern"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.memory.find_pattern"

const (
	OptionPattern = "windows.memory.find_pattern.pattern"
	OptionMaxSize = "windows.memory.find_pattern.maxsize"
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Search the VAD ranges of each process for a regular expression (needs the windows.memory.find_pattern.pattern option)",
		},
		RunAny,
	)
}

type Match struct {
	PID     uint64
	Process string
	Address uint64
	Text    string
	Bytes   []byte
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type tally struct {
	count int
	first string
}

func (t *tally) add(format string, args ...any) {
	if t.count == 0 {
		t.first = fmt.Sprintf(format, args...)
	}
	t.count++
}

func (t tally) report(ctx tools.Context, what string) {
	if t.count > 0 {
		ctx.AddDiagnostic("%s: %d processes %s, first: %s", Name, t.count, what, t.first)
	}
}

func Run(ctx tools.Context) ([]Match, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	pattern, err := kernelpattern.PatternOption(ctx, OptionPattern)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	maxSize, err := kernelpattern.MaxSizeOption(ctx, OptionMaxSize)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return nil, fmt.Errorf("%s: %w", Name, kernelpattern.ErrNoPhysical)
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	mask := modulelist.AddressMask(ctx)
	scanner := &kernelpattern.Scanner{Pattern: pattern, Limit: ctx.Bounds().MaxMatchesPerChunk}
	pids := ctx.PIDs()

	var out []Match
	var noRoot, noTree, noTables tally
	var missed layers.MappingStats
	unread := 0
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		if p.DirectoryTableBase == 0 {
			noRoot.add("pid %d _EPROCESS at 0x%x", p.PID, p.EPROCESS)
			continue
		}
		vads, err := memoryranges.ProcessVADs(ctx, p)
		if err != nil {
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: pid %d _EPROCESS at 0x%x: VAD tree not read: %w", Name, p.PID, p.EPROCESS, err)
			}
			noTree.add("pid %d _EPROCESS at 0x%x: %v", p.PID, p.EPROCESS, err)
			continue
		}
		if len(vads) == 0 {
			continue
		}
		tr, err := kernelpattern.Translator(ctx, p.DirectoryTableBase)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		sections := make([]kernelpattern.Section, 0, len(vads))
		for _, v := range vads {
			sections = append(sections, kernelpattern.Section{Start: v.Start, Size: v.End - v.Start + 1})
		}
		process := util.ReplaceInvalidUTF8(p.Name)
		stats, err := kernelpattern.SectionBlocks(tr, mask, sections, func(b kernelpattern.Block) {
			unread += kernelpattern.ScanBlock(physical, b, func(data []byte, start uint64) {
				scanner.Matches(data, start, func(at uint64, match []byte) {
					kept := kernelpattern.Truncate(match, maxSize)
					out = append(out, Match{PID: p.PID, Process: process, Address: at,
						Text: util.DecodeUTF8Replace(kept), Bytes: kept})
				})
			})
		})
		if err != nil {
			noTables.add("pid %d page tables at 0x%x: %v", p.PID, p.DirectoryTableBase, err)
			continue
		}
		missed.UnreadableTables += stats.UnreadableTables
		missed.UncapturedPages += stats.UncapturedPages
	}
	kernelpattern.ReportMapping(ctx, Name, "process address spaces", missed)
	noRoot.report(ctx, "without a page-table root, not searched")
	noTree.report(ctx, "whose VAD tree did not read, not searched")
	noTables.report(ctx, "whose page tables did not walk, not searched")
	if unread > 0 {
		ctx.AddDiagnostic("%s: %d chunks of mapped frames did not read and were not searched", Name, unread)
	}
	if scanner.Capped > 0 {
		ctx.AddDiagnostic("%s: %d chunks held more than MaxMatchesPerChunk (%d) matches; the rest of each was not reported",
			Name, scanner.Capped, scanner.Limit)
	}
	return out, nil
}
