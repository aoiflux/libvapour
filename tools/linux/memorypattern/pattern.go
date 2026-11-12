package memorypattern

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	"github.com/aoiflux/libvapour/tools/windows/kernelpattern"
	"github.com/aoiflux/libvapour/util"
)

const Name = "linux.memory.find_pattern"

const (
	OptionPattern = "linux.memory.find_pattern.pattern"
	OptionMaxSize = "linux.memory.find_pattern.maxsize"
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Search the mapped memory areas of each Linux process for a regular expression (needs the linux.memory.find_pattern.pattern option)",
		},
		RunAny,
	)
}

type Match struct {
	PID     int64
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

func Run(ctx tools.Context) ([]Match, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
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
		return nil, fmt.Errorf("%s: session has no physical memory to walk page tables in", Name)
	}
	k := linuxobj.New(ctx)
	lw, err := memoryranges.NewLinuxWalker(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk, err := k.Walker().Tasks(false, k.PIDSkip(ctx.PIDs()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)

	var out []Match
	var skipped, noSpace, cut tally
	var unreadChunks int
	var missed layers.MappingStats
	scanner := &kernelpattern.Scanner{Pattern: pattern, Limit: ctx.Bounds().MaxMatchesPerChunk}
	for _, addr := range walk.Tasks {
		t := linuxobj.Task{Addr: addr}
		comm, err := k.Comm(t)
		if err != nil {
			skipped.add("task_struct at %#x: %v", addr, err)
			continue
		}
		pid, err := k.TGID(t)
		if err != nil {
			skipped.add("task_struct at %#x: %v", addr, err)
			continue
		}
		dtb, ok, why, err := k.TaskDTB(t)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		if !ok {
			if why != nil {
				noSpace.add("task_struct at %#x: %v", addr, why)
			}
			continue
		}
		_, areas, walkErr := lw.TaskVMAs(addr)
		if walkErr != nil {
			cut.add("task_struct at %#x: %v", addr, walkErr)
		}
		tr, err := k.Translator(dtb)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		sections := make([]kernelpattern.Section, 0, len(areas))
		for _, a := range areas {
			sections = append(sections, kernelpattern.Section{Start: a.Start, Size: a.End - a.Start})
		}
		stats, err := kernelpattern.SectionBlocks(tr, k.AddressMask(), sections, func(b kernelpattern.Block) {
			unreadChunks += kernelpattern.ScanBlock(physical, b, func(data []byte, start uint64) {
				scanner.Matches(data, start, func(at uint64, match []byte) {
					kept := kernelpattern.Truncate(match, maxSize)
					out = append(out, Match{PID: pid, Process: comm, Address: at,
						Text: util.DecodeUTF8Replace(kept), Bytes: kept})
				})
			})
		})
		if err != nil {
			noSpace.add("task_struct at %#x: page tables at %#x: %v", addr, dtb, err)
			continue
		}
		missed.UnreadableTables += stats.UnreadableTables
		missed.UncapturedPages += stats.UncapturedPages
	}
	kernelpattern.ReportMapping(ctx, Name, "process address spaces", missed)
	if scanner.Capped > 0 {
		ctx.AddDiagnostic("%s: %d chunks held more than MaxMatchesPerChunk (%d) matches; the rest of each was not reported",
			Name, scanner.Capped, scanner.Limit)
	}
	if noSpace.count > 0 {
		ctx.AddDiagnostic("%s: %d processes without a usable address space, first: %s", Name, noSpace.count, noSpace.first)
	}
	if unreadChunks > 0 {
		ctx.AddDiagnostic("%s: %d mapped chunks did not read in physical memory and were not searched", Name, unreadChunks)
	}
	for _, f := range []struct {
		what string
		t    tally
	}{{"processes not read", skipped}, {"area lists cut short", cut}} {
		if f.t.count == 0 {
			continue
		}
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: strict mode: %d %s, first: %s", Name, f.t.count, f.what, f.t.first)
		}
		ctx.AddDiagnostic("%s: %d %s, first: %s", Name, f.t.count, f.what, f.t.first)
	}
	return out, nil
}
