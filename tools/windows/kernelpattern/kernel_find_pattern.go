package kernelpattern

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.kernel.find_pattern"

const (
	OptionPattern = "windows.kernel.find_pattern.pattern"
	OptionMaxSize = "windows.kernel.find_pattern.maxsize"
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Search the kernel half of the kernel's address space for a regular expression (needs the windows.kernel.find_pattern.pattern option)",
		},
		RunAny,
	)
}

var ErrNoKernelDTB = errors.New("kernelpattern: session has no kernel directory table base")

type Match struct {
	Offset uint64
	Text   string
	Hex    []byte
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Match, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	pattern, err := PatternOption(ctx, OptionPattern)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	maxSize, err := MaxSizeOption(ctx, OptionMaxSize)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	dtb, ok := ctx.KernelDTB()
	if !ok {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoKernelDTB)
	}
	tr, err := Translator(ctx, dtb)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	physical := ctx.PhysicalMemory()
	half := modulelist.KernelHalfStart(ctx)
	mask := modulelist.AddressMask(ctx)
	// The kernel's page tables also map the user half of whichever process
	// they were taken from; only the half every process shares is searched.
	kernelHalf := []Section{{Start: half, Size: ^half + 1}}
	s := &Scanner{Pattern: pattern, Limit: ctx.Bounds().MaxMatchesPerChunk}
	var out []Match
	unread := 0
	stats, err := SectionBlocks(tr, mask, kernelHalf, func(b Block) {
		unread += ScanBlock(physical, b, func(data []byte, start uint64) {
			s.Matches(data, start, func(at uint64, match []byte) {
				kept := Truncate(match, maxSize)
				out = append(out, Match{Offset: modulelist.CanonicalAddress(at, mask, ctx.Symbols.PointerSize()),
					Text: util.DecodeUTF8Replace(kept), Hex: kept})
			})
		})
	})
	if err != nil {
		return nil, fmt.Errorf("%s: kernel address space at 0x%x: %w", Name, dtb, err)
	}
	ReportMapping(ctx, Name, "kernel address space", stats)
	if unread > 0 {
		ctx.AddDiagnostic("%s: %d chunks of mapped frames did not read and were not searched", Name, unread)
	}
	if s.Capped > 0 {
		ctx.AddDiagnostic("%s: %d chunks held more than MaxMatchesPerChunk (%d) matches; the rest of each was not reported",
			Name, s.Capped, s.Limit)
	}
	return out, nil
}
