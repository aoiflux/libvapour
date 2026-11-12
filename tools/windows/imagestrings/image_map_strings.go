package imagestrings

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

const Name = "windows.image.map_strings"

const OptionFile = "windows.image.map_strings.file"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name: Name,
			Description: "Map each line of a strings listing (decimal image file offset, a blank, the string) to the kernel " +
				"and process virtual addresses whose pages hold it; needs " + OptionFile,
		},
		RunAny,
	)
}

var (
	ErrNotWindows       = errors.New("imagestrings: profile os is not windows")
	ErrNoFile           = errors.New("imagestrings: no strings file given")
	ErrNoPhysicalMemory = errors.New("imagestrings: no physical memory layer")
	ErrNoKernelRoot     = errors.New("imagestrings: kernel page-table root not known")
)

type Mapping struct {
	Kernel  bool
	PID     uint64
	Process string
	Address uint64
}

type Located struct {
	Line            int
	String          string
	FileOffset      uint64
	PhysicalAddress uint64
	InMemory        bool
	Mappings        []Mapping
	Result          string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Located, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %q: %w", Name, ctx.Profile.OS(), ErrNotWindows)
	}
	path, err := ctx.StringOption(OptionFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if path == "" {
		return nil, fmt.Errorf("%s: %s: %w", Name, OptionFile, ErrNoFile)
	}
	phys := ctx.PhysicalMemory()
	if phys == nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPhysicalMemory)
	}
	l := ctx.Bounds()
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: strings file: %w", Name, err)
	}
	lines, rejected, readErr := ReadLines(f, l.MaxTextBytes, l.MaxRowsPerObject)
	if cerr := f.Close(); cerr != nil && readErr == nil {
		readErr = cerr
	}
	if readErr != nil {
		return nil, fmt.Errorf("%s: strings file %q: %w", Name, path, readErr)
	}
	reportRejected(ctx, rejected)

	rows := make([]Located, len(lines))
	pages := map[uint64][]int{}
	outside := 0
	for i, ln := range lines {
		rows[i] = Located{Line: ln.Number, String: ln.Text, FileOffset: ln.Offset}
		pa, ok := physicalAddress(phys, ln.Offset)
		if !ok {
			outside++
			continue
		}
		rows[i].PhysicalAddress, rows[i].InMemory = pa, true
		pages[pa/pageSize] = append(pages[pa/pageSize], i)
	}
	if outside > 0 {
		ctx.AddDiagnostic("%s: %d strings lie at file offsets that hold no physical memory", Name, outside)
	}
	if err := mapPages(ctx, phys, pages, rows); err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	for i := range rows {
		rows[i].Result = render(rows[i].Mappings)
	}
	return rows, nil
}

const rejectedNamed = 10

func reportRejected(ctx tools.Context, rejected []Rejected) {
	if len(rejected) == 0 {
		return
	}
	parts := make([]string, 0, rejectedNamed)
	for _, r := range rejected[:min(len(rejected), rejectedNamed)] {
		parts = append(parts, fmt.Sprintf("%d (%s)", r.Number, r.Reason))
	}
	more := ""
	if len(rejected) > rejectedNamed {
		more = fmt.Sprintf(" and %d more", len(rejected)-rejectedNamed)
	}
	ctx.AddDiagnostic("%s: %d strings file lines skipped: lines %s%s", Name, len(rejected), strings.Join(parts, ", "), more)
}

// A segmented image (crash dump, ELF core, LiME) stores physical memory in
// runs after its own headers; a raw image is physical memory byte for byte.
func physicalAddress(phys memory.MemoryReader, offset uint64) (uint64, bool) {
	segs, ok := phys.(interface{ Segments() []memory.Segment })
	if !ok {
		return offset, offset < phys.Size()
	}
	for _, s := range segs.Segments() {
		if offset >= s.FileOffset && offset-s.FileOffset < s.Length {
			return s.PhysicalBase + (offset - s.FileOffset), true
		}
	}
	return 0, false
}

func render(ms []Mapping) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		if m.Kernel {
			parts[i] = fmt.Sprintf("kernel 0x%x", m.Address)
		} else {
			parts[i] = fmt.Sprintf("pid %d 0x%x", m.PID, m.Address)
		}
	}
	return strings.Join(parts, "; ")
}
