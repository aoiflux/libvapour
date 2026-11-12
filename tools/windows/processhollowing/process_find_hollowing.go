package processhollowing

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

const Name = "windows.process.find_hollowing"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name: Name,
			Description: "Find processes whose PEB image base, image view, image file and mapped headers " +
				"disagree with the image the kernel recorded at process creation",
		},
		RunAny,
	)
}

type Finding string

const (
	FindingImageBaseUnmapped      Finding = "image_base_unmapped"
	FindingImageBaseInsideRange   Finding = "image_base_inside_range"
	FindingImageBaseNotImage      Finding = "image_base_not_image"
	FindingSectionBaseDiffers     Finding = "section_base_differs"
	FindingSectionBaseUnmapped    Finding = "section_base_unmapped"
	FindingControlAreaDiffers     Finding = "control_area_differs"
	FindingSectionObjectDiffers   Finding = "section_object_differs"
	FindingFileNameDiffers        Finding = "file_name_differs"
	FindingImageFileNameDiffers   Finding = "image_file_name_differs"
	FindingHeaderNotPE            Finding = "header_not_pe"
	FindingHeaderImageBaseDiffers Finding = "header_image_base_differs"
	FindingImageSizeExceedsRange  Finding = "image_size_exceeds_range"
	FindingHeaderDiffersFromFile  Finding = "header_differs_from_section"
)

type Row struct {
	PID                uint64
	Process            string
	EPROCESS           uint64
	Finding            Finding
	ImageBaseAddress   uint64
	SectionBaseAddress uint64
	RangeStart         uint64
	RangeEnd           uint64
	RangeType          string
	Protection         string
	Path               string
	Detail             string
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	e, err := newExaminer(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	pids := ctx.PIDs()
	active := processlist.ResolveActiveProcessFilter(ctx)
	var rows []Row
	kept, examined := 0, 0
	skipped := map[string]int{}
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		kept++
		if why := active.Why(ctx, p); why != nil {
			skipped[inactiveReason(why)]++
			continue
		}
		found, s := e.examine(p)
		if s != nil {
			skipped[s.reason.Error()]++
			if s.cause == nil {
				continue
			}
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: pid %d _EPROCESS at 0x%x: %w", Name, p.PID, p.EPROCESS, s)
			}
			ctx.AddDiagnostic("%s: pid %d _EPROCESS at 0x%x: not examined: %v", Name, p.PID, p.EPROCESS, s)
			continue
		}
		examined++
		rows = append(rows, found...)
	}
	e.report()
	ctx.AddDiagnostic("%s: %d processes, %d examined%s", Name, kept, examined, reasons(skipped))
	return rows, nil
}

func inactiveReason(err error) string {
	switch {
	case errors.Is(err, processlist.ErrSystemProcess):
		return "system process"
	case errors.Is(err, processlist.ErrExited):
		return "exited"
	case errors.Is(err, processlist.ErrNoThreads):
		return "no threads"
	}
	return "failed the process check"
}

func reasons(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
	}
	return "; not examined: " + strings.Join(parts, ", ")
}
