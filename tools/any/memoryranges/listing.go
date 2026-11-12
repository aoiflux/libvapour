package memoryranges

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

const (
	Name           = "any.memory.list_pages"
	MemoryListName = "any.memory.list"
)

func init() {
	tools.MustRegister(tools.Spec{Name: Name, Description: "List every page mapped by each process"}, RunPagesAny)
	tools.MustRegister(tools.Spec{Name: MemoryListName, Description: "List process memory ranges (Windows VADs, Linux VMAs)"}, RunMemoryList)
}

type Mapping struct {
	PID                uint64
	Start              uint64
	End                uint64
	Protection         string
	Type               string
	DirectoryTableBase uint64
	Process            string
	VadAddress         uint64
	PageOffset         uint64
	Inode              uint64
	Major, Minor       uint32
	Path               string
	PathUnreadable     bool
	NoFile             bool
	Parent             uint64
	ParentUnreadable   bool
	Tag                string
	CommitCharge       uint64
	CommitChargeKnown  bool
	PrivateMemory      bool
	PrivateMemoryKnown bool
}

const (
	ProtectionUnknown = "unknown"

	KindPrivate = "private"
	KindImage   = "image"
	KindMapped  = "mapped"
	KindUnknown = "unknown"
)

func Run(ctx tools.Context) ([]Mapping, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	switch {
	case strings.EqualFold(ctx.Profile.OS(), "windows"):
		return runWindows(ctx)
	case strings.EqualFold(ctx.Profile.OS(), "linux"):
		return runLinux(ctx)
	default:
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
}

// Another tool can run this walk for its own rows; its diagnostics then carry
// that tool's name.
func walkLabel(ctx tools.Context) string {
	if name := ctx.Running(); name != "" {
		return name
	}
	return Name
}

func runWindows(ctx tools.Context) ([]Mapping, error) {
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	decoder, err := NewDecoder(ctx)
	if err != nil {
		return nil, err
	}
	pids := ctx.PIDs()
	out := make([]Mapping, 0, 256)
	for _, proc := range procs {
		if !pids.Keep(proc.PID) {
			continue
		}
		rows, err := decoder.Mappings(ctx, proc)
		if err != nil {
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: pid %d _EPROCESS at 0x%x: %w", walkLabel(ctx), proc.PID, proc.EPROCESS, err)
			}
			ctx.AddDiagnostic("%s: pid %d _EPROCESS at 0x%x: VAD tree not read: %v", walkLabel(ctx), proc.PID, proc.EPROCESS, err)
			continue
		}
		out = append(out, rows...)
	}
	return out, nil
}

func processName(proc processlist.Process) string { return util.ReplaceInvalidUTF8(proc.Name) }
