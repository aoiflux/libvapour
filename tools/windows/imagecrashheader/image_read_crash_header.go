package imagecrashheader

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.image.read_crash_header"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the header of the Windows crash dump the session reads: kernel pointers, processor count, bug check, dump type and times",
		},
		RunAny,
	)
}

var ErrNotCrashDump = errors.New("imagecrashheader: the image is not a windows crash dump")

type Info struct {
	Signature           string
	MajorVersion        uint32
	MinorVersion        uint32
	DirectoryTableBase  uint64
	PfnDataBase         uint64
	PsLoadedModuleList  uint64
	PsActiveProcessHead uint64
	MachineImageType    uint32
	NumberProcessors    uint32
	BugCheckCode        uint32
	KdDebuggerDataBlock uint64
	NumberOfRuns        uint32
	NumberOfPages       uint64

	DumpType      string
	DumpTypeKnown bool

	SystemUpTime      time.Duration
	SystemUpTimeValid bool
	SystemTime        time.Time
	SystemTimeValid   bool
	Comment           string
}

type crashHeader interface {
	CrashHeader() memory.CrashDumpHeader
}

// The layer opens only dumps whose header carries the "PAGE" signature; the
// same four bytes fill the header fields a writer leaves unset.
const headerSignature = "PAGE"

const dumpTypeFull = 1

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Info, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	src, ok := ctx.PhysicalMemory().(crashHeader)
	if !ok {
		return nil, fmt.Errorf("%s: %w", Name, ErrNotCrashDump)
	}
	h := src.CrashHeader()
	info := describe(h)
	if !info.DumpTypeKnown {
		ctx.AddDiagnostic("%s: crash dump header: %d physical memory runs overrun DumpType and the fields after it: "+
			"dump type, system time, comment and up time are not given", Name, h.NumberOfRuns)
	}
	return []Info{info}, nil
}

func describe(h memory.CrashDumpHeader) Info {
	info := Info{
		Signature:           headerSignature,
		MajorVersion:        h.MajorVersion,
		MinorVersion:        h.MinorVersion,
		DirectoryTableBase:  h.DirectoryTableBase,
		PfnDataBase:         h.PfnDataBase,
		PsLoadedModuleList:  h.PsLoadedModuleList,
		PsActiveProcessHead: h.PsActiveProcessHead,
		MachineImageType:    h.MachineImageType,
		NumberProcessors:    h.NumberProcessors,
		BugCheckCode:        h.BugCheckCode,
		KdDebuggerDataBlock: h.KdDebuggerDataBlock,
		NumberOfRuns:        h.NumberOfRuns,
		NumberOfPages:       h.NumberOfPages,
	}
	if !h.DumpTypeIntact {
		return info
	}
	info.DumpTypeKnown = true
	info.DumpType = dumpTypeName(h.DumpType)
	info.SystemUpTime, info.SystemUpTimeValid = UpTime(h.SystemUpTime)
	info.SystemTime, info.SystemTimeValid = util.FiletimeToTime(h.SystemTime)
	info.Comment = commentText(h.Comment[:])
	return info
}

func dumpTypeName(v uint32) string {
	if v == dumpTypeFull {
		return "full"
	}
	return strconv.FormatUint(uint64(v), 10)
}

// A dump writer that sets no comment leaves the header's fill pattern in the
// field (S66 CM2), which is not text anyone wrote.
func commentText(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	if len(b) > 0 && len(b)%len(headerSignature) == 0 && bytes.Equal(b, bytes.Repeat([]byte(headerSignature), len(b)/len(headerSignature))) {
		return ""
	}
	return util.ReplaceInvalidUTF8(string(b))
}

const upTimeTick = 100 * time.Nanosecond

func UpTime(ticks uint64) (time.Duration, bool) {
	if ticks > uint64(math.MaxInt64/int64(upTimeTick)) {
		return 0, false
	}
	return time.Duration(ticks) * upTimeTick, true
}
