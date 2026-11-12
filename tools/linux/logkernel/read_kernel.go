package logkernel

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
)

const Name = "linux.log.read_kernel"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "Read the Linux kernel log, one row per printed line, from the lockless ring, the record buffer or the character ring"},
		RunAny,
	)
}

type Row struct {
	Sequence       uint64
	HasSequence    bool
	TimestampNsec  uint64
	HasTimestamp   bool
	Facility       Facility
	FacilityNumber uint8
	HasFacility    bool
	Level          Level
	Caller         string
	Fragment       bool
	Final          bool
	Subsystem      string
	Device         string
	Line           string
	LineEscaped    string
}

var (
	ErrNoLog  = errors.New("logkernel: no kernel log symbol in the symbol table")
	ErrLayout = errors.New("logkernel: kernel log layout unknown")
	ErrHeader = errors.New("logkernel: kernel log header out of range")
	ErrLimit  = errors.New("logkernel: kernel log over the limits")
)

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	k, err := linuxkern.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	b := ctx.Bounds()
	src := &layoutSource{k: k, physical: ctx.PhysicalMemory(), bounds: b}
	var recs []record
	var lossy bool
	switch {
	case k.HasSymbol("prb"):
		recs, lossy, err = readRing(k, src, ctx.AddDiagnostic, b)
	case k.HasSymbol("log_first_idx"):
		recs, lossy, err = readRecords(k, src, ctx.AddDiagnostic, b)
	case k.HasSymbol("log_end"):
		recs, lossy, err = readPlain(k, ctx.AddDiagnostic, b)
	default:
		err = ErrNoLog
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if lossy && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: records left out", Name)
	}
	return rowsOf(recs), nil
}
