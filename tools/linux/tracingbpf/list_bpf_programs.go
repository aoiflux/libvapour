package tracingbpf

import (
	"errors"
	"fmt"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const Name = "linux.tracing.list_bpf_programs"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "List the BPF programs the kernel holds in its program registry"},
		RunAny,
	)
}

var (
	ErrNoProgIDR   = errors.New("tracingbpf: prog_idr not in the symbol table")
	ErrUnsupported = linuxwalk.ErrUnsupported
)

type Program struct {
	Address         uint64
	ID              uint64
	Type            string
	TypeValue       int64
	AttachType      string
	AttachTypeValue int64
	Name            string
	Tag             string
	Instructions    uint64
	JITed           bool
	JITedSize       uint64
	FuncAddress     uint64
	AuxAddress      uint64
	AuxRead         bool
	LoadedAfterBoot time.Duration
	Linked          bool
	IDMatches       bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Program, error) {
	k, err := linuxkern.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	idr, err := k.Symbol("prog_idr")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoProgIDR)
	}
	s, err := newShape(k)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	tree, err := k.Walker().IDR(idr)
	if err != nil {
		return nil, fmt.Errorf("%s: prog_idr at %#x: %w", Name, idr, err)
	}
	lossy := false
	if tree.Unread+tree.Revisited+tree.Inconsistent+tree.Mismatched > 0 || tree.Capped {
		lossy = true
		ctx.AddDiagnostic("%s: prog_idr at %#x: walk incomplete: %d nodes unread, %d revisited, %d inconsistent, %d mismatched, capped %t",
			Name, idr, tree.Unread, tree.Revisited, tree.Inconsistent, tree.Mismatched, tree.Capped)
	}
	var out []Program
	var unnamedType, unterminated int
	for i, at := range tree.Entries {
		p, err := s.read(at, tree.Indexes[i])
		if err != nil {
			lossy = true
			ctx.AddDiagnostic("%s: bpf_prog at %#x: does not read: %v", Name, at, err)
			continue
		}
		if p.auxErr != nil {
			lossy = true
			ctx.AddDiagnostic("%s: bpf_prog at %#x: aux at %#x does not read: %v", Name, at, p.AuxAddress, p.auxErr)
		}
		if p.AuxRead && !p.Linked {
			ctx.AddDiagnostic("%s: bpf_prog at %#x: aux at %#x points back at %#x", Name, at, p.AuxAddress, p.backLink)
		}
		if p.AuxRead && !p.IDMatches {
			ctx.AddDiagnostic("%s: bpf_prog at %#x: aux id %d is not its registry id %d", Name, at, p.auxID, p.ID)
		}
		if p.Type == "" {
			unnamedType++
		}
		if p.unterminated {
			unterminated++
		}
		out = append(out, p.Program)
	}
	if unnamedType > 0 {
		ctx.AddDiagnostic("%s: %d programs have a type value with no bpf_prog_type name", Name, unnamedType)
	}
	if unterminated > 0 {
		ctx.AddDiagnostic("%s: %d programs have a name with no NUL in its %d bytes", Name, unterminated, s.nameLen)
	}
	if lossy && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: programs were left out or read in part", Name)
	}
	return out, nil
}
