package pedump

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const (
	OptionBase         = "windows.pe.dump.base"
	OptionKernelModule = "windows.pe.dump.kernel_module"
)

var (
	ErrKernelModuleAndPID = errors.New("pedump: " + OptionKernelModule + " and pid are both set")
	ErrNoDumpTarget       = errors.New("pedump: " + OptionBase + " is set without pid or " + OptionKernelModule)
	ErrNoBase             = errors.New("pedump: " + OptionKernelModule + " is set without " + OptionBase)
)

// The System process has PID 4 on every Windows capture measured; a kernel
// image is reported under it, as the process that owns system space.
const (
	systemPID     = 4
	systemProcess = "System"
)

type request struct {
	base   uint64
	given  bool
	kernel bool
}

func readRequest(ctx tools.Context) (request, error) {
	base, given, err := ctx.UintOption(OptionBase)
	if err != nil {
		return request{}, err
	}
	kernel, err := ctx.BoolOption(OptionKernelModule)
	if err != nil {
		return request{}, err
	}
	pids := !ctx.PIDs().All()
	switch {
	case kernel && !given:
		return request{}, ErrNoBase
	case kernel && pids:
		return request{}, ErrKernelModuleAndPID
	case given && !kernel && !pids:
		return request{}, ErrNoDumpTarget
	}
	return request{base: base, given: given, kernel: kernel}, nil
}

// The examiner may type a base with its upper bits cleared; the image is
// relocated to, and listed at, the sign-extended address.
func (w writer) atBase(req request) ([]Artifact, error) {
	mask := modulelist.AddressMask(w.ctx)
	at := modulelist.CanonicalAddress(req.base, mask, w.ctx.Symbols.PointerSize())
	if at != req.base && at&mask != req.base {
		w.ctx.AddDiagnostic("%s: %s 0x%x is read as 0x%x: paging translates %d bits", Name, OptionBase, req.base, at,
			modulelist.AddressBits(mask))
	}
	if req.kernel {
		a := Artifact{Source: SourceKernel, PID: systemPID, Process: systemProcess, Base: at,
			FileName: w.imageFileName(extract.Kernel, at, 0)}
		w.write(ReaderForModule(KernelReaders(w.ctx), at), &a)
		return []Artifact{a}, nil
	}
	procs, err := processlist.Run(w.ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: processes not listed: %w", Name, err)
	}
	pids := w.ctx.PIDs()
	var out []Artifact
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		a := Artifact{Source: SourceProcess, PID: p.PID, Process: p.Name, Base: at,
			FileName: w.imageFileName(extract.Process(p.PID), at, p.EPROCESS)}
		space, err := w.processSpace(p.EPROCESS)
		if err != nil {
			a.Skipped = "process address space: " + err.Error()
			w.ctx.AddDiagnostic("%s: pid %d: no address space, nothing read at 0x%x: %v", Name, p.PID, at, err)
		} else {
			w.write(space, &a)
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		w.ctx.AddDiagnostic("%s: no listed process has a PID the pid option names: nothing read at 0x%x", Name, at)
	}
	return out, nil
}
