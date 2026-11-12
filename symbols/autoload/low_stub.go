package autoload

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
)

// An application processor starts in real mode at 000VV000H, VV being the
// 8-bit STARTUP IPI vector, so the page the kernel prepares for it lies
// page-aligned below 1 MiB and begins with the code the processor runs
// first. The field offsets were measured on builds 14393, 19045 and 26100:
// the long-mode target at 0x70 and the saved processor state at 0x90, whose
// CR3 the kernel's PDB places 0x10 into _KPROCESSOR_STATE.
const (
	startPagesEnd   = 0x100000
	startJumpNear   = 0xe9
	startJumpLength = 3
	startTargetAt   = 0x70
	startStateAt    = 0x90
	stateCR3At      = 0x10
	startFieldsEnd  = startStateAt + stateCR3At + 8
	cr3FrameMask    = uint64(0x000ffffffffff000)
)

type RunningKernel struct {
	Fingerprint Fingerprint
	Base        uint64
	DTB         uint64
}

type processorStart struct {
	page, target, dtb uint64
}

var errStartsDisagree = errors.New("autoload: processor start pages name different kernels")

// The jump must land past the fields this reads and inside the page, since
// the code it starts is in the same page.
func startPageAt(page []byte, at uint64) (processorStart, bool) {
	if len(page) < kernelPageSize || page[0] != startJumpNear {
		return processorStart{}, false
	}
	target := startJumpLength + int(int16(binary.LittleEndian.Uint16(page[1:])))
	if target < startFieldsEnd || target >= kernelPageSize {
		return processorStart{}, false
	}
	return processorStart{
		page:   at,
		target: binary.LittleEndian.Uint64(page[startTargetAt:]),
		dtb:    binary.LittleEndian.Uint64(page[startStateAt+stateCR3At:]) & cr3FrameMask,
	}, true
}

// lowStubKernel reports whether any start page was found and, when one leads
// to a kernel, that kernel. Pages that lead to different kernels are refused:
// one machine runs one.
func lowStubKernel(r memory.MemoryReader, span uint64) (*RunningKernel, bool, error) {
	var found *RunningKernel
	var first error
	seen := false
	for at := uint64(0); at < startPagesEnd && at+kernelPageSize <= r.Size(); at += kernelPageSize {
		page, err := r.ReadAt(at, kernelPageSize)
		if err != nil {
			continue
		}
		start, ok := startPageAt(page, at)
		if !ok {
			continue
		}
		seen = true
		k, err := start.kernel(r, span)
		switch {
		case err != nil:
			if first == nil {
				first = err
			}
		case found == nil:
			found = k
		case *found != *k:
			return nil, true, fmt.Errorf("%w: %s at 0x%x and %s at 0x%x", errStartsDisagree, found.Fingerprint, found.Base, k.Fingerprint, k.Base)
		}
	}
	if found != nil {
		return found, true, nil
	}
	return nil, seen, first
}

// The long-mode target is code in the kernel or in an image loaded after it,
// so the kernel's headers are the first image below it whose CodeView record
// names a kernel PDB. Unmapped pages are passed over: a kernel frees the
// pages of its discardable sections.
func (s processorStart) kernel(r memory.MemoryReader, span uint64) (*RunningKernel, error) {
	if s.dtb == 0 || s.dtb >= r.Size() {
		return nil, fmt.Errorf("autoload: processor start page at 0x%x: CR3 0x%x is outside the image", s.page, s.dtb)
	}
	if s.target < layers.CanonicalKernelMinVA {
		return nil, fmt.Errorf("autoload: processor start page at 0x%x: long-mode target 0x%x is not a kernel address", s.page, s.target)
	}
	v := &kernelVirtual{phys: r, dtb: s.dtb}
	if _, err := v.translate(s.target); err != nil {
		return nil, fmt.Errorf("autoload: processor start page at 0x%x: long-mode target 0x%x: %w", s.page, s.target, err)
	}
	top := s.target &^ (kernelPageSize - 1)
	for back := uint64(0); back <= span && top-back >= layers.CanonicalKernelMinVA; back += kernelPageSize {
		base := top - back
		fp, err := codeViewAt(v, base)
		if err != nil || !isKernelPDB(fp.PDBName) {
			continue
		}
		return &RunningKernel{Fingerprint: *fp, Base: base, DTB: s.dtb}, nil
	}
	return nil, fmt.Errorf("autoload: processor start page at 0x%x: no kernel image within MaxKernelImageBytes (%d) below 0x%x", s.page, span, s.target)
}
