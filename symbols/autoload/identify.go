package autoload

import (
	"fmt"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
)

type KernelMethod string

const (
	MethodCrashDumpHeader KernelMethod = "crash dump header's loaded module list"
	MethodLowStub         KernelMethod = "processor start page"
	MethodScan            KernelMethod = "kernel codeview record scan"
)

type KernelIdentity struct {
	Fingerprint Fingerprint
	Method      KernelMethod
	Base        uint64
	DTB         uint64
	Provisional bool
}

// The two direct paths name the kernel the processor runs; the scan only
// finds the builds the image holds, so it comes last.
func IdentifyKernel(r memory.MemoryReader, l limits.Limits) (*KernelIdentity, error) {
	id, direct := identifyDirectly(r, l)
	if id != nil {
		return id, nil
	}
	candidates, err := ScanKernelCandidates(r, l)
	if err == nil {
		var fp *Fingerprint
		var provisional bool
		if fp, provisional, err = selectKernel(candidates); err == nil {
			return &KernelIdentity{Fingerprint: *fp, Method: MethodScan, Provisional: provisional}, nil
		}
	}
	return nil, direct.explain(err)
}

// Nil without error when the image has neither a crash dump header nor a
// processor start page.
func IdentifyRunningKernel(r memory.MemoryReader, l limits.Limits) (*KernelIdentity, error) {
	id, direct := identifyDirectly(r, l)
	if id != nil {
		return id, nil
	}
	if direct.header == nil && direct.stub == nil {
		return nil, nil
	}
	return nil, direct.explain(nil)
}

type directFailures struct{ header, stub error }

func identifyDirectly(r memory.MemoryReader, l limits.Limits) (*KernelIdentity, directFailures) {
	var failed directFailures
	k, isDump, err := crashDumpKernel(r)
	if isDump && err == nil {
		return &KernelIdentity{Fingerprint: k.Fingerprint, Method: MethodCrashDumpHeader, Base: k.Base, DTB: k.DTB}, failed
	}
	failed.header = err
	k, hasStart, err := lowStubKernel(r, uint64(l.Effective().MaxKernelImageBytes))
	if hasStart && err == nil {
		return &KernelIdentity{Fingerprint: k.Fingerprint, Method: MethodLowStub, Base: k.Base, DTB: k.DTB}, failed
	}
	failed.stub = err
	return nil, failed
}

func (f directFailures) explain(last error) error {
	err := last
	for _, step := range []struct {
		method KernelMethod
		err    error
	}{{MethodCrashDumpHeader, f.header}, {MethodLowStub, f.stub}} {
		if step.err == nil {
			continue
		}
		if err == nil {
			err = fmt.Errorf("autoload: the %s did not lead to a kernel: %w", step.method, step.err)
			continue
		}
		err = fmt.Errorf("%w; the %s did not lead to a kernel either: %w", err, step.method, step.err)
	}
	return err
}
