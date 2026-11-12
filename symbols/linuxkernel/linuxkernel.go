// Package linuxkernel finds the running Linux kernel in a capture from its
// VMCOREINFO note and builds, from the kernel's own kallsyms and BTF, the
// symbol table the Linux tools read it with.
package linuxkernel

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols/autoload"
	ksyms "github.com/aoiflux/libvapour/symbols/kallsyms"
)

type Kernel struct {
	VMCoreInfo  autoload.VMCoreInfo
	Layout      autoload.VMCoreInfoLayout
	Space       memory.MemoryReader
	Seeds       ksyms.Seeds
	Damaged     []autoload.DamagedVMCoreInfo
	Diagnostics []string
	Limits      limits.Limits
}

var ErrNoVMCoreInfo = errors.New("linuxkernel: no VMCOREINFO note in the image")

// Copies of the note are tried in the order the scan found them; the first
// that gives both a page-table layout and the kallsyms tables is the kernel.
func FindKernel(physical memory.MemoryReader, l limits.Limits) (Kernel, error) {
	l = l.Effective()
	scan, err := autoload.ScanVMCoreInfo(physical, l)
	if err != nil {
		return Kernel{}, fmt.Errorf("linuxkernel: find VMCOREINFO: %w", err)
	}
	if len(scan.Tables) == 0 {
		return Kernel{}, ErrNoVMCoreInfo
	}
	var refused []string
	for _, note := range scan.Tables {
		layout, err := note.KernelLayout()
		if err != nil {
			refused = append(refused, err.Error())
			continue
		}
		seeds, err := ksyms.SeedsFromVMCoreInfo(note)
		if err != nil {
			refused = append(refused, err.Error())
			continue
		}
		layout, depthErr := note.ConfirmDepth(physical, layout)
		k := Kernel{
			VMCoreInfo: note,
			Layout:     layout,
			Space:      KernelSpace(physical, layout, l.PTECacheEntries),
			Seeds:      seeds,
			Damaged:    scan.Damaged,
			Limits:     l,
		}
		for _, d := range scan.Damaged {
			k.Diagnostics = append(k.Diagnostics, d.String())
		}
		if depthErr != nil {
			k.Diagnostics = append(k.Diagnostics, depthErr.Error())
		}
		return k, nil
	}
	err = fmt.Errorf("linuxkernel: no VMCOREINFO note gives a page-table layout and kallsyms: %s", strings.Join(refused, "; "))
	if len(scan.Damaged) > 0 {
		return Kernel{}, fmt.Errorf("%w: %w", err, &autoload.VMCoreInfoDamageError{Damaged: scan.Damaged})
	}
	return Kernel{}, err
}

func (k Kernel) DamageError() error {
	if len(k.Damaged) == 0 {
		return nil
	}
	return &autoload.VMCoreInfoDamageError{Damaged: k.Damaged}
}

func KernelSpace(physical memory.MemoryReader, layout autoload.VMCoreInfoLayout, cacheEntries int) memory.MemoryReader {
	return AddressSpace(physical, layout, layout.DTB, cacheEntries)
}

func AddressSpace(physical memory.MemoryReader, layout autoload.VMCoreInfoLayout, dtb uint64, cacheEntries int) memory.MemoryReader {
	walk := &layers.IntelTranslator{Physical: physical, CR3: dtb, Mode: PagingMode(layout)}
	if memory.IsImmutableSnapshot(physical) {
		walk.EnableCache(cacheEntries)
	}
	return layers.NewVirtualMemoryLayer(physical, walk)
}

// The frame bits stop at the kernel's physical width, and the memory
// encryption bit is not part of a frame address.
func PagingMode(layout autoload.VMCoreInfoLayout) layers.PagingMode {
	levels := layers.ModeX64
	if layout.FiveLevel {
		levels = layers.ModeLA57
	}
	return layers.LinuxMode(levels, layout.PhysAddrBits, layout.SMEMask)
}
