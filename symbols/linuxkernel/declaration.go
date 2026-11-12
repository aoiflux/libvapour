package linuxkernel

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/symbols/btf"
	"github.com/aoiflux/libvapour/symbols/generator"
	ksyms "github.com/aoiflux/libvapour/symbols/kallsyms"
)

// linux_banner and VMCOREINFO's OSRELEASE both state the kernel's release; a
// table from a banner that names another release would describe the wrong
// kernel.
func (k Kernel) Declaration() (symbols.Declaration, generator.LinuxReport, error) {
	var none generator.LinuxReport
	table, err := ksyms.Decode(k.Space, k.Seeds, k.Limits)
	if err != nil {
		return symbols.Declaration{}, none, fmt.Errorf("linuxkernel: decode kallsyms: %w", err)
	}
	start, err := soleAddress(table, "__start_BTF")
	if err != nil {
		return symbols.Declaration{}, none, err
	}
	stop, err := soleAddress(table, "__stop_BTF")
	if err != nil {
		return symbols.Declaration{}, none, err
	}
	bannerAt, err := soleAddress(table, "linux_banner")
	if err != nil {
		return symbols.Declaration{}, none, err
	}
	_, spec, err := btf.ReadKernel(k.Space, start, stop, k.Limits)
	if err != nil {
		return symbols.Declaration{}, none, fmt.Errorf("linuxkernel: read btf: %w", err)
	}
	banner, release, err := autoload.ReadLinuxBanner(k.Space, bannerAt, k.Limits)
	if err != nil {
		return symbols.Declaration{}, none, fmt.Errorf("linuxkernel: %w", err)
	}
	// The banner is printable, so a doubled backslash is the only escape
	// OSRELEASE's Text can hold for it (S05 4.2 step 1).
	if osrelease, _ := k.VMCoreInfo.Lookup("OSRELEASE"); osrelease.Text != strings.ReplaceAll(release, `\`, `\\`) {
		return symbols.Declaration{}, none, fmt.Errorf("linuxkernel: linux_banner release %q differs from VMCOREINFO OSRELEASE %q", release, osrelease.Text)
	}
	return generator.AssembleLinux(generator.LinuxKernel{
		Banner:       banner,
		Symbols:      table.Symbols,
		Rule:         table.Rule,
		VirtualShift: k.Layout.VirtualShift,
		BTF:          spec,
		PointerSize:  k.PointerSize(),
		Limits:       k.Limits,
	})
}

// KernelLayout accepts only x86-64 kernels.
func (k Kernel) PointerSize() int64 { return 8 }

func soleAddress(table ksyms.Table, name string) (uint64, error) {
	var at uint64
	found := false
	for _, s := range table.Symbols {
		if s.Name != name {
			continue
		}
		if found && s.Address != at {
			return 0, fmt.Errorf("linuxkernel: kallsyms holds %s at both 0x%x and 0x%x", name, at, s.Address)
		}
		at, found = s.Address, true
	}
	if !found {
		return 0, fmt.Errorf("linuxkernel: kallsyms holds no %s", name)
	}
	return at, nil
}
