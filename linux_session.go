package libvapour

import (
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/linuxkernel"
	"github.com/aoiflux/libvapour/tools"
)

func OpenLinuxMemory(imagePath string, cfg OpenConfig) (*Session, error) {
	o, err := beginOpen(imagePath, cfg)
	if err != nil {
		return nil, err
	}
	k, err := linuxkernel.FindKernel(o.physical, o.bounds)
	if err != nil {
		return o.fail(fmt.Errorf("libvapour: find the linux kernel: %w", err))
	}
	root := k.Layout.DTB
	if given := cfg.KernelCR3; given != 0 && rootFrame(given) != rootFrame(root) {
		return o.fail(fmt.Errorf("libvapour: kernel page-table root 0x%x was given, VMCOREINFO at 0x%x gives 0x%x",
			given, k.VMCoreInfo.Offset, root))
	}
	if cfg.Strict {
		if err := k.DamageError(); err != nil {
			return o.fail(fmt.Errorf("libvapour: strict mode: %w", err))
		}
	}
	o.notes = append(o.notes, k.Diagnostics...)

	table, source, err := o.linuxSymbols(k, imagePath)
	if err != nil {
		return o.fail(err)
	}
	banner, _ := table.LinuxBanner()
	running := movedTable{inner: table, shift: k.Layout.VirtualShift, moves: linuxkernel.InKernelImage}
	agreed, err := k.CheckTable(running, banner)
	if err != nil {
		return o.fail(fmt.Errorf("libvapour: symbol table %s does not match the kernel: %w", source, err))
	}
	mode := linuxkernel.PagingMode(k.Layout)
	release, _ := k.VMCoreInfo.Lookup("OSRELEASE")
	o.note("libvapour: linux %s from VMCOREINFO at 0x%x: page-table root 0x%x, paging mode %s, image shift 0x%x; "+
		"symbols %s: banner matches, %d VMCOREINFO symbols agree", release.Text, k.VMCoreInfo.Offset, root, mode.Name(),
		k.Layout.VirtualShift, source, agreed)

	options, err := o.options()
	if err != nil {
		return o.fail(err)
	}
	options[tools.OptionPhysicalMemory] = o.physical
	options[tools.OptionKernelDTB] = root
	options[tools.OptionPagingMode] = mode.Name()

	spaces := newSpaceCache(o.physical, func(r uint64) memory.MemoryReader {
		return linuxkernel.AddressSpace(o.physical, k.Layout, r, o.bounds.PTECacheEntries)
	})
	return o.finish(tools.Context{
		Memory:        k.Space,
		Symbols:       running,
		Profile:       profiles.LinuxX64Profile{},
		Options:       options,
		ProcessMemory: spaces.get,
		Limits:        o.bounds,
	}), nil
}

func (o *opening) linuxSymbols(k linuxkernel.Kernel, imagePath string) (*symbols.Table, string, error) {
	if path := o.cfg.SymbolsPath; path != "" {
		table, err := symbols.ReadFileWith(path, o.load.Read)
		if err != nil {
			return nil, "", fmt.Errorf("libvapour: read symbol table %s: %w", path, err)
		}
		return table, path, nil
	}
	release, _ := k.VMCoreInfo.Lookup("OSRELEASE")
	table, report, err := k.AssembledTable(fmt.Sprintf("linux %s assembled from %s", release.Text, imagePath))
	if err != nil {
		return nil, "", fmt.Errorf("libvapour: no symbol table given and none assembled from the capture: %w", err)
	}
	o.note("libvapour: symbol table assembled from the capture: %d kallsyms names, %d typed, %d untyped, %d unplaced, "+
		"%d with several addresses, %d not UTF-8", report.Names, report.Typed, report.Untyped, report.Unplaced,
		len(report.Ambiguous), report.NotUTF8)
	return table, "assembled from the capture", nil
}
