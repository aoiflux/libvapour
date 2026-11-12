package libvapour

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/autoload"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

func OpenWindowsMemory(imagePath string, cfg OpenConfig) (*Session, error) {
	o, err := beginOpen(imagePath, cfg)
	if err != nil {
		return nil, err
	}
	table, id, err := o.windowsSymbols()
	if err != nil {
		return o.fail(err)
	}
	system := &systemProcess{physical: o.physical, table: table}

	root, rootFrom, err := o.windowsRoot(id, system)
	if err != nil {
		return o.fail(err)
	}
	mode := o.windowsPagingMode(root, table)
	pagefiles, err := o.windowsPagefiles(table)
	if err != nil {
		return o.fail(err)
	}
	spaces := newSpaceCache(o.physical, windowsSpaceBuilder(o.physical, mode, o.bounds.PTECacheEntries, pagefiles))
	kernel, err := spaces.get(root)
	if err != nil {
		return o.fail(fmt.Errorf("libvapour: kernel page-table root from %s: %w", rootFrom, err))
	}

	running, base, err := o.windowsKernelBase(kernel, table, id, root, system)
	if err != nil {
		return o.fail(err)
	}
	options, err := o.options()
	if err != nil {
		return o.fail(err)
	}
	options[tools.OptionPhysicalMemory] = o.physical
	options[tools.OptionKernelDTB] = root
	options[tools.OptionPagingMode] = mode.Name()
	if base != 0 {
		options[tools.OptionKernelBase] = base
	}
	if boot := system.found(); boot != nil && boot.ListFlink != 0 {
		options[optionStartFlink] = boot.ListFlink
	}

	if extra, err := tcpipLayout(winkernel.ReadBuild("libvapour", kernel, running)); err != nil {
		o.note("libvapour: windows.network.scan and windows.network.list have no layout: %v", err)
	} else {
		running = layeredTable{kernel: running, extra: extra}
		options[tools.OptionNetworkScanLayout] = extra.Name()
	}

	return o.finish(tools.Context{
		Memory:        kernel,
		Symbols:       running,
		Profile:       profiles.WindowsX64Profile{},
		Options:       options,
		ProcessMemory: spaces.get,
		LoadPDB:       newModulePDBs(o.load).load,
		Limits:        o.bounds,
	}), nil
}

func (o *opening) windowsSymbols() (symbols.SymbolTable, *autoload.KernelIdentity, error) {
	path := o.cfg.SymbolsPath
	if path == "" {
		id, err := autoload.IdentifyKernel(o.physical, o.bounds)
		if err != nil {
			return nil, nil, fmt.Errorf("libvapour: identify the windows kernel: %w", err)
		}
		table, err := autoload.LoadWithOptions(&id.Fingerprint, o.load)
		if err != nil {
			return nil, nil, fmt.Errorf("libvapour: load symbols for %s: %w", id.Fingerprint, err)
		}
		o.note("libvapour: kernel %s from the %s; symbols from %s", id.Fingerprint, id.Method, table.Name())
		return table, id, nil
	}
	table, err := symbols.ReadFileWith(path, o.load.Read)
	if err != nil {
		return nil, nil, fmt.Errorf("libvapour: read symbol table %s: %w", path, err)
	}
	running, runErr := autoload.IdentifyRunningKernel(o.physical, o.bounds)
	id, why, err := explicitTableKernel(table, running, runErr)
	if err != nil {
		return nil, nil, fmt.Errorf("libvapour: symbol table %s: %w", path, err)
	}
	if why != "" {
		o.note("libvapour: symbol table %s %s", path, why)
	}
	return table, id, nil
}

// The System process scan costs seconds on a large capture (S76 M3), so it
// runs only when the identification gives no root or no confirmed base.
type systemProcess struct {
	physical memory.MemoryReader
	table    symbols.SymbolTable
	ran      bool
	boot     *layers.KernelBootstrap
	err      error
}

func (s *systemProcess) find() (*layers.KernelBootstrap, error) {
	if !s.ran {
		s.ran = true
		s.boot, s.err = layers.FindKernelBootstrap(s.physical, s.table)
	}
	return s.boot, s.err
}

func (s *systemProcess) found() *layers.KernelBootstrap {
	if s.ran && s.err == nil {
		return s.boot
	}
	return nil
}

// The crash dump header and the processor start page each give the root the
// kernel ran on, the same root the System process holds on every capture
// measured (S76 M3).
func (o *opening) windowsRoot(id *autoload.KernelIdentity, system *systemProcess) (uint64, string, error) {
	var root uint64
	var from string
	if id != nil && id.DTB != 0 {
		root, from = rootFrame(id.DTB), "the "+string(id.Method)
	} else {
		boot, err := system.find()
		if err != nil {
			return 0, "", fmt.Errorf("libvapour: find the kernel page-table root: %w", err)
		}
		root, from = rootFrame(boot.CR3), "the System process"
	}
	if given := o.cfg.KernelCR3; given != 0 && rootFrame(given) != root {
		return 0, "", fmt.Errorf("libvapour: kernel page-table root 0x%x was given, the capture's is 0x%x from %s", given, root, from)
	}
	o.note("libvapour: kernel page-table root 0x%x from %s", root, from)
	return root, from, nil
}

// An undecided root is read with 4-level paging, the mode of every 64-bit
// Windows capture measured (S76 M4).
func (o *opening) windowsPagingMode(root uint64, table symbols.SymbolTable) layers.PagingMode {
	decision, err := layers.DetectPagingMode(o.physical, root, int(table.PointerSize()))
	if err != nil {
		o.note("libvapour: paging mode undecided, read as %s: %v", layers.ModeX64.Name(), err)
		return layers.ModeX64
	}
	o.note("libvapour: paging mode %s: %s", decision.Mode.Name(), decision.Evidence)
	return decision.Mode
}

// A paged-out entry is decoded in one layout only (S53 4.3); on a kernel
// using another, reading the pagefile would return the wrong page, so the
// files stay closed and such pages stay unread.
func (o *opening) windowsPagefiles(table symbols.SymbolTable) (map[int]memory.MemoryReader, error) {
	if !slices.ContainsFunc(o.cfg.PagefilePaths, func(p string) bool { return p != "" }) {
		return nil, nil
	}
	if err := layers.CheckPagefilePTELayout(table); err != nil {
		o.note("libvapour: pagefiles not read: %v; a paged-out page reads as %q", err, layers.ErrPageInPagefile)
		return nil, nil
	}
	files, closers, err := openPagefiles(o.cfg.PagefilePaths)
	if err != nil {
		return nil, err
	}
	o.files = append(o.files, closers...)
	return files, nil
}

var errStrictKernelBase = errors.New("libvapour: strict mode refuses a kernel base nothing confirmed")

func (o *opening) windowsKernelBase(kernel memory.MemoryReader, table symbols.SymbolTable, id *autoload.KernelIdentity,
	root uint64, system *systemProcess) (symbols.SymbolTable, uint64, error) {
	if !needsKernelBase(table) {
		return table, 0, nil
	}
	if id == nil {
		if o.cfg.Strict {
			return nil, 0, fmt.Errorf("libvapour: kernel base: %w: no kernel build to check a base against", errStrictKernelBase)
		}
		return table, 0, nil
	}
	found, err := findKernelBase(kernel, id, o.baseCandidates(table, id, root, system))
	if err != nil {
		return nil, 0, fmt.Errorf("libvapour: kernel base: %w", err)
	}
	return o.acceptKernelBase(table, id, found)
}

// Strict mode refuses what the notes would otherwise only report: symbols at
// their RVAs, or moved by a base no codeview record confirmed.
func (o *opening) acceptKernelBase(table symbols.SymbolTable, id *autoload.KernelIdentity, found kernelBase) (symbols.SymbolTable, uint64, error) {
	switch {
	case found.address == 0 && o.cfg.Strict:
		return nil, 0, fmt.Errorf("libvapour: kernel base: %w: kernel %s: no kernel base found (tried: %s)",
			errStrictKernelBase, id.Fingerprint, strings.Join(found.tried, "; "))
	case found.address == 0:
		o.note("libvapour: kernel %s: no kernel base found, so kernel symbols stay at their RVAs and tools that read "+
			"kernel globals fail (tried: %s)", id.Fingerprint, strings.Join(found.tried, "; "))
		return table, 0, nil
	case !found.confirmed && o.cfg.Strict:
		return nil, 0, fmt.Errorf("libvapour: kernel base: %w: 0x%x from %s: %v", errStrictKernelBase, found.address, found.from, found.unread)
	case found.confirmed:
		o.note("libvapour: kernel base 0x%x from %s, confirmed by its codeview record", found.address, found.from)
	default:
		o.note("libvapour: kernel base 0x%x from %s is unconfirmed: %v", found.address, found.from, found.unread)
	}
	return movedTable{inner: table, shift: found.address, moves: isRVA}, found.address, nil
}

// Cheapest first (S53 9.2): the identification's own base, the two list
// methods, then the two scans, the image scan first because it found the
// base on every capture and the debugger data block on two of five.
func (o *opening) baseCandidates(table symbols.SymbolTable, id *autoload.KernelIdentity, root uint64,
	system *systemProcess) []baseCandidate {
	var c []baseCandidate
	if id.Base != 0 {
		c = append(c, baseCandidate{from: "the " + string(id.Method), find: func() (uint64, error) { return id.Base, nil }})
	}
	c = append(c,
		baseCandidate{from: "the System process's list Blink", find: func() (uint64, error) {
			boot, err := system.find()
			if err != nil {
				return 0, err
			}
			return layers.FindKernelBaseFromListHead(o.physical, root, table, boot.ListBlink)
		}},
		baseCandidate{from: "the active process list", find: func() (uint64, error) {
			boot, err := system.find()
			if err != nil {
				return 0, err
			}
			return layers.FindKernelBaseByProcessListAnchor(o.physical, root, table, boot.ListFlink, o.bounds.MaxListEntries)
		}},
	)
	if id.Fingerprint.PDBName != "" {
		c = append(c, baseCandidate{from: "the kernel image scan", find: func() (uint64, error) {
			return layers.FindKernelImageBase(o.physical, root, id.Fingerprint.PDBName)
		}})
	}
	return append(c, baseCandidate{from: "the debugger data block scan", find: func() (uint64, error) {
		return layers.FindKernelBaseFromKDBG(o.physical)
	}})
}
