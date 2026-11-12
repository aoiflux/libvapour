package registryhive

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/registryhivescan"
)

var ErrUserCellNoSpace = errors.New("registryhive: cell at a user address and no Registry process space")

// Learn: user space ends at 0x7FFFFFFF on 32-bit Windows and at
// 0x7FFF'FFFFFFFF on 64-bit Windows.
func userAddress(addr uint64, width uint64) bool {
	if width == 4 {
		return addr <= 0x7fffffff
	}
	return addr <= 0x7fffffffffff
}

type cellSpace struct {
	kernel memory.MemoryReader
	user   memory.MemoryReader
	width  uint64
}

func (s cellSpace) ReadAt(addr, n uint64) ([]byte, error) {
	if userAddress(addr, s.width) {
		if s.user == nil {
			return nil, fmt.Errorf("0x%x: %w", addr, ErrUserCellNoSpace)
		}
		return s.user.ReadAt(addr, n)
	}
	return s.kernel.ReadAt(addr, n)
}

func (s cellSpace) Size() uint64 { return s.kernel.Size() }

const registryParentPID = 4

// Builds that keep hive bins in the Registry process name it in
// CmpRegistryProcess; a build without the symbol keeps every bin in kernel
// memory, so its reader is the kernel layer alone.
func defaultCells(ctx tools.Context) memory.MemoryReader {
	if _, err := ctx.Symbols.LookupSymbol("CmpRegistryProcess"); err != nil {
		return ctx.Memory
	}
	return cellSpace{kernel: ctx.Memory, width: uint64(ctx.Symbols.PointerSize())}
}

// Only a process named Registry started by the System process counts.
func CellReader(ctx tools.Context) memory.MemoryReader {
	if ctx.Symbols == nil || ctx.Memory == nil {
		return nil
	}
	width := uint64(ctx.Symbols.PointerSize())
	kernelOnly := cellSpace{kernel: ctx.Memory, width: width}
	if _, err := ctx.Symbols.LookupSymbol("CmpRegistryProcess"); err != nil {
		return ctx.Memory
	}
	procs, err := processlist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		ctx.AddDiagnostic("registryhive: process list: %v: hives in the Registry process do not read", err)
		return kernelOnly
	}
	parent, parentErr := ctx.Symbols.Field("_EPROCESS", "InheritedFromUniqueProcessId")
	for _, p := range procs {
		if !strings.EqualFold(p.Name, "Registry") {
			continue
		}
		if parentErr == nil {
			ppid, err := ctx.Symbols.ReadPointer(ctx.Memory, p.EPROCESS+parent.Offset)
			if err != nil || ppid != registryParentPID {
				continue
			}
		}
		space, err := ctx.ProcessSpace(p.DirectoryTableBase)
		if err != nil {
			ctx.AddDiagnostic("registryhive: Registry process %d at 0x%x: address space: %v: hives in it do not read",
				p.PID, p.EPROCESS, err)
			return kernelOnly
		}
		if space == ctx.Memory {
			return kernelOnly
		}
		return cellSpace{kernel: ctx.Memory, user: space, width: width}
	}
	ctx.AddDiagnostic("registryhive: no Registry process started by pid %d: hives in it do not read", registryParentPID)
	return kernelOnly
}

func GatherHives(ctx tools.Context) []Hive {
	hives, _ := gatherHives(ctx)
	return hives
}

// Listed hives come first in list order; a hive the pool scan alone found
// may be one Windows has unloaded, so it follows them.
func gatherHives(ctx tools.Context) ([]Hive, int) {
	var out []Hive
	at := map[uint64]int{}
	add := func(hv Hive) {
		if hv.Address == 0 {
			return
		}
		if i, dup := at[hv.Address]; dup {
			if out[i].FileFullPath == "" {
				out[i].FileFullPath = hv.FileFullPath
			}
			if out[i].Name == "" {
				out[i].Name = hv.Name
			}
			return
		}
		at[hv.Address] = len(out)
		out = append(out, hv)
	}
	if listed, err := listHives(ctx); err == nil {
		for _, hv := range listed {
			add(hv)
		}
	} else {
		ctx.AddDiagnostic("registryhive: hive list: %v", err)
	}
	listed := len(out)
	if found, err := registryhivescan.Run(ctx); err == nil {
		for _, f := range found {
			add(Hive{Address: f.Address, FileFullPath: f.FilePath, Name: LastPathComponent(f.FilePath), RegistryPath: f.RegistryPath})
		}
	} else {
		ctx.AddDiagnostic("registryhive: hive pool scan: %v", err)
	}
	return out, listed
}

type OpenedHive struct {
	Hive  Hive
	Layer *HiveLayer
}

// Load order puts the boot-time hive before any later copy of the same name.
func OpenHive(ctx tools.Context, name string, cellReader memory.MemoryReader) (*HiveLayer, error) {
	hives, listed := gatherHives(ctx)
	matches := preferListed(hives, listed, nameIs(name))
	if len(matches) > 1 {
		where := make([]string, len(matches))
		for i, hv := range matches {
			where[i] = fmt.Sprintf("%q at 0x%x", hv.FileFullPath, hv.Address)
		}
		ctx.AddDiagnostic("registryhive: %d hives named %q (%s): the first that opens is used",
			len(matches), name, strings.Join(where, ", "))
	}
	opened := openHives(ctx, matches, cellReader, true)
	if len(opened) == 0 {
		return nil, fmt.Errorf("registryhive: no hive named %q opens", name)
	}
	return opened[0].Layer, nil
}

func OpenFirstHiveContaining(ctx tools.Context, sub string, cellReader memory.MemoryReader) (*HiveLayer, error) {
	hives, listed := gatherHives(ctx)
	opened := openHives(ctx, preferListed(hives, listed, pathContains(sub)), cellReader, true)
	if len(opened) == 0 {
		return nil, fmt.Errorf("registryhive: no hive whose path contains %q opens", sub)
	}
	return opened[0].Layer, nil
}

func OpenHivesContaining(ctx tools.Context, sub string, cellReader memory.MemoryReader) []OpenedHive {
	hives, listed := gatherHives(ctx)
	return openHives(ctx, preferListed(hives, listed, pathContains(sub)), cellReader, false)
}

func OpenEveryHive(ctx tools.Context, cellReader memory.MemoryReader) []OpenedHive {
	hives, listed := gatherHives(ctx)
	return openHives(ctx, preferListed(hives, listed, func(Hive) bool { return true }), cellReader, false)
}

func openHives(ctx tools.Context, hives []Hive, cellReader memory.MemoryReader, firstOnly bool) []OpenedHive {
	if len(hives) == 0 {
		return nil
	}
	if cellReader == nil {
		cellReader = CellReader(ctx)
	}
	var out []OpenedHive
	for _, hv := range hives {
		layer, err := NewHiveLayer(ctx, hv.Address)
		if err != nil {
			ctx.AddDiagnostic("registryhive: hive %q at 0x%x: not opened: %v", hv.FileFullPath, hv.Address, err)
			continue
		}
		layer.SetCellReader(cellReader)
		out = append(out, OpenedHive{Hive: hv, Layer: layer})
		if firstOnly {
			break
		}
	}
	return out
}

func preferListed(hives []Hive, listed int, match func(Hive) bool) []Hive {
	listed = min(max(listed, 0), len(hives))
	pick := func(part []Hive) []Hive {
		var out []Hive
		for _, hv := range part {
			if match(hv) {
				out = append(out, hv)
			}
		}
		return out
	}
	if found := pick(hives[:listed]); len(found) > 0 {
		return found
	}
	return pick(hives[listed:])
}

func nameIs(name string) func(Hive) bool {
	return func(hv Hive) bool {
		return strings.EqualFold(LastPathComponent(hv.FileFullPath), name) || strings.EqualFold(hv.Name, name) ||
			strings.EqualFold(LastPathComponent(hv.RegistryPath), name)
	}
}

func pathContains(sub string) func(Hive) bool {
	lower := strings.ToLower(sub)
	return func(hv Hive) bool {
		return strings.Contains(strings.ToLower(hv.FileFullPath), lower) ||
			strings.Contains(strings.ToLower(hv.Name), lower) ||
			strings.Contains(strings.ToLower(hv.RegistryPath), lower)
	}
}

// An exact name wins: as a substring "system" also matches every path
// under System32.
func SelectHives(hives []Hive, filter string) []Hive {
	if filter == "" {
		return hives
	}
	var exact, partial []Hive
	for _, hv := range hives {
		switch {
		case nameIs(filter)(hv):
			exact = append(exact, hv)
		case pathContains(filter)(hv):
			partial = append(partial, hv)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	return partial
}
