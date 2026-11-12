package poolscan

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

// A body reader judges what the pool and object headers could not, and names
// the row. The body lies inside its allocation, which lies inside one page,
// so physical reads of it stay in the allocation.
type bodyReader func(physical memory.MemoryReader, objectHeader, body uint64) (name string, ok bool)

type objectKind struct {
	filter scan.PoolFilter
	tag    scan.TypeTag
	// Only kinds whose body check is structural keep a header whose TypeIndex
	// no longer decodes: a freed object loses it first.
	keepMismatch bool
	read         bodyReader
}

type structureKind struct {
	filter scan.PoolFilter
	read   func(physical memory.MemoryReader, body uint64) string
}

type countedString struct {
	at       uint64
	ok       bool
	layout   util.UnicodeStringLayout
	maxBytes uint64
	kernel   memory.MemoryReader
}

func newCountedString(ctx tools.Context, path ...string) countedString {
	c := countedString{layout: util.ResolveUnicodeStringLayout(ctx.Symbols), kernel: ctx.Memory,
		maxBytes: uint64(ctx.Bounds().MaxNameBytes)}
	for i := 0; i+1 < len(path); i += 2 {
		f, err := ctx.Symbols.Field(path[i], path[i+1])
		if err != nil {
			return countedString{}
		}
		c.at += f.Offset
	}
	c.ok = true
	return c
}

// The descriptor is in the body; its characters are wherever Buffer points in
// kernel memory.
func (c countedString) read(physical memory.MemoryReader, body uint64) string {
	if !c.ok {
		return ""
	}
	raw, err := physical.ReadAt(body+c.at, c.layout.Size)
	if err != nil || uint64(len(raw)) < c.layout.Size || c.layout.LengthOffset+2 > c.layout.Size {
		return ""
	}
	length := uint64(binary.LittleEndian.Uint16(raw[c.layout.LengthOffset:]))
	var buffer uint64
	switch width := c.layout.Size - c.layout.BufferOffset; {
	case width >= 8:
		buffer = binary.LittleEndian.Uint64(raw[c.layout.BufferOffset:])
	case width >= 4:
		buffer = uint64(binary.LittleEndian.Uint32(raw[c.layout.BufferOffset:]))
	}
	length = min(length, c.maxBytes)
	if length == 0 || buffer == 0 {
		return ""
	}
	chars, err := c.kernel.ReadAt(buffer, length)
	if err != nil || uint64(len(chars)) < length {
		return ""
	}
	return util.DecodeCountedUTF16LE(chars)
}

func dispatcherTag(t symbols.SymbolTable, want uint64, body, member, core string) scan.TypeTag {
	return scan.ResolveTypeTag(t, want,
		scan.Member{Struct: body, Field: member},
		scan.Member{Struct: core, Field: "Header"},
		scan.Member{Struct: "_DISPATCHER_HEADER", Field: "Type"})
}

func objectKinds(ctx tools.Context, namer *scan.ObjectNamer) []objectKind {
	t := ctx.Symbols
	named := func(physical memory.MemoryReader, header, _ uint64) (string, bool) {
		if namer == nil {
			return "", true
		}
		name, _ := namer.Lookup(physical, ctx.Memory, ctx.Memory, header)
		return name, true
	}
	var kinds []objectKind

	processes := processlist.NewProcessCheck(ctx)
	if processes.Usable() {
		kinds = append(kinds, objectKind{
			filter:       scan.ProcessFilter,
			tag:          dispatcherTag(t, scan.ProcessObject, "_EPROCESS", "Pcb", "_KPROCESS"),
			keepMismatch: true,
			read: func(physical memory.MemoryReader, _, body uint64) (string, bool) {
				id, err := processes.Check(physical, body)
				return util.ReplaceInvalidUTF8(id.Name), err == nil
			},
		})
	} else {
		ctx.AddDiagnostic("%s: _EPROCESS lacks ImageFileName or UniqueProcessId; processes not scanned", Name)
	}

	threads := processlist.NewThreadCheck(ctx)
	if threads.Usable() {
		kinds = append(kinds, objectKind{
			filter:       scan.ThreadFilter,
			tag:          dispatcherTag(t, scan.ThreadObject, "_ETHREAD", "Tcb", "_KTHREAD"),
			keepMismatch: true,
			read: func(physical memory.MemoryReader, _, body uint64) (string, bool) {
				return "", threads.Check(physical, body) == nil
			},
		})
	} else {
		ctx.AddDiagnostic("%s: _ETHREAD lacks Cid; threads not scanned", Name)
	}

	fileName := newCountedString(ctx, "_FILE_OBJECT", "FileName")
	kinds = append(kinds,
		objectKind{
			filter: scan.FileFilter,
			tag:    scan.ResolveTypeTag(t, scan.IOTypeFile, scan.Member{Struct: "_FILE_OBJECT", Field: "Type"}),
			read: func(physical memory.MemoryReader, _, body uint64) (string, bool) {
				return fileName.read(physical, body), true
			},
		},
		objectKind{
			filter: scan.MutantFilter,
			tag: scan.ResolveTypeTag(t, scan.MutantObject, scan.Member{Struct: "_KMUTANT", Field: "Header"},
				scan.Member{Struct: "_DISPATCHER_HEADER", Field: "Type"}),
			read: named,
		},
		objectKind{
			filter: scan.DriverFilter,
			tag:    scan.ResolveTypeTag(t, scan.IOTypeDriver, scan.Member{Struct: "_DRIVER_OBJECT", Field: "Type"}),
			read:   named,
		},
		objectKind{filter: scan.SymlinkFilter, read: named},
	)
	return kinds
}

func structureKinds(ctx tools.Context) []structureKind {
	module := scan.ModuleFilterFor(ctx.Symbols)
	moduleName := newCountedString(ctx, module.Body, "BaseDllName")
	return []structureKind{
		{filter: scan.AtomTableFilter, read: func(memory.MemoryReader, uint64) string { return "" }},
		{filter: module, read: moduleName.read},
	}
}
