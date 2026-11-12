package peimports

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

const Name = "windows.pe.list_imports"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the functions each process's main image imports, from its import directory, with the address of each import address table slot",
		},
		RunAny,
	)
}

var (
	ErrNotWindows = errors.New("peimports: profile is not windows")
	ErrNoPEBTypes = errors.New("peimports: symbol table lacks _EPROCESS.Peb or _PEB.ImageBaseAddress")
)

type Import struct {
	PID                uint64
	Name               string
	ImageBase          uint64
	Library            string
	LibraryUnreadable  bool
	Bound              bool
	ByOrdinal          bool
	Ordinal            uint16
	Function           string
	FunctionUnreadable bool
	FunctionFrom       string
	Address            uint64
}

const (
	OrdinalFromExports = "exports"
	OrdinalFromTable   = "table"
)

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Import, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %q: %w", Name, ctx.Profile.OS(), ErrNotWindows)
	}
	l, err := readLayout(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	pids := ctx.PIDs()
	t := newTally()
	names := newOrdinalNamer(ctx)
	var out []Import
	for _, p := range procs {
		if pids.Keep(p.PID) {
			out = append(out, processImports(ctx, l, p, names, t)...)
		}
	}
	names.report(ctx)
	t.report(ctx)
	return out, nil
}

type layout struct {
	peb         uint64
	imageBase   uint64
	sectionBase uint64
	hasSection  bool
}

func readLayout(ctx tools.Context) (layout, error) {
	peb, err := ctx.Symbols.Field("_EPROCESS", "Peb")
	if err != nil {
		return layout{}, fmt.Errorf("%w: %w", ErrNoPEBTypes, err)
	}
	ib, err := ctx.Symbols.Field("_PEB", "ImageBaseAddress")
	if err != nil {
		return layout{}, fmt.Errorf("%w: %w", ErrNoPEBTypes, err)
	}
	l := layout{peb: peb.Offset, imageBase: ib.Offset}
	if sb, err := ctx.Symbols.Field("_EPROCESS", "SectionBaseAddress"); err == nil {
		l.sectionBase, l.hasSection = sb.Offset, true
	}
	return l, nil
}

// The PEB is the loader's own record of the main image. A process without
// one, or whose PEB does not read, falls back to the kernel's record of the
// section it was created from.
func mainImageBase(ctx tools.Context, l layout, p processlist.Process, space memory.MemoryReader, t *tally) (uint64, bool) {
	if peb, err := ctx.Symbols.ReadPointer(ctx.Memory, p.EPROCESS+l.peb); err == nil && peb != 0 {
		if base, err := ctx.Symbols.ReadPointer(space, peb+l.imageBase); err == nil && base != 0 {
			return base, true
		}
		t.pebUnread++
	} else if err == nil {
		t.noPEB++
		return 0, false
	}
	if l.hasSection {
		if base, err := ctx.Symbols.ReadPointer(ctx.Memory, p.EPROCESS+l.sectionBase); err == nil && base != 0 {
			t.fromSection++
			return base, true
		}
	}
	t.baseUnread++
	return 0, false
}

func processImports(ctx tools.Context, l layout, p processlist.Process, names *ordinalNamer, t *tally) []Import {
	space, err := ctx.ProcessSpace(p.DirectoryTableBase)
	if err != nil {
		t.noSpace++
		return nil
	}
	base, ok := mainImageBase(ctx, l, p, space, t)
	if !ok {
		return nil
	}
	h, err := extract.ReadHeaders(space, base)
	if err != nil {
		t.image[failure(err)]++
		return nil
	}
	read := pe.MappedReader(space, base, h.Optional.SizeOfImage)
	dir, err := h.ReadDataDirectory(read, pe.DirectoryEntryImport)
	if errors.Is(err, pe.ErrNoDataDirectory) || err == nil && dir.VirtualAddress == 0 {
		t.noImports++
		return nil
	}
	if err != nil {
		t.image[failure(err)]++
		return nil
	}
	table, err := pe.ParseImports(read, h.Optional.PE32Plus, dir, ctx.Bounds())
	if errors.Is(err, pe.ErrNoImportDirectory) {
		t.noImports++
		return nil
	}
	if err != nil {
		t.image[failure(err)]++
		return nil
	}
	for _, problem := range table.Problems {
		t.parts[failure(problem)]++
	}
	var out []Import
	for _, d := range table.Descriptors {
		if d.LibraryErr != nil {
			t.libraryUnread++
		}
		for _, imp := range d.Imports {
			row := Import{
				PID:               p.PID,
				Name:              p.Name,
				ImageBase:         base,
				Library:           d.Library,
				LibraryUnreadable: d.LibraryErr != nil,
				Bound:             d.TimeDateStamp != 0,
				ByOrdinal:         imp.ByOrdinal,
				Ordinal:           imp.Ordinal,
				Function:          imp.Name,
				Address:           imp.SlotAddress(base),
			}
			switch {
			case imp.ByOrdinal && d.LibraryErr == nil:
				row.Function, row.FunctionFrom = names.name(p, d.Library, h.Optional.PE32Plus, imp.Ordinal)
			case !imp.ByOrdinal && imp.NameErr != nil:
				row.FunctionUnreadable = true
				t.functionUnread++
			}
			out = append(out, row)
		}
	}
	return out
}
