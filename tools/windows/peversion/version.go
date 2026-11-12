package peversion

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/librarylist"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/tools/windows/pedump"
)

const Name = "windows.pe.read_version"

const OptionExtensive = "windows.pe.read_version.extensive"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the product version in the version resource of every kernel and process module; with the extensive option, kernel modules whose resource is not mapped are matched to a cached copy in physical memory",
		},
		RunAny,
	)
}

var ErrNotWindows = errors.New("peversion: profile is not windows")

type Version struct {
	Kernel                       bool
	PID                          uint64
	Process                      string
	Base                         uint64
	Name                         string
	NameUnreadable               bool
	SizeOfImage                  uint32
	Major, Minor, Product, Build uint16
	VersionUnreadable            bool
	VersionPhysical              uint64
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Version, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %q: %w", Name, ctx.Profile.OS(), ErrNotWindows)
	}
	extensive, err := ctx.BoolOption(OptionExtensive)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	t := tally{kernel: map[string]int{}, process: map[string]int{}}
	rows, paths, err := kernelVersions(ctx, &t)
	if err != nil {
		return nil, err
	}
	if extensive {
		fillFromPhysical(ctx, rows, paths)
	}
	procRows, err := processVersions(ctx, &t)
	if err != nil {
		return nil, err
	}
	t.report(ctx)
	return append(rows, procRows...), nil
}

// paths holds each kernel row's loader path, used only to match a cached
// version resource by file name.
func kernelVersions(ctx tools.Context, t *tally) ([]Version, []string, error) {
	mods, err := modulelist.Run(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: kernel modules: %w", Name, err)
	}
	readers := pedump.KernelReaders(ctx)
	rows := make([]Version, 0, len(mods))
	paths := make([]string, 0, len(mods))
	for _, m := range mods {
		if m.BaseUnreadable {
			t.noBase++
			continue
		}
		row := Version{Kernel: true, Base: m.Base, Name: m.Name, NameUnreadable: m.NameUnreadable}
		if err := readImageVersion(&row, pedump.ReaderForModule(readers, m.Base), ctx.Bounds()); err != nil {
			t.kernel[failure(err)]++
		}
		rows = append(rows, row)
		paths = append(paths, m.Path)
	}
	return rows, paths, nil
}

// Each module is read through its own process's space only; the pid option
// narrows the processes.
func processVersions(ctx tools.Context, t *tally) ([]Version, error) {
	dlls, err := librarylist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process modules: %w", Name, err)
	}
	spaces := map[uint64]memory.MemoryReader{}
	var rows []Version
	for _, d := range dlls {
		if d.BaseUnreadable {
			t.noProcessBase++
			continue
		}
		space, ok := spaces[d.DirectoryTableBase]
		if !ok {
			if s, err := ctx.ProcessSpace(d.DirectoryTableBase); err == nil {
				space = s
			}
			spaces[d.DirectoryTableBase] = space
		}
		if space == nil {
			t.noSpace++
			continue
		}
		row := Version{PID: d.PID, Process: d.ProcName, Base: d.Base, Name: d.Name, NameUnreadable: d.NameUnreadable}
		if err := readImageVersion(&row, space, ctx.Bounds()); err != nil {
			t.process[failure(err)]++
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func readImageVersion(row *Version, reader memory.MemoryReader, l limits.Limits) error {
	row.VersionUnreadable = true
	h, err := extract.ReadHeaders(reader, row.Base)
	if err != nil {
		return err
	}
	row.SizeOfImage = h.Optional.SizeOfImage
	read := pe.MappedReader(reader, row.Base, h.Optional.SizeOfImage)
	dir, err := h.ReadDataDirectory(read, pe.DirectoryEntryResource)
	if err != nil {
		return err
	}
	info, err := pe.ReadVersion(read, dir, l)
	if err != nil {
		return err
	}
	setProductVersion(row, info)
	return nil
}

func setProductVersion(row *Version, info pe.FixedFileInfo) {
	v := info.ProductVersion()
	row.Major, row.Minor, row.Product, row.Build = v[0], v[1], v[2], v[3]
	row.VersionUnreadable = false
}

func failure(err error) string {
	switch {
	case errors.Is(err, extract.ErrHeadersUnreadable):
		return "headers do not read"
	case errors.Is(err, pe.ErrNotPE), errors.Is(err, pe.ErrNoNTSignature), errors.Is(err, pe.ErrUnsupportedOptionalMagic):
		return "not a PE image"
	case errors.Is(err, pe.ErrNoDataDirectory), errors.Is(err, pe.ErrNoResourceDirectory), errors.Is(err, pe.ErrNoResource),
		errors.Is(err, pe.ErrNoFixedFileInfo):
		return "no version resource"
	case errors.Is(err, pe.ErrBadVersionInfo), errors.Is(err, pe.ErrBadFixedFileInfoSignature), errors.Is(err, pe.ErrResourceLimit):
		return "malformed version resource"
	case errors.Is(err, pe.ErrUnreadable), errors.Is(err, pe.ErrOutsideImage):
		return "resource bytes do not read"
	}
	return err.Error()
}

type tally struct {
	kernel, process                map[string]int
	noBase, noProcessBase, noSpace int
}

func (t tally) report(ctx tools.Context) {
	if t.noBase > 0 {
		ctx.AddDiagnostic("%s: %d kernel modules passed over: DllBase does not read", Name, t.noBase)
	}
	if t.noProcessBase > 0 {
		ctx.AddDiagnostic("%s: %d process modules passed over: DllBase does not read", Name, t.noProcessBase)
	}
	if t.noSpace > 0 {
		ctx.AddDiagnostic("%s: %d process modules passed over: their process's address space does not open", Name, t.noSpace)
	}
	for _, why := range slices.Sorted(maps.Keys(t.kernel)) {
		ctx.AddDiagnostic("%s: %d kernel modules without a version: %s", Name, t.kernel[why], why)
	}
	for _, why := range slices.Sorted(maps.Keys(t.process)) {
		ctx.AddDiagnostic("%s: %d process modules without a version: %s", Name, t.process[why], why)
	}
}
