// A dumped image is for analysis, not for loading: relocations stay applied
// and the import address table keeps the loader's pointers (S18).
package pedump

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/librarylist"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const Name = "windows.pe.dump"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Rebuild loaded PE images of processes and of the kernel as files",
		},
		RunAny,
	)
}

var (
	ErrNoOutputDir = errors.New("pedump: option " + tools.OptionOutputDir + " is not set")
	ErrNotWindows  = errors.New("pedump: profile is not windows")
)

type Source string

const (
	SourceProcess Source = "process"
	SourceKernel  Source = "kernel"
)

type Artifact struct {
	Source         Source
	PID            uint64
	Process        string
	Name           string
	Path           string
	NameUnreadable bool
	PathUnreadable bool
	Base           uint64
	Entry          uint64

	FileName          string
	Size              uint32
	Captured          uint64
	Gaps              extract.GapMap
	OriginalImageBase uint64
	ImageBaseFixed    bool
	Sections          int

	Skipped string
}

func (a Artifact) Written() bool { return a.Skipped == "" }

func (a Artifact) Complete() bool { return a.Written() && len(a.Gaps) == 0 }

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Artifact, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %w", Name, ErrNotWindows)
	}
	req, err := readRequest(ctx)
	if err != nil {
		return nil, err
	}
	dir, ok := ctx.OutputDir()
	if !ok {
		return nil, ErrNoOutputDir
	}
	w := writer{ctx: ctx, dir: dir}
	if req.given {
		return w.atBase(req)
	}
	return w.loaded()
}

type writer struct {
	ctx tools.Context
	dir string
}

func (w writer) loaded() ([]Artifact, error) {
	out, err := w.processModules()
	if err != nil {
		return nil, err
	}
	kernel, err := w.kernelModules()
	if err != nil {
		return nil, err
	}
	return append(out, kernel...), nil
}

func (w writer) listFailed(what string, err error) error {
	if w.ctx.StrictMode() {
		return fmt.Errorf("%s: %s not listed: %w", Name, what, err)
	}
	w.ctx.AddDiagnostic("%s: %s not listed, none dumped: %v", Name, what, err)
	return nil
}

// A process module is read only through its own process's space: the
// kernel reader runs on some other process's page tables, and would file
// that process's bytes under this PID.
func (w writer) processModules() ([]Artifact, error) {
	dlls, err := librarylist.Run(w.ctx)
	if err != nil {
		return nil, w.listFailed("process modules", err)
	}
	out := make([]Artifact, 0, len(dlls))
	noSpace := map[uint64]bool{}
	for _, d := range dlls {
		a := Artifact{
			Source: SourceProcess, PID: d.PID, Process: d.ProcName,
			Name: d.Name, Path: d.FullPath, NameUnreadable: d.NameUnreadable, PathUnreadable: d.FullPathUnreadable,
			Base: d.Base, Entry: d.Entry,
		}
		a.FileName = w.moduleFileName(extract.Process(d.PID), a)
		space, err := w.ctx.ProcessSpace(d.DirectoryTableBase)
		switch {
		case err != nil:
			a.Skipped = "process address space: " + err.Error()
			if !noSpace[d.PID] {
				noSpace[d.PID] = true
				w.ctx.AddDiagnostic("%s: pid %d: no address space, its modules are not dumped: %v", Name, d.PID, err)
			}
		case d.BaseUnreadable:
			a.Skipped = "DllBase does not read"
		case a.Base == 0:
			a.Skipped = "DllBase is 0"
		default:
			w.write(space, &a)
		}
		out = append(out, a)
	}
	return out, nil
}

func (w writer) kernelModules() ([]Artifact, error) {
	mods, err := modulelist.Run(w.ctx)
	if err != nil {
		return nil, w.listFailed("kernel modules", err)
	}
	readers := KernelReaders(w.ctx)
	out := make([]Artifact, 0, len(mods))
	for _, m := range mods {
		a := Artifact{
			Source: SourceKernel, Name: m.Name, Path: m.Path,
			NameUnreadable: m.NameUnreadable, PathUnreadable: m.PathUnreadable,
			Base: m.Base, Entry: m.Entry,
		}
		a.FileName = w.moduleFileName(extract.Kernel, a)
		switch {
		case m.BaseUnreadable:
			a.Skipped = "DllBase does not read"
			w.ctx.AddDiagnostic("%s: kernel module, loader entry at 0x%x: %s", Name, m.Entry, a.Skipped)
		case m.Base == 0:
			a.Skipped = "DllBase is 0"
			w.ctx.AddDiagnostic("%s: kernel module, loader entry at 0x%x: %s", Name, m.Entry, a.Skipped)
		default:
			w.write(ReaderForModule(readers, m.Base), &a)
		}
		out = append(out, a)
	}
	return out, nil
}

// The label is the file the image came from; the loader's base name differs
// from it for some modules (S55 M4).
func (w writer) moduleFileName(scope extract.Scope, a Artifact) string {
	n := extract.Name{Kind: extract.KindModule, Scope: scope, Width: w.ctx.Symbols.PointerSize(),
		Addresses: []uint64{a.Base, a.Entry}, Ext: extract.ExtPE}
	switch {
	case !a.PathUnreadable && a.Path != "":
		n.Labels = []string{a.Path}
	case !a.NameUnreadable && a.Name != "":
		n.Labels = []string{a.Name}
	}
	return n.String()
}

func (w writer) imageFileName(scope extract.Scope, base, process uint64) string {
	n := extract.Name{Kind: extract.KindImage, Scope: scope, Width: w.ctx.Symbols.PointerSize(),
		Addresses: []uint64{base}, Ext: extract.ExtPE}
	if process != 0 {
		n.Addresses = append(n.Addresses, process)
	}
	return n.String()
}

func (a Artifact) what() string {
	name := a.Name
	if name == "" {
		name = a.FileName
	}
	return fmt.Sprintf("%s %s at 0x%x", a.Source, name, a.Base)
}

func (w writer) skip(a *Artifact, reason string) {
	a.Skipped = reason
	w.ctx.AddDiagnostic("%s: %s: %s", Name, a.what(), reason)
}

func (w writer) write(r memory.MemoryReader, a *Artifact) {
	headers, err := extract.ReadHeaders(r, a.Base)
	if err != nil {
		w.skip(a, err.Error())
		return
	}
	size := uint64(headers.Optional.SizeOfImage)
	limit := w.ctx.Bounds().MaxArtifactBytes
	if int64(size) > limit {
		w.skip(a, fmt.Sprintf("SizeOfImage %d is over MaxArtifactBytes %d", size, limit))
		return
	}
	image, gaps := extract.ReadPadded(r, a.Base, size)
	rebuilt, err := pe.Rebuild(image, a.Base, w.ctx.Bounds())
	if err != nil {
		w.skip(a, err.Error())
		return
	}
	if err := w.save(a.FileName, rebuilt.File); err != nil {
		w.skip(a, err.Error())
		return
	}
	a.Size = uint32(len(rebuilt.File))
	a.Captured = size - gaps.PaddedBytes()
	a.Gaps = gaps
	a.OriginalImageBase = rebuilt.OriginalImageBase
	a.ImageBaseFixed = rebuilt.ImageBaseSet
	a.Sections = len(rebuilt.Sections)
	if !rebuilt.ImageBaseSet {
		w.ctx.AddDiagnostic("%s: %s: base does not fit a 32-bit ImageBase, kept 0x%x", Name, a.what(), rebuilt.OriginalImageBase)
	}
	if n := len(rebuilt.Empty) + len(rebuilt.Clipped); n > 0 {
		w.ctx.AddDiagnostic("%s: %s: %d sections hold no bytes inside SizeOfImage, %d end past it",
			Name, a.what(), len(rebuilt.Empty), len(rebuilt.Clipped))
	}
}

// A partial file is removed: a file under an artefact name is a whole image.
func (w writer) save(name string, data []byte) error {
	f, err := extract.CreateNew(w.dir, name)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		extract.RemoveArtifact(w.dir, name)
		return err
	}
	if err := f.Close(); err != nil {
		extract.RemoveArtifact(w.dir, name)
		return err
	}
	return nil
}
