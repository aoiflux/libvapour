package autoload

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
)

// The kernel's PDB is what identification finds, so these two offsets cannot
// come from it. They are the same in every kernel PDB measured: Flink first in
// _LIST_ENTRY and DllBase at 0x30 in _KLDR_DATA_TABLE_ENTRY. Each step after
// them is checked against the image itself.
const (
	listFlinkAt    = 0
	loaderBaseAt   = 0x30
	kernelPageSize = 0x1000
)

var (
	errNoModuleList = errors.New("autoload: crash dump header does not lead to the loaded module list")
	errNotKernelPDB = errors.New("autoload: first loaded module is not a kernel image")
)

type crashHeaderSource interface {
	CrashHeader() memory.CrashDumpHeader
}

func KernelFromCrashDump(r memory.MemoryReader) (*Fingerprint, bool, error) {
	k, isDump, err := crashDumpKernel(r)
	if k == nil {
		return nil, isDump, err
	}
	fp := k.Fingerprint
	return &fp, isDump, nil
}

// The first entry of PsLoadedModuleList is the kernel image; its CodeView
// record names the kernel's PDB.
func crashDumpKernel(r memory.MemoryReader) (*RunningKernel, bool, error) {
	source, ok := r.(crashHeaderSource)
	if !ok {
		return nil, false, nil
	}
	h := source.CrashHeader()
	if h.DirectoryTableBase == 0 || h.PsLoadedModuleList == 0 {
		return nil, true, fmt.Errorf("%w: DirectoryTableBase 0x%x, PsLoadedModuleList 0x%x", errNoModuleList, h.DirectoryTableBase, h.PsLoadedModuleList)
	}
	v := &kernelVirtual{phys: r, dtb: h.DirectoryTableBase}
	first, err := v.pointer(h.PsLoadedModuleList + listFlinkAt)
	if err != nil {
		return nil, true, fmt.Errorf("%w: list head at 0x%x: %w", errNoModuleList, h.PsLoadedModuleList, err)
	}
	if first == 0 || first == h.PsLoadedModuleList {
		return nil, true, fmt.Errorf("%w: the list at 0x%x is empty", errNoModuleList, h.PsLoadedModuleList)
	}
	base, err := v.pointer(first + loaderBaseAt)
	if err != nil {
		return nil, true, fmt.Errorf("%w: entry at 0x%x: DllBase: %w", errNoModuleList, first, err)
	}
	fp, err := codeViewAt(v, base)
	if err != nil {
		return nil, true, fmt.Errorf("%w: image at 0x%x: %w", errNoModuleList, base, err)
	}
	if !isKernelPDB(fp.PDBName) {
		return nil, true, fmt.Errorf("%w: image at 0x%x names %s", errNotKernelPDB, base, fp.PDBName)
	}
	return &RunningKernel{Fingerprint: *fp, Base: base, DTB: h.DirectoryTableBase}, true, nil
}

// kernelVirtual reads the kernel's address space from physical memory through
// the 4-level tables at dtb.
type kernelVirtual struct {
	phys  memory.MemoryReader
	dtb   uint64
	space *layers.VirtualMemoryLayer
}

func (v *kernelVirtual) layer() *layers.VirtualMemoryLayer {
	if v.space == nil {
		v.space = layers.NewVirtualMemoryLayer(v.phys, &layers.IntelTranslator{Physical: v.phys, CR3: v.dtb, Mode: layers.ModeX64})
	}
	return v.space
}

func (v *kernelVirtual) translate(va uint64) (uint64, error) { return v.layer().Translate(va) }

func (v *kernelVirtual) ReadAt(offset, size uint64) ([]byte, error) {
	return v.layer().ReadAt(offset, size)
}

func (v *kernelVirtual) Size() uint64 { return v.phys.Size() }

func (v *kernelVirtual) pointer(va uint64) (uint64, error) {
	b, err := v.ReadAt(va, 8)
	if err != nil {
		return 0, err
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("read %d of 8 bytes at 0x%x", len(b), va)
	}
	return binary.LittleEndian.Uint64(b), nil
}

// The image's first CodeView record that names a PDB.
func codeViewAt(r memory.MemoryReader, base uint64) (*Fingerprint, error) {
	records, err := layers.ImageCodeViews(r, base)
	if err != nil {
		return nil, err
	}
	for _, rec := range records {
		if name := pdbBaseName(rec.PDBPath); name != "" {
			return &Fingerprint{PDBName: name, GUID: formatGUID(rec.GUID[:]), Age: rec.Age}, nil
		}
	}
	return nil, fmt.Errorf("autoload: image at 0x%x has no codeview record", base)
}

// A CodeView path is the linker's path to the PDB, with Windows separators.
func pdbBaseName(path string) string {
	return path[strings.LastIndexAny(path, `\/`)+1:]
}
