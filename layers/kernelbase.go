package layers

import (
	"encoding/binary"
	"fmt"
	"path"
	"strings"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

// The debugger data block as measured on the captures whose block is not
// encoded (S53 M5): the tag "KDBG" 16 bytes in, the block's size after it,
// then KernBase.
const (
	debuggerTag      = "KDBG"
	debuggerTagAt    = 0x10
	debuggerSizeAt   = 0x14
	debuggerBaseAt   = 0x18
	debuggerMinBytes = debuggerBaseAt + 8
	debuggerScanStep = uint64(8 << 20)
)

// A kernel-base candidate is a page-aligned upper-half address whose first
// bytes read "MZ" through the kernel's own page tables. The caller confirms
// the build from the image's CodeView record.
type kernelSpace struct {
	space memory.MemoryReader
	mode  PagingMode
}

func newKernelSpace(physical memory.MemoryReader, cr3 uint64) kernelSpace {
	mode := ModeX64
	if d, err := DetectPagingMode(physical, cr3, 8); err == nil {
		mode = d.Mode
	}
	t := &IntelTranslator{Physical: physical, CR3: cr3, Mode: mode}
	return kernelSpace{space: NewVirtualMemoryLayer(physical, t), mode: mode}
}

func (k kernelSpace) imageAt(base uint64) bool {
	if base < upperHalfStart || base%pageBytes != 0 {
		return false
	}
	mz, err := k.space.ReadAt(base, 2)
	return err == nil && len(mz) == 2 && mz[0] == 'M' && mz[1] == 'Z'
}

func listHeadRVA(table symbols.SymbolTable) (uint64, error) {
	if table == nil {
		return 0, fmt.Errorf("no symbol table")
	}
	sym, err := table.LookupSymbol("PsActiveProcessHead")
	if err != nil {
		return 0, fmt.Errorf("PsActiveProcessHead: %w", err)
	}
	if sym.Address == 0 || sym.Address >= upperHalfStart {
		return 0, fmt.Errorf("PsActiveProcessHead at 0x%x is not image-relative", sym.Address)
	}
	return sym.Address, nil
}

func FindKernelBaseFromListHead(physical memory.MemoryReader, cr3 uint64, table symbols.SymbolTable, head uint64) (uint64, error) {
	if head == 0 {
		return 0, fmt.Errorf("layers: kernel base from the list head: no head address")
	}
	rva, err := listHeadRVA(table)
	if err != nil {
		return 0, fmt.Errorf("layers: kernel base from the list head: %w", err)
	}
	if head < upperHalfStart+rva {
		return 0, fmt.Errorf("layers: kernel base from the list head: 0x%x less 0x%x is not in the kernel half", head, rva)
	}
	base := head - rva
	if !newKernelSpace(physical, cr3).imageAt(base) {
		return 0, fmt.Errorf("layers: kernel base from the list head: no image at 0x%x", base)
	}
	return base, nil
}

func FindKernelBaseByProcessListAnchor(physical memory.MemoryReader, cr3 uint64, table symbols.SymbolTable, listFlink uint64, maxNodes int) (uint64, error) {
	if listFlink == 0 {
		return 0, fmt.Errorf("layers: kernel base from the process list: no list entry")
	}
	rva, err := listHeadRVA(table)
	if err != nil {
		return 0, fmt.Errorf("layers: kernel base from the process list: %w", err)
	}
	if maxNodes <= 0 {
		maxNodes = limits.DefaultMaxListEntries
	}
	k := newKernelSpace(physical, cr3)
	node := listFlink
	for range maxNodes {
		if node >= upperHalfStart+rva && k.imageAt(node-rva) {
			return node - rva, nil
		}
		raw, err := k.space.ReadAt(node, 8)
		if err != nil {
			return 0, fmt.Errorf("layers: kernel base from the process list: entry at 0x%x: %w", node, err)
		}
		next := binary.LittleEndian.Uint64(raw)
		switch {
		case next == listFlink:
			return 0, fmt.Errorf("layers: kernel base from the process list: entry at 0x%x: the list returns to its start without the head", node)
		case next == node:
			return 0, fmt.Errorf("layers: kernel base from the process list: entry at 0x%x: points to itself", node)
		case next < upperHalfStart:
			return 0, fmt.Errorf("layers: kernel base from the process list: entry at 0x%x: next entry 0x%x is outside the kernel half", node, next)
		}
		node = next
	}
	return 0, fmt.Errorf("layers: kernel base from the process list: no head in the first %d entries", maxNodes)
}

// Windows 8 and later may keep the block encoded (KdpDataBlockEncoded); an
// encoded block has no readable tag and the scan finds nothing.
func FindKernelBaseFromKDBG(physical memory.MemoryReader) (uint64, error) {
	var base uint64
	tag := []byte(debuggerTag)
	coverage := memory.ScanWindows(physical, debuggerScanStep, debuggerMinBytes, func(_ uint64, w []byte) bool {
		for i := debuggerTagAt; i+debuggerMinBytes-debuggerTagAt <= len(w); i += 8 {
			if w[i] != tag[0] || string(w[i:i+4]) != debuggerTag {
				continue
			}
			size := binary.LittleEndian.Uint32(w[i-debuggerTagAt+debuggerSizeAt:])
			candidate := binary.LittleEndian.Uint64(w[i-debuggerTagAt+debuggerBaseAt:])
			if size >= debuggerMinBytes && uint64(size) <= pageBytes && candidate >= upperHalfStart && candidate%pageBytes == 0 {
				base = candidate
				return true
			}
		}
		return false
	})
	if base != 0 {
		return base, nil
	}
	if err := coverage.Incomplete(); err != nil {
		return 0, fmt.Errorf("layers: kernel base from the debugger data block: none in the readable part of the image: %w", err)
	}
	return 0, fmt.Errorf("layers: kernel base from the debugger data block: none in the image")
}

// Every page start the kernel half maps is a candidate base, read through the
// address-space listing so that only mapped, captured pages are touched.
func FindKernelImageBase(physical memory.MemoryReader, cr3 uint64, pdbName string) (uint64, error) {
	want := strings.ToLower(path.Base(strings.ReplaceAll(pdbName, `\`, "/")))
	if want == "" || want == "." {
		return 0, fmt.Errorf("layers: kernel image scan: no PDB name")
	}
	k := newKernelSpace(physical, cr3)
	t := &IntelTranslator{Physical: physical, CR3: cr3, Mode: k.mode}
	var found uint64
	errFound := fmt.Errorf("found")
	_, err := t.Mapping(func(r MappedRun) error {
		if r.Virtual < upperHalfStart {
			return nil
		}
		for off := uint64(0); off < r.Size; off += pageBytes {
			mz, err := physical.ReadAt(r.Physical+off, 2)
			if err != nil || len(mz) != 2 || mz[0] != 'M' || mz[1] != 'Z' {
				continue
			}
			records, err := ImageCodeViews(k.space, r.Virtual+off)
			if err != nil {
				continue
			}
			for _, rec := range records {
				if strings.ToLower(path.Base(strings.ReplaceAll(rec.PDBPath, `\`, "/"))) == want {
					found = r.Virtual + off
					return errFound
				}
			}
		}
		return nil
	})
	if found != 0 {
		return found, nil
	}
	if err != nil {
		return 0, fmt.Errorf("layers: kernel image scan: %w", err)
	}
	return 0, fmt.Errorf("layers: kernel image scan: no image in the kernel half names %s", pdbName)
}
