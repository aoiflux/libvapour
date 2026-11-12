package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

const (
	systemProcessID   = 4
	systemProcessName = "System\x00"
	scanWindowBytes   = uint64(4 << 20)
	upperHalfStart    = uint64(0xFFFF800000000000)
)

// The lowest canonical upper-half address of 4-level paging (SDM 4.5), the
// half both Windows and Linux x64 kernels run in.
const CanonicalKernelMinVA = upperHalfStart

type KernelBootstrap struct {
	CR3       uint64
	ListFlink uint64
	// System is the first process inserted into PsActiveProcessHead, so its
	// Blink is the head itself on every capture measured (S53 M2). Zero when
	// the symbol table has no _LIST_ENTRY.Blink.
	ListBlink uint64
}

type systemLayout struct {
	pid, name, root, flink, blink uint64
	hasBlink                      bool
	span                          uint64
}

func readSystemLayout(table symbols.SymbolTable) (systemLayout, error) {
	if table == nil {
		return systemLayout{}, fmt.Errorf("layers: system process scan: no symbol table")
	}
	var l systemLayout
	need := func(typ, member string) (uint64, error) {
		f, err := table.Field(typ, member)
		if err != nil {
			return 0, fmt.Errorf("layers: system process scan: %s.%s: %w", typ, member, err)
		}
		return f.Offset, nil
	}
	var err error
	if l.pid, err = need("_EPROCESS", "UniqueProcessId"); err != nil {
		return l, err
	}
	if l.name, err = need("_EPROCESS", "ImageFileName"); err != nil {
		return l, err
	}
	links, err := need("_EPROCESS", "ActiveProcessLinks")
	if err != nil {
		return l, err
	}
	flink, err := need("_LIST_ENTRY", "Flink")
	if err != nil {
		return l, err
	}
	l.flink = links + flink
	if b, err := table.Field("_LIST_ENTRY", "Blink"); err == nil {
		l.blink, l.hasBlink = links+b.Offset, true
	}
	pcb, err := need("_EPROCESS", "Pcb")
	if err != nil {
		return l, err
	}
	dtb, err := need("_KPROCESS", "DirectoryTableBase")
	if err != nil {
		return l, err
	}
	l.root = pcb + dtb
	l.span = max(l.pid+8, l.name+uint64(len(systemProcessName)), l.root+8, l.flink+8, l.blink+8)
	return l, nil
}

func FindKernelCR3(r memory.MemoryReader, table symbols.SymbolTable) (uint64, error) {
	b, err := FindKernelBootstrap(r, table)
	if err != nil {
		return 0, err
	}
	return b.CR3, nil
}

// The image's first _EPROCESS, in physical order, that is the System process
// and whose page-table root the processor could have loaded and that maps the
// kernel half (S53 4.1).
func FindKernelBootstrap(r memory.MemoryReader, table symbols.SymbolTable) (*KernelBootstrap, error) {
	l, err := readSystemLayout(table)
	if err != nil {
		return nil, err
	}
	size := r.Size()
	var found *KernelBootstrap
	coverage := memory.ScanWindows(r, scanWindowBytes, l.span, func(_ uint64, w []byte) bool {
		for i := uint64(0); i+l.span <= uint64(len(w)); i += 8 {
			if binary.LittleEndian.Uint64(w[i+l.pid:]) != systemProcessID ||
				!bytes.Equal(w[i+l.name:i+l.name+uint64(len(systemProcessName))], []byte(systemProcessName)) {
				continue
			}
			b := KernelBootstrap{
				CR3:       binary.LittleEndian.Uint64(w[i+l.root:]),
				ListFlink: binary.LittleEndian.Uint64(w[i+l.flink:]),
			}
			if l.hasBlink {
				b.ListBlink = binary.LittleEndian.Uint64(w[i+l.blink:])
			}
			if plausibleRoot(r, b.CR3, size) && b.ListFlink >= upperHalfStart {
				found = &b
				return true
			}
		}
		return false
	})
	if found != nil {
		return found, nil
	}
	if err := coverage.Incomplete(); err != nil {
		return nil, fmt.Errorf("layers: system process scan: no System process in the readable part of the image: %w", err)
	}
	return nil, fmt.Errorf("layers: system process scan: no System process in the %d-byte image", size)
}

// Bits 11:0 of the value are CR3 flags or a PCID (SDM Table 5-12), so only the
// root they leave is tested.
func plausibleRoot(r memory.MemoryReader, cr3, size uint64) bool {
	root := ModeX64.root(cr3)
	if root == 0 || root >= size || cr3&bitRange(60, 52) != 0 {
		return false
	}
	raw, ok := readTable(r, root, pageBytes)
	if !ok {
		return false
	}
	for i := uint64(256); i < 512; i++ {
		if ModeX64.entryAt(raw, i)&bitPresent != 0 {
			return true
		}
	}
	return false
}
