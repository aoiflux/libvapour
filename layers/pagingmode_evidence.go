package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
)

type PagingModeDecision struct {
	Mode     PagingMode
	Evidence string
}

func bitRange(hi, lo uint) uint64 {
	return (uint64(1)<<(hi-lo+1) - 1) << lo
}

const (
	entryPresent   = uint64(1)
	entryPageSize  = uint64(1) << 7
	wideAddress    = uint64(0x000ffffffffff000)
	narrowAddress  = uint64(0xfffff000)
	pdptAddress    = uint64(0xffffffe0)
	below4G        = uint64(1) << 32
	evidenceBudget = 256
	tableBytes     = 4096
	pdptBytes      = 32
)

type evidenceLevel struct {
	name        string
	refTable    string
	refReserved uint64
	leafOK      bool
	leafTable   string
	leafRes     uint64
}

type evidenceMode struct {
	mode       PagingMode
	label      string
	entryBytes int
	rootBytes  uint64
	rootMask   uint64
	rootTable  string
	wide       bool
	upperFrom  int
	address    uint64
	levels     []evidenceLevel
	// Recent AMD processors load PAE PDPTEs when a walk uses them, not at
	// MOV to CR3 (S04 A16), so only the PDPTEs a kernel runs through are
	// evidence.
	rootUsedOnly bool
}

var (
	evPML5 = evidenceLevel{name: "PML5E", refTable: "5-14", refReserved: entryPageSize}
	evPML4 = evidenceLevel{name: "PML4E", refTable: "5-15", refReserved: entryPageSize}
	evPDPT = evidenceLevel{name: "PDPTE", refTable: "5-17", leafOK: true, leafTable: "5-16", leafRes: bitRange(29, 13)}
	evPD   = evidenceLevel{name: "PDE", refTable: "5-19", leafOK: true, leafTable: "5-18", leafRes: bitRange(20, 13)}

	evLA57 = evidenceMode{mode: ModeLA57, label: "5-level", entryBytes: 8, rootBytes: tableBytes, rootMask: wideAddress,
		rootTable: "5-12", wide: true, upperFrom: 256, address: wideAddress, levels: []evidenceLevel{evPML5, evPML4, evPDPT, evPD}}
	evX64 = evidenceMode{mode: ModeX64, label: "4-level", entryBytes: 8, rootBytes: tableBytes, rootMask: wideAddress,
		rootTable: "5-12", wide: true, upperFrom: 256, address: wideAddress, levels: []evidenceLevel{evPML4, evPDPT, evPD}}
	evPAE = evidenceMode{mode: ModeX86PAE, label: "PAE", entryBytes: 8, rootBytes: pdptBytes, rootMask: pdptAddress,
		rootTable: "5-7", upperFrom: 2, address: wideAddress, rootUsedOnly: true, levels: []evidenceLevel{
			{name: "PDPTE", refTable: "5-8", refReserved: bitRange(2, 1) | bitRange(8, 5) | bitRange(63, 52)},
			{name: "PDE", refTable: "5-10", refReserved: bitRange(62, 52), leafOK: true, leafTable: "5-9",
				leafRes: bitRange(20, 13) | bitRange(62, 52)},
		}}
	evX86 = evidenceMode{mode: ModeX86NonPAE, label: "32-bit", entryBytes: 4, rootBytes: tableBytes, rootMask: narrowAddress,
		rootTable: "5-3", upperFrom: 512, address: narrowAddress, levels: []evidenceLevel{
			{name: "PDE", refTable: "5-5", leafOK: true, leafTable: "5-4", leafRes: uint64(1) << 21},
		}}
)

type modeReading struct {
	ev      evidenceMode
	refuted string
	upper   int
	tables  int
	large   int
	skipped int
}

func (m modeReading) fits() bool { return m.refuted == "" }

func (m modeReading) String() string {
	if !m.fits() {
		return fmt.Sprintf("%s reading refuted: %s", m.ev.label, m.refuted)
	}
	return fmt.Sprintf("%s reading fits: %d upper-half root entries, %d tables read, %d large pages, %d tables unreadable",
		m.ev.label, m.upper, m.tables, m.large, m.skipped)
}

// The stricter reading comes first in each pair: 5-level before 4-level, PAE
// before 32-bit. Its entry formats reserve bits that the other mode's tables
// set, so it survives only on its own tables (S04 section 4).
func DetectPagingMode(r memory.MemoryReader, root uint64, pointerBytes int) (PagingModeDecision, error) {
	var pair [2]evidenceMode
	switch pointerBytes {
	case 8:
		pair = [2]evidenceMode{evLA57, evX64}
	case 4:
		pair = [2]evidenceMode{evPAE, evX86}
	default:
		return PagingModeDecision{}, fmt.Errorf("layers: page table at 0x%x: pointer width %d names no paging mode", root, pointerBytes)
	}
	strict, err := readAs(r, root, pair[0])
	if err != nil {
		return PagingModeDecision{}, err
	}
	loose, err := readAs(r, root, pair[1])
	if err != nil {
		return PagingModeDecision{}, err
	}
	decide := func(chosen, other modeReading) (PagingModeDecision, error) {
		return PagingModeDecision{Mode: chosen.ev.mode, Evidence: chosen.String() + "; " + other.String()}, nil
	}
	if pointerBytes == 4 {
		switch {
		case strict.fits():
			return decide(strict, loose)
		case loose.fits():
			return decide(loose, strict)
		}
	} else {
		switch {
		case strict.fits() && strict.large > 0:
			return decide(strict, loose)
		case loose.fits() && !strict.fits():
			return decide(loose, strict)
		case strict.fits() && !loose.fits():
			return decide(strict, loose)
		}
	}
	return PagingModeDecision{}, fmt.Errorf("layers: page table at 0x%x: paging mode undecided: %s; %s", root, strict, loose)
}

func readAs(r memory.MemoryReader, root uint64, ev evidenceMode) (modeReading, error) {
	rd := modeReading{ev: ev}
	if ev.wide {
		if res := root & bitRange(60, 52); res != 0 {
			rd.refuted = fmt.Sprintf("CR3 value 0x%x sets reserved bits 0x%x (SDM Table %s)", root, res, ev.rootTable)
			return rd, nil
		}
	} else if root >= below4G {
		rd.refuted = fmt.Sprintf("CR3 value 0x%x is at or above 4 GBytes (SDM Table %s)", root, ev.rootTable)
		return rd, nil
	}
	base := root & ev.rootMask
	page, err := r.ReadAt(base, ev.rootBytes)
	if err != nil {
		return rd, fmt.Errorf("layers: page table at 0x%x: read root: %w", base, err)
	}
	if uint64(len(page)) < ev.rootBytes {
		return rd, fmt.Errorf("layers: page table at 0x%x: read root: %d of %d bytes", base, len(page), ev.rootBytes)
	}

	type node struct {
		addr  uint64
		level int
	}
	var queue []node
	seen := map[node]bool{}
	size := r.Size()

	visit := func(table []byte, at uint64, level int) {
		lv := ev.levels[level]
		for i := 0; i*ev.entryBytes < len(table); i++ {
			var e uint64
			if ev.entryBytes == 8 {
				e = binary.LittleEndian.Uint64(table[i*8:])
			} else {
				e = uint64(binary.LittleEndian.Uint32(table[i*4:]))
			}
			if e&entryPresent == 0 {
				continue
			}
			upper := level > 0 || i >= ev.upperFrom
			if level == 0 && !upper && ev.rootUsedOnly {
				continue
			}
			if level == 0 && upper {
				rd.upper++
			}
			if lv.leafOK && e&entryPageSize != 0 {
				if res := e & lv.leafRes; res != 0 {
					rd.refuted = fmt.Sprintf("%s %d of the table at 0x%x is 0x%x, a large page with reserved bits 0x%x set (SDM Table %s)",
						lv.name, i, at, e, res, lv.leafTable)
					return
				}
				rd.large++
				continue
			}
			if res := e & lv.refReserved; res != 0 {
				rd.refuted = fmt.Sprintf("%s %d of the table at 0x%x is 0x%x, with reserved bits 0x%x set (SDM Table %s)",
					lv.name, i, at, e, res, lv.refTable)
				return
			}
			next := e & ev.address
			if next >= size {
				rd.refuted = fmt.Sprintf("%s %d of the table at 0x%x is 0x%x, naming a table at 0x%x past the image's end 0x%x",
					lv.name, i, at, e, next, size)
				return
			}
			if n := (node{next, level + 1}); upper && n.level < len(ev.levels) && !seen[n] {
				seen[n] = true
				queue = append(queue, n)
			}
		}
	}

	visit(page, base, 0)
	if rd.fits() && rd.upper == 0 {
		rd.refuted = fmt.Sprintf("the root at 0x%x maps nothing in the upper half", base)
	}
	for len(queue) > 0 && rd.fits() && rd.tables+rd.skipped < evidenceBudget {
		n := queue[0]
		queue = queue[1:]
		table, err := r.ReadAt(n.addr, tableBytes)
		if err != nil || len(table) < tableBytes {
			rd.skipped++
			continue
		}
		rd.tables++
		visit(table, n.addr, n.level)
	}
	return rd, nil
}
