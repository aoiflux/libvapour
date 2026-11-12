package memory

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/limits"
)

var (
	ErrELFCore = errors.New("memory: elf core unusable")
	// Its load segments are one process's virtual memory: read as physical
	// memory they give plausible answers that are wrong.
	ErrProcessCore = errors.New("memory: ELF core of one process, not a memory image")
)

// ELF gABI and include/uapi/linux/elf.h (S71 E1 to E6).
const (
	elfMagic      = "\x7fELF"
	elfClass32    = 1
	elfClass64    = 2
	elfDataLSB    = 1
	elfDataMSB    = 2
	elfTypeCore   = 4
	elfLoad       = 1
	elfNote       = 4
	elfManyPhdrs  = 0xffff
	noteAuxv      = 6
	noteSigInfo   = 0x53494749
	noteFileMap   = 0x46494c45
	noteOwnerCore = "CORE"
	noteVMCore    = "VMCOREINFO"
	noteHeader    = 12
)

type elfShape struct {
	order                  binary.ByteOrder
	wide                   bool
	headerBytes, phdrBytes uint64
	noPhysical             uint64
	phoffAt, shoffAt       int
	phentAt, phnumAt       int
	shentAt                int
	shInfoAt               int
	pOffsetAt, pPhysAt     int
	pFileAt, pAlignAt      int
	sectionBytes           int
}

var (
	elf64 = elfShape{wide: true, headerBytes: 64, phdrBytes: 56, noPhysical: ^uint64(0), phoffAt: 32, shoffAt: 40,
		phentAt: 54, phnumAt: 56, shentAt: 58, shInfoAt: 44, pOffsetAt: 8, pPhysAt: 24, pFileAt: 32, pAlignAt: 48,
		sectionBytes: 64}
	elf32 = elfShape{headerBytes: 52, phdrBytes: 32, noPhysical: 0xffffffff, phoffAt: 28, shoffAt: 32,
		phentAt: 42, phnumAt: 44, shentAt: 46, shInfoAt: 28, pOffsetAt: 4, pPhysAt: 12, pFileAt: 16, pAlignAt: 28,
		sectionBytes: 40}
)

func (s elfShape) word(b []byte, at int) uint64 {
	if s.wide {
		return s.order.Uint64(b[at:])
	}
	return uint64(s.order.Uint32(b[at:]))
}

type elfCoreDetector struct{ l limits.Limits }

func (elfCoreDetector) Name() string { return "elf" }

func (d elfCoreDetector) Detect(backing MemoryReader) (MemoryReader, bool, error) {
	if !hasPrefix(backing, elfMagic) {
		return nil, false, nil
	}
	r, err := openELFCore(backing, d.l)
	if err != nil {
		return nil, true, err
	}
	return r, true, nil
}

type elfProgram struct {
	kind               uint32
	offset, phys, file uint64
	align              uint64
}

func openELFCore(backing MemoryReader, l limits.Limits) (*SegmentedReader, error) {
	shape, progs, err := readProgramHeaders(backing, l.MaxTableEntries)
	if err != nil {
		return nil, err
	}
	process, err := isProcessCore(backing, shape, progs, l)
	if err != nil {
		return nil, err
	}
	if process {
		return nil, fmt.Errorf("%w: notes hold a process's auxiliary vector, signal or file map and no %s", ErrProcessCore, noteVMCore)
	}
	segs, notes, err := loadSegments(backing, shape, progs)
	if err != nil {
		return nil, err
	}
	r, err := NewSegmentedReader(backing, segs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrELFCore, err)
	}
	r.notes = notes
	return r, nil
}

func readProgramHeaders(backing MemoryReader, maxEntries int) (elfShape, []elfProgram, error) {
	ident, err := readFull(backing, 0, 16)
	if err != nil {
		return elfShape{}, nil, fmt.Errorf("%w: identification: %w", ErrELFCore, err)
	}
	var shape elfShape
	switch ident[4] {
	case elfClass64:
		shape = elf64
	case elfClass32:
		shape = elf32
	default:
		return elfShape{}, nil, fmt.Errorf("%w: class %d", ErrELFCore, ident[4])
	}
	switch ident[5] {
	case elfDataLSB:
		shape.order = binary.LittleEndian
	case elfDataMSB:
		shape.order = binary.BigEndian
	default:
		return elfShape{}, nil, fmt.Errorf("%w: data encoding %d", ErrELFCore, ident[5])
	}
	if backing.Size() < shape.headerBytes {
		return elfShape{}, nil, fmt.Errorf("%w: file shorter than its header", ErrELFCore)
	}
	eh, err := readFull(backing, 0, shape.headerBytes)
	if err != nil {
		return elfShape{}, nil, fmt.Errorf("%w: header: %w", ErrELFCore, err)
	}
	if t := shape.order.Uint16(eh[16:]); t != elfTypeCore {
		return elfShape{}, nil, fmt.Errorf("%w: file type %d is not a core file", ErrELFCore, t)
	}
	phoff := shape.word(eh, shape.phoffAt)
	phent := uint64(shape.order.Uint16(eh[shape.phentAt:]))
	count := uint64(shape.order.Uint16(eh[shape.phnumAt:]))
	if count == elfManyPhdrs {
		if count, err = extendedCount(backing, shape, eh); err != nil {
			return elfShape{}, nil, err
		}
	}
	if count == 0 {
		return elfShape{}, nil, fmt.Errorf("%w: no program headers", ErrELFCore)
	}
	if phent < shape.phdrBytes {
		return elfShape{}, nil, fmt.Errorf("%w: program header entries of %d bytes, %d needed", ErrELFCore, phent, shape.phdrBytes)
	}
	if count > uint64(maxEntries) {
		return elfShape{}, nil, fmt.Errorf("%w: %d program headers, over the MaxTableEntries limit of %d", ErrELFCore, count, maxEntries)
	}
	if phoff > backing.Size() || count > (backing.Size()-phoff)/phent {
		return elfShape{}, nil, fmt.Errorf("%w: %d program headers at 0x%x pass the end of the file", ErrELFCore, count, phoff)
	}
	table, err := readFull(backing, phoff, count*phent)
	if err != nil {
		return elfShape{}, nil, fmt.Errorf("%w: program headers: %w", ErrELFCore, err)
	}
	progs := make([]elfProgram, count)
	for i := range progs {
		p := table[uint64(i)*phent:]
		progs[i] = elfProgram{
			kind:   shape.order.Uint32(p),
			offset: shape.word(p, shape.pOffsetAt),
			phys:   shape.word(p, shape.pPhysAt),
			file:   shape.word(p, shape.pFileAt),
			align:  shape.word(p, shape.pAlignAt),
		}
	}
	return shape, progs, nil
}

func extendedCount(backing MemoryReader, shape elfShape, eh []byte) (uint64, error) {
	shoff := shape.word(eh, shape.shoffAt)
	shent := uint64(shape.order.Uint16(eh[shape.shentAt:]))
	if shoff == 0 || shent < uint64(shape.sectionBytes) || shoff > backing.Size() || shent > backing.Size()-shoff {
		return 0, fmt.Errorf("%w: program header count is in section header 0, which is missing", ErrELFCore)
	}
	sh, err := readFull(backing, shoff, shent)
	if err != nil {
		return 0, fmt.Errorf("%w: section header 0: %w", ErrELFCore, err)
	}
	return uint64(shape.order.Uint32(sh[shape.shInfoAt:])), nil
}

// A VMCOREINFO note marks the kernel's own capture even where a process
// note type also appears (/proc/kcore writes NT_PRPSINFO, E4); only the
// notes that the kernel writes for a process dump mark a process core.
func isProcessCore(backing MemoryReader, shape elfShape, progs []elfProgram, l limits.Limits) (bool, error) {
	process, notes := false, 0
	for _, p := range progs {
		if p.kind != elfNote || p.file == 0 {
			continue
		}
		if p.file > uint64(l.MaxBufferBytes) {
			return false, fmt.Errorf("%w: note segment of 0x%x bytes at 0x%x, over the MaxBufferBytes limit", ErrELFCore, p.file, p.offset)
		}
		if p.offset > backing.Size() || p.file > backing.Size()-p.offset {
			return false, fmt.Errorf("%w: note segment at 0x%x passes the end of the file", ErrELFCore, p.offset)
		}
		body, err := readFull(backing, p.offset, p.file)
		if err != nil {
			return false, fmt.Errorf("%w: note segment at 0x%x: %w", ErrELFCore, p.offset, err)
		}
		align := uint64(4)
		if p.align == 8 {
			align = 8
		}
		for at := uint64(0); uint64(len(body))-at >= noteHeader; {
			namesz := uint64(shape.order.Uint32(body[at:]))
			descsz := uint64(shape.order.Uint32(body[at+4:]))
			typ := shape.order.Uint32(body[at+8:])
			if namesz == 0 {
				break
			}
			nameEnd := at + noteHeader + namesz
			if nameEnd > uint64(len(body)) {
				break
			}
			if notes == l.MaxListEntries {
				return false, fmt.Errorf("%w: more than %d notes, the MaxListEntries limit", ErrELFCore, l.MaxListEntries)
			}
			notes++
			name := strings.TrimRight(string(body[at+noteHeader:nameEnd]), "\x00")
			switch {
			case name == noteVMCore:
				return false, nil
			case name == noteOwnerCore && (typ == noteAuxv || typ == noteSigInfo || typ == noteFileMap):
				process = true
			}
			next := alignUp(alignUp(nameEnd, align)+descsz, align)
			if next <= at || next > uint64(len(body)) {
				break
			}
			at = next
		}
	}
	return process, nil
}

func alignUp(v, align uint64) uint64 {
	if v > ^uint64(0)-(align-1) {
		return ^uint64(0)
	}
	return (v + align - 1) &^ (align - 1)
}

// The kernel's capture header maps its text twice, once inside the RAM range
// that holds it (E3), so a segment inside another is the same bytes and is
// left out. A partial overlap has no such reading and is refused.
func loadSegments(backing MemoryReader, shape elfShape, progs []elfProgram) ([]Segment, []string, error) {
	var segs []Segment
	unplaced := 0
	for i, p := range progs {
		if p.kind != elfLoad || p.file == 0 {
			continue
		}
		if p.phys == shape.noPhysical {
			unplaced++
			continue
		}
		if p.offset > backing.Size() || p.file > backing.Size()-p.offset {
			return nil, nil, fmt.Errorf("%w: load segment %d (0x%x bytes at 0x%x) passes the end of the file", ErrELFCore, i, p.file, p.offset)
		}
		if p.phys+p.file < p.phys {
			return nil, nil, fmt.Errorf("%w: load segment %d at physical 0x%x passes the top of the address space", ErrELFCore, i, p.phys)
		}
		segs = append(segs, Segment{PhysicalBase: p.phys, FileOffset: p.offset, Length: p.file})
	}
	if len(segs) == 0 {
		return nil, nil, fmt.Errorf("%w: no load segment with a physical address", ErrELFCore)
	}
	slices.SortStableFunc(segs, func(a, b Segment) int {
		switch {
		case a.PhysicalBase != b.PhysicalBase:
			if a.PhysicalBase < b.PhysicalBase {
				return -1
			}
			return 1
		case a.Length > b.Length:
			return -1
		case a.Length < b.Length:
			return 1
		}
		return 0
	})
	kept := segs[:0]
	var reach uint64
	inside := 0
	for _, s := range segs {
		end := s.PhysicalBase + s.Length
		switch {
		case len(kept) == 0 || s.PhysicalBase >= reach:
			kept = append(kept, s)
			reach = end
		case end <= reach:
			inside++
		default:
			return nil, nil, fmt.Errorf("%w: load segment at physical 0x%x overlaps the one before it, which ends at 0x%x", ErrELFCore, s.PhysicalBase, reach)
		}
	}
	var notes []string
	if inside > 0 {
		notes = append(notes, fmt.Sprintf("elf: %d load segments lie inside another and were left out", inside))
	}
	if unplaced > 0 {
		notes = append(notes, fmt.Sprintf("elf: %d load segments have no physical address and were left out", unplaced))
	}
	return kept, notes, nil
}
