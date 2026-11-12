package memory

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

var ErrCrashDump = errors.New("memory: crash dump unusable")

// Only the physical memory descriptor has a type source (S71 W2); every other
// offset is measured on the two crash dumps (C2, C3, C5).
const (
	crashSignature   = "PAGE"
	crashKind64      = "DU64"
	crashKind32      = "DUMP"
	crashHeaderBytes = 0x2000
	crashPageBytes   = 0x1000

	crashMajorAt      = 0x08
	crashMinorAt      = 0x0c
	crashRootAt       = 0x10
	crashPfnAt        = 0x18
	crashModulesAt    = 0x20
	crashProcessesAt  = 0x28
	crashMachineAt    = 0x30
	crashProcessorsAt = 0x34
	crashBugCheckAt   = 0x38
	crashDebuggerAt   = 0x80

	// _PHYSICAL_MEMORY_DESCRIPTOR and _PHYSICAL_MEMORY_RUN in the kernel
	// PDBs (S71 W2).
	crashDescriptorAt = 0x88
	crashTotalAt      = crashDescriptorAt + 0x08
	crashRunsAt       = crashDescriptorAt + 0x10
	crashRunBytes     = 0x10
	crashMaxRuns      = (crashHeaderBytes - crashRunsAt) / crashRunBytes

	crashDumpTypeAt   = 0xf98
	crashRequiredAt   = 0xfa0
	crashSystemTimeAt = 0xfa8
	crashCommentAt    = 0xfb0
	crashUpTimeAt     = 0x1030

	crashCommentLength = 128
	crashDumpTypeFull  = 1

	// The writer stores the dump's size over this run's page count when the
	// run array reaches that far (S71 C4).
	crashOverwrittenRun = (crashRequiredAt - crashRunsAt) / crashRunBytes
)

type CrashDumpHeader struct {
	MajorVersion        uint32
	MinorVersion        uint32
	DirectoryTableBase  uint64
	PfnDataBase         uint64
	PsLoadedModuleList  uint64
	PsActiveProcessHead uint64
	MachineImageType    uint32
	NumberProcessors    uint32
	BugCheckCode        uint32
	KdDebuggerDataBlock uint64
	NumberOfRuns        uint32
	NumberOfPages       uint64

	// False when the run array reaches DumpType: the fields from DumpType on
	// then hold run entries.
	DumpType       uint32
	DumpTypeIntact bool

	SystemTime   uint64
	SystemUpTime uint64
	Comment      [crashCommentLength]byte

	RepairedRun       int
	RepairedPageCount uint64
}

type CrashDumpReader struct {
	*SegmentedReader
	header CrashDumpHeader
}

func (r *CrashDumpReader) CrashHeader() CrashDumpHeader { return r.header }

type crashDumpDetector struct{}

func (crashDumpDetector) Name() string { return "crashdump" }

func (crashDumpDetector) Detect(backing MemoryReader) (MemoryReader, bool, error) {
	switch {
	case hasPrefix(backing, crashSignature+crashKind64):
	case hasPrefix(backing, crashSignature+crashKind32):
		return nil, true, fmt.Errorf("%w: 32-bit dump layout is not read", ErrCrashDump)
	default:
		return nil, false, nil
	}
	r, err := openCrashDump(backing)
	if err != nil {
		return nil, true, err
	}
	return r, true, nil
}

type crashRun struct{ base, count uint64 }

func openCrashDump(backing MemoryReader) (*CrashDumpReader, error) {
	if backing.Size() < crashHeaderBytes {
		return nil, fmt.Errorf("%w: file of 0x%x bytes is shorter than the 0x%x-byte header", ErrCrashDump, backing.Size(), crashHeaderBytes)
	}
	raw, err := readFull(backing, 0, crashHeaderBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrCrashDump, err)
	}
	h := parseCrashHeader(raw)
	if h.NumberOfRuns == 0 || h.NumberOfRuns > crashMaxRuns {
		return nil, fmt.Errorf("%w: %d physical memory runs, the header holds 1 to %d", ErrCrashDump, h.NumberOfRuns, crashMaxRuns)
	}
	if h.DumpTypeIntact && h.DumpType != crashDumpTypeFull {
		return nil, fmt.Errorf("%w: dump type %d is not a full dump", ErrCrashDump, h.DumpType)
	}
	runs := make([]crashRun, h.NumberOfRuns)
	for i := range runs {
		at := crashRunsAt + crashRunBytes*i
		runs[i] = crashRun{binary.LittleEndian.Uint64(raw[at:]), binary.LittleEndian.Uint64(raw[at+8:])}
	}
	if err := settleRunTotal(&h, runs); err != nil {
		return nil, err
	}
	segs, err := crashSegments(runs)
	if err != nil {
		return nil, err
	}
	need := crashHeaderBytes + h.NumberOfPages*crashPageBytes
	if h.NumberOfPages > (^uint64(0)-crashHeaderBytes)/crashPageBytes || backing.Size() < need {
		return nil, fmt.Errorf("%w: 0x%x pages need 0x%x bytes, the file has 0x%x", ErrCrashDump, h.NumberOfPages, need, backing.Size())
	}
	seg, err := NewSegmentedReader(backing, segs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCrashDump, err)
	}
	if h.RepairedRun >= 0 {
		seg.repairs = append(seg.repairs, fmt.Sprintf("crash dump: run %d page count 0x%x taken from the page total; its slot held 0x%x",
			h.RepairedRun, h.RepairedPageCount, binary.LittleEndian.Uint64(raw[crashRequiredAt:])))
	}
	return &CrashDumpReader{SegmentedReader: seg, header: h}, nil
}

func parseCrashHeader(raw []byte) CrashDumpHeader {
	u32 := func(at int) uint32 { return binary.LittleEndian.Uint32(raw[at:]) }
	u64 := func(at int) uint64 { return binary.LittleEndian.Uint64(raw[at:]) }
	h := CrashDumpHeader{
		MajorVersion:        u32(crashMajorAt),
		MinorVersion:        u32(crashMinorAt),
		DirectoryTableBase:  u64(crashRootAt),
		PfnDataBase:         u64(crashPfnAt),
		PsLoadedModuleList:  u64(crashModulesAt),
		PsActiveProcessHead: u64(crashProcessesAt),
		MachineImageType:    u32(crashMachineAt),
		NumberProcessors:    u32(crashProcessorsAt),
		BugCheckCode:        u32(crashBugCheckAt),
		KdDebuggerDataBlock: u64(crashDebuggerAt),
		NumberOfRuns:        u32(crashDescriptorAt),
		NumberOfPages:       u64(crashTotalAt),
		RepairedRun:         -1,
	}
	h.DumpTypeIntact = uint64(crashRunsAt)+uint64(h.NumberOfRuns)*crashRunBytes <= crashDumpTypeAt
	if h.DumpTypeIntact {
		h.DumpType = u32(crashDumpTypeAt)
		h.SystemTime = u64(crashSystemTimeAt)
		h.SystemUpTime = u64(crashUpTimeAt)
		copy(h.Comment[:], raw[crashCommentAt:])
	}
	return h
}

// The page counts must add up to the header's total. Only one slot is known
// to be overwritten (C4), so only that run may be recounted from the total,
// and only to a count that fits before the next run.
func settleRunTotal(h *CrashDumpHeader, runs []crashRun) error {
	sum, carry := uint64(0), uint64(0)
	for _, r := range runs {
		var c uint64
		sum, c = bits.Add64(sum, r.count, 0)
		carry |= c
	}
	if carry == 0 && sum == h.NumberOfPages {
		return nil
	}
	if len(runs) <= crashOverwrittenRun {
		return fmt.Errorf("%w: run page counts do not add up to the header's 0x%x pages", ErrCrashDump, h.NumberOfPages)
	}
	var others uint64
	for i, r := range runs {
		if i == crashOverwrittenRun {
			continue
		}
		var c uint64
		if others, c = bits.Add64(others, r.count, 0); c != 0 {
			return fmt.Errorf("%w: run page counts overflow", ErrCrashDump)
		}
	}
	if others >= h.NumberOfPages {
		return fmt.Errorf("%w: runs other than %d already hold 0x%x of the header's 0x%x pages", ErrCrashDump, crashOverwrittenRun, others, h.NumberOfPages)
	}
	count := h.NumberOfPages - others
	run := runs[crashOverwrittenRun]
	if next := crashOverwrittenRun + 1; next < len(runs) && (runs[next].base < run.base || count > runs[next].base-run.base) {
		return fmt.Errorf("%w: run %d recounted to 0x%x pages would reach run %d", ErrCrashDump, crashOverwrittenRun, count, next)
	}
	runs[crashOverwrittenRun].count = count
	h.RepairedRun, h.RepairedPageCount = crashOverwrittenRun, count
	return nil
}

func crashSegments(runs []crashRun) ([]Segment, error) {
	const maxPage = ^uint64(0) / crashPageBytes
	segs := make([]Segment, 0, len(runs))
	file := uint64(crashHeaderBytes)
	var floor uint64
	for i, r := range runs {
		if r.base > maxPage || r.count > maxPage-r.base {
			return nil, fmt.Errorf("%w: run %d (page 0x%x, 0x%x pages) passes the address space", ErrCrashDump, i, r.base, r.count)
		}
		if i > 0 && r.base < floor {
			return nil, fmt.Errorf("%w: run %d at page 0x%x starts before the end of run %d (page 0x%x)", ErrCrashDump, i, r.base, i-1, floor)
		}
		floor = r.base + r.count
		if r.count == 0 {
			continue
		}
		length := r.count * crashPageBytes
		segs = append(segs, Segment{PhysicalBase: r.base * crashPageBytes, FileOffset: file, Length: length})
		if file+length < file {
			return nil, fmt.Errorf("%w: run %d passes the largest file offset", ErrCrashDump, i)
		}
		file += length
	}
	return segs, nil
}
