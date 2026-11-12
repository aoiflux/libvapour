package layers

import "encoding/binary"

const (
	pageShift = 12
	pageBytes = uint64(1) << pageShift
)

type tableLevel struct {
	indexBits uint
	mapsPage  bool
}

type PagingMode struct {
	name       string
	levels     []tableLevel
	entryBytes uint64
	rootMask   uint64
	frameMask  uint64
	pse36      bool
	// The x64 presets give a not-present entry the meanings of the Windows
	// _MMPTE union; LinuxMode and the 32-bit presets give it none.
	windowsEntries bool
}

var (
	ModeX64 = PagingMode{
		name:           "x64",
		levels:         []tableLevel{{9, false}, {9, true}, {9, true}, {9, false}},
		entryBytes:     8,
		rootMask:       bitRange(51, 12),
		frameMask:      bitRange(51, 12),
		windowsEntries: true,
	}
	ModeLA57 = PagingMode{
		name:           "la57",
		levels:         []tableLevel{{9, false}, {9, false}, {9, true}, {9, true}, {9, false}},
		entryBytes:     8,
		rootMask:       bitRange(51, 12),
		frameMask:      bitRange(51, 12),
		windowsEntries: true,
	}
	ModeX86PAE = PagingMode{
		name:       "x86pae",
		levels:     []tableLevel{{2, false}, {9, true}, {9, false}},
		entryBytes: 8,
		rootMask:   bitRange(31, 5),
		frameMask:  bitRange(51, 12),
	}
	ModeX86NonPAE = PagingMode{
		name:       "x86",
		levels:     []tableLevel{{10, true}, {10, false}},
		entryBytes: 4,
		rootMask:   bitRange(31, 12),
		frameMask:  bitRange(31, 12),
		pse36:      true,
	}
)

func (m PagingMode) Name() string { return m.name }

func PagingModeByName(name string) (PagingMode, bool) {
	for _, m := range []PagingMode{ModeX64, ModeLA57, ModeX86PAE, ModeX86NonPAE} {
		if m.name == name {
			return m, true
		}
	}
	return PagingMode{}, false
}

// Linux keeps swap entries, PROT_NONE pages and L1TF-inverted frames in
// not-present entries, so only what the processor would follow is followed.
// The frame field is the kernel's PTE_PFN_MASK: bits below its physical width,
// less the SME encryption bit it removes from physical_mask.
func LinuxMode(mode PagingMode, physicalBits uint, encryptionMask uint64) PagingMode {
	m := mode.effective()
	m.name = "linux-" + m.name
	m.windowsEntries = false
	if m.entryBytes == 8 && m.rootMask == bitRange(51, 12) {
		frame := bitRange(51, 12)
		if physicalBits > pageShift && physicalBits < 52 {
			frame = bitRange(physicalBits-1, pageShift)
		}
		frame &^= encryptionMask
		m.frameMask, m.rootMask = frame, frame
	}
	return m
}

func (m PagingMode) effective() PagingMode {
	if len(m.levels) == 0 {
		return ModeX64
	}
	return m
}

func (m PagingMode) shift(level int) uint {
	s := uint(pageShift)
	for _, l := range m.levels[level+1:] {
		s += l.indexBits
	}
	return s
}

func (m PagingMode) span(level int) uint64 { return uint64(1) << m.shift(level) }

func (m PagingMode) leaf() int { return len(m.levels) - 1 }

func (m PagingMode) addressBits() uint { return m.shift(-1) }

func (m PagingMode) index(va uint64, level int) uint64 {
	return va >> m.shift(level) & (uint64(1)<<m.levels[level].indexBits - 1)
}

func (m PagingMode) tableSize(level int) uint64 {
	return m.entryBytes << m.levels[level].indexBits
}

func (m PagingMode) root(cr3 uint64) uint64 { return cr3 & m.rootMask }

func (m PagingMode) entryAt(table []byte, i uint64) uint64 {
	if m.entryBytes == 8 {
		return binary.LittleEndian.Uint64(table[i*8:])
	}
	return uint64(binary.LittleEndian.Uint32(table[i*4:]))
}

// A 64-bit address space is canonical: the upper half repeats its top
// address bit through bit 63 (SDM 4.5).
func (m PagingMode) canonical(va uint64) uint64 {
	bits := m.addressBits()
	if bits <= 32 || bits >= 64 || va&(uint64(1)<<(bits-1)) == 0 {
		return va
	}
	return va | ^(uint64(1)<<bits - 1)
}
