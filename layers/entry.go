package layers

const (
	bitPresent    = uint64(1) << 0
	bitDirty      = uint64(1) << 6
	bitPageSize   = uint64(1) << 7
	bitPrototype  = uint64(1) << 10
	bitTransition = uint64(1) << 11
)

type stepKind uint8

const (
	stepNothing stepKind = iota
	stepTable
	stepPage
	stepSoftware
)

type step struct {
	kind stepKind
	addr uint64
	size uint64
}

// What the entry at a level gives a walk: the processor's rules for a present
// entry, and for a not-present one the Windows _MMPTE_TRANSITION reading where
// the mode carries it. A transition entry's bit 7 is part of its Protection
// field, so above the leaf it names a table, never a large page. Reserved bits
// are not tested: the address field alone is read (S53 4.2, O2).
func (m PagingMode) step(level int, e uint64) step {
	last := level == m.leaf()
	if e&bitPresent == 0 {
		switch {
		case !m.windowsEntries:
			return step{kind: stepNothing}
		case e&bitPrototype == 0 && e&bitTransition != 0:
			if last {
				return step{kind: stepPage, addr: e & m.frameMask, size: pageBytes}
			}
			return step{kind: stepTable, addr: e & m.frameMask}
		case last:
			return step{kind: stepSoftware}
		}
		return step{kind: stepNothing}
	}
	switch {
	case last:
		return step{kind: stepPage, addr: e & m.frameMask, size: pageBytes}
	case m.levels[level].mapsPage && e&bitPageSize != 0:
		size := m.span(level)
		if m.pse36 {
			return step{kind: stepPage, addr: e&bitRange(31, 22) | (e>>13&0xff)<<32, size: size}
		}
		return step{kind: stepPage, addr: e & m.frameMask &^ (size - 1), size: size}
	}
	return step{kind: stepTable, addr: e & m.frameMask}
}

func PTEIsHardwareValid(pte uint64) bool { return pte&bitPresent != 0 }

func PTEIsPrototype(pte uint64) bool { return pte&bitPrototype != 0 }

func PTEIsTransition(pte uint64) bool { return pte&bitTransition != 0 }

func PTEHardwareFrame(pte uint64) uint64 { return pte & ModeX64.frameMask }

func PTETransitionFrame(pte uint64) uint64 { return pte & ModeX64.frameMask }
