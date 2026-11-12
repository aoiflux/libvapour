package layers

import (
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
)

// _MMPTE_SOFTWARE as builds before 17134 declare it: PageFileLow bits 4:1,
// Protection 9:5, PageFileHigh 63:32.
var (
	softwarePageFile   = bitRange(4, 1)
	softwareProtection = bitRange(9, 5)
	softwareOffset     = bitRange(63, 32)
)

// The _MMPTE union's members are told apart by Prototype (bit 10) and then
// Transition (bit 11): _MMPTE_PROTOTYPE uses bit 11 as Combined, so the
// prototype test comes first, and with both clear the entry is
// _MMPTE_SOFTWARE.
func softwareFault(e, va uint64) UnmappedPageError {
	miss := UnmappedPageError{VirtualAddress: va}
	switch {
	case e&bitPrototype != 0:
		miss.Kind = PagePrototype
	case e&softwareOffset != 0:
		miss.Kind = PageInPagefile
		miss.PageFileNumber = int(e & softwarePageFile >> 1)
		miss.PageFileOffset = e >> 32 << pageShift
	case e&softwareProtection != 0:
		miss.Kind = PageDemandZero
	default:
		miss.Kind = PageInvalid
	}
	return miss
}

// Unlike a page-table entry, a prototype entry is read by the memory manager,
// not the processor, and very often holds a valid hardware entry for a shared
// page; so the valid case comes first here.
func ResolveProtoPTE(pte, virtualAddress uint64) (uint64, error) {
	offset := virtualAddress & (pageBytes - 1)
	switch {
	case pte&bitPresent != 0, pte&bitPrototype == 0 && pte&bitTransition != 0:
		return pte&ModeX64.frameMask | offset, nil
	}
	return 0, softwareFault(pte, virtualAddress)
}

// ProtoAddress is a signed 48-bit member at bits 63:16 on every build, so an
// arithmetic shift gives the canonical address of the entry it names.
func PrototypeEntryAddress(entry uint64) (uint64, bool) {
	if entry&bitPresent != 0 || entry&bitPrototype == 0 {
		return 0, false
	}
	return uint64(int64(entry) >> protoAddressShift), true
}

const protoAddressShift = 16

// The pagefile number and offset are decoded in the pre-17134 layout only.
// Later builds move PageFileLow to bits 15:12 and may XOR PageFileHigh with
// MiState.Hardware.InvalidPteMask, so a pagefile read there would return
// another page's bytes.
func CheckPagefilePTELayout(table symbols.SymbolTable) error {
	if table == nil {
		return fmt.Errorf("layers: no symbol table describes _MMPTE_SOFTWARE")
	}
	for _, want := range []struct {
		member  string
		low, hi uint
	}{{"PageFileLow", 1, 4}, {"PageFileHigh", 32, 63}} {
		f, err := table.Field("_MMPTE_SOFTWARE", want.member)
		if err != nil {
			return fmt.Errorf("layers: _MMPTE_SOFTWARE.%s: %w", want.member, err)
		}
		low := uint(f.Offset*8) + uint(f.Type.BitOffset)
		if f.Type.BitLength == 0 || low != want.low || low+uint(f.Type.BitLength)-1 != want.hi {
			return fmt.Errorf("layers: _MMPTE_SOFTWARE.%s is bits %d:%d, not the %d:%d decoded", want.member,
				low+uint(f.Type.BitLength)-1, low, want.hi, want.low)
		}
	}
	if _, err := table.Field("_MMPTE_SOFTWARE", "SwizzleBit"); err == nil {
		return fmt.Errorf("layers: _MMPTE_SOFTWARE has SwizzleBit, and swizzled entries are not decoded")
	}
	if _, err := table.Field("_MI_HARDWARE_STATE", "InvalidPteMask"); err == nil {
		return fmt.Errorf("layers: _MI_HARDWARE_STATE has InvalidPteMask, and swizzled entries are not decoded")
	}
	return nil
}
