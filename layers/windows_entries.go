package layers

import (
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
)

var softwareProtection = bitRange(9, 5)

type bitField struct{ low, length uint }

func (f bitField) mask() uint64 { return (uint64(1)<<f.length - 1) << f.low }

func (f bitField) get(e uint64) uint64 { return e & f.mask() >> f.low }

// Where _MMPTE_SOFTWARE keeps the pagefile number and the page's place in
// it; builds from 17134 on moved PageFileLow, so it is read from the kernel's
// own types when they are at hand (S53 4.3).
type SoftwareLayout struct {
	pageFile bitField
	offset   bitField
}

var DefaultSoftwareLayout = SoftwareLayout{pageFile: bitField{1, 4}, offset: bitField{32, 32}}

// The fields must not reach the bits the walk tests before them, or one
// entry would decode two ways.
func ReadSoftwareLayout(table symbols.SymbolTable) (SoftwareLayout, error) {
	if table == nil {
		return SoftwareLayout{}, fmt.Errorf("layers: no symbol table describes _MMPTE_SOFTWARE")
	}
	taken := bitPresent | softwareProtection | bitPrototype | bitTransition
	var fields [2]bitField
	for i, member := range []string{"PageFileLow", "PageFileHigh"} {
		f, err := table.Field("_MMPTE_SOFTWARE", member)
		if err != nil {
			return SoftwareLayout{}, fmt.Errorf("layers: _MMPTE_SOFTWARE.%s: %w", member, err)
		}
		if f.Offset >= 8 || f.Type.BitLength == 0 {
			return SoftwareLayout{}, fmt.Errorf("layers: _MMPTE_SOFTWARE.%s is not a bit field of the entry", member)
		}
		b := bitField{low: uint(f.Offset*8) + uint(f.Type.BitOffset), length: uint(f.Type.BitLength)}
		if b.low+b.length > 64 || b.mask()&taken != 0 {
			return SoftwareLayout{}, fmt.Errorf("layers: _MMPTE_SOFTWARE.%s at bits %d:%d overlaps another field of the entry",
				member, b.low+b.length-1, b.low)
		}
		taken |= b.mask()
		fields[i] = b
	}
	return SoftwareLayout{pageFile: fields[0], offset: fields[1]}, nil
}

// The _MMPTE union's members are told apart by Prototype (bit 10) and then
// Transition (bit 11): _MMPTE_PROTOTYPE uses bit 11 as Combined, so the
// prototype test comes first, and with both clear the entry is
// _MMPTE_SOFTWARE.
func (l SoftwareLayout) fault(e, va uint64) UnmappedPageError {
	miss := UnmappedPageError{VirtualAddress: va}
	switch {
	case e&bitPrototype != 0:
		miss.Kind = PagePrototype
	case l.offset.get(e) != 0:
		miss.Kind = PageInPagefile
		miss.PageFileNumber = int(l.pageFile.get(e))
		miss.PageFileOffset = l.offset.get(e) << pageShift
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
func (l SoftwareLayout) ResolveProtoPTE(pte, virtualAddress uint64) (uint64, error) {
	offset := virtualAddress & (pageBytes - 1)
	switch {
	case pte&bitPresent != 0, pte&bitPrototype == 0 && pte&bitTransition != 0:
		return pte&ModeX64.frameMask | offset, nil
	}
	return 0, l.fault(pte, virtualAddress)
}

func ResolveProtoPTE(pte, virtualAddress uint64) (uint64, error) {
	return DefaultSoftwareLayout.ResolveProtoPTE(pte, virtualAddress)
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

// No public source states how SwizzleBit or InvalidPteMask change an entry,
// so a kernel declaring either could send a pagefile read to another page.
func CheckPagefilePTELayout(table symbols.SymbolTable) error {
	if _, err := ReadSoftwareLayout(table); err != nil {
		return err
	}
	if _, err := table.Field("_MMPTE_SOFTWARE", "SwizzleBit"); err == nil {
		return fmt.Errorf("layers: _MMPTE_SOFTWARE has SwizzleBit, and swizzled entries are not decoded")
	}
	if _, err := table.Field("_MI_HARDWARE_STATE", "InvalidPteMask"); err == nil {
		return fmt.Errorf("layers: _MI_HARDWARE_STATE has InvalidPteMask, and swizzled entries are not decoded")
	}
	return nil
}
