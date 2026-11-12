package modulelist

import (
	"errors"
	"fmt"
	"math/bits"
	"strings"

	"github.com/aoiflux/libvapour/tools"
)

var ErrNoSystemRangeStart = errors.New("modulelist: symbol table has no MmSystemRangeStart")

// Paging translates 32 bits of a linear address with 4-byte pointers, 48 with
// 4-level paging and 57 with 5-level paging (SDM Vol. 3A 4.5, 5.3, 5.4).
const (
	translatedBits32     = 32
	translatedBits4Level = 48
	translatedBits5Level = 57
)

// Learn: 32-bit Windows gives the upper 2 GB to system space by default.
const systemHalf32 = uint64(1) << 31

func fiveLevel(ctx tools.Context) bool { return strings.HasSuffix(ctx.PagingMode(), "la57") }

func AddressMask(ctx tools.Context) uint64 {
	n := translatedBits4Level
	switch {
	case ctx.Symbols.PointerSize() == 4:
		n = translatedBits32
	case fiveLevel(ctx):
		n = translatedBits5Level
	}
	return uint64(1)<<n - 1
}

func AddressBits(mask uint64) int { return bits.Len64(mask) }

func CanonicalAddress(address, mask uint64, pointerSize uint8) uint64 {
	low := address & mask
	if pointerSize == 4 || mask == ^uint64(0) {
		return low
	}
	if low&(mask^mask>>1) != 0 {
		return low | ^mask
	}
	return low
}

// The lowest address whose top translated bit is set, sign-extended: the
// first address of the upper canonical half.
func KernelHalfStart(ctx tools.Context) uint64 {
	if ctx.Symbols.PointerSize() == 4 {
		return systemHalf32
	}
	return ^(AddressMask(ctx) >> 1)
}

// MmSystemRangeStart is the kernel's own boundary (ntddk.h); it moves up on a
// 32-bit system booted with increaseuserva, so it beats the half start.
func KernelSpaceStart(ctx tools.Context, tool string) (uint64, error) {
	sym, err := ctx.Symbols.LookupSymbol("MmSystemRangeStart")
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrNoSystemRangeStart, err)
	}
	half := KernelHalfStart(ctx)
	start, err := ctx.Symbols.ReadPointer(ctx.Memory, sym.Address)
	if err != nil {
		ctx.AddDiagnostic("%s: MmSystemRangeStart at 0x%x does not read: system space taken to start at 0x%x: %v",
			tool, sym.Address, half, err)
		return half, nil
	}
	mask := AddressMask(ctx)
	if start < half || CanonicalAddress(start, mask, ctx.Symbols.PointerSize()) != start {
		ctx.AddDiagnostic("%s: MmSystemRangeStart at 0x%x holds 0x%x, outside the upper half: system space taken to start at 0x%x",
			tool, sym.Address, start, half)
		return half, nil
	}
	return start, nil
}

type systemSpace struct {
	start uint64
}

func newSystemSpace(ctx tools.Context) systemSpace {
	start, err := KernelSpaceStart(ctx, Name)
	if err != nil {
		start = KernelHalfStart(ctx)
	}
	return systemSpace{start: start}
}

// A driver image is mapped in system space, so a base below it or an empty
// image is a damaged or forged entry; the row stays, the examiner is told.
func (s systemSpace) check(ctx tools.Context, m Module) {
	if !m.BaseUnreadable && m.Base < s.start {
		ctx.AddDiagnostic("%s: loader entry at 0x%x: DllBase 0x%x lies below system space at 0x%x", Name, m.Entry, m.Base, s.start)
	}
	if !m.SizeUnreadable && m.Size == 0 {
		ctx.AddDiagnostic("%s: loader entry at 0x%x: SizeOfImage is 0", Name, m.Entry)
	}
}
