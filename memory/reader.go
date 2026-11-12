package memory

import (
	"errors"
	"fmt"
	"math"
)

type MemoryReader interface {
	ReadAt(offset uint64, size uint64) ([]byte, error)
	Size() uint64
}

var (
	ErrOutOfBounds = errors.New("memory: read out of bounds")
	// Checked before allocating: the size often comes from the image itself.
	ErrSizeOverflow = errors.New("memory: read size overflows int")
	ErrUnmapped     = errors.New("memory: physical address not in image")
)

// A content cache is safe only over bytes that never change, so a live
// source must not claim this.
type ImmutableSnapshot interface {
	ImmutableSnapshot() bool
}

func IsImmutableSnapshot(r MemoryReader) bool {
	s, ok := r.(ImmutableSnapshot)
	return ok && s.ImmutableSnapshot()
}

// checkSpan applies the contract every reader here shares: a size above int
// is refused before anything is allocated, and the span must lie below
// limit without wrapping.
func checkSpan(offset, size, limit uint64) error {
	if size > math.MaxInt {
		return fmt.Errorf("%w: 0x%x bytes at 0x%x", ErrSizeOverflow, size, offset)
	}
	if offset > limit || size > limit-offset {
		return fmt.Errorf("%w: 0x%x bytes at 0x%x, size 0x%x", ErrOutOfBounds, size, offset, limit)
	}
	return nil
}
