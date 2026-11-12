package util

// An alignment of 0 means none. Any other alignment works, power of two or not;
// AlignUp wraps past the top of the uint64 range as unsigned arithmetic does.

func AlignDown(value uint64, alignment uint64) uint64 {
	if alignment == 0 {
		return value
	}
	return value - value%alignment
}

func AlignUp(value uint64, alignment uint64) uint64 {
	if alignment == 0 {
		return value
	}
	if r := value % alignment; r != 0 {
		return value + (alignment - r)
	}
	return value
}

func IsAligned(value uint64, alignment uint64) bool {
	return alignment == 0 || value%alignment == 0
}
