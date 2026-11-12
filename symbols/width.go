package symbols

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strings"
)

// The data model that sizes a C type name in a table declaring no scalars.
type Platform uint8

const (
	PlatformUnknown Platform = iota
	PlatformWindows
	PlatformLinux
)

var ErrPlatformUnknown = errors.New("symbols: table platform not known")

// The width of a type expression: a pointer is the table's pointer width, an
// array its count times its element, a bitfield its storage unit, and a name
// whatever named says. 0 means the width is not known.
func exprWidth(ref TypeRef, pointer uint64, named func(string) (uint64, error)) (uint64, error) {
	times := uint64(1)
	for range MaxTypeOperators + 1 {
		op, _ := ref.operators()
		switch op {
		case opPointer:
			return product(times, pointer), nil
		case opArray:
			times = product(times, ref.ArrayLength)
			if times == 0 {
				return 0, nil
			}
		case opNone:
			w, err := named(ref.Name)
			return product(times, w), err
		}
		ref = ref.inner()
	}
	return 0, nil
}

func product(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return 0
	}
	return lo
}

// The C type names whose width the data model decides rather than C itself.
type modelled uint8

const (
	modelFixed modelled = iota
	modelLong
	modelLongDouble
	modelWideChar
)

// Microsoft Learn, "Data Type Ranges": long 4, long double 8 and wchar_t 2
// bytes, for 32- and 64-bit code alike.
var windowsWidths = map[modelled]uint64{modelLong: 4, modelLongDouble: 8, modelWideChar: 2}

// The width of a C type name that is the same under every data model the
// package knows; a name such as long, whose width the platform decides, is
// unknown here (ScalarWidth answers it).
func BaseTypeWidth(name string, pointerSize uint8) uint64 {
	w, m := cTypeWidth(name, pointerSize)
	if m != modelFixed {
		return 0
	}
	return w
}

// A platform-dependent name in a table of unknown platform is an error
// rather than a guess, since long is 4 bytes on Windows and 8 on 64-bit Linux.
func ScalarWidth(p Platform, name string, pointerSize uint8) (uint64, error) {
	w, m := cTypeWidth(name, pointerSize)
	if m == modelFixed {
		return w, nil
	}
	switch p {
	case PlatformWindows:
		return windowsWidths[m], nil
	case PlatformLinux:
		return linuxWidth(m, pointerSize), nil
	}
	return 0, fmt.Errorf("%w: width of %q depends on it", ErrPlatformUnknown, strings.TrimSpace(name))
}

// The x86-64 System V psABI, Figure 3.1 "Scalar Types": long is 8 bytes under
// LP64 and 4 under ILP32, long double 16 under both. It does not size
// wchar_t, which stays unknown.
func linuxWidth(m modelled, pointerSize uint8) uint64 {
	switch {
	case m == modelLong && (pointerSize == 4 || pointerSize == 8):
		return uint64(pointerSize)
	case m == modelLongDouble:
		return 16
	}
	return 0
}

// A name is the multiset of its C type specifiers, in any order (C11 6.7.2),
// so "long unsigned int" is unsigned long.
func cTypeWidth(name string, pointerSize uint8) (uint64, modelled) {
	name = strings.TrimSpace(name)
	if name == "pointer" || strings.HasSuffix(name, "*") {
		return uint64(pointerSize), modelFixed
	}
	if w, ok := fixedWidth[name]; ok {
		return w, modelFixed
	}
	if name == "wchar_t" || name == "__wchar_t" {
		return 0, modelWideChar
	}
	var signs, chars, shorts, ints, longs, doubles int
	sized := uint64(0)
	for _, word := range strings.Fields(name) {
		switch word {
		case "signed", "unsigned":
			signs++
		case "char":
			chars++
		case "short":
			shorts++
		case "int":
			ints++
		case "long":
			longs++
		case "double":
			doubles++
		case "__int8", "__int16", "__int32", "__int64":
			if sized != 0 {
				return 0, modelFixed
			}
			sized = fixedWidth[word]
		default:
			return 0, modelFixed
		}
	}
	switch {
	case signs > 1:
		return 0, modelFixed
	case sized != 0:
		if chars+shorts+ints+longs+doubles > 0 {
			return 0, modelFixed
		}
		return sized, modelFixed
	case doubles == 1:
		switch {
		case signs+chars+shorts+ints > 0 || longs > 1:
			return 0, modelFixed
		case longs == 1:
			return 0, modelLongDouble
		}
		return 8, modelFixed
	case doubles > 1 || ints > 1:
		return 0, modelFixed
	case chars == 1:
		if shorts+ints+longs > 0 {
			return 0, modelFixed
		}
		return 1, modelFixed
	case chars > 1:
		return 0, modelFixed
	case shorts == 1:
		if longs > 0 {
			return 0, modelFixed
		}
		return 2, modelFixed
	case shorts > 1:
		return 0, modelFixed
	case longs == 2:
		return 8, modelFixed
	case longs > 2:
		return 0, modelFixed
	case longs == 1:
		return 0, modelLong
	case ints == 1, signs == 1:
		return 4, modelFixed
	}
	return 0, modelFixed
}

var fixedWidth = map[string]uint64{
	"bool": 1, "_Bool": 1, "char8_t": 1, "char16_t": 2, "char32_t": 4,
	"float":  4,
	"__int8": 1, "__int16": 2, "__int32": 4, "__int64": 8,
	"int8": 1, "uint8": 1, "int16": 2, "uint16": 2, "int32": 4, "uint32": 4, "int64": 8, "uint64": 8,
	"int8_t": 1, "uint8_t": 1, "int16_t": 2, "uint16_t": 2, "int32_t": 4, "uint32_t": 4, "int64_t": 8, "uint64_t": 8,
}

// An enumeration whose width the source does not give is stored as an int
// (Microsoft Learn, "C Enumeration Declarations"), widened to 8 bytes only when
// a constant does not fit 32 bits, since the storage holds every constant
// (C11 6.7.2.2).
func enumWidth(e EnumType) uint64 {
	if e.Size > 0 {
		return e.Size
	}
	signed, unsigned := true, true
	for _, v := range e.Values {
		if v.Value < math.MinInt32 || v.Value > math.MaxInt32 {
			signed = false
		}
		if v.Value < 0 || v.Value > math.MaxUint32 {
			unsigned = false
		}
	}
	if signed || unsigned {
		return 4
	}
	return 8
}

// Least significant byte first (x86-64; Intel SDM Vol. 1, byte order). Any
// width up to 8 is decoded, since 3-, 5-, 6- and 7-byte members exist.
func littleEndian(raw []byte) uint64 {
	var v uint64
	for i := len(raw) - 1; i >= 0; i-- {
		v = v<<8 | uint64(raw[i])
	}
	return v
}

func bitsOf(word uint64, offset, length uint8) uint64 {
	if length == 0 {
		return word
	}
	if offset >= 64 {
		return 0
	}
	word >>= offset
	if length >= 64 {
		return word
	}
	return word & (1<<length - 1)
}
