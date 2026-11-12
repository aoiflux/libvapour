package symbols

import (
	"errors"
	"math"
	"testing"
)

func TestScalarWidthsCommonToEveryPlatform(t *testing.T) {
	for name, want := range map[string]uint64{
		"char": 1, "signed char": 1, "unsigned char": 1, "bool": 1, "_Bool": 1, "char8_t": 1,
		"short": 2, "short int": 2, "unsigned short": 2, "short unsigned int": 2, "signed short int": 2,
		"char16_t": 2,
		"int":      4, "signed": 4, "unsigned": 4, "unsigned int": 4, "float": 4, "char32_t": 4,
		"long long": 8, "unsigned long long": 8, "long long unsigned int": 8, "double": 8,
		"__int8": 1, "unsigned __int16": 2, "__int32": 4, "unsigned __int64": 8,
		"uint8": 1, "int16": 2, "uint32_t": 4, "int64": 8,
		" unsigned  int ": 4, "pointer": 8, "char *": 8,
		"": 0, "_LIST_ENTRY": 0, "u32": 0, "unsigned unsigned": 0, "short long": 0, "char int": 0,
		"long long long": 0, "long float": 0, "signed double": 0, "unsigned bool": 0, "__int8 int": 0,
		"Unsigned Int": 0, "long long double": 0,
		"long": 0, "unsigned long": 0, "long double": 0, "wchar_t": 0,
	} {
		if got := BaseTypeWidth(name, 8); got != want {
			t.Errorf("BaseTypeWidth(%q) = %d, want %d", name, got, want)
		}
		for _, p := range []Platform{PlatformUnknown, PlatformWindows, PlatformLinux} {
			if want == 0 {
				continue
			}
			if got, err := ScalarWidth(p, name, 8); err != nil || got != want {
				t.Errorf("ScalarWidth(%d, %q) = %d, %v, want %d", p, name, got, err, want)
			}
		}
	}
	if got := BaseTypeWidth("pointer", 4); got != 4 {
		t.Errorf("4-byte pointer: %d", got)
	}
}

func TestPlatformDependentWidthsFollowTheDataModel(t *testing.T) {
	for _, tc := range []struct {
		platform Platform
		pointer  uint8
		name     string
		want     uint64
	}{
		{PlatformWindows, 8, "long", 4}, {PlatformWindows, 8, "long unsigned int", 4},
		{PlatformWindows, 4, "signed long int", 4}, {PlatformWindows, 8, "long double", 8},
		{PlatformWindows, 8, "wchar_t", 2}, {PlatformWindows, 8, "__wchar_t", 2},
		{PlatformLinux, 8, "long", 8}, {PlatformLinux, 8, "long unsigned int", 8},
		{PlatformLinux, 4, "unsigned long", 4}, {PlatformLinux, 8, "long double", 16},
		{PlatformLinux, 4, "long double", 16}, {PlatformLinux, 8, "wchar_t", 0},
	} {
		if got, err := ScalarWidth(tc.platform, tc.name, tc.pointer); err != nil || got != tc.want {
			t.Errorf("ScalarWidth(%d, %q, %d) = %d, %v, want %d", tc.platform, tc.name, tc.pointer, got, err, tc.want)
		}
	}
	for _, name := range []string{"long", "unsigned long", "long int", "long double", "wchar_t"} {
		if got, err := ScalarWidth(PlatformUnknown, name, 8); !errors.Is(err, ErrPlatformUnknown) || got != 0 {
			t.Errorf("unknown platform, %q: %d, %v", name, got, err)
		}
	}
}

func TestAnEnumerationWithNoWidthIsAnInt(t *testing.T) {
	for _, tc := range []struct {
		values []int64
		size   uint64
		want   uint64
	}{
		{nil, 0, 4},
		{[]int64{0, 1, 2}, 0, 4},
		{[]int64{math.MinInt32, math.MaxInt32}, 0, 4},
		{[]int64{0, math.MaxUint32}, 0, 4},
		{[]int64{-1, math.MaxUint32}, 0, 8},
		{[]int64{math.MaxUint32 + 1}, 0, 8},
		{[]int64{0}, 1, 1},
	} {
		e := EnumType{Name: "e", Size: tc.size}
		for _, v := range tc.values {
			e.Values = append(e.Values, EnumValue{Name: "v", Value: v})
		}
		if got := enumWidth(e); got != tc.want {
			t.Errorf("%v size %d: %d, want %d", tc.values, tc.size, got, tc.want)
		}
	}
}

func TestExpressionWidths(t *testing.T) {
	named := func(n string) (uint64, error) { return map[string]uint64{"x": 3, "big": 1 << 40}[n], nil }
	for expr, want := range map[string]uint64{
		"x": 3, "*x": 8, "[4]x": 12, "[2][3]x": 18, "[4]*y": 32, "@1:2 x": 3, "[0]x": 0, "y": 0, "[5]y": 0,
		"[16777216][16777216]big": 0,
	} {
		if got, _ := exprWidth(ref(t, expr), 8, named); got != want {
			t.Errorf("%q: %d, want %d", expr, got, want)
		}
	}
	if got, _ := exprWidth(TypeRef{Name: "x", ArrayLength: 2}, 8, named); got != 6 {
		t.Errorf("an array with no element sizes its named element: %d", got)
	}
}

func TestBitsAreCountedFromTheLeastSignificant(t *testing.T) {
	for _, tc := range []struct {
		word           uint64
		offset, length uint8
		want           uint64
	}{
		{0xff, 0, 0, 0xff},
		{0b1011_0100, 2, 3, 0b101},
		{1 << 63, 63, 1, 1},
		{math.MaxUint64, 0, 64, math.MaxUint64},
		{math.MaxUint64, 4, 200, math.MaxUint64 >> 4},
		{math.MaxUint64, 64, 1, 0},
	} {
		if got := bitsOf(tc.word, tc.offset, tc.length); got != tc.want {
			t.Errorf("bits %d:%d of %#x = %#x, want %#x", tc.offset, tc.length, tc.word, got, tc.want)
		}
	}
	if got := littleEndian([]byte{1, 2, 3}); got != 0x030201 {
		t.Errorf("3 bytes: %#x", got)
	}
}
