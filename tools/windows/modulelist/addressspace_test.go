package modulelist

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

func spaceContext(width uint8, paging string) tools.Context {
	return tools.Context{Memory: sparse{}, Symbols: symbols.NewTable("s", width), Profile: profiles.WindowsX64Profile{},
		Options: map[string]any{tools.OptionPagingMode: paging}}
}

func TestTheMaskAndTheUpperHalfFollowThePagingMode(t *testing.T) {
	for _, tc := range []struct {
		width      uint8
		paging     string
		mask, half uint64
		bits       int
	}{
		{4, "x86pae", 0xffffffff, 0x80000000, 32},
		{4, "x86", 0xffffffff, 0x80000000, 32},
		{8, "x64", 1<<48 - 1, 0xffff800000000000, 48},
		{8, "la57", 1<<57 - 1, 0xff00000000000000, 57},
		{8, "linux-la57", 1<<57 - 1, 0xff00000000000000, 57},
		{8, "linux-x64", 1<<48 - 1, 0xffff800000000000, 48},
	} {
		ctx := spaceContext(tc.width, tc.paging)
		if got := AddressMask(ctx); got != tc.mask {
			t.Errorf("%d-byte %s: mask 0x%x, want 0x%x", tc.width, tc.paging, got, tc.mask)
		}
		if got := KernelHalfStart(ctx); got != tc.half {
			t.Errorf("%d-byte %s: upper half 0x%x, want 0x%x", tc.width, tc.paging, got, tc.half)
		}
		if got := AddressBits(tc.mask); got != tc.bits {
			t.Errorf("%d-byte %s: %d bits, want %d", tc.width, tc.paging, got, tc.bits)
		}
	}
}

func TestTheCanonicalFormSignExtendsTheTopTranslatedBit(t *testing.T) {
	const m48, m57 = uint64(1<<48 - 1), uint64(1<<57 - 1)
	for _, tc := range []struct {
		in, mask, want uint64
		width          uint8
	}{
		{0x0000f80566510000, m48, 0xfffff80566510000, 8},
		{0xfffff80566510000, m48, 0xfffff80566510000, 8},
		{0x00007ff600000000, m48, 0x00007ff600000000, 8},
		{0x1234f80566510000, m48, 0xfffff80566510000, 8},
		{0x0100000000001000, m57, 0xff00000000001000, 8},
		{0x0000f80566510000, m57, 0x0000f80566510000, 8},
		{0xffffffff80001000, 0xffffffff, 0x80001000, 4},
	} {
		if got := CanonicalAddress(tc.in, tc.mask, tc.width); got != tc.want {
			t.Errorf("CanonicalAddress(0x%x, 0x%x, %d) = 0x%x, want 0x%x", tc.in, tc.mask, tc.width, got, tc.want)
		}
	}
}

func rangeContext(width uint8, value []byte, paging string) (tools.Context, *[]string) {
	m := sparse{}
	tab := symbols.NewTable("s", width)
	tab.AddSymbol(symbols.Symbol{Name: "MmSystemRangeStart", Address: rangeStart})
	if value != nil {
		m.write(rangeStart, value)
	}
	diags := &[]string{}
	return tools.Context{Memory: m, Symbols: tab, Profile: profiles.WindowsX64Profile{},
		Options: map[string]any{tools.OptionPagingMode: paging, "diagnostics": diags}}, diags
}

func le(v uint64, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(v >> (8 * i))
	}
	return b
}

func TestSystemSpaceStartsAtMmSystemRangeStart(t *testing.T) {
	for _, tc := range []struct {
		what   string
		width  uint8
		value  []byte
		want   uint64
		saying string
	}{
		{"x64 value", 8, le(0xffff800000000000, 8), 0xffff800000000000, ""},
		{"a higher x64 value", 8, le(0xffffa00000000000, 8), 0xffffa00000000000, ""},
		{"32-bit with a 3 GB user space", 4, le(0xc0000000, 4), 0xc0000000, ""},
		{"unreadable", 8, nil, 0xffff800000000000, "does not read: system space taken to start at 0xffff800000000000"},
		{"zero", 8, le(0, 8), 0xffff800000000000, "holds 0x0, outside the upper half"},
		{"user space", 8, le(0x7fffffff0000, 8), 0xffff800000000000, "outside the upper half"},
		{"not canonical", 8, le(0xffff000000000000, 8), 0xffff800000000000, "outside the upper half"},
		{"32-bit below the half", 4, le(0x7fff0000, 4), 0x80000000, "outside the upper half"},
	} {
		ctx, diags := rangeContext(tc.width, tc.value, "x64")
		got, err := KernelSpaceStart(ctx, "test")
		if err != nil || got != tc.want {
			t.Errorf("%s: 0x%x, %v; want 0x%x", tc.what, got, err, tc.want)
		}
		said := strings.Join(*diags, "\n")
		if tc.saying == "" && said != "" || tc.saying != "" && !strings.Contains(said, "test: MmSystemRangeStart at 0x") ||
			!strings.Contains(said, tc.saying) {
			t.Errorf("%s: diagnostics %q, want %q", tc.what, *diags, tc.saying)
		}
	}
	ctx, _ := rangeContext(8, nil, "x64")
	ctx.Symbols = symbols.NewTable("bare", 8)
	if _, err := KernelSpaceStart(ctx, "test"); !errors.Is(err, ErrNoSystemRangeStart) {
		t.Errorf("no symbol: %v, want ErrNoSystemRangeStart", err)
	}
}

func FuzzCanonicalAddress(f *testing.F) {
	f.Add(uint64(0x0000f80566510000), uint8(48))
	f.Add(uint64(0x7fffffffffff), uint8(57))
	f.Add(uint64(0xffffffff), uint8(32))
	f.Fuzz(func(t *testing.T, addr uint64, n uint8) {
		bits := []int{32, 48, 57}[int(n)%3]
		mask := uint64(1)<<bits - 1
		width := uint8(8)
		if bits == 32 {
			width = 4
		}
		c := CanonicalAddress(addr, mask, width)
		if c&mask != addr&mask {
			t.Fatalf("0x%x: canonical 0x%x changes the translated bits", addr, c)
		}
		if CanonicalAddress(c, mask, width) != c {
			t.Fatalf("0x%x: canonical 0x%x is not a fixed point", addr, c)
		}
		if width == 4 {
			if c > mask {
				t.Fatalf("0x%x: 32-bit canonical 0x%x above the mask", addr, c)
			}
			return
		}
		top := c >> (bits - 1)
		if top != 0 && top != ^uint64(0)>>(bits-1) {
			t.Fatalf("0x%x: canonical 0x%x has unequal bits from %d up", addr, c, bits-1)
		}
	})
}
