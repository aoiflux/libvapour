package tools

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
)

func opts(kv ...any) Context {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return Context{Options: m}
}

func wantWrongForm(t *testing.T, what string, err error, key string) {
	t.Helper()
	if !errors.Is(err, ErrOptionType) || !strings.Contains(err.Error(), `"`+key+`"`) {
		t.Errorf("%s: %v, want ErrOptionType naming %q", what, err, key)
	}
}

func TestBoolOptionForms(t *testing.T) {
	for v, want := range map[any]bool{true: true, false: false, " TRUE ": true, "1": true, "Yes": true, "on": true,
		"false": false, "0": false, "NO": false, "Off": false} {
		got, err := opts("k", v).BoolOption("k")
		if err != nil || got != want {
			t.Errorf("%#v: %v %v", v, got, err)
		}
	}
	for _, v := range []any{"", "maybe", "t", 1, nil, 1.0} {
		_, err := opts("k", v).BoolOption("k")
		wantWrongForm(t, "bool", err, "k")
	}
	if got, err := opts().BoolOption("k"); got || err != nil {
		t.Errorf("absent: %v %v", got, err)
	}
}

func TestUintOptionForms(t *testing.T) {
	for v, want := range map[any]uint64{uint8(7): 7, uint64(1 << 63): 1 << 63, int(4): 4, int64(0): 0, uintptr(9): 9,
		"42": 42, " 0x1F ": 31, "0XfF": 255, "010": 10, "18446744073709551615": 1<<64 - 1} {
		got, present, err := opts("k", v).UintOption("k")
		if err != nil || !present || got != want {
			t.Errorf("%#v: %d %v %v, want %d", v, got, present, err, want)
		}
	}
	for _, v := range []any{-1, int8(-1), "", "0x", "-4", "+4", "1_000", "18446744073709551616", "four", 4.0, true, nil} {
		_, present, err := opts("k", v).UintOption("k")
		if !present {
			t.Errorf("%#v: a present value reported absent", v)
		}
		wantWrongForm(t, "uint", err, "k")
	}
	if n, present, err := opts().UintOption("k"); n != 0 || present || err != nil {
		t.Errorf("absent: %d %v %v", n, present, err)
	}
}

func TestStringOptions(t *testing.T) {
	if s, err := opts("k", "x").StringOption("k"); s != "x" || err != nil {
		t.Errorf("%q %v", s, err)
	}
	_, err := opts("k", 3).StringOption("k")
	wantWrongForm(t, "string", err, "k")

	for v, want := range map[any][]string{"a, b,,c ": {"a", "b", "c"}, "": {}} {
		got, err := opts("k", v).StringListOption("k")
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%#v: %q %v", v, got, err)
		}
	}
	got, err := opts("k", []string{" a", "", "b"}).StringListOption("k")
	if err != nil || !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("slice: %q %v", got, err)
	}
	_, err = opts("k", []any{"a"}).StringListOption("k")
	wantWrongForm(t, "string list", err, "k")
}

func TestUintListOptionForms(t *testing.T) {
	src := []uint64{1, 2}
	got, err := opts("k", src).UintListOption("k")
	got[0] = 9
	if err != nil || src[0] != 1 {
		t.Errorf("the caller's slice must be copied: %v %v", src, err)
	}
	for v, want := range map[any][]uint64{"1, 0x10,,3": {1, 16, 3}} {
		got, err := opts("k", v).UintListOption("k")
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%#v: %v %v", v, got, err)
		}
	}
	if got, err := opts("k", []int{0, 5}).UintListOption("k"); err != nil || !slices.Equal(got, []uint64{0, 5}) {
		t.Errorf("[]int: %v %v", got, err)
	}
	for _, v := range []any{[]int{-1}, "1,x", []uint32{1}, 5} {
		_, err := opts("k", v).UintListOption("k")
		wantWrongForm(t, "uint list", err, "k")
	}
}

func TestValidateOptionsJoinsEveryBadOption(t *testing.T) {
	c := opts(optionPID, "four", OptionMaxDumpSize, "big", optionStrict, 2, OptionOutputDir, 1,
		OptionPhysicalMemory, "disk", optionDiagnostics, []string{}, "some.tool.option", struct{}{})
	err := c.ValidateOptions()
	for _, key := range []string{optionPID, OptionMaxDumpSize, optionStrict, OptionOutputDir, OptionPhysicalMemory, optionDiagnostics} {
		wantWrongForm(t, "validate", err, key)
	}
	if strings.Contains(err.Error(), "some.tool.option") {
		t.Error("an unknown key was judged")
	}
	if err := opts(optionPID, 4, OptionKernelDTB, "0x1aa000", OptionPhysicalMemory, pages{}).ValidateOptions(); err != nil {
		t.Errorf("good options: %v", err)
	}
}

func TestSessionValueAccessors(t *testing.T) {
	c := opts(OptionOutputDir, "out", OptionKernelBase, uint64(0xfffff80000000000), OptionKernelDTB, "0x1aa000",
		OptionPagingMode, "4-level", OptionNetworkScanLayout, "26100", OptionPhysicalMemory, pages{})
	if dir, ok := c.OutputDir(); dir != "out" || !ok {
		t.Errorf("output dir %q %v", dir, ok)
	}
	if base, ok := c.KernelBase(); base != 0xfffff80000000000 || !ok {
		t.Errorf("kernel base %x %v", base, ok)
	}
	if root, ok := c.KernelDTB(); root != 0x1aa000 || !ok {
		t.Errorf("dtb %x %v", root, ok)
	}
	if c.PagingMode() != "4-level" || c.NetworkScanLayout() != "26100" || c.PhysicalMemory() == nil {
		t.Error("string or reader accessor")
	}
	bad := opts(OptionOutputDir, 1, OptionKernelBase, "x", OptionPagingMode, 1, OptionPhysicalMemory, "disk")
	if _, ok := bad.OutputDir(); ok {
		t.Error("output dir of the wrong type")
	}
	if _, ok := bad.KernelBase(); ok {
		t.Error("kernel base of the wrong type")
	}
	if bad.PagingMode() != "" || bad.PhysicalMemory() != nil {
		t.Error("wrongly typed values must read as absent")
	}
	if _, ok := opts(OptionOutputDir, "").OutputDir(); ok {
		t.Error("an empty output dir is no directory")
	}
}

func TestDumpLimitHoldsToTheArtifactCap(t *testing.T) {
	caps := limits.Limits{MaxArtifactBytes: 0x10000}
	cases := []struct {
		option any
		want   uint64
	}{
		{nil, 0x10000},
		{uint64(0), 0x10000},
		{uint64(0x1000), 0x1000},
		{uint64(0x20000), 0x10000},
		{"bad", 0x10000},
	}
	for _, tc := range cases {
		c := Context{Options: map[string]any{}, Limits: caps}
		if tc.option != nil {
			c.Options[OptionMaxDumpSize] = tc.option
		}
		if got := c.DumpLimit(); got != tc.want {
			t.Errorf("%v: %#x, want %#x", tc.option, got, tc.want)
		}
	}
	if got := (Context{}).DumpLimit(); got != limits.DefaultMaxArtifactBytes {
		t.Errorf("default %#x", got)
	}
	if opts(OptionMaxDumpSize, "x").MaxDumpSize() != 0 || opts(OptionMaxDumpSize, 7).MaxDumpSize() != 7 {
		t.Error("max dump size")
	}
}
