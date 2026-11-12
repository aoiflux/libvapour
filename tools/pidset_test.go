package tools

import (
	"strconv"
	"strings"
	"testing"
)

func TestPIDSetForms(t *testing.T) {
	cases := []struct {
		value any
		key   string
	}{
		{4, "4"},
		{uint32(0), "0"},
		{"0", "0"},
		{"8, 4,0x4", "4,8"},
		{[]uint64{12, 4}, "4,12"},
		{[]int{0, 4}, "0,4"},
		{" 4294967295 ", "4294967295"},
	}
	for _, c := range cases {
		ctx := opts(optionPID, c.value)
		if err := ctx.ValidateOptions(); err != nil {
			t.Errorf("%#v: %v", c.value, err)
		}
		s := ctx.PIDs()
		if s.All() || s.Key() != c.key {
			t.Errorf("%#v: all %v key %q, want %q", c.value, s.All(), s.Key(), c.key)
		}
	}
}

func TestPIDZeroIsTheIdleProcess(t *testing.T) {
	s := opts(optionPID, 0).PIDs()
	if !s.Keep(0) || s.Keep(4) {
		t.Error("pid 0 must keep PID 0 only")
	}
}

func TestPIDSetRefusals(t *testing.T) {
	for _, v := range []any{"", " ", "4,,8", "4,", []uint64{}, []int{}, []int{-4}, -4, "four", "0x100000000",
		uint64(1 << 32), []uint64{4, 1 << 40}, 4.0, true, nil, []string{"4"}} {
		ctx := opts(optionPID, v)
		wantWrongForm(t, "pid", ctx.ValidateOptions(), optionPID)
		s := ctx.PIDs()
		if s.All() || s.Keep(0) || s.Keep(4) || s.Key() != "unread" {
			t.Errorf("%#v: an unreadable filter must keep nothing", v)
		}
	}
}

func TestAbsentPIDKeepsEveryProcess(t *testing.T) {
	s := opts().PIDs()
	if !s.All() || !s.Keep(0) || !s.Keep(1<<40) || s.Key() != "" {
		t.Error("absent filter")
	}
	if !(PIDSet{}).All() {
		t.Error("the zero set keeps every process")
	}
}

func FuzzPIDText(f *testing.F) {
	for _, s := range []string{"4", "0,4,8", "0x10, 3", "", ",", "4294967296", " 7 "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		ctx := opts(optionPID, text)
		s, err := ctx.pidSet()
		if err != nil {
			if !ctx.PIDs().Keep(0) && ctx.PIDs().Key() == "unread" {
				return
			}
			t.Fatalf("%q: an unread set keeps a process", text)
		}
		again, err := opts(optionPID, s.Key()).pidSet()
		if err != nil || again.Key() != s.Key() {
			t.Fatalf("%q: key %q does not read back: %v", text, s.Key(), err)
		}
		for _, item := range strings.Split(text, ",") {
			n, ok := parseUintText(item)
			if !ok || !s.Keep(n) {
				t.Fatalf("%q: item %q not kept", text, item)
			}
			if n > maxPID {
				t.Fatalf("%q: %s above the PID range accepted", text, strconv.FormatUint(n, 10))
			}
		}
	})
}

func FuzzUintText(f *testing.F) {
	for _, s := range []string{"0", "0x0", "0X1f", "010", "-1", "+1", "1_0", "0x", "18446744073709551615"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		n, _, err := opts("k", text).UintOption("k")
		if err != nil {
			return
		}
		trimmed := strings.TrimSpace(text)
		hex := strings.TrimPrefix(strings.TrimPrefix(trimmed, "0x"), "0X")
		if hex != trimmed {
			if strconv.FormatUint(n, 16) != strings.TrimLeft(strings.ToLower(hex), "0") && n != 0 {
				t.Fatalf("%q read as %#x", text, n)
			}
			return
		}
		if strconv.FormatUint(n, 10) != strings.TrimLeft(trimmed, "0") && n != 0 {
			t.Fatalf("%q read as %d", text, n)
		}
		list, err := opts("k", text+","+text).UintListOption("k")
		if err != nil || len(list) != 2 || list[0] != n {
			t.Fatalf("%q as a list: %v %v", text, list, err)
		}
	})
}
