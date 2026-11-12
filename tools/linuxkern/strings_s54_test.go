package linuxkern_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools/linuxkern"
)

func TestStringsEndAtTheFirstNULOrTheCount(t *testing.T) {
	k, mem := sampleKernel(t, nil)
	mem.Str(sample+0x100, "swapper/0")
	mem.Write(sample+0x200, []byte("abcdefgh"))
	mem.Str(sample+0xffc, "crosses")
	mem.Write(sample+0x300, []byte{'o', 'k', 0xff, 0})
	for _, c := range []struct {
		at    uint64
		count uint64
		want  string
	}{
		{sample + 0x100, 64, "swapper/0"},
		{sample + 0x100, 4, "swap"},
		{sample + 0x200, 8, "abcdefgh"},
		{sample + 0xffc, 16, "crosses"},
		{sample + 0x300, 8, "ok�"},
	} {
		if got, err := k.StringAt(c.at, c.count); err != nil || got != c.want {
			t.Errorf("StringAt(%#x, %d) = %q, %v, want %q", c.at, c.count, got, err, c.want)
		}
	}
	if _, err := k.StringAt(sample, 0); !errors.Is(err, linuxkern.ErrNoString) {
		t.Errorf("zero count: %v", err)
	}
	mem.Write(sample+0x1ff8, []byte("no-nul-h"))
	if _, err := k.StringAt(sample+0x1ff8, 32); !errors.Is(err, linuxkern.ErrStringUnread) {
		t.Errorf("string into an unmapped page: %v, want ErrStringUnread", err)
	}
	if s, err := k.StringAt(sample+0x1ff8, 8); err != nil || s != "no-nul-h" {
		t.Errorf("string that ends at the count before the unmapped page: %q, %v", s, err)
	}
}

func TestMemberStringsReadWholeByteArrays(t *testing.T) {
	k, mem := sampleKernel(t, nil)
	mem.Str(sample+0x28, "ttyS0")
	if s, err := k.MemberString(sample, "sample", "name"); err != nil || s != "ttyS0" {
		t.Errorf("name = %q, %v", s, err)
	}
	mem.Write(sample+0x28, []byte(strings.Repeat("x", 16)))
	mem.U8(sample+0x38, 'y')
	if s, err := k.MemberString(sample, "sample", "name"); err != nil || s != strings.Repeat("x", 16) {
		t.Errorf("full array = %q, %v; the byte after it must not be read", s, err)
	}
	for _, member := range []string{"wide", "i32", "chars"} {
		if _, err := k.MemberString(sample, "sample", member); !errors.Is(err, linuxkern.ErrNotByteArray) {
			t.Errorf("MemberString(%s): %v, want ErrNotByteArray", member, err)
		}
	}
	if _, err := k.MemberString(sample, "sample", "missing"); err == nil {
		t.Error("MemberString of a missing member")
	}
}
