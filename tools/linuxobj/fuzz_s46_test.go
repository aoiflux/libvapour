package linuxobj_test

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

var fuzzModes = []struct {
	name  string
	width uint8
	sizes map[uint64]bool
}{
	{"linux-x64", 8, map[uint64]bool{1 << 12: true, 1 << 21: true, 1 << 30: true}},
	{"linux-la57", 8, map[uint64]bool{1 << 12: true, 1 << 21: true, 1 << 30: true}},
	{"linux-x86pae", 4, map[uint64]bool{1 << 12: true, 1 << 21: true}},
	{"linux-x86", 4, map[uint64]bool{1 << 12: true, 1 << 22: true}},
}

func FuzzPageTableWalk(f *testing.F) {
	seed := make([]byte, 0x5000)
	binary.LittleEndian.PutUint64(seed[0:], 0x1000|7)
	binary.LittleEndian.PutUint64(seed[0x1000:], 0x2000|7)
	binary.LittleEndian.PutUint64(seed[0x1008:], 0x4000_0000|0x81)
	binary.LittleEndian.PutUint64(seed[0x2000:], 0x3000|7)
	binary.LittleEndian.PutUint64(seed[0x2008:], 0x20_0000|0x81)
	binary.LittleEndian.PutUint64(seed[0x3000:], 0x4000|0x41)
	f.Add(byte(0), uint64(0x123), seed)
	f.Add(byte(0), uint64(0x4000_1234), seed)
	f.Add(byte(3), uint64(0xc000_0000), seed[:0x2000])
	f.Fuzz(func(t *testing.T, mode byte, va uint64, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		m := fuzzModes[int(mode)%len(fuzzModes)]
		ctx := tools.Context{Memory: lt.NewMemory(), Symbols: symbols.NewTable("s46fuzz", m.width),
			Profile: profiles.LinuxX64Profile{}, Limits: limits.Limits{PTECacheEntries: 1024},
			Options: map[string]any{tools.OptionPhysicalMemory: &lt.Flat{Buf: data}, tools.OptionPagingMode: m.name}}
		pt, err := linuxobj.New(ctx).PageTables(0)
		if err != nil {
			t.Fatal(err)
		}
		pa, size, _, err := pt.Translate(va)
		var fault *linuxobj.PageFault
		switch {
		case err == nil:
			if !m.sizes[size] {
				t.Fatalf("%s: page size %#x", m.name, size)
			}
			if pa&(size-1) != va&(size-1) {
				t.Fatalf("%s: %#x maps to %#x across a %#x page", m.name, va, pa, size)
			}
		case errors.As(err, &fault):
			if s := fault.Span(); s < 1<<12 || bits.OnesCount64(s) != 1 {
				t.Fatalf("%s: fault span %#x", m.name, s)
			}
		case !errors.Is(err, linuxobj.ErrTableUnread):
			t.Fatalf("%s: %v", m.name, err)
		}
		b, padded := pt.ReadPadded(va, 64)
		if len(b) != 64 || padded < 0 || padded > 64 {
			t.Fatalf("ReadPadded gave %d bytes, %d padded", len(b), padded)
		}
	})
}

func FuzzCapabilityText(f *testing.F) {
	f.Add(uint64(0), int64(40))
	f.Add(uint64(1<<41-1), int64(40))
	f.Add(uint64(1<<63|1), int64(37))
	f.Fuzz(func(t *testing.T, v uint64, last int64) {
		if last < 0 || last > 63 {
			return
		}
		mask := ^uint64(0)
		if last < 63 {
			mask = 1<<(last+1) - 1
		}
		full := linuxobj.CapFull{Last: last, Mask: mask}
		text := linuxobj.DecodeCapabilities(v, full)
		if v == mask {
			if text != "CAP_FULL_SET" {
				t.Fatalf("full set %#x reads %q", v, text)
			}
			return
		}
		names, rest := linuxobj.CapabilityNames(v)
		if bits.OnesCount64(v) != len(names)+bits.OnesCount64(rest) {
			t.Fatalf("%#x: %d names and rest %#x", v, len(names), rest)
		}
		if (v == 0) != (text == "") {
			t.Fatalf("%#x reads %q", v, text)
		}
		for _, n := range names {
			if !strings.Contains(text, n) {
				t.Fatalf("%#x: %q lacks %s", v, text, n)
			}
		}
	})
}

func FuzzPtraceFlagNames(f *testing.F) {
	f.Add(uint64(1 | 1<<16))
	f.Add(^uint64(0))
	f.Fuzz(func(t *testing.T, v uint64) {
		names, rest := linuxobj.PtraceFlagNames(v)
		if rest&^v != 0 {
			t.Fatalf("%#x: rest %#x has bits the word lacks", v, rest)
		}
		n := 0
		if names != "" {
			n = len(strings.Split(names, "|"))
		}
		if n+bits.OnesCount64(rest) != bits.OnesCount64(v) {
			t.Fatalf("%#x: %q and rest %#x", v, names, rest)
		}
	})
}
