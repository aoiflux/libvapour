package linuxobj_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func FuzzHardwareAddressText(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x52, 0x54, 0x00, 0x12, 0x34, 0x56})
	f.Add(make([]byte, 32))
	f.Fuzz(func(t *testing.T, b []byte) {
		s := linuxobj.FormatHardwareAddress(b)
		if s != strings.ToLower(s) {
			t.Fatalf("%q is not lower case", s)
		}
		back, err := hex.DecodeString(strings.ReplaceAll(s, ":", ""))
		if err != nil || string(back) != string(b) {
			t.Fatalf("% x -> %q -> % x, %v", b, s, back, err)
		}
		if len(b) > 0 && strings.Count(s, ":") != len(b)-1 {
			t.Fatalf("%q: %d separators for %d bytes", s, strings.Count(s, ":"), len(b))
		}
	})
}

func FuzzReportedFlags(f *testing.F) {
	f.Add(uint64(iffUp|iffRunning), uint64(0), uint64(operUp), uint64(linkStart))
	f.Add(uint64(iffPromisc), uint64(iffPromisc), uint64(9), uint64(linkNoCarrier))
	f.Fuzz(func(t *testing.T, flags, gflags, oper, state uint64) {
		d := linuxobj.NetDevice{Flags: flags, GFlags: gflags, OperState: oper, LinkState: state}
		got := d.ReportedFlags()
		const derived = iffRunning | iffLowerUp | iffDormant
		const user = iffPromisc | iffAllMulti
		if keep := flags &^ (derived | user); got&^(derived|user) != keep {
			t.Fatalf("stored bits changed: %#x from %#x", got, flags)
		}
		if got&user != gflags&user {
			t.Fatalf("user bits %#x, gflags %#x", got&user, gflags)
		}
		if !d.Running() && got&derived != 0 {
			t.Fatalf("device not running reports %#x", got&derived)
		}
	})
}

// Arbitrary bytes stand in for a chain of in_ifaddr records whose next
// pointers lead to any record, back to one already walked, or to null.
func FuzzIPv4AddressChain(f *testing.F) {
	f.Add([]byte{}, uint8(0))
	f.Add(make([]byte, 0x100), uint8(3))
	f.Fuzz(func(t *testing.T, region []byte, pick uint8) {
		k := lt.NewKernel(1700000000, 0)
		lt.AddNetTypes(k)
		const records = 4
		base := k.Alloc(records * 0x40)
		region = region[:min(len(region), records*0x40)/0x40*0x40]
		k.Mem.Write(base, region)
		for i := uint64(0); i < records; i++ {
			at := base + i*0x40 + lt.IfaNext
			if i >= uint64(len(region))/0x40 {
				continue
			}
			next := uint64(0)
			if j := uint64(region[i*0x40]) % (records + 1); j < records {
				next = base + j*0x40
			}
			k.Mem.U64(at, next)
		}
		in := k.Alloc(0x40)
		k.Mem.U64(in+lt.InDevIfaList, base+uint64(pick%records)*0x40)
		ctx, _ := k.Context(nil)
		ctx.Limits = limits.Limits{MaxListEntries: 8}
		w, err := linuxobj.New(ctx).IPv4Addresses(in)
		if err != nil {
			t.Fatal(err)
		}
		if len(w.Addresses) > records {
			t.Fatalf("%d addresses from %d records", len(w.Addresses), records)
		}
		for _, a := range w.Addresses {
			if a.Address == "" || a.Scope == "" {
				t.Fatalf("empty field in %+v", a)
			}
		}
	})
}
