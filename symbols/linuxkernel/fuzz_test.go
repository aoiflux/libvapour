package linuxkernel

import (
	"testing"

	"github.com/aoiflux/libvapour/limits"
	lt "github.com/aoiflux/libvapour/symbols/linuxkernel/linuxtest"
)

func FuzzFindKernel(f *testing.F) {
	base := "OSRELEASE=6.17.0\n" + lt.LayoutKeys(0) + lt.KallsymsKeys(0)
	f.Add(base, uint32(0), byte(0))
	f.Add(base+"NUMBER(pgtable_l5_enabled)=1\n", uint32(0x2000), byte(0xff))
	f.Add(base+"NUMBER(MAX_PHYSMEM_BITS)=46\nNUMBER(sme_mask)=0x800000000000\n", uint32(0x5000), byte(0x63))
	f.Add("OSRELEASE=6.17.0\n", uint32(0x130), byte('='))
	f.Fuzz(func(t *testing.T, note string, at uint32, b byte) {
		buf := minimal()
		lt.PutNote(buf, 0x100, note)
		buf[int(at%uint32(len(buf)))] = b
		k, err := FindKernel(&lt.Memory{Buf: buf}, limits.Limits{})
		if err != nil {
			if k.Space != nil || len(k.VMCoreInfo.Entries) > 0 {
				t.Fatalf("an error with a kernel: %v", err)
			}
			return
		}
		if k.Space == nil {
			t.Fatal("a kernel without an address space")
		}
		if _, err := k.VMCoreInfo.KernelLayout(); err != nil {
			t.Fatalf("the chosen note refuses its own layout: %v", err)
		}
		if len(k.Diagnostics) < len(k.Damaged) {
			t.Fatalf("%d damaged notes, %d diagnostics", len(k.Damaged), len(k.Diagnostics))
		}
		if b, err := k.Space.ReadAt(lt.ProbeVA, 16); err == nil && len(b) != 16 {
			t.Fatalf("a read of 16 bytes gave %d", len(b))
		}
	})
}
