package linuxkernel

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols/autoload"
	lt "github.com/aoiflux/libvapour/symbols/linuxkernel/linuxtest"
)

func minimal() []byte {
	return lt.Capture(0, []string{"T_stext", "Tfoo", "B_end"}, []uint32{0, 0x10, 0x100})
}

func spaceFor(t *testing.T, buf []byte, note string) *layers.VirtualMemoryLayer {
	t.Helper()
	lt.PutNote(buf, 0x100, note)
	k, err := FindKernel(&lt.Memory{Buf: buf}, limits.Limits{})
	if err != nil {
		t.Fatalf("find kernel: %v", err)
	}
	return k.Space.(*layers.VirtualMemoryLayer)
}

func TestTheKernelSpaceMasksFramesToTheKernelsWidth(t *testing.T) {
	const frame = 0x5000
	buf := minimal()
	high := uint64(1)<<45 | uint64(1)<<50
	sme := uint64(1) << 47
	lt.PutEntry(buf, lt.PT, 0, frame|high|sme|lt.Present)
	base := "OSRELEASE=6.17.0\n" + lt.LayoutKeys(0) + lt.KallsymsKeys(0)
	for _, tc := range []struct {
		name, keys string
		want       uint64
	}{
		{"46 bits less SME", "NUMBER(MAX_PHYSMEM_BITS)=46\nNUMBER(sme_mask)=0x800000000000\n", frame | 1<<45},
		{"52 bits", "", frame | high | sme},
		{"52 bits less SME", "NUMBER(MAX_PHYSMEM_BITS)=52\nNUMBER(sme_mask)=0x800000000000\n", frame | high},
	} {
		pa, err := spaceFor(t, append([]byte(nil), buf...), base+tc.keys).Translate(lt.ProbeVA + 0x123)
		if err != nil || pa != tc.want|0x123 {
			t.Errorf("%s: 0x%x (%v), want 0x%x", tc.name, pa, err, tc.want|0x123)
		}
	}
	if pa, err := spaceFor(t, append([]byte(nil), buf...), base).Translate(lt.ProbeVA + 0x1000); err == nil {
		t.Errorf("a not-present entry translated to 0x%x", pa)
	}
}

func TestFiveLevelTablesAreWalkedWhenVMCoreInfoSaysSo(t *testing.T) {
	keys := "OSRELEASE=6.17.0\nSYMBOL(swapper_pg_dir)=ffffffff80006000\nNUMBER(phys_base)=0\nKERNELOFFSET=0\n" + lt.KallsymsKeys(0)
	five := spaceFor(t, minimal(), keys+"NUMBER(pgtable_l5_enabled)=1\n")
	if pa, err := five.Translate(lt.ArraysVA + 0x10); err != nil || pa != lt.ArraysPA+0x10 {
		t.Errorf("five levels: 0x%x (%v)", pa, err)
	}
	four := spaceFor(t, minimal(), keys+"NUMBER(pgtable_l5_enabled)=0\n")
	if pa, err := four.Translate(lt.ArraysVA + 0x10); err == nil && pa == lt.ArraysPA+0x10 {
		t.Error("four levels from the PML5 reached the arrays too; the fixture shows nothing")
	}
	buf := minimal()
	lt.PutNote(buf, 0x100, keys)
	k, err := FindKernel(&lt.Memory{Buf: buf}, limits.Limits{})
	if err != nil || !k.Layout.FiveLevel || k.Layout.DepthEvidence == "" || len(k.Diagnostics) != 0 {
		t.Fatalf("without the flag the tables decide: layout %+v, diagnostics %q, err %v", k.Layout, k.Diagnostics, err)
	}
	if pa, err := k.Space.(*layers.VirtualMemoryLayer).Translate(lt.ArraysVA + 0x10); err != nil || pa != lt.ArraysPA+0x10 {
		t.Errorf("five levels from the tables: 0x%x (%v)", pa, err)
	}
}

func TestTheFirstNoteWithALayoutAndKallsymsIsTheKernel(t *testing.T) {
	full := "OSRELEASE=6.17.0\n" + lt.LayoutKeys(0) + lt.KallsymsKeys(0)
	buf := minimal()
	lt.PutNote(buf, 0x100, "OSRELEASE=6.17.0\n"+lt.LayoutKeys(0))
	lt.PutNote(buf, 0x800, full)
	k, err := FindKernel(&lt.Memory{Buf: buf}, limits.Limits{})
	if err != nil || k.VMCoreInfo.Offset != 0x800 || k.Seeds.Stext != lt.KernelBase || k.DamageError() != nil || len(k.Diagnostics) != 0 {
		t.Fatalf("kernel at 0x%x seeds %+v (%v)", k.VMCoreInfo.Offset, k.Seeds, err)
	}
	if k.PointerSize() != 8 || k.Limits.MaxNameBytes == 0 {
		t.Errorf("pointer size %d, limits %+v", k.PointerSize(), k.Limits)
	}

	buf = minimal()
	lt.PutNote(buf, 0x100, "OSRELEASE=6.17.0\nGARBAGE\n")
	lt.PutNote(buf, 0x800, full)
	k, err = FindKernel(&lt.Memory{Buf: buf}, limits.Limits{})
	var damage *autoload.VMCoreInfoDamageError
	if err != nil || !errors.As(k.DamageError(), &damage) || len(k.Diagnostics) != 1 || !strings.Contains(k.Diagnostics[0], "0x100") {
		t.Errorf("a damaged copy before the kernel's: %v, diagnostics %q", err, k.Diagnostics)
	}

	buf = minimal()
	lt.PutNote(buf, 0x100, "OSRELEASE=6.17.0\nGARBAGE\n")
	lt.PutNote(buf, 0x800, "OSRELEASE=6.17.0\n"+lt.KallsymsKeys(0))
	if _, err := FindKernel(&lt.Memory{Buf: buf}, limits.Limits{}); !errors.As(err, &damage) || !strings.Contains(err.Error(), "swapper_pg_dir") {
		t.Errorf("damage and no layout: %v", err)
	}
	if _, err := FindKernel(&lt.Memory{Buf: minimal()}, limits.Limits{}); !errors.Is(err, ErrNoVMCoreInfo) {
		t.Errorf("no note: %v", err)
	}
	buf = minimal()
	lt.PutNote(buf, 0x100, "OSRELEASE=6.17.0\n"+lt.LayoutKeys(0))
	if _, err := FindKernel(&lt.Memory{Buf: buf}, limits.Limits{}); err == nil || !strings.Contains(err.Error(), "kallsyms_num_syms") {
		t.Errorf("no kallsyms keys: %v", err)
	}
}

func TestOnlyTheKernelMappingMoves(t *testing.T) {
	for address, want := range map[uint64]bool{
		0:                  false,
		0x36d40:            false,
		0xffffffff7fffffff: false,
		0xffffffff80000000: true,
		0xffffffff9434f000: true,
		0xffffffffbfffffff: true,
		0xffffffffc0000000: false,
		0xffff8d7e7ffce000: false,
	} {
		if InKernelImage(address) != want {
			t.Errorf("InKernelImage(0x%x) = %v", address, !want)
		}
	}
}
