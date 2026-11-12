package cpulist

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

func processors(k *testsupport.S64Kernel, n int) (block uint64, pcrs []uint64) {
	block = k.Global("KiProcessorBlock", 8*uint64(n+1))
	count := k.Global("KeNumberProcessors", 4)
	k.Write(count, []byte{byte(n)})
	for i := 0; i < n; i++ {
		pcr := k.Alloc(0x1000)
		prcb := pcr + testsupport.S64PcrPrcb
		k.U64(pcr+testsupport.S64PcrSelf, pcr)
		k.U64(pcr+testsupport.S64PcrCurrentPrcb, prcb)
		k.U32(prcb+testsupport.S64PrcbNumber, uint32(i))
		k.U64(block+uint64(i)*8, prcb)
		pcrs = append(pcrs, pcr)
	}
	return block, pcrs
}

func TestEachProcessorBlockEntryGivesItsControlRegion(t *testing.T) {
	k := testsupport.NewS64Kernel()
	_, pcrs := processors(k, 3)
	k.U64(pcrs[2]+testsupport.S64PcrSelf, 0)
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	for i, r := range rows {
		if r.Index != i || r.Offset != pcrs[i] || r.PRCB != pcrs[i]+testsupport.S64PcrPrcb || r.Number != uint32(i) {
			t.Errorf("row %d = %+v", i, r)
		}
		if r.PointsBack != (i != 2) {
			t.Errorf("row %d PointsBack = %v", i, r.PointsBack)
		}
	}
}

func TestACountOfZeroOrAboveTheCapacityIsRefused(t *testing.T) {
	k := testsupport.NewS64Kernel()
	processors(k, 1)
	count, _ := k.Table.LookupSymbol("KeNumberProcessors")
	k.Write(count.Address, []byte{0})
	if _, err := Run(k.Context()); !errors.Is(err, ErrNoProcessors) {
		t.Errorf("err = %v", err)
	}
	st, _ := k.Table.Struct("_KAFFINITY_EX")
	st.Fields[0].Type.ArrayLength = 1
	k.Table.AddStruct(st)
	k.Write(count.Address, []byte{65})
	ctx := k.Context()
	ctx.Options["strict"] = true
	if _, err := Run(ctx); !errors.Is(err, ErrCountTooLarge) {
		t.Errorf("strict err = %v", err)
	}
	delete(ctx.Options, "strict")
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 {
		t.Errorf("lenient: rows %v err %v, want the one readable processor", rows, err)
	}
}

func TestCapacityFollowsTheAffinityBitmap(t *testing.T) {
	k := testsupport.NewS64Kernel()
	if Capacity(k.Table) != 2048 {
		t.Errorf("capacity %d", Capacity(k.Table))
	}
}

func FuzzProcessorBlock(f *testing.F) {
	f.Add(uint8(2), uint64(0xffffa00000000180), uint64(0))
	k := testsupport.NewS64Kernel()
	block := k.Global("KiProcessorBlock", 16)
	count := k.Global("KeNumberProcessors", 4)
	ctx := k.Context()
	f.Fuzz(func(t *testing.T, n uint8, a, b uint64) {
		k.Write(count, []byte{n})
		k.U64(block, a)
		k.U64(block+8, b)
		rows, err := Run(ctx)
		if err == nil && len(rows) > int(n) {
			t.Errorf("%d rows for a count of %d", len(rows), n)
		}
		for _, r := range rows {
			if r.PRCB-r.Offset != testsupport.S64PcrPrcb {
				t.Errorf("row %+v", r)
			}
		}
	})
}
