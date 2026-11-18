package registrycellroutine

import (
	"testing"

	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

func FuzzEachRoutineIsPlacedByTheModuleThatHoldsIt(f *testing.F) {
	f.Add(uint64(getCell), uint64(driverBase+0x40), false)
	f.Add(uint64(0), uint64(0x7ff000000000), true)
	f.Add(uint64(kernelBase+0x100000), uint64(driverBase+0xffff), false)
	f.Add(^uint64(0), uint64(kernelBase-1), false)
	f.Fuzz(func(t *testing.T, get, release uint64, releaseUnread bool) {
		mem := words{0x1008: get}
		if !releaseUnread {
			mem[0x1010] = release
		}
		rows, _, err := run(t, mem, []registryhive.Hive{{Address: 0x1000, Name: "SYSTEM"}}, false)
		if err != nil || len(rows) != 2 {
			t.Fatalf("rows %+v, %v", rows, err)
		}
		mods := modules()
		for _, r := range rows {
			in := modulelist.Containing(mods, r.Address)
			ok := false
			switch r.Placement {
			case NullRoutine, NotRead:
				ok = r.Address == 0 && r.Module == ""
			case InNoModule:
				ok = r.Address != 0 && len(in) == 0 && r.Module == ""
			case InKernelImage:
				ok = len(in) > 0 && in[0].Base == kernelBase
			case InOtherModule:
				ok = len(in) > 0 && in[0].Base != kernelBase && r.Symbol == ""
			}
			if !ok {
				t.Fatalf("%s at 0x%x placed %s (module %q, symbol %q)", r.Member, r.Address, r.Placement, r.Module, r.Symbol)
			}
		}
		if releaseUnread && rows[1].Placement != NotRead {
			t.Fatalf("an unread pointer placed %s", rows[1].Placement)
		}
	})
}
