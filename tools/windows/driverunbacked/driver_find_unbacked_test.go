package driverunbacked

import (
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
)

func TestOnlyDriversOutsideEveryModuleAreListed(t *testing.T) {
	k := testsupport.NewS64Kernel()
	k.AddModule("ntoskrnl.exe", 0xfffff80000400000, 0x100000)
	k.AddModule("alpha.sys", 0xfffff80001000000, 0x5000)
	k.AddDriver(testsupport.S64Driver{Name: `\Driver\alpha`, Start: 0xfffff80001000000, Size: 0x5000})
	hidden := k.AddDriver(testsupport.S64Driver{Name: `\Driver\hidden`, Start: 0xfffff80009000000, Size: 0x3000})
	raw := k.AddDriver(testsupport.S64Driver{Name: `\FileSystem\RAW`})
	rows, err := Run(k.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := map[uint64]bool{}
	for _, r := range rows {
		got[r.VirtualOffset] = r.NoImage
	}
	if len(rows) != 2 || got[hidden] || !got[raw] {
		t.Errorf("rows = %+v, want the hidden driver and RAW with NoImage", rows)
	}
	if _, ok := got[hidden]; !ok {
		t.Error("the driver outside every module is missing")
	}
}

func TestTheModuleListIsRequired(t *testing.T) {
	k := testsupport.NewS64Kernel()
	k.AddDriver(testsupport.S64Driver{Name: `\Driver\alpha`, Start: 0xfffff80001000000, Size: 0x5000})
	ctx := k.Context()
	k.U64(0xfffff80000001000, 0)
	k.U64(0xfffff80000001008, 0)
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Error("strict mode listed drivers over a module list that does not walk")
	}
}
