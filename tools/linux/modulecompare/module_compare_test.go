package modulecompare

import (
	"testing"

	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

const mask = 1<<48 - 1

func TestEachModuleSaysWhichViewsHoldIt(t *testing.T) {
	f := NewFixture(0)
	both := uint64(ModuleArea + 0x10000)
	listOnly := uint64(ModuleArea + 0x20000)
	sysfsOnly := uint64(ModuleArea + 0x30000)
	f.AddModule(ModuleSpec{At: both, Name: "ext4", Base: ModuleArea + 0x80000, TextSize: 0x1000})
	f.AddModule(ModuleSpec{At: listOnly, Name: "nosys", Base: ModuleArea + 0x90000, TextSize: 0x1000, NotInKset: true,
		Taints: 1<<9 | 1<<12})
	f.AddModule(ModuleSpec{At: sysfsOnly, Name: "rk", Base: ModuleArea + 0xa0000, TextSize: 0x1000, NotListed: true, Taints: 1})
	ctx, _ := f.Context(t, nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []Row{
		{Name: "ext4", Address: both & mask, InList: true, InSysfs: true, InScan: true},
		{Name: "nosys", Address: listOnly & mask, InList: true, InScan: true, Taints: "WARN,OOT_MODULE"},
		{Name: "rk", Address: sysfsOnly & mask, InSysfs: true, InScan: true, Taints: "PROPRIETARY_MODULE"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d %+v, want %+v", i, rows[i], want[i])
		}
	}
	ctx, _ = f.Context(t, map[string]any{OptionPlainTaints: true})
	rows, err = Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Taints != "" || rows[1].Taints != "O" || rows[2].Taints != "P" {
		t.Errorf("letters %q %q %q", rows[0].Taints, rows[1].Taints, rows[2].Taints)
	}
}
