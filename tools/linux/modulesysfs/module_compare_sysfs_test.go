package modulesysfs

import (
	"testing"

	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

const mask = 1<<48 - 1

func TestModulesInOnlyOneOfListAndSysfs(t *testing.T) {
	f := NewFixture(0)
	f.AddModule(ModuleSpec{At: ModuleArea + 0x10000, Name: "ext4", Base: ModuleArea + 0x40000, TextSize: 0x1000})
	f.AddModule(ModuleSpec{At: ModuleArea + 0x20000, Name: "nosys", Base: ModuleArea + 0x80000, TextSize: 0x1000, NotInKset: true})
	f.AddModule(ModuleSpec{At: ModuleArea + 0x30000, Name: "rk", Base: ModuleArea + 0xc0000, TextSize: 0x1000, NotListed: true})
	ctx, _ := f.Context(t, nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	if rows[0].Name != "nosys" || rows[0].Source != "list" || rows[0].Address != (ModuleArea+0x20000)&mask {
		t.Errorf("row 0 %+v", rows[0])
	}
	if rows[1].Name != "rk" || rows[1].Source != "sysfs" || rows[1].Address != (ModuleArea+0x30000)&mask {
		t.Errorf("row 1 %+v", rows[1])
	}
}
