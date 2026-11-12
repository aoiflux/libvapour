package modulehidden

import (
	"testing"

	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const mask = 1<<48 - 1

func fixture() *Fixture {
	f := NewFixture(0)
	f.AddModule(ModuleSpec{At: ModuleArea + 0x10000, Name: "ext4", Base: ModuleArea + 0x40000, TextSize: 0x1000})
	f.AddModule(ModuleSpec{At: ModuleArea + 0x30000, Name: "rk", Base: ModuleArea + 0xc0000, TextSize: 0x1000,
		NotListed: true, NotInKset: true})
	return f
}

func TestTheScanFindsAModuleMissingFromTheList(t *testing.T) {
	ctx, _ := fixture().Context(t, nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Address != (ModuleArea+0x30000)&mask || rows[0].Name != "rk" || rows[0].Source != "scan" ||
		rows[0].FileState != linuxmodule.FileNone {
		t.Errorf("rows %+v", rows)
	}
}

func TestNothingIsHiddenWhenEveryModuleIsListed(t *testing.T) {
	f := NewFixture(0)
	f.AddModule(ModuleSpec{At: ModuleArea + 0x10000, Name: "ext4", Base: ModuleArea + 0x40000, TextSize: 0x1000})
	ctx, _ := f.Context(t, nil)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 {
		t.Errorf("rows %+v err %v", rows, err)
	}
}

func TestStrictModeFailsWhenTheListBreaks(t *testing.T) {
	f := fixture()
	f.Mem.U64(ModuleArea+0x10000+ModList, 0xffff888000000000)
	ctx, _ := f.Context(t, map[string]any{"strict": true})
	if _, err := Run(ctx); err == nil {
		t.Error("a broken list in strict mode")
	}
}
