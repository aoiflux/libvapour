package modulelist

import (
	"debug/elf"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const mask = 1<<48 - 1

func fixture() *Fixture {
	f := NewFixture(0)
	f.AddModule(ModuleSpec{At: ModuleArea + 0x10000, Name: "ext4", Base: ModuleArea + 0x40000, TextSize: 0x1000, DataSize: 0x800})
	f.AddModule(ModuleSpec{At: ModuleArea + 0x20000, Name: "vboxguest", Base: ModuleArea + 0x80000, TextSize: 0x2000,
		InitSz: 0x100, Taints: 1<<12 | 1<<13})
	f.AddModule(ModuleSpec{At: ModuleArea + 0x30000, Name: "rk", Base: ModuleArea + 0xc0000, TextSize: 0x1000,
		NotListed: true})
	return f
}

func TestTheListGivesOneRowPerListedModule(t *testing.T) {
	ctx, _ := fixture().Context(t, nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []Row{
		{Address: (ModuleArea + 0x10000) & mask, Name: "ext4", State: "live", Source: "list",
			Base: (ModuleArea + 0x40000) & mask, CoreSize: 0x1800, FileState: linuxmodule.FileNone},
		{Address: (ModuleArea + 0x20000) & mask, Name: "vboxguest", State: "live", Source: "list",
			Base: (ModuleArea + 0x80000) & mask, CoreSize: 0x2000 + ModSize, InitSize: 0x100,
			Taints: "OOT_MODULE,UNSIGNED_MODULE", FileState: linuxmodule.FileNone},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v, want %+v", rows, want)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d %+v, want %+v", i, rows[i], want[i])
		}
	}
}

func TestDumpNeedsAnOutputDirectory(t *testing.T) {
	ctx, _ := fixture().Context(t, map[string]any{OptionDump: true})
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), tools.OptionOutputDir) {
		t.Errorf("a dump with no output directory: %v", err)
	}
}

func TestDumpWritesEachRebuiltModule(t *testing.T) {
	f := fixture()
	at := uint64(ModuleArea + 0x10000)
	f.AddELF(at, []string{".text", ".symtab", ".strtab"}, []uint64{ModuleArea + 0x40000, ModuleArea + 0x44000, ModuleArea + 0x45000})
	dir := t.TempDir()
	ctx, diags := f.Context(t, map[string]any{OptionDump: true, tools.OptionOutputDir: dir})
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].FileState != linuxmodule.FileWritten || rows[0].File == "" {
		t.Fatalf("rows %+v", rows)
	}
	file, err := elf.Open(filepath.Join(dir, rows[0].File))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if file.Section(".text") == nil {
		t.Error("no .text in the rebuilt file")
	}
	if rows[1].FileState != linuxmodule.FileFailed {
		t.Errorf("vboxguest has no section entries, so its rebuild fails: %+v", rows[1])
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "ELF rebuild") {
		t.Errorf("diags %q", *diags)
	}
}

func TestADumpOptionOfTheWrongTypeIsAnError(t *testing.T) {
	ctx, _ := fixture().Context(t, map[string]any{OptionDump: "maybe"})
	if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("err %v, want ErrOptionType", err)
	}
}
