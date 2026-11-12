package moduledump

import (
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/tools"
	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

const mask = 1<<48 - 1

func fixture() (*Fixture, uint64) {
	f := NewFixture(0)
	mod := uint64(ModuleArea + 0x10000)
	f.AddModule(ModuleSpec{At: mod, Name: "lkm", Base: ModuleArea + 0x80000, TextSize: 0x1000})
	f.AddELF(mod, []string{".text", ".data", ".init.text"}, []uint64{ModuleArea + 0x80000, mod + 0x100, ModuleArea + 0x85000})
	return f, mod
}

func TestTheDumpWritesARebuiltModule(t *testing.T) {
	f, mod := fixture()
	dir := t.TempDir()
	ctx, _ := f.Context(t, map[string]any{OptionBase: mod & mask, tools.OptionOutputDir: dir})
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Address != mod&mask || rows[0].Name != "lkm" || rows[0].Sections != 2 || rows[0].Dropped != 1 {
		t.Fatalf("rows %+v", rows)
	}
	path := filepath.Join(dir, rows[0].File)
	st, err := os.Stat(path)
	if err != nil || uint64(st.Size()) != rows[0].Size {
		t.Fatalf("file %v %v, want %d bytes", st, err, rows[0].Size)
	}
	ef, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()
	if ef.Section(".text") == nil || ef.Section(".data") == nil || ef.Section(".symtab") == nil {
		t.Errorf("sections %+v", ef.Sections)
	}
	if _, err := Run(ctx); !errors.Is(err, extract.ErrArtifactExists) {
		t.Errorf("second run: %v", err)
	}
}

func TestTheDumpNeedsABaseAndAnOutputDirectory(t *testing.T) {
	f, mod := fixture()
	ctx, _ := f.Context(t, map[string]any{tools.OptionOutputDir: t.TempDir()})
	if _, err := Run(ctx); !errors.Is(err, ErrNoBase) {
		t.Errorf("no base: %v", err)
	}
	ctx, _ = f.Context(t, map[string]any{OptionBase: mod})
	if _, err := Run(ctx); !errors.Is(err, ErrNoOutputDir) {
		t.Errorf("no output directory: %v", err)
	}
	ctx, _ = f.Context(t, map[string]any{OptionBase: "0x1000", tools.OptionOutputDir: t.TempDir()})
	if _, err := Run(ctx); err == nil {
		t.Error("a base that does not read is an error")
	}
}
