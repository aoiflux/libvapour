package linuxmodule_test

import (
	"bytes"
	"debug/elf"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

// The image is untrusted: whatever a struct module, its kallsyms or its
// section entries hold, every reader ends, and a rebuild either fails or
// gives a file debug/elf can parse.
func FuzzModuleReaders(f *testing.F) {
	seed := symbolFixture()
	sections(seed, extAt, []string{".text", ".data"}, []uint64{extBase, extAt + 0x400})
	raw, _ := seed.Mem.ReadAt(extAt, ModSize)
	ks, _ := seed.Mem.ReadAt(extAt+KallsymsAt, 0x1000)
	sa, _ := seed.Mem.ReadAt(extAt+0x2000, 0x100)
	f.Add(raw, ks, sa)
	f.Add(make([]byte, ModSize), []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, module, kallsyms, attrs []byte) {
		fx := symbolFixture()
		sections(fx, extAt, []string{".text", ".data"}, []uint64{extBase, extAt + 0x400})
		fx.Mem.Write(extAt, module)
		fx.Mem.Write(extAt+KallsymsAt, kallsyms)
		fx.Mem.Write(extAt+0x2000, attrs)
		ctx, _ := fx.Context(t, nil)
		ctx.Limits = limits.Limits{MaxTableEntries: 512, MaxListEntries: 64, MaxRegionScanBytes: 1 << 20, MaxNameBytes: 256}
		k, err := linuxkern.New(ctx)
		if err != nil {
			t.Fatal(err)
		}
		m, err := k.Modules()
		if err != nil {
			t.Fatal(err)
		}
		mod, err := m.Read(extAt)
		if err != nil {
			return
		}
		_, _ = m.Symbols(mod)
		_, _ = m.Parameters(mod)
		_ = m.Taints(mod.Taints)
		if _, err := m.Views(); err != nil {
			t.Fatal(err)
		}
		rb, err := m.RebuildELF(mod, 1<<20)
		if err != nil {
			return
		}
		file, err := elf.NewFile(bytes.NewReader(rb.File))
		if err != nil {
			t.Fatalf("rebuilt file does not parse: %v", err)
		}
		if rb.Symbols > 0 {
			if _, err := file.Symbols(); err != nil {
				t.Fatalf("rebuilt symbols do not parse: %v", err)
			}
		}
	})
}
