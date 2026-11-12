package modulelist

import (
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

func TestALinuxProfileListsTheModuleListView(t *testing.T) {
	f := NewFixture(0)
	f.AddModule(ModuleSpec{At: ModuleArea + 0x10000, Name: "ext4", Base: ModuleArea + 0x40000, TextSize: 0x1000, DataSize: 0x800})
	f.AddModule(ModuleSpec{At: ModuleArea + 0x20000, Name: "vboxguest", Base: ModuleArea + 0x80000, TextSize: 0x2000, InitSz: 0x100})
	f.AddModule(ModuleSpec{At: ModuleArea + 0x30000, Name: "hidden", Base: ModuleArea + 0xc0000, TextSize: 0x1000, NotListed: true})
	ctx, _ := f.Context(t, nil)
	mods := mustRun(t, ctx)
	if len(mods) != 2 {
		t.Fatalf("modules %+v, want the two on the list", mods)
	}
	const mask = 1<<48 - 1
	ext4, vbox := mods[0], mods[1]
	if ext4.Name != "ext4" || ext4.Entry&mask != (ModuleArea+0x10000)&mask || ext4.Base&mask != (ModuleArea+0x40000)&mask ||
		ext4.Size != 0x1000 || ext4.InitSize != 0 || !ext4.SeparateRegions {
		t.Errorf("ext4 = %+v", ext4)
	}
	if vbox.Name != "vboxguest" || vbox.Size != 0x2000 || vbox.InitSize != 0x100 || vbox.Path != "" || vbox.PathUnreadable {
		t.Errorf("vboxguest = %+v", vbox)
	}
	want := []Region{{Kind: "text", Base: vbox.Base, Size: 0x2000}, {Kind: "data", Base: vbox.Entry, Size: ModSize},
		{Kind: "init_text", Base: 0, Size: 0x100}}
	if len(vbox.Regions) != len(want) {
		t.Fatalf("vboxguest regions %+v", vbox.Regions)
	}
	for i := range want {
		if vbox.Regions[i] != want[i] {
			t.Errorf("region %d %+v, want %+v", i, vbox.Regions[i], want[i])
		}
	}
}

func TestSeparateRegionsAttributeOnlyTheAddressesTheyHold(t *testing.T) {
	text, data := uint64(0xffffffffc0040000), uint64(0xffffffffc0010000)
	m := Module{Base: text, Size: 0x1000, Name: "ext4", SeparateRegions: true,
		Regions: []Region{{Kind: "text", Base: text, Size: 0x1000}, {Kind: "data", Base: data, Size: 0x800}}}
	for _, c := range []struct {
		at   uint64
		want bool
	}{{text + 0x10, true}, {data + 0x10, true}, {data + 0x800, false}, {text + 0x1000, false}, {text - 0x10000, false}} {
		if got := len(Containing([]Module{m}, c.at)) == 1; got != c.want {
			t.Errorf("address %#x held %v, want %v", c.at, got, c.want)
		}
	}
	joined := m
	joined.SeparateRegions, joined.Size = false, 0x2000
	if len(Containing([]Module{joined}, text+0x1800)) != 1 {
		t.Error("one allocation is not held through Base and Size")
	}
}

func TestALinuxTableWithoutTheModuleTypesIsAnError(t *testing.T) {
	f := NewFixture(0)
	ctx, _ := f.Context(t, nil)
	ctx.Symbols = symbols.NewTable("bare", 8)
	if _, err := Run(ctx); err == nil || !strings.HasPrefix(err.Error(), Name+": ") {
		t.Errorf("Run: %v, want an error that names the tool", err)
	}
}
