package registryhive

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
)

func twoHiveImage() (*fxImage, *fxHive, *fxHive) {
	img := newFxImage()
	sys := img.newHive([3]string{"", "", `\REGISTRY\MACHINE\SYSTEM`})
	sys.root = sys.key(0, fxKey{name: "ROOT", flags: keyHiveRoot})
	sys.commit()
	user := img.newHive([3]string{"", `\??\C:\Users\x\NTUSER.DAT`, `\REGISTRY\USER\S-1-5-21-1`})
	user.root = user.key(0, fxKey{name: "ROOT", flags: keyHiveRoot})
	user.key(1, fxKey{name: "Volatile"})
	user.commit()
	return img, sys, user
}

func TestTheHiveListGivesPathsSizesAndRootInListOrder(t *testing.T) {
	img, sys, user := twoHiveImage()
	hives, err := Run(img.context(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(hives) != 2 {
		t.Fatalf("%d hives", len(hives))
	}
	if h := hives[0]; h.Address != sys.cmhive || h.FileFullPath != `\REGISTRY\MACHINE\SYSTEM` || h.Name != "SYSTEM" ||
		h.RegistryPath != `\REGISTRY\MACHINE\SYSTEM` || h.RootCell != fxRootCellSize || h.StableSize != fxBlock || h.VolatileSize != 0 {
		t.Errorf("system %+v", h)
	}
	if h := hives[1]; h.Address != user.cmhive || h.FileFullPath != `\??\C:\Users\x\NTUSER.DAT` || h.Name != "NTUSER.DAT" ||
		h.RegistryPath != `\REGISTRY\USER\S-1-5-21-1` || h.VolatileSize != fxBlock {
		t.Errorf("user %+v", h)
	}
}

func TestAListEntryThatIsNotAHiveIsReportedAndSkipped(t *testing.T) {
	img, sys, _ := twoHiveImage()
	img.mem.u32(sys.cmhive, 0x1234)
	hives, err := Run(img.context(nil))
	if err != nil || len(hives) != 1 || hives[0].Name != "NTUSER.DAT" {
		t.Fatalf("%+v %v", hives, err)
	}
	if !slices.ContainsFunc(*img.diags, func(d string) bool { return strings.Contains(d, "not opened") }) {
		t.Errorf("diagnostics %q", *img.diags)
	}
	if _, err := Run(img.context(map[string]any{"strict": true})); !errors.Is(err, ErrNotHive) {
		t.Errorf("strict: %v", err)
	}
}

func TestTheNameOptionSelectsHives(t *testing.T) {
	img, _, _ := twoHiveImage()
	hives, err := Run(img.context(map[string]any{optionNameFilter: "ntuser.dat"}))
	if err != nil || len(hives) != 1 || hives[0].Name != "NTUSER.DAT" {
		t.Fatalf("%+v %v", hives, err)
	}
}

func TestNoHiveListSymbolIsAnError(t *testing.T) {
	img := newFxImage()
	tbl := symbols.NewTable("bare", 8)
	ctx := img.context(nil)
	ctx.Symbols = tbl
	if _, err := Run(ctx); !errors.Is(err, ErrLayout) {
		t.Errorf("no types: %v", err)
	}
	ctx.Symbols = fxTableWithout("CmpHiveListHead")
	if _, err := Run(ctx); !errors.Is(err, ErrNoHiveList) {
		t.Errorf("no symbol: %v", err)
	}
}

func fxTableWithout(symbol string) *symbols.Table {
	full := fxTable()
	t := symbols.NewTable("s49", 8)
	for _, name := range []string{"_LIST_ENTRY", "_UNICODE_STRING", "_CMHIVE", "_CM_KEY_CONTROL_BLOCK", "_HHIVE", "_DUAL",
		"_HMAP_DIRECTORY", "_HMAP_TABLE", "_HMAP_ENTRY", "_HBASE_BLOCK", "_CHILD_LIST", "_CM_KEY_NODE", "_CM_KEY_VALUE",
		"_CM_KEY_INDEX", "_CM_INDEX", "_CM_BIG_DATA"} {
		st, _ := full.Struct(name)
		t.AddStruct(st)
	}
	for _, s := range full.TableSymbols() {
		if s.Name != symbol {
			t.AddSymbol(s)
		}
	}
	return t
}

func TestSelectHivesPrefersAnExactName(t *testing.T) {
	hives := []Hive{
		{Name: "SYSTEM", FileFullPath: `\REGISTRY\MACHINE\SYSTEM`},
		{Name: "SOFTWARE", FileFullPath: `\SystemRoot\System32\Config\SOFTWARE`},
		{Name: "x.dat", FileFullPath: `\??\C:\SystemAppData\x.dat`, RegistryPath: `\REGISTRY\A\{1}`},
	}
	if got := SelectHives(hives, "system"); len(got) != 1 || got[0].Name != "SYSTEM" {
		t.Errorf("exact %+v", got)
	}
	if got := SelectHives(hives, "config"); len(got) != 1 || got[0].Name != "SOFTWARE" {
		t.Errorf("substring %+v", got)
	}
	if got := SelectHives(hives, "{1}"); len(got) != 1 || got[0].Name != "x.dat" {
		t.Errorf("registry path %+v", got)
	}
	if got := SelectHives(hives, ""); len(got) != 3 {
		t.Errorf("no filter %d", len(got))
	}
}

func TestOpenHiveFindsAListedHiveByName(t *testing.T) {
	img, sys, _ := twoHiveImage()
	l, err := OpenHive(img.context(nil), "system", nil)
	if err != nil || l.cmhive != sys.cmhive {
		t.Fatalf("%v", err)
	}
	if _, err := OpenHive(img.context(nil), "SAM", nil); err == nil || err.Error() != `registryhive: no hive named "SAM" opens` {
		t.Errorf("absent: %v", err)
	}
	if l, err := OpenFirstHiveContaining(img.context(nil), "users", nil); err != nil || l.cmhive == sys.cmhive {
		t.Errorf("containing: %v", err)
	}
	if got := OpenHivesContaining(img.context(nil), "REGISTRY", nil); len(got) != 2 {
		t.Errorf("all containing %d", len(got))
	}
	if got := OpenEveryHive(img.context(nil), nil); len(got) != 2 || got[0].Hive.Name != "SYSTEM" {
		t.Errorf("every %+v", got)
	}
	if got := GatherHives(img.context(nil)); len(got) != 2 {
		t.Errorf("gathered %d", len(got))
	}
}

func TestPreferListedFallsBackToScanOnlyHives(t *testing.T) {
	hives := []Hive{{Name: "A", Address: 1}, {Name: "B", Address: 2}, {Name: "A", Address: 3}}
	if got := preferListed(hives, 2, nameIs("a")); len(got) != 1 || got[0].Address != 1 {
		t.Errorf("listed %+v", got)
	}
	if got := preferListed(hives, 1, nameIs("b")); len(got) != 1 || got[0].Address != 2 {
		t.Errorf("scan-only %+v", got)
	}
}

func TestACellReaderSendsUserAddressesToTheRegistryProcess(t *testing.T) {
	kernel, user := newFxMemory(), newFxMemory()
	kernel.write(0xffff800000001000, []byte{1})
	user.write(0x10000, []byte{2})
	s := cellSpace{kernel: kernel, user: user, width: 8}
	if b, err := s.ReadAt(0x10000, 1); err != nil || b[0] != 2 {
		t.Errorf("user %v %v", b, err)
	}
	if b, err := s.ReadAt(0xffff800000001000, 1); err != nil || b[0] != 1 {
		t.Errorf("kernel %v %v", b, err)
	}
	if _, err := (cellSpace{kernel: kernel, width: 8}).ReadAt(0x10000, 1); !errors.Is(err, ErrUserCellNoSpace) {
		t.Errorf("no user space: %v", err)
	}
	if !userAddress(0x7fffffff, 4) || userAddress(0x80000000, 4) || !userAddress(0x7fffffffffff, 8) || userAddress(0x800000000000, 8) {
		t.Error("user space bounds")
	}
}

func TestCellReaderKeepsTheKernelWhenTheBuildHasNoRegistryProcess(t *testing.T) {
	img, _, _ := twoHiveImage()
	if r := CellReader(img.context(nil)); r != img.mem {
		t.Errorf("reader %T", r)
	}
	img.table.AddSymbol(symbols.Symbol{Name: "CmpRegistryProcess", Address: 0xfffff80000002000})
	*img.diags = nil
	r := CellReader(img.context(nil))
	if s, ok := r.(cellSpace); !ok || s.user != nil || len(*img.diags) == 0 {
		t.Errorf("reader %T diagnostics %q", r, *img.diags)
	}
}
