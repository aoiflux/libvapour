package modulelist

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

func TestTheLoaderListIsReadInLoadOrder(t *testing.T) {
	ctx, diags := windowsContext(loaderList(threeMods), loaderTable("_KLDR_DATA_TABLE_ENTRY", true), nil)
	mods := mustRun(t, ctx)
	if len(mods) != len(threeMods) {
		t.Fatalf("%d modules, want %d: %+v", len(mods), len(threeMods), mods)
	}
	for i, want := range threeMods {
		got := mods[i]
		if got.Entry != entryAt(i) || got.Base != want.base || got.Size != want.size || got.Name != want.name || got.Path != want.path {
			t.Errorf("module %d = %+v, want entry 0x%x %+v", i, got, entryAt(i), want)
		}
		if got.BaseUnreadable || got.SizeUnreadable || got.NameUnreadable || got.PathUnreadable {
			t.Errorf("module %d flagged unreadable: %+v", i, got)
		}
	}
	if len(*diags) != 0 {
		t.Errorf("a clean list gave diagnostics %q", *diags)
	}
}

func TestSizeOfImageIsFourBytesWhateverFollowsIt(t *testing.T) {
	ctx, _ := windowsContext(loaderList(threeMods[:1]), loaderTable("_KLDR_DATA_TABLE_ENTRY", true), nil)
	if got := mustRun(t, ctx)[0].Size; got != threeMods[0].size {
		t.Errorf("Size 0x%x, want 0x%x: the bytes after SizeOfImage were read into it", got, threeMods[0].size)
	}
}

func TestAMemberThatDoesNotReadIsFlaggedAndTheModuleKept(t *testing.T) {
	m := loaderList(threeMods)
	delete(m, entryAt(1))
	moved := entryAt(10) - 0x10
	m.u64(entryAt(0)+offLinks, moved)
	m.u64(moved, entryAt(2))
	m.u64(moved+8, entryAt(0))
	m.u64(entryAt(2)+8, moved)
	ctx, diags := windowsContext(m, loaderTable("_KLDR_DATA_TABLE_ENTRY", true), nil)
	mods := mustRun(t, ctx)
	if len(mods) != 3 {
		t.Fatalf("%d modules, want 3", len(mods))
	}
	got := mods[1]
	if got.Entry != moved || !got.BaseUnreadable || !got.SizeUnreadable || !got.NameUnreadable || !got.PathUnreadable {
		t.Errorf("module = %+v, want every member after the links unreadable", got)
	}
	if got.RangeKnown() {
		t.Error("a module whose base did not read has a known range")
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "_KLDR_DATA_TABLE_ENTRY at 0x"+hex(moved)+": DllBase does not read") {
		t.Errorf("no diagnostic names the unread DllBase: %q", *diags)
	}
}

func hex(v uint64) string { return strconv.FormatUint(v, 16) }

func TestABrokenFlinkIsWalkedAroundThroughBlink(t *testing.T) {
	m := loaderList(threeMods)
	m.u64(entryAt(0)+offLinks, 0)
	ctx, diags := windowsContext(m, loaderTable("_KLDR_DATA_TABLE_ENTRY", true), nil)
	mods := mustRun(t, ctx)
	var names []string
	for _, mod := range mods {
		names = append(names, mod.Name)
	}
	if strings.Join(names, " ") != "ntoskrnl.exe acme.sys kdcom.dll" {
		t.Errorf("modules %v, want the forward entry then the two found through Blink", names)
	}
	want := "windows.module.list: PsLoadedModuleList head at 0x" + hex(listHead) + ": 2 of 3 modules were reached only through Blink"
	if !hasDiag(*diags, want) {
		t.Errorf("no diagnostic %q in %q", want, *diags)
	}
}

func TestStrictModeRefusesABrokenList(t *testing.T) {
	m := loaderList(threeMods)
	m.u64(entryAt(1)+8, 0x1234)
	ctx, _ := windowsContext(m, loaderTable("_KLDR_DATA_TABLE_ENTRY", true), map[string]any{"strict": true})
	mods, err := Run(ctx)
	if !errors.Is(err, winkernel.ErrListBackLink) || mods != nil {
		t.Fatalf("Run = %v, %v; want no modules and the back-link break", mods, err)
	}
}

func TestAnUnreadableHeadIsAnError(t *testing.T) {
	m := loaderList(threeMods)
	delete(m, listHead&^(page-1))
	ctx, _ := windowsContext(m, loaderTable("_KLDR_DATA_TABLE_ENTRY", true), nil)
	if _, err := Run(ctx); !errors.Is(err, winkernel.ErrListUnreadable) {
		t.Fatalf("Run error %v, want ErrListUnreadable", err)
	}
}

func TestTheProcessLoaderTypeServesATableWithoutTheKernelOne(t *testing.T) {
	ctx, _ := windowsContext(loaderList(threeMods), loaderTable("_LDR_DATA_TABLE_ENTRY", true), nil)
	if mods := mustRun(t, ctx); len(mods) != 3 || mods[2].Name != "acme.sys" {
		t.Errorf("modules %+v, want the three through _LDR_DATA_TABLE_ENTRY", mods)
	}
}

func TestATableWithoutFullDllNameReadsNoPath(t *testing.T) {
	ctx, diags := windowsContext(loaderList(threeMods), loaderTable("_KLDR_DATA_TABLE_ENTRY", false), nil)
	mods := mustRun(t, ctx)
	if mods[0].Path != "" || !mods[0].PathUnreadable || mods[0].Name != "ntoskrnl.exe" {
		t.Errorf("module %+v, want the name and an unreadable path", mods[0])
	}
	if !hasDiag(*diags, "windows.module.list: _KLDR_DATA_TABLE_ENTRY has no FullDllName: module paths are not read") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestARequiredMemberOrTheHeadMissingIsAnError(t *testing.T) {
	ctx, _ := windowsContext(loaderList(threeMods), symbols.NewTable("empty", 8), nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoLoaderEntry) {
		t.Errorf("no loader type: %v, want ErrNoLoaderEntry", err)
	}
	tab := symbols.NewTable("t", 8)
	tab.AddStruct(symbols.StructType{Name: "_KLDR_DATA_TABLE_ENTRY", Size: entryBytes, Fields: []symbols.Field{
		field("InLoadOrderLinks", 0, "_LIST_ENTRY"), field("DllBase", offDllBase, "void")}})
	ctx.Symbols = tab
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "BaseDllName") {
		t.Errorf("no BaseDllName: %v, want an error naming it", err)
	}
	full := loaderTable("_KLDR_DATA_TABLE_ENTRY", true)
	bare := symbols.NewTable("t", 8)
	for _, name := range []string{"_LIST_ENTRY", "_UNICODE_STRING", "_KLDR_DATA_TABLE_ENTRY"} {
		st, _ := full.Struct(name)
		bare.AddStruct(st)
	}
	ctx.Symbols = bare
	if _, err := Run(ctx); !errors.Is(err, ErrNoListHead) {
		t.Errorf("no PsLoadedModuleList: %v, want ErrNoListHead", err)
	}
}

func TestABaseOutsideSystemSpaceOrAnEmptyImageIsReported(t *testing.T) {
	mods := append([]fixMod{}, threeMods...)
	mods[1].base = 0x7ff600000000
	mods[2].size = 0
	ctx, diags := windowsContext(loaderList(mods), loaderTable("_KLDR_DATA_TABLE_ENTRY", true), nil)
	got := mustRun(t, ctx)
	if len(got) != 3 || got[1].Base != 0x7ff600000000 {
		t.Fatalf("modules %+v, want all three as read", got)
	}
	for _, want := range []string{
		"windows.module.list: loader entry at 0x" + hex(entryAt(1)) + ": DllBase 0x7ff600000000 lies below system space at 0xffff800000000000",
		"windows.module.list: loader entry at 0x" + hex(entryAt(2)) + ": SizeOfImage is 0",
	} {
		if !hasDiag(*diags, want) {
			t.Errorf("no diagnostic %q in %q", want, *diags)
		}
	}
}

type otherOS struct{}

func (otherOS) Name() string       { return "other" }
func (otherOS) OS() string         { return "plan9" }
func (otherOS) PointerSize() uint8 { return 8 }

func TestAnOSOtherThanWindowsOrLinuxIsRefused(t *testing.T) {
	ctx, _ := windowsContext(loaderList(threeMods), loaderTable("_KLDR_DATA_TABLE_ENTRY", true), nil)
	ctx.Profile = otherOS{}
	if _, err := Run(ctx); !errors.Is(err, ErrUnsupportedOS) {
		t.Errorf("Run error %v, want ErrUnsupportedOS", err)
	}
}

func TestTheToolIsRegisteredUnderItsName(t *testing.T) {
	if _, err := tools.Get(Name); err != nil {
		t.Fatalf("%s: %v", Name, err)
	}
}

func FuzzLoadedModules(f *testing.F) {
	f.Add(make([]byte, 64), uint64(0))
	f.Add(make([]byte, 0x200), uint64(0x10))
	f.Fuzz(func(t *testing.T, raw []byte, flink uint64) {
		m := loaderList(threeMods)
		m.write(entryAt(1), raw)
		m.u64(entryAt(0)+offLinks, flink)
		ctx, _ := windowsContext(m, loaderTable("_KLDR_DATA_TABLE_ENTRY", true), map[string]any{})
		ctx.Limits.MaxListEntries = 16
		mods, err := Run(ctx)
		if err != nil {
			return
		}
		if len(mods) > 16 {
			t.Fatalf("%d modules past the list cap", len(mods))
		}
		seen := map[uint64]bool{}
		for _, mod := range mods {
			if seen[mod.Entry] {
				t.Fatalf("entry 0x%x listed twice", mod.Entry)
			}
			seen[mod.Entry] = true
			if mod.BaseUnreadable && mod.Base != 0 || mod.SizeUnreadable && mod.Size != 0 || mod.Size > 0xffffffff {
				t.Fatalf("module %+v breaks the read rules", mod)
			}
		}
	})
}
