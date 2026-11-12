package modulelist

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
)

func filtered(t *testing.T, opts map[string]any) ([]Module, []string, error) {
	t.Helper()
	mods := append([]fixMod{}, threeMods...)
	mods = append(mods, fixMod{0xfffff80005000000, 0x3000, "acme2.sys", `\SystemRoot\acme2.sys`})
	m := loaderList(mods)
	m.u64(entryAt(3)+offBaseName+8, 0x1000)
	ctx, diags := windowsContext(m, loaderTable("_KLDR_DATA_TABLE_ENTRY", true), opts)
	out, err := RunAny(ctx)
	if err != nil {
		return nil, *diags, err
	}
	return out.([]Module), *diags, nil
}

func names(mods []Module) []string {
	var out []string
	for _, m := range mods {
		out = append(out, m.Name)
	}
	return out
}

func TestTheNameFilterKeepsMatchesAndModulesWhoseNameDidNotRead(t *testing.T) {
	mods, diags, err := filtered(t, map[string]any{OptionName: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 || mods[0].Name != "acme.sys" || !mods[1].NameUnreadable {
		t.Fatalf("kept %q, want acme.sys and the unread name", names(mods))
	}
	for _, want := range []string{
		`windows.module.list: windows.module.list.name "acme" keep 2 of 4 modules`,
		"windows.module.list: 1 of them are kept because BaseDllName does not read, whatever windows.module.list.name says",
	} {
		if !hasDiag(diags, want) {
			t.Errorf("no diagnostic %q in %q", want, diags)
		}
	}
	for _, text := range []string{"ACME", "AcMe.SyS", "cme"} {
		if mods, _, _ := filtered(t, map[string]any{OptionName: text}); len(mods) != 2 || mods[0].Name != "acme.sys" {
			t.Errorf("%q kept %q, want acme.sys and the unread name: the match ignores case", text, names(mods))
		}
	}
	if upcase("é\U00010428") != "É\U00010428" {
		t.Errorf("upcase %q: only BMP characters change case", upcase("é\U00010428"))
	}
}

func TestTheBaseFilterTakesEitherFormOfTheBase(t *testing.T) {
	for _, base := range []any{uint64(0xfffff80003000000), uint64(0x0000f80003000000), "0xfffff80003000000"} {
		mods, _, err := filtered(t, map[string]any{OptionBase: base})
		if err != nil || len(mods) != 1 || mods[0].Name != "kdcom.dll" {
			t.Errorf("base %v: %q, %v; want kdcom.dll", base, names(mods), err)
		}
	}
	_, diags, _ := filtered(t, map[string]any{OptionBase: uint64(0xfffff80003000000)})
	want := "windows.module.list: windows.module.list.base 0xfffff80003000000 is a sign-extended base; its masked form 0xf80003000000 names the same module"
	if !hasDiag(diags, want) {
		t.Errorf("diagnostics %q, want %q", diags, want)
	}
	mods, diags, _ := filtered(t, map[string]any{OptionBase: uint64(0)})
	if len(mods) != 4 || !hasDiag(diags, "windows.module.list.base: 0 names no base: the option filters nothing") {
		t.Errorf("base 0: %q, %q", names(mods), diags)
	}
	if mods, _, _ := filtered(t, map[string]any{OptionBase: uint64(0xfffff80003000000), OptionName: "acme"}); len(mods) != 0 {
		t.Errorf("base and name both apply: %q", names(mods))
	}
}

func TestAFilterOptionOfTheWrongKindIsAnError(t *testing.T) {
	for _, opts := range []map[string]any{
		{OptionName: "\xff\xfe"},
		{OptionName: 7},
		{OptionBase: "not a number"},
	} {
		if _, _, err := filtered(t, opts); !errors.Is(err, tools.ErrOptionType) {
			t.Errorf("%v: %v, want ErrOptionType", opts, err)
		}
	}
}

func TestFiltersNeedAWindowsProfile(t *testing.T) {
	ctx, _ := windowsContext(sparse{}, loaderTable("_KLDR_DATA_TABLE_ENTRY", true), map[string]any{OptionName: "x"})
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := RunAny(ctx); !errors.Is(err, ErrFilterUnsupported) {
		t.Errorf("RunAny: %v, want ErrFilterUnsupported", err)
	}
}

func TestIsBaseAndTheCanonicalNote(t *testing.T) {
	const mask = uint64(1<<48 - 1)
	if !IsBase(0xfffff80003000000, 0xfffff80003000000, mask) || !IsBase(0xf80003000000, 0xfffff80003000000, mask) ||
		IsBase(0xfffff80003001000, 0xfffff80003000000, mask) {
		t.Error("IsBase compares the wrong forms")
	}
	ctx, diags := windowsContext(sparse{}, loaderTable("_KLDR_DATA_TABLE_ENTRY", true), nil)
	NoteCanonicalBase(ctx, "t", "k", 0xf80003000000, mask)
	if len(*diags) != 0 {
		t.Errorf("a masked base was noted: %q", *diags)
	}
}
