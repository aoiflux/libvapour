package filedump

import (
	"errors"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/tools"
)

func TestAnAddressOptionMustNameAnAddress(t *testing.T) {
	for _, v := range []any{[]uint64{}, "", "x", -1} {
		f := buildFixture()
		f.opts[OptionVirtAddr] = v
		if _, err := readSelection(f.context()); !errors.Is(err, tools.ErrOptionType) {
			t.Errorf("%#v: %v", v, err)
		}
	}
	f := buildFixture()
	f.opts[OptionPhysAddr] = []uint64{}
	if _, err := readSelection(f.context()); !errors.Is(err, ErrEmptyAddressList) {
		t.Errorf("empty physaddr: %v", err)
	}
}

func TestAFilterExcludesGivenAddresses(t *testing.T) {
	for _, key := range []string{OptionVirtAddr, OptionPhysAddr} {
		f := buildFixture()
		delete(f.opts, OptionVirtAddr)
		f.opts[key] = []uint64{0x1000}
		f.opts[OptionFilter] = `\.txt$`
		if _, err := readSelection(f.context()); !errors.Is(err, ErrFilterWithAddress) {
			t.Errorf("%s: %v", key, err)
		}
	}
}

func TestAPhysicalAddressNeedsThePhysicalLayer(t *testing.T) {
	f := buildFixture()
	delete(f.opts, tools.OptionPhysicalMemory)
	f.opts[OptionPhysAddr] = []uint64{0x1000}
	if _, err := readSelection(f.context()); !errors.Is(err, ErrNoPhysicalMemory) {
		t.Fatal(err)
	}
}

func TestOptionsThatDoNothingSaySo(t *testing.T) {
	f := buildFixture()
	f.opts[OptionIgnoreCase] = true
	f.opts["pid"] = uint64(4)
	sel, err := readSelection(f.context())
	if err != nil || !sel.addressed() {
		t.Fatalf("%+v, %v", sel, err)
	}
	if !f.said(OptionIgnoreCase, "does nothing without", OptionFilter) || !f.said("pid is not applied") {
		t.Errorf("diagnostics %q", f.diags)
	}
}

func TestIgnoreCaseFoldsTheFilter(t *testing.T) {
	f := buildFixture()
	delete(f.opts, OptionVirtAddr)
	f.opts[OptionFilter] = `A\.TXT$`
	f.opts[OptionIgnoreCase] = "true"
	sel, err := readSelection(f.context())
	if err != nil || sel.pattern == nil || !sel.pattern.MatchString(`\docs\a.txt`) {
		t.Fatalf("%+v, %v", sel, err)
	}
	sel.reportFilter(f.context(), filterTally{tested: 3, kept: 1, unnamed: 1})
	if !f.said(`windows.file.dump.filter "A\\.TXT$", ignoring case keeps 1 of 3 file objects`) ||
		!f.said("leaves out 1 file objects whose name does not read as a full device path") {
		t.Errorf("diagnostics %q", f.diags)
	}
}

func TestEachGivenFileObjectIsCarvedOnce(t *testing.T) {
	f := buildFixture()
	masked := fxFO & 0x0000ffffffffffff
	f.opts[OptionVirtAddr] = []uint64{fxFO, masked, 0x1234800000001000}
	f.opts[OptionPhysAddr] = []uint64{f.k.at(fxFO), f.k.at(fxFO2), f.k.at(fxFO2), 1 << 40}
	ctx := f.context()
	sel, err := readSelection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := sel.owners(ctx)
	want := []fileOwner{
		{fileObject: fxFO, addressed: true},
		{fileObject: f.k.at(fxFO2), physical: true, addressed: true},
	}
	if len(got) != len(want) {
		t.Fatalf("owners %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("owner %d %+v, want %+v", i, got[i], want[i])
		}
	}
	for _, d := range []string{
		"names file object 0xffff800000001000 again (given first as 0xffff800000001000)",
		"0x1234800000001000 is read as 0xffff800000001000: the paging mode translates 48 address bits",
		"is where windows.file.dump.virtaddr 0xffff800000001000 lies: carved once, through the virtual address",
		"lies past the end of physical memory",
	} {
		if !f.said(d) {
			t.Errorf("no diagnostic %q in %q", d, f.diags)
		}
	}
}

func TestTheFilterMatchesTheNameTheHandleListShows(t *testing.T) {
	f := buildFixture()
	ctx := f.context()
	if name, ok := fullName(ctx, fields{}, nil, ctx.Memory, fxFO); !ok || name != fxName {
		t.Errorf("absolute: %q, %v", name, ok)
	}
	rel := utf16.Encode([]rune(`a.txt`))
	for i, c := range rel {
		f.k.WriteU16(fxNameBuf+uint64(2*i), c)
	}
	f.k.WriteU16(fxFO+0x58, uint16(2*len(rel)))
	if name, ok := fullName(ctx, fields{}, nil, ctx.Memory, fxFO); ok {
		t.Errorf("relative name %q matched", name)
	}
}
