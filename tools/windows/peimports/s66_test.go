package peimports

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
)

const (
	mainBase = uint64(0x7ff600400000)
	ws2Base  = uint64(0x7ff810000000)

	importSlot  = 0x98 + 112 + 1*8
	descRVA     = uint32(0x5000)
	iltRVA      = uint32(0x5100)
	iatRVA      = uint32(0x5200)
	stringsRVA  = uint32(0x5400)
	ordinalFlag = uint64(1) << 63
)

type wantedImport struct {
	name    string
	ordinal uint16
	hintRVA uint32
}

type library struct {
	name    string
	stamp   uint32
	imports []wantedImport
}

// mainImage adds an import directory to an image from
// testsupport.BuildExportingPE (optional header at 0x98, PE32+).
func mainImage(libs ...library) []byte {
	img := testsupport.BuildExportingPE(mainBase, nil)
	binary.LittleEndian.PutUint32(img[importSlot:], descRVA)
	binary.LittleEndian.PutUint32(img[importSlot+4:], uint32(20*(len(libs)+1)))
	str := stringsRVA
	putString := func(s string, hint bool) uint32 {
		at := str
		if hint {
			str += 2
		}
		copy(img[str:], s)
		str += uint32(len(s)) + 1
		str += str & 1
		return at
	}
	slot := uint32(0)
	for i, l := range libs {
		d := img[descRVA+uint32(20*i):]
		binary.LittleEndian.PutUint32(d[0:], iltRVA+8*slot)
		binary.LittleEndian.PutUint32(d[4:], l.stamp)
		binary.LittleEndian.PutUint32(d[12:], putString(l.name, false))
		binary.LittleEndian.PutUint32(d[16:], iatRVA+8*slot)
		for _, imp := range l.imports {
			var v uint64
			switch {
			case imp.name == "":
				v = ordinalFlag | uint64(imp.ordinal)
			case imp.hintRVA != 0:
				v = uint64(imp.hintRVA)
			default:
				v = uint64(putString(imp.name, true))
			}
			binary.LittleEndian.PutUint64(img[iltRVA+8*slot:], v)
			binary.LittleEndian.PutUint64(img[iatRVA+8*slot:], v)
			slot++
		}
		slot++
	}
	return img
}

func process(pid uint64, name string, img []byte, mods ...testsupport.FixtureModule) testsupport.FixtureProcess {
	return testsupport.FixtureProcess{PID: pid, Name: name, ImageBaseAddress: mainBase, SectionBaseAddress: mainBase,
		Modules: mods, VADs: []testsupport.FixtureVAD{{Start: mainBase, End: mainBase + uint64(len(img)) - 1}}}
}

func build(procs []testsupport.FixtureProcess, images map[uint64][]byte) *testsupport.ProcessFixture {
	f := testsupport.BuildProcessFixture(procs)
	for pid, img := range images {
		f.Space(pid).MapImage(mainBase, img)
	}
	return f
}

func withDiagnostics(ctx tools.Context) (tools.Context, *[]string) {
	sink := []string{}
	ctx.Options["diagnostics"] = &sink
	return ctx, &sink
}

func TestRowsFollowTheDescriptorsAndGiveTheSlotAddress(t *testing.T) {
	img := mainImage(
		library{name: "KERNEL32.dll", imports: []wantedImport{{name: "CreateFileW"}, {name: "ReadFile"}}},
		library{name: "USER32.dll", stamp: 0xFFFFFFFF, imports: []wantedImport{{name: "MessageBoxW"}}},
	)
	f := build([]testsupport.FixtureProcess{process(100, "app.exe", img)}, map[uint64][]byte{100: img})
	rows, err := Run(f.Context())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.Library+"!"+r.Function)
	}
	if !slices.Equal(got, []string{"KERNEL32.dll!CreateFileW", "KERNEL32.dll!ReadFile", "USER32.dll!MessageBoxW"}) {
		t.Fatalf("rows %v", got)
	}
	if rows[1].Address != mainBase+uint64(iatRVA)+8 || rows[1].PID != 100 || rows[1].Name != "app.exe" || rows[1].ImageBase != mainBase {
		t.Errorf("ReadFile row %+v", rows[1])
	}
	if rows[0].Bound || !rows[2].Bound {
		t.Errorf("Bound: %v %v, want false then true", rows[0].Bound, rows[2].Bound)
	}
	if rows[2].Address != mainBase+uint64(iatRVA)+3*8 {
		t.Errorf("the slot after the first library's terminator is 0x%x", rows[2].Address)
	}
}

func TestOrdinalsAreNamedFromTheMappedLibraryThenTheTable(t *testing.T) {
	ws2 := testsupport.BuildExportingPE(ws2Base, []testsupport.FixtureExport{
		{Name: "accept", Body: []byte{0xC3}}, {Name: "", Body: []byte{0xC3}}, {Name: "NamedHere", Body: []byte{0xC3}}})
	img := mainImage(
		library{name: "WS2_32.dll", imports: []wantedImport{{ordinal: 3}, {ordinal: 2}}},
		library{name: "ws2_32.dll", imports: []wantedImport{{ordinal: 9999}}},
		library{name: "OTHER.dll", imports: []wantedImport{{ordinal: 1}}},
	)
	f := build([]testsupport.FixtureProcess{
		process(100, "app.exe", img, testsupport.FixtureModule{Name: "ws2_32.dll", Base: ws2Base, Image: ws2}),
	}, map[uint64][]byte{100: img})
	rows, err := Run(f.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ fn, from string }{
		{"NamedHere", OrdinalFromExports},
		{"bind", OrdinalFromTable},
		{"", ""},
		{"", ""},
	}
	if len(rows) != len(want) {
		t.Fatalf("%d rows, want %d", len(rows), len(want))
	}
	for i, w := range want {
		if !rows[i].ByOrdinal || rows[i].Function != w.fn || rows[i].FunctionFrom != w.from {
			t.Errorf("row %d = %+v, want %q from %q", i, rows[i], w.fn, w.from)
		}
	}
	if rows[2].Ordinal != 9999 {
		t.Errorf("ordinal %d, want 9999", rows[2].Ordinal)
	}
}

func TestTheSectionBaseServesAProcessWhosePEBGivesNoImage(t *testing.T) {
	img := mainImage(library{name: "a.dll", imports: []wantedImport{{name: "F"}}})
	p := process(100, "app.exe", img)
	p.ImageBaseAddress = 0
	f := build([]testsupport.FixtureProcess{p, {PID: 4, Name: "System", NoPeb: true}}, map[uint64][]byte{100: img})
	ctx, diags := withDiagnostics(f.Context())
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || rows[0].ImageBase != mainBase {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
	joined := strings.Join(*diags, "\n")
	for _, want := range []string{"1 main images found through _EPROCESS.SectionBaseAddress", "1 processes passed over: no PEB"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no diagnostic %q in %q", want, joined)
		}
	}
}

func TestAnUnreadableHintNameIsFlaggedAndTheRowKept(t *testing.T) {
	img := mainImage(library{name: "a.dll", imports: []wantedImport{{name: "F", hintRVA: 0x7FF0}, {name: "G"}}})
	f := build([]testsupport.FixtureProcess{process(100, "app.exe", img)}, map[uint64][]byte{100: img})
	ctx := f.Context()
	testsupport.HoleInProcess(&ctx, f.DirectoryTableBase(100), mainBase+0x7000, mainBase+0x8000)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
	if !rows[0].FunctionUnreadable || rows[0].Function != "" || rows[1].FunctionUnreadable || rows[1].Function != "G" {
		t.Errorf("rows %+v", rows)
	}
}

func TestThePIDOptionNarrowsTheProcesses(t *testing.T) {
	img := mainImage(library{name: "a.dll", imports: []wantedImport{{name: "F"}}})
	f := build([]testsupport.FixtureProcess{process(100, "a.exe", img), process(200, "b.exe", img)},
		map[uint64][]byte{100: img, 200: img})
	ctx := f.Context()
	ctx.Options["pid"] = uint64(200)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || rows[0].PID != 200 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
}

func TestAMainImageWithoutImportsGivesNoRows(t *testing.T) {
	img := testsupport.BuildExportingPE(mainBase, nil)
	f := build([]testsupport.FixtureProcess{process(100, "a.exe", img)}, map[uint64][]byte{100: img})
	ctx, diags := withDiagnostics(f.Context())
	rows, err := Run(ctx)
	if err != nil || len(rows) != 0 || !strings.Contains(strings.Join(*diags, "\n"), "1 main images have no import directory") {
		t.Fatalf("rows %+v, err %v, diagnostics %v", rows, err, *diags)
	}
}

func TestRefusals(t *testing.T) {
	f := build([]testsupport.FixtureProcess{{PID: 4, Name: "System", NoPeb: true}}, nil)
	ctx := f.Context()
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); !errors.Is(err, ErrNotWindows) {
		t.Errorf("linux: %v", err)
	}
	if _, err := tools.Get(Name); err != nil {
		t.Errorf("not registered: %v", err)
	}
}
