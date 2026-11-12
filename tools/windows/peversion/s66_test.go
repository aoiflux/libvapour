package peversion

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	resourceSlot   = 0x98 + 112 + 2*8
	resourceRVA    = uint32(0x6000)
	versionDataRVA = uint32(0x6100)

	moduleBase  = uint64(0xfffff80040000000)
	entryBase   = uint64(0xfffff80030000000)
	moduleList  = uint64(0xfffff80030100000)
	processBase = uint64(0x7ff600400000)
)

func align4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func utf16z(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s + "\x00")) {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}

// node builds one VS_VERSIONINFO tree node starting on a 32-bit boundary.
func node(key string, wType uint16, value []byte, valueLength uint16, children ...[]byte) []byte {
	b := make([]byte, 6)
	b = append(b, utf16z(key)...)
	b = align4(b)
	b = append(b, value...)
	for _, c := range children {
		b = align4(b)
		b = append(b, c...)
	}
	binary.LittleEndian.PutUint16(b[0:], uint16(len(b)))
	binary.LittleEndian.PutUint16(b[2:], valueLength)
	binary.LittleEndian.PutUint16(b[4:], wType)
	return b
}

func versionInfo(product [4]uint16, original string) []byte {
	fixed := make([]byte, 52)
	binary.LittleEndian.PutUint32(fixed[0:], 0xFEEF04BD)
	binary.LittleEndian.PutUint32(fixed[4:], 0x00010000)
	binary.LittleEndian.PutUint32(fixed[8:], 1<<16|1)
	binary.LittleEndian.PutUint32(fixed[16:], uint32(product[0])<<16|uint32(product[1]))
	binary.LittleEndian.PutUint32(fixed[20:], uint32(product[2])<<16|uint32(product[3]))
	name := utf16z(original)
	str := node("OriginalFilename", 1, name, uint16(len(name)/2))
	other := node("CompanyName", 1, utf16z("x"), 2)
	table := node("040904B0", 1, nil, 0, other, str)
	sfi := node("StringFileInfo", 1, nil, 0, table)
	vfi := node("VarFileInfo", 1, nil, 0)
	return node("VS_VERSION_INFO", 0, fixed, 52, vfi, sfi)
}

// imageWithVersion adds a resource directory holding one RT_VERSION
// resource to an image from testsupport.BuildExportingPE.
func imageWithVersion(base uint64, info []byte) []byte {
	img := testsupport.BuildExportingPE(base, nil)
	binary.LittleEndian.PutUint32(img[resourceSlot:], resourceRVA)
	binary.LittleEndian.PutUint32(img[resourceSlot+4:], 0x200)
	dir := func(at uint32, id, target uint32) {
		binary.LittleEndian.PutUint16(img[at+14:], 1)
		binary.LittleEndian.PutUint32(img[at+16:], id)
		binary.LittleEndian.PutUint32(img[at+20:], target)
	}
	dir(resourceRVA, 16, 0x80000000|0x18)
	dir(resourceRVA+0x18, 1, 0x80000000|0x30)
	dir(resourceRVA+0x30, 0x409, 0x48)
	binary.LittleEndian.PutUint32(img[resourceRVA+0x48:], versionDataRVA)
	binary.LittleEndian.PutUint32(img[resourceRVA+0x4C:], uint32(len(info)))
	copy(img[versionDataRVA:], info)
	return img
}

type kernelModule struct {
	name, path string
	image      []byte
}

// addKernelModules writes a PsLoadedModuleList of _KLDR_DATA_TABLE_ENTRY
// records (S55 T1 offsets) into the fixture's kernel space.
func addKernelModules(f *testsupport.ProcessFixture, mods []kernelModule) {
	f.Table.AddStruct(symbols.StructType{Name: "_KLDR_DATA_TABLE_ENTRY", Size: 0xa0, Fields: []symbols.Field{
		{Name: "InLoadOrderLinks", Offset: 0},
		{Name: "DllBase", Offset: 0x30},
		{Name: "SizeOfImage", Offset: 0x40, Type: symbols.TypeRef{Name: "unsigned int"}},
		{Name: "FullDllName", Offset: 0x48},
		{Name: "BaseDllName", Offset: 0x58},
	}})
	f.Table.AddSymbol(symbols.Symbol{Name: "PsLoadedModuleList", Address: moduleList})
	headPA := f.Kernel.MapPage(moduleList)
	link := func(i int) uint64 {
		if i < 0 || i == len(mods) {
			return moduleList
		}
		return entryBase + uint64(i)*0x1000
	}
	f.Memory.WriteU64(headPA, link(0))
	f.Memory.WriteU64(headPA+8, link(len(mods)-1))
	for i, m := range mods {
		pa := f.Kernel.MapPage(link(i))
		base := moduleBase + uint64(i)*0x100000
		f.Memory.WriteU64(pa, link(i+1))
		f.Memory.WriteU64(pa+8, link(i-1))
		f.Memory.WriteU64(pa+0x30, base)
		f.Memory.WriteU32(pa+0x40, testsupport.ExportImageSize)
		for j, s := range []struct {
			at   uint64
			text string
		}{{0x48, m.path}, {0x58, m.name}} {
			raw := utf16z(s.text)
			buf := link(i) + 0x200 + uint64(j)*0x100
			f.Memory.WriteU16(pa+s.at, uint16(len(raw)-2))
			f.Memory.WriteU16(pa+s.at+2, uint16(len(raw)))
			f.Memory.WriteU64(pa+s.at+8, buf)
			f.Memory.WriteAt(pa+(buf-link(i)), raw)
		}
		if m.image != nil {
			f.Kernel.MapImage(base, m.image)
		}
	}
}

func fixture(mods []kernelModule, procs ...testsupport.FixtureProcess) *testsupport.ProcessFixture {
	if len(procs) == 0 {
		procs = []testsupport.FixtureProcess{{PID: 4, Name: "System", NoPeb: true}}
	}
	f := testsupport.BuildProcessFixture(procs)
	addKernelModules(f, mods)
	return f
}

func withDiagnostics(ctx tools.Context) (tools.Context, *[]string) {
	sink := []string{}
	ctx.Options["diagnostics"] = &sink
	return ctx, &sink
}

func TestKernelRowsGiveTheProductVersionAndFlagWhatDoesNotRead(t *testing.T) {
	f := fixture([]kernelModule{
		{name: "a.sys", path: `\SystemRoot\a.sys`, image: imageWithVersion(moduleBase, versionInfo([4]uint16{10, 0, 26100, 7}, "a.sys"))},
		{name: "plain.sys", path: `\SystemRoot\plain.sys`, image: testsupport.BuildExportingPE(moduleBase+0x100000, nil)},
		{name: "gone.sys", path: `\SystemRoot\gone.sys`},
	})
	ctx, diags := withDiagnostics(f.Context())
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("%d rows, want 3", len(rows))
	}
	a := rows[0]
	if !a.Kernel || a.Name != "a.sys" || a.Base != moduleBase || a.VersionUnreadable ||
		[4]uint16{a.Major, a.Minor, a.Product, a.Build} != [4]uint16{10, 0, 26100, 7} || a.SizeOfImage != testsupport.ExportImageSize {
		t.Errorf("a.sys = %+v", a)
	}
	if !rows[1].VersionUnreadable || !rows[2].VersionUnreadable || rows[2].SizeOfImage != 0 {
		t.Errorf("plain and gone = %+v %+v", rows[1], rows[2])
	}
	joined := strings.Join(*diags, "\n")
	for _, want := range []string{"1 kernel modules without a version: no version resource", "1 kernel modules without a version: headers do not read"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no diagnostic %q in %q", want, joined)
		}
	}
}

func TestProcessModulesAreReadThroughTheirProcessAndNarrowedByPID(t *testing.T) {
	img := imageWithVersion(processBase, versionInfo([4]uint16{2, 5, 100, 7}, "app.exe"))
	f := fixture(nil,
		testsupport.FixtureProcess{PID: 100, Name: "app.exe", Modules: []testsupport.FixtureModule{{Name: "app.exe", Base: processBase, Image: img}}},
		testsupport.FixtureProcess{PID: 200, Name: "b.exe", Modules: []testsupport.FixtureModule{{Name: "b.exe", Base: processBase}}},
	)
	ctx := f.Context()
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].PID != 100 || rows[0].Process != "app.exe" || rows[0].Major != 2 || rows[0].Build != 7 || !rows[1].VersionUnreadable {
		t.Fatalf("rows %+v", rows)
	}
	ctx.Options["pid"] = uint64(200)
	rows, err = Run(ctx)
	if err != nil || len(rows) != 1 || rows[0].PID != 200 {
		t.Fatalf("pid 200: rows %+v, err %v", rows, err)
	}
}

func TestTheExtensiveOptionMatchesACachedCopyByOriginalFilename(t *testing.T) {
	f := fixture([]kernelModule{
		{name: "kdcom.dll", path: `\SystemRoot\system32\kd.dll`, image: testsupport.BuildExportingPE(moduleBase, nil)},
		{name: "x.sys", path: `\SystemRoot\x.sys`, image: testsupport.BuildExportingPE(moduleBase+0x100000, nil)},
	})
	cached := f.Memory.AllocPage()
	f.Memory.WriteAt(cached, versionInfo([4]uint16{10, 0, 1, 2}, "KD.DLL"))
	other := f.Memory.AllocPage()
	f.Memory.WriteAt(other+0x200, versionInfo([4]uint16{10, 0, 9, 9}, "kd.dll"))
	ctx, diags := withDiagnostics(f.Context())
	ctx.Options[tools.OptionPhysicalMemory] = memory.MemoryReader(f.Memory)
	ctx.Options[OptionExtensive] = "true"
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kd := rows[0]
	if kd.VersionUnreadable || kd.Product != 1 || kd.Build != 2 || kd.VersionPhysical != cached {
		t.Errorf("kdcom.dll = %+v, want 10.0.1.2 from 0x%x", kd, cached)
	}
	if !rows[1].VersionUnreadable || rows[1].VersionPhysical != 0 {
		t.Errorf("x.sys = %+v, want no version", rows[1])
	}
	joined := strings.Join(*diags, "\n")
	for _, want := range []string{"1 of 2 kernel modules without a mapped version resource matched", "naming kd.dll hold different product versions"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no diagnostic %q in %q", want, joined)
		}
	}
}

func TestTheExtensiveOptionWithoutPhysicalMemoryIsReported(t *testing.T) {
	f := fixture([]kernelModule{{name: "x.sys", path: `\SystemRoot\x.sys`}})
	ctx, diags := withDiagnostics(f.Context())
	ctx.Options[OptionExtensive] = true
	if _, err := Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "there is no physical memory: 1 kernel modules not searched") {
		t.Errorf("diagnostics %v", *diags)
	}
}

func TestRefusals(t *testing.T) {
	f := fixture(nil)
	ctx := f.Context()
	ctx.Options[OptionExtensive] = "ture"
	if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("extensive=ture: %v", err)
	}
	ctx = f.Context()
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := Run(ctx); !errors.Is(err, ErrNotWindows) {
		t.Errorf("linux: %v", err)
	}
	if _, err := tools.Get(Name); err != nil {
		t.Errorf("not registered: %v", err)
	}
}

func TestOriginalFilenameFollowsTheTreeAndItsAlignment(t *testing.T) {
	info := versionInfo([4]uint16{1, 2, 3, 4}, "tcpip.sys")
	if got, ok := originalFilename(info, 0x1000); !ok || got != "tcpip.sys" {
		t.Errorf("aligned: %q %v", got, ok)
	}
	shifted := append([]byte{0, 0}, info...)
	if _, ok := originalFilename(shifted[2:], 0x1002); ok {
		t.Error("a block at an address 2 mod 4 was read with the alignment of offset 0")
	}
	if _, ok := originalFilename(info[:40], 0); ok {
		t.Error("a truncated block gave a name")
	}
}

func TestScanPhysicalFindsMatchesAcrossChunksAndSkipsHoles(t *testing.T) {
	needle := versionKeyBytes
	size := uint64(2*scanChunkBytes + 0x3000)
	at := []uint64{uint64(scanChunkBytes) - 10, uint64(scanChunkBytes) + 0x1000, 2*uint64(scanChunkBytes) + 0x2000 - 4}
	h := holey{size: size, hole: 2*uint64(scanChunkBytes) + 0x1000, at: at, needle: needle}
	var got []uint64
	scanPhysical(h, needle, func(a uint64) { got = append(got, a) })
	if len(got) != 2 || got[0] != at[0] || got[1] != at[1] {
		t.Errorf("found %#x, want %#x and %#x (the third crosses a hole)", got, at[0], at[1])
	}
}

type holey struct {
	size, hole uint64
	at         []uint64
	needle     []byte
}

func (h holey) Size() uint64 { return h.size }

func (h holey) ReadAt(off, n uint64) ([]byte, error) {
	if off < h.hole+0x1000 && off+n > h.hole {
		return nil, memory.ErrOutOfBounds
	}
	out := make([]byte, n)
	for _, a := range h.at {
		for i, c := range h.needle {
			if p := a + uint64(i); p >= off && p < off+n {
				out[p-off] = c
			}
		}
	}
	return out, nil
}

func FuzzOriginalFilename(f *testing.F) {
	f.Add(versionInfo([4]uint16{1, 0, 0, 0}, "a.sys"), uint64(0))
	f.Add([]byte{6, 0, 0, 0, 0, 0}, uint64(2))
	f.Fuzz(func(t *testing.T, data []byte, base uint64) {
		name, ok := originalFilename(data, base)
		if !ok && name != "" {
			t.Fatalf("no match but name %q", name)
		}
		if ok && len(name) > len(data) {
			t.Fatalf("name %q longer than the block", name)
		}
	})
}
