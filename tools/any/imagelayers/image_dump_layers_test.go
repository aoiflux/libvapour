package imagelayers

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const kernelVA = uint64(0xffff800000200000)

type fixture struct {
	pm     *testsupport.PagedMemory
	kernel *testsupport.AddressSpace
	pages  map[uint64]uint64
}

func newFixture() *fixture {
	pm := testsupport.NewPagedMemory(1 << 20)
	f := &fixture{pm: pm, kernel: pm.NewAddressSpace(), pages: map[uint64]uint64{}}
	for i := range uint64(3) {
		data := bytes.Repeat([]byte{byte(0xa0 + i)}, 0x1000)
		f.pages[kernelVA+i*0x1000] = f.kernel.MapData(kernelVA+i*0x1000, data)
	}
	return f
}

func context(physical memory.MemoryReader, opts map[string]any) (tools.Context, *[]string) {
	diags := &[]string{}
	if opts == nil {
		opts = map[string]any{}
	}
	opts["diagnostics"] = diags
	if physical != nil {
		opts[tools.OptionPhysicalMemory] = physical
	}
	return tools.Context{Memory: physical, Symbols: symbols.NewTable("t", 8), Profile: profiles.WindowsX64Profile{},
		Options: opts}, diags
}

func (f *fixture) context(opts map[string]any) (tools.Context, *[]string) {
	if opts == nil {
		opts = map[string]any{}
	}
	opts[tools.OptionKernelDTB] = f.kernel.DTB
	opts[tools.OptionPagingMode] = layers.ModeX64.Name()
	return context(f.pm, opts)
}

func TestTheLayersAreListed(t *testing.T) {
	f := newFixture()
	ctx, _ := f.context(map[string]any{OptionList: true})
	got, err := RunAny(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows := got.([]Layer)
	if len(rows) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	if p := rows[0]; p.Name != PhysicalLayer || p.Type != TypeFlat || p.Size != 1<<20 || p.Held != 1<<20 {
		t.Errorf("physical %+v", p)
	}
	if k := rows[1]; k.Name != KernelLayer || k.Type != "x64" || k.Held != 0x3000 || k.Runs == 0 || k.Unavailable != "" {
		t.Errorf("kernel %+v", k)
	}
	ctx, _ = context(f.pm, nil)
	if rows, err := List(ctx); err != nil || len(rows) != 1 {
		t.Errorf("without a kernel root: %+v %v", rows, err)
	}
}

func TestThePhysicalLayerIsWrittenByAddress(t *testing.T) {
	f := newFixture()
	dir := t.TempDir()
	ctx, _ := f.context(map[string]any{tools.OptionOutputDir: dir, OptionBlockSize: uint64(0x3000)})
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Artifact != "region.phys.bin" || rows[0].Read != 1<<20 || rows[0].Zeroed != 0 {
		t.Fatalf("rows %+v", rows)
	}
	got, err := os.ReadFile(filepath.Join(dir, rows[0].Artifact))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := f.pm.ReadAt(0, 1<<20)
	if !bytes.Equal(got, want) {
		t.Fatal("the file differs from physical memory")
	}
	again, err := Run(ctx)
	if err != nil || again[0].Artifact != "region.phys-1.bin" {
		t.Fatalf("second write %+v %v", again, err)
	}
}

type patchy struct {
	*memory.SegmentedReader
	bad uint64
}

func (p patchy) ReadAt(off, n uint64) ([]byte, error) {
	if off <= p.bad && p.bad < off+n {
		return nil, memory.ErrOutOfBounds
	}
	return p.SegmentedReader.ReadAt(off, n)
}

func TestGapsAndUnreadPiecesAreZeros(t *testing.T) {
	backing := make(flat, 0x3000)
	for i := range backing {
		backing[i] = 0x55
	}
	seg, err := memory.NewSegmentedReader(backing, []memory.Segment{
		{PhysicalBase: 0x1000, FileOffset: 0, Length: 0x1000},
		{PhysicalBase: 0x5000, FileOffset: 0x1000, Length: 0x2000},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := patchy{seg, 0x6000}
	dir := t.TempDir()
	ctx, diags := context(r, map[string]any{tools.OptionOutputDir: dir, OptionBlockSize: uint64(0x1000)})
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Size != 0x7000 || rows[0].Read != 0x2000 || rows[0].Zeroed != 0x1000 {
		t.Fatalf("rows %+v", rows)
	}
	if len(*diags) != 1 || !strings.Contains((*diags)[0], "first at 0x6000") {
		t.Errorf("diagnostics %q", *diags)
	}
	got, _ := os.ReadFile(filepath.Join(dir, rows[0].Artifact))
	want := make([]byte, 0x7000)
	for _, at := range []uint64{0x1000, 0x5000} {
		copy(want[at:at+0x1000], bytes.Repeat([]byte{0x55}, 0x1000))
	}
	if !bytes.Equal(got, want) {
		t.Fatal("gaps or the unread piece are not zeros")
	}
	list, _ := List(ctx)
	if list[0].Type != TypeSegmented || list[0].Held != 0x3000 {
		t.Errorf("list %+v", list)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Fatal("strict mode kept an unread piece")
	}
	if names, _ := filepath.Glob(filepath.Join(dir, "*")); len(names) != 1 {
		t.Errorf("files left after the strict failure: %v", names)
	}
}

type flat []byte

func (f flat) ReadAt(off, n uint64) ([]byte, error) {
	if off > uint64(len(f)) || n > uint64(len(f))-off {
		return nil, memory.ErrOutOfBounds
	}
	return f[off : off+n], nil
}

func (f flat) Size() uint64 { return uint64(len(f)) }

func TestTheKernelLayerIsAnELFCoreOfItsRuns(t *testing.T) {
	f := newFixture()
	dir := t.TempDir()
	ctx, _ := f.context(map[string]any{tools.OptionOutputDir: dir, OptionLayers: []string{KernelLayer}})
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Artifact != "region.kernel.elf" || rows[0].Read != 0x3000 {
		t.Fatalf("rows %+v", rows)
	}
	file, err := elf.Open(filepath.Join(dir, rows[0].Artifact))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if file.Type != elf.ET_CORE || file.Machine != elf.EM_X86_64 || file.Class != elf.ELFCLASS64 {
		t.Fatalf("header %v %v %v", file.Type, file.Machine, file.Class)
	}
	seen := map[uint64]bool{}
	for _, p := range file.Progs {
		if p.Type != elf.PT_LOAD || p.Filesz != p.Memsz || p.Off%0x1000 != 0 {
			t.Errorf("program header %+v", p.ProgHeader)
		}
		data := make([]byte, p.Filesz)
		if _, err := p.ReadAt(data, 0); err != nil {
			t.Fatal(err)
		}
		for off := uint64(0); off < p.Filesz; off += 0x1000 {
			va := p.Vaddr + off
			pa, ok := f.pages[va]
			if !ok || p.Paddr+off != pa || data[off] != byte(0xa0+(va-kernelVA)/0x1000) {
				t.Errorf("page %#x in run %#x: paddr %#x", va, p.Vaddr, p.Paddr+off)
			}
			seen[va] = true
		}
	}
	if len(seen) != 3 {
		t.Errorf("pages %v", seen)
	}
}

func TestManyRunsUseTheExtendedCount(t *testing.T) {
	runs := make([]layers.MappedRun, pnXNum+2)
	for i := range runs {
		runs[i] = layers.MappedRun{Virtual: uint64(i) * 0x2000, Physical: uint64(i) * 0x1000, Size: 0x1000}
	}
	head, offsets := elfHeaders(runs, machineX8664)
	le := binary.LittleEndian
	shoff := le.Uint64(head[40:])
	if le.Uint16(head[56:]) != pnXNum || le.Uint32(head[shoff+44:]) != uint32(len(runs)) || le.Uint16(head[60:]) != 1 {
		t.Fatal("PN_XNUM not used")
	}
	if !slices.IsSorted(offsets) || offsets[0] != uint64(len(head)) || elfSize(runs) != offsets[len(offsets)-1]+0x1000 {
		t.Fatalf("offsets start %#x end %#x size %#x", offsets[0], offsets[len(offsets)-1], elfSize(runs))
	}
}

func TestTheLimitAndOptionsAreChecked(t *testing.T) {
	f := newFixture()
	dir := t.TempDir()
	ctx, _ := f.context(map[string]any{tools.OptionOutputDir: dir, tools.OptionMaxDumpSize: uint64(0x1000)})
	if _, err := Run(ctx); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over the limit: %v", err)
	}
	if names, _ := filepath.Glob(filepath.Join(dir, "*")); len(names) != 0 {
		t.Errorf("files written over the limit: %v", names)
	}
	for _, opts := range []map[string]any{
		{OptionLayers: []string{"image"}},
		{OptionBlockSize: uint64(0)},
		{OptionBlockSize: uint64(1) << 40},
		{OptionList: "x"},
	} {
		opts[tools.OptionOutputDir] = dir
		ctx, _ := f.context(opts)
		if _, err := RunAny(ctx); !errors.Is(err, tools.ErrOptionType) {
			t.Errorf("%v: %v", opts, err)
		}
	}
	ctx, _ = f.context(nil)
	if _, err := Run(ctx); !errors.Is(err, ErrNoOutputDir) {
		t.Errorf("no output directory: %v", err)
	}
	ctx, _ = context(nil, map[string]any{tools.OptionOutputDir: dir})
	ctx.Memory = f.pm
	if _, err := Run(ctx); !errors.Is(err, ErrNoPhysical) {
		t.Errorf("no physical layer: %v", err)
	}
}
