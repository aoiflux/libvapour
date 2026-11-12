package testsupport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

func TestMappedPEHeaders(t *testing.T) {
	img := BuildMappedPE(0x140000000)
	h, err := pe.ParseHeaders(img)
	if err != nil {
		t.Fatal(err)
	}
	if h.DOS.Lfanew != MappedPELfanew || h.File.Machine != MappedPEMachine || !h.Optional.PE32Plus ||
		h.Optional.ImageBase != 0x140000000 || h.Optional.SizeOfImage != MappedPESize ||
		h.Optional.CheckSum != MappedPECheckSum || h.Optional.SizeOfHeaders%h.Optional.FileAlignment != 0 {
		t.Fatalf("headers %+v %+v", h.File, h.Optional)
	}
	if binary.LittleEndian.Uint32(img[MappedPELfanew+8:]) != MappedPETimeDateStamp {
		t.Fatal("TimeDateStamp is not 8 bytes past the signature")
	}
	if len(h.Sections) != len(MappedPESections) {
		t.Fatalf("%d sections", len(h.Sections))
	}
	for i, s := range MappedPESections {
		got := h.Sections[i]
		if got.Name != s.Name || got.VirtualAddress != s.VirtualAddress || got.PointerToRawData != s.StaleRawPointer ||
			got.PointerToRawData < h.Optional.SizeOfHeaders {
			t.Errorf("section %d %+v", i, got)
		}
		if img[s.VirtualAddress] != s.Fill || img[s.VirtualAddress+s.VirtualSize] == s.Fill {
			t.Errorf("section %s fill does not span exactly VirtualSize", s.Name)
		}
	}
}

func TestExportingPEDirectory(t *testing.T) {
	img := BuildExportingPE(0x180000000, []FixtureExport{
		{Name: "Zeta", Body: []byte{0xC3}}, {}, {Name: "Alpha", Forwarder: "other.Fn"}, {Name: "Mid", RVA: 0x1800},
	})
	h, err := pe.ParseHeaders(img)
	if err != nil {
		t.Fatal(err)
	}
	dir := binary.LittleEndian.Uint32(img[h.OptionalOffset+exportDirectoryAt:])
	size := binary.LittleEndian.Uint32(img[h.OptionalOffset+exportDirectoryAt+4:])
	if dir != ExportDirRVA || size == 0 || dir+size > 0x3000 {
		t.Fatalf("export directory 0x%x+0x%x", dir, size)
	}
	read := func(rva uint32, n int) ([]byte, error) { return img[rva : rva+uint32(n)], nil }
	exports, err := pe.ParseExports(read, pe.DataDirectory{VirtualAddress: dir, Size: size}, limits.Default())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]pe.Export{}
	for _, e := range exports {
		byName[e.Name] = e
	}
	le := binary.LittleEndian
	var names []string
	pointers := le.Uint32(img[dir+32:])
	for i := range le.Uint32(img[dir+24:]) {
		at := le.Uint32(img[pointers+4*i:])
		names = append(names, string(img[at:at+uint32(bytes.IndexByte(img[at:], 0))]))
	}
	if !slices.IsSorted(names) || len(names) != 3 {
		t.Errorf("name table %v is not in lexical order", names)
	}
	if e := byName["Zeta"]; e.RVA != ExportRVA(0) || e.Ordinal != ExportOrdinalBase || img[e.RVA] != 0xC3 {
		t.Errorf("Zeta %+v", e)
	}
	if e := byName["Alpha"]; e.Forwarder != "other.Fn" || e.RVA < dir || e.RVA >= dir+size {
		t.Errorf("Alpha %+v", e)
	}
	if e := byName["Mid"]; e.RVA != 0x1800 || e.Ordinal != ExportOrdinalBase+3 {
		t.Errorf("Mid %+v", e)
	}
}

func TestPoolHeaderRoundTrip(t *testing.T) {
	buf := make([]byte, 0x20)
	WritePoolHeader(buf, 0x10, "Proc", BlocksFor(0x41), PagedPoolType)
	h, err := ReadPoolHeader(memoryOf(buf), "_POOL_HEADER", 0x10)
	if err != nil {
		t.Fatal(err)
	}
	if h.Fields["BlockSize"] != 5 || h.Fields["PoolType"] != PagedPoolType || h.Fields["PoolIndex"] != 0 ||
		h.Fields["PoolTag"] != uint64(binary.LittleEndian.Uint32([]byte("Proc"))) {
		t.Fatalf("decoded %v", h.Fields)
	}
	table := symbols.NewTable("pool", 8)
	addPoolTypes(table)
	inst, err := table.ReadStruct(memoryOf(buf), "_POOL_HEADER", 0x10)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"BlockSize", "PoolType", "PoolIndex", "PoolTag"} {
		if inst.Fields[name] != h.Fields[name] {
			t.Errorf("%s: table reads %d, decoder %d", name, inst.Fields[name], h.Fields[name])
		}
	}
	if _, err := ReadPoolHeader(memoryOf(buf), "_OTHER", 0); err == nil {
		t.Fatal("a type with no fixture layout decoded")
	}
	fields, structs := map[string]symbols.Field{}, map[string]symbols.StructType{}
	AddPoolHeaderSymbols(fields, structs)
	if fields["_POOL_HEADER.PoolType"].Type.BitOffset != 8 || structs["_POOL_HEADER"].Size != PoolHeaderSize {
		t.Fatal("pool symbols do not carry the T6 layout")
	}
}

func FuzzPoolHeaderRoundTrip(f *testing.F) {
	f.Add([]byte("Proc"), byte(0xa8), byte(2))
	f.Fuzz(func(t *testing.T, tag []byte, blocks, kind byte) {
		buf := make([]byte, PoolHeaderSize)
		WritePoolHeader(buf, 0, string(tag), blocks, kind)
		h, err := ReadPoolHeader(memoryOf(buf), "_POOL_HEADER", 0)
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, 4)
		copy(want, tag)
		if h.Fields["BlockSize"] != uint64(blocks) || h.Fields["PoolType"] != uint64(kind) ||
			h.Fields["PoolTag"] != uint64(binary.LittleEndian.Uint32(want)) {
			t.Fatalf("decoded %v", h.Fields)
		}
	})
}

func TestWindowsVersionAgreesInEveryPlace(t *testing.T) {
	table, mem := WithWindowsVersion(symbols.NewTable("empty", 8), memoryOf(nil), 10, 0, 22631)
	field := func(typ, name string) uint64 {
		f, err := table.Field(typ, name)
		if err != nil {
			t.Fatal(err)
		}
		return f.Offset
	}
	u32 := func(at uint64) uint32 {
		raw, err := mem.ReadAt(at, 4)
		if err != nil {
			t.Fatal(err)
		}
		return binary.LittleEndian.Uint32(raw)
	}
	global, err := table.LookupSymbol("NtBuildNumber")
	if err != nil {
		t.Fatal(err)
	}
	block, err := table.LookupSymbol("KdVersionBlock")
	if err != nil {
		t.Fatal(err)
	}
	if u32(KUserSharedData+field("_KUSER_SHARED_DATA", "NtBuildNumber")) != 22631 ||
		u32(KUserSharedData+field("_KUSER_SHARED_DATA", "NtMajorVersion")) != 10 ||
		u32(global.Address) != FreeBuildDecoration|22631 ||
		u32(block.Address+field("_DBGKD_GET_VERSION64", "MinorVersion"))&0xffff != 22631 {
		t.Fatal("the three build sources disagree")
	}
	if _, err := mem.ReadAt(global.Address, 8); err == nil {
		t.Fatal("read past the 4-byte NtBuildNumber served")
	}
}

type flatMemory []byte

func memoryOf(b []byte) memory.MemoryReader { return flatMemory(b) }

func (m flatMemory) Size() uint64 { return uint64(len(m)) }

func (m flatMemory) ReadAt(at, n uint64) ([]byte, error) {
	if at > uint64(len(m)) || n > uint64(len(m))-at {
		return nil, memory.ErrOutOfBounds
	}
	return append([]byte(nil), m[at:at+n]...), nil
}

func spaceContext(t *testing.T) (tools.Context, *ProcessFixture) {
	f := BuildProcessFixture([]FixtureProcess{{PID: 4, NoPeb: true}, {PID: 8, NoPeb: true}})
	for _, pid := range []uint64{4, 8} {
		f.Space(pid).MapData(0x10000, bytes.Repeat([]byte{byte(pid)}, int(pageSize)))
	}
	return f.Context(), f
}

func TestProcessSpaceWrappers(t *testing.T) {
	ctx, f := spaceContext(t)
	HoleInProcess(&ctx, f.DirectoryTableBase(4), 0x10800, 0x10900)
	PatchInProcess(&ctx, f.DirectoryTableBase(4), 0x10010, []byte{0xEE, 0xEF})
	four, _ := ctx.ProcessMemory(f.DirectoryTableBase(4))
	eight, _ := ctx.ProcessMemory(f.DirectoryTableBase(8))
	if _, err := four.ReadAt(0x108f0, 0x20); !errors.Is(err, memory.ErrOutOfBounds) {
		t.Fatalf("read across the hole: %v", err)
	}
	if b, err := four.ReadAt(0x1000f, 4); err != nil || !bytes.Equal(b, []byte{4, 0xEE, 0xEF, 4}) {
		t.Fatalf("patched read %x, %v", b, err)
	}
	if b, err := eight.ReadAt(0x10800, 0x20); err != nil || b[0] != 8 {
		t.Fatalf("other process %x, %v", b, err)
	}

	ctx, f = spaceContext(t)
	refused, reads := RefuseProcessSpace(ctx, f.DirectoryTableBase(4)|0x18)
	if _, err := refused.ProcessMemory(f.DirectoryTableBase(4)); err == nil {
		t.Fatal("refused root served")
	}
	if _, err := refused.ProcessMemory(f.DirectoryTableBase(8)); err != nil {
		t.Fatal(err)
	}
	_, _ = refused.Memory.ReadAt(0x10000, 8)
	_, _ = refused.Memory.ReadAt(FixtureProcessListHeadVA, 8)
	if got := reads.Addresses(); !slices.Equal(got, []uint64{0x10000}) {
		t.Fatalf("recorded %s", fmt.Sprint(got))
	}
}
