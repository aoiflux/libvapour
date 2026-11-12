package processdump

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/minidump"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	sExe      = uint64(0x7ff700000000)
	sData     = uint64(0x10000)
	sStackLo  = uint64(0x200000)
	sStackHi  = uint64(0x210000)
	sTeb      = uint64(0x300000)
	sStackRsp = uint64(0x20f800)

	sTibOffset   = uint64(0)
	sStackBase   = uint64(8)
	sStackLimit  = uint64(0x10)
	sProductType = uint64(0x264)
	sSuiteMask   = uint64(0x2d0)
	sProcessors  = uint64(0x3c0)
)

func sProcess(pid uint64, name string) testsupport.FixtureProcess {
	return testsupport.FixtureProcess{
		PID: pid, Name: name,
		Modules: []testsupport.FixtureModule{{Name: name, FullPath: `C:\p\` + name, Base: sExe, Image: testsupport.BuildMappedPE(sExe)}},
		VADs: []testsupport.FixtureVAD{
			{Start: sData, End: sData + 0x2fff, Protection: 4},
			{Start: sStackLo, End: sStackHi - 1, Protection: 4},
			{Start: sTeb, End: sTeb + 0xfff, Protection: 4},
			{Start: sExe, End: sExe + uint64(testsupport.MappedPESize) - 1, Path: `\p\` + name, Protection: 7, VadType: 2},
		},
	}
}

func sFixture(t *testing.T) *testsupport.ProcessFixture {
	t.Helper()
	f := testsupport.BuildProcessFixture([]testsupport.FixtureProcess{sProcess(1200, "one.exe"), sProcess(3000, "two.exe")})
	for _, pid := range []uint64{1200, 3000} {
		space := f.Space(pid)
		space.MapData(sData, bytes.Repeat([]byte{byte(pid)}, 0x1000))
		space.MapData(sData+0x2000, bytes.Repeat([]byte{0xEE}, 0x1000))
		space.MapData(sStackHi-0x1000, bytes.Repeat([]byte{0x5C}, 0x1000))
		teb := make([]byte, 0x1000)
		binary.LittleEndian.PutUint64(teb[sTibOffset+sStackBase:], sStackHi)
		binary.LittleEndian.PutUint64(teb[sTibOffset+sStackLimit:], sStackLo)
		space.MapData(sTeb, teb)
	}
	f.AddS50Threads([]testsupport.S50Thread{
		{TID: 1204, Owner: 1200, Teb: sTeb, Win32Start: sExe + 0x1000,
			TrapFrame: &testsupport.S50TrapFrame{Rip: sExe + 0x1234, Rsp: sStackRsp, Rax: 7, SegCs: 0x33, SegSs: 0x2b}},
		{TID: 1208, Owner: 1200, Teb: sTeb,
			TrapFrame: &testsupport.S50TrapFrame{Rip: sExe + 0x1234, Rsp: sStackHi + 0x100, SegCs: 0x33, SegSs: 0x2b}},
		{TID: 3004, Owner: 3000, Teb: sTeb,
			TrapFrame: &testsupport.S50TrapFrame{Rip: 0xfffff80000001000, Rsp: 0xfffff80000002000, SegCs: 0x10}},
	}, `\SystemRoot\system32\ntoskrnl.exe`)
	sKernelValues(f)
	return f
}

func sKernelValues(f *testsupport.ProcessFixture) {
	kuser := make([]byte, 0x1000)
	binary.LittleEndian.PutUint32(kuser[testsupport.NtBuildNumberOffset:], 19045)
	binary.LittleEndian.PutUint32(kuser[testsupport.NtMajorVersionOffset:], 10)
	binary.LittleEndian.PutUint32(kuser[testsupport.NtMinorVersionOffset:], 0)
	binary.LittleEndian.PutUint32(kuser[sProductType:], 1)
	binary.LittleEndian.PutUint32(kuser[sSuiteMask:], 0x110)
	binary.LittleEndian.PutUint32(kuser[sProcessors:], 8)
	f.Kernel.MapData(testsupport.KUserSharedData, kuser)
	global := make([]byte, 0x1000)
	binary.LittleEndian.PutUint32(global, testsupport.FreeBuildDecoration|19045)
	f.Kernel.MapData(testsupport.NtBuildNumberGlobal, global)
	f.Table.AddSymbol(symbols.Symbol{Name: "NtBuildNumber", Address: testsupport.NtBuildNumberGlobal})
	f.Table.AddStruct(symbols.StructType{Name: "_KUSER_SHARED_DATA", Size: 0x1000, Fields: []symbols.Field{
		{Name: "NtBuildNumber", Offset: testsupport.NtBuildNumberOffset},
		{Name: "NtMajorVersion", Offset: testsupport.NtMajorVersionOffset},
		{Name: "NtMinorVersion", Offset: testsupport.NtMinorVersionOffset},
		{Name: "NtProductType", Offset: sProductType},
		{Name: "SuiteMask", Offset: sSuiteMask},
		{Name: "ActiveProcessorCount", Offset: sProcessors},
	}})
	f.Table.AddStruct(symbols.StructType{Name: "_TEB", Size: 0x1000, Fields: []symbols.Field{{Name: "NtTib", Offset: sTibOffset}}})
	f.Table.AddStruct(symbols.StructType{Name: "_NT_TIB", Size: 0x38, Fields: []symbols.Field{
		{Name: "StackBase", Offset: sStackBase, Type: symbols.TypeRef{Name: "void", IsPointer: true}},
		{Name: "StackLimit", Offset: sStackLimit, Type: symbols.TypeRef{Name: "void", IsPointer: true}},
	}})
}

func sRun(t *testing.T, f *testsupport.ProcessFixture, opts map[string]any) ([]Artifact, []string, string) {
	t.Helper()
	ctx := f.Context()
	dir := t.TempDir()
	var diags []string
	ctx.Options["diagnostics"] = &diags
	ctx.Options[tools.OptionOutputDir] = dir
	for k, v := range opts {
		ctx.Options[k] = v
	}
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return rows, diags, dir
}

type dump struct {
	data    []byte
	streams map[minidump.StreamType]minidump.StreamRecord
}

func readDump(t *testing.T, path string) dump {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	audit := minidump.Validate(data)
	if !audit.OK() {
		t.Fatalf("%s does not validate: %v", path, audit.Problems)
	}
	d := dump{data: data, streams: map[minidump.StreamType]minidump.StreamRecord{}}
	for _, s := range audit.Streams {
		d.streams[s.Type] = s
	}
	return d
}

func (d dump) stream(t *testing.T, st minidump.StreamType) []byte {
	t.Helper()
	s, ok := d.streams[st]
	if !ok {
		t.Fatalf("no %v stream", st)
	}
	return d.data[s.RVA : s.RVA+s.Size]
}

func u32(b []byte, at int) uint32 { return binary.LittleEndian.Uint32(b[at:]) }
func u64(b []byte, at int) uint64 { return binary.LittleEndian.Uint64(b[at:]) }

func TestEachKeptProcessBecomesOneMinidumpWithTheSystemValues(t *testing.T) {
	rows, _, dir := sRun(t, sFixture(t), nil)
	if len(rows) != 2 || rows[0].PID != 1200 || rows[1].PID != 3000 {
		t.Fatalf("rows %+v", rows)
	}
	for _, r := range rows {
		if !r.Written() || !strings.HasPrefix(r.FileName, "process.pid") || !strings.HasSuffix(r.FileName, ".dmp") {
			t.Errorf("row %+v", r)
		}
	}
	d := readDump(t, filepath.Join(dir, rows[0].FileName))
	si := d.stream(t, minidump.StreamSystemInfo)
	if arch := binary.LittleEndian.Uint16(si); arch != minidump.ProcessorArchitectureAMD64 {
		t.Errorf("architecture %d", arch)
	}
	if si[6] != 8 || si[7] != 1 || u32(si, 8) != 10 || u32(si, 12) != 0 || u32(si, 16) != 19045 || u32(si, 20) != 2 ||
		binary.LittleEndian.Uint16(si[28:]) != 0x110 {
		t.Errorf("system info processors %d product %d version %d.%d.%d platform %d suite 0x%x",
			si[6], si[7], u32(si, 8), u32(si, 12), u32(si, 16), u32(si, 20), binary.LittleEndian.Uint16(si[28:]))
	}
	mods := d.stream(t, minidump.StreamModuleList)
	if u32(mods, 0) != 1 || u64(mods, 4) != sExe || u32(mods, 12) != uint32(testsupport.MappedPESize) ||
		u32(mods, 16) != testsupport.MappedPECheckSum || u32(mods, 20) != testsupport.MappedPETimeDateStamp {
		t.Errorf("module list %x", mods[:28])
	}
}

func TestMemoryHoldsOnlyPagesThatReadAndTheInfoListCoversEveryRange(t *testing.T) {
	rows, _, dir := sRun(t, sFixture(t), map[string]any{"pid": uint64(1200)})
	d := readDump(t, filepath.Join(dir, rows[0].FileName))
	mem := d.stream(t, minidump.StreamMemory64List)
	n, rva := u64(mem, 0), u64(mem, 8)
	got := map[uint64][]byte{}
	for i := 0; i < int(n); i++ {
		start, size := u64(mem, 16+16*i), u64(mem, 24+16*i)
		got[start] = d.data[rva : rva+size]
		rva += size
	}
	if b := got[sData]; !bytes.Equal(b, bytes.Repeat([]byte{byte(1200 & 0xff)}, 0x1000)) {
		t.Errorf("the first data page is %d bytes, not the page", len(b))
	}
	if _, ok := got[sData+0x1000]; ok {
		t.Errorf("the unmapped page in the middle was written")
	}
	if b := got[sData+0x2000]; !bytes.Equal(b, bytes.Repeat([]byte{0xEE}, 0x1000)) {
		t.Errorf("the third page is missing")
	}
	if rows[0].Gaps.PaddedBytes() != 0 {
		t.Errorf("gaps %+v: only read pages are written, so nothing is padded", rows[0].Gaps)
	}

	info := d.stream(t, minidump.StreamMemoryInfoList)
	head, entry, count := int(u32(info, 0)), int(u32(info, 4)), int(u64(info, 8))
	var pieces [][3]uint64
	covered := uint64(0)
	for i := 0; i < count; i++ {
		e := info[head+i*entry:]
		base, alloc, size := u64(e, 0), u64(e, 8), u64(e, 24)
		if base >= sData && base < sData+0x3000 {
			pieces = append(pieces, [3]uint64{base, alloc, size})
		}
		covered += size
	}
	want := [][3]uint64{{sData, sData, 0x1000}, {sData + 0x1000, sData, 0x1000}, {sData + 0x2000, sData, 0x1000}}
	if len(pieces) != 3 || pieces[0] != want[0] || pieces[1] != want[1] || pieces[2] != want[2] {
		t.Errorf("data range pieces %x, want %x", pieces, want)
	}
	if wantCovered := uint64(0x3000 + 0x10000 + 0x1000 + uint64(testsupport.MappedPESize)); covered != wantCovered {
		t.Errorf("info list covers 0x%x bytes, want every VAD range 0x%x", covered, wantCovered)
	}
	if rows[0].RegionsWithoutContents == 0 || rows[0].BytesWithoutContents == 0 {
		t.Errorf("row %+v does not count the unread pages", rows[0])
	}
}

func TestThreadsCarryTheirStackAndOnlyAUserFrameInsideItGivesRegisters(t *testing.T) {
	rows, diags, dir := sRun(t, sFixture(t), nil)
	threadsOf := func(row Artifact) map[uint32][]byte {
		d := readDump(t, filepath.Join(dir, row.FileName))
		list := d.stream(t, minidump.StreamThreadList)
		out := map[uint32][]byte{}
		for i := 0; i < int(u32(list, 0)); i++ {
			e := append([]byte(nil), list[4+48*i:4+48*(i+1)]...)
			out[u32(e, 0)] = e
			if ctxSize := u32(e, 40); ctxSize != 0 {
				c := d.data[u32(e, 44) : u32(e, 44)+ctxSize]
				out[u32(e, 0)] = append(e, c...)
			}
		}
		return out
	}
	one := threadsOf(rows[0])
	good, outside := one[1204], one[1208]
	if good == nil || outside == nil {
		t.Fatalf("threads of pid 1200: %v", one)
	}
	if u64(good, 16) != sTeb || u64(good, 24) != sStackLo {
		t.Errorf("thread 1204 teb 0x%x stack at 0x%x", u64(good, 16), u64(good, 24))
	}
	if u32(good, 40) != minidump.ContextAMD64Size {
		t.Fatalf("thread 1204 context %d bytes", u32(good, 40))
	}
	ctxBytes := good[48:]
	var want minidump.AMD64Context
	want.Flags = minidump.ContextAMD64 | minidump.ContextControl | minidump.ContextSegments
	want.Rip, want.Rsp, want.Rax, want.SegCs, want.SegSs = sExe+0x1234, sStackRsp, 7, 0x33, 0x2b
	if !bytes.Equal(ctxBytes, want.Bytes()) {
		t.Errorf("thread 1204 context differs from its trap frame")
	}
	if u32(outside, 40) != 0 {
		t.Errorf("thread 1208's stack pointer is outside its stack, yet it has a context")
	}
	if two := threadsOf(rows[1]); u32(two[3004], 40) != 0 {
		t.Errorf("a kernel-mode frame gave thread 3004 a context")
	}
	if rows[0].Threads != 2 || rows[0].ThreadsWithContext != 1 || rows[1].ThreadsWithContext != 0 {
		t.Errorf("thread counts %+v %+v", rows[0], rows[1])
	}
	all := strings.Join(diags, "\n")
	if !strings.Contains(all, "1 of 3 threads with registers") || !strings.Contains(all, "1 kernel-mode trap frame") ||
		!strings.Contains(all, "1 stack pointer outside the stack") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestAnExistingFileIsKeptAndStrictModeStops(t *testing.T) {
	f := sFixture(t)
	ctx := f.Context()
	dir := t.TempDir()
	ctx.Options[tools.OptionOutputDir] = dir
	ctx.Options["pid"] = uint64(3000)
	first, err := Run(ctx)
	if err != nil || len(first) != 1 || !first[0].Written() {
		t.Fatalf("first run %+v %v", first, err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, first[0].FileName))
	again, err := Run(ctx)
	if err != nil || again[0].Written() {
		t.Errorf("second run %+v %v: the file exists, so the row is skipped", again, err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, first[0].FileName))
	if !bytes.Equal(before, after) {
		t.Errorf("the existing dump was changed")
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); err == nil {
		t.Errorf("strict second run: no error")
	}
}

func TestAProcessWithoutUserMemoryListsRangesWithoutContents(t *testing.T) {
	f := sFixture(t)
	ctx := f.Context()
	dtb := f.DirectoryTableBase(3000)
	inner := ctx.ProcessMemory
	ctx.ProcessMemory = func(d uint64) (memoryReader, error) {
		if d == dtb {
			return nil, errors.New("no layer")
		}
		return inner(d)
	}
	dir := t.TempDir()
	var diags []string
	ctx.Options["diagnostics"] = &diags
	ctx.Options[tools.OptionOutputDir] = dir
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r := rows[1]
	if !r.Written() || r.MemoryBytes != 0 || r.RegionsWithoutContents != r.Regions || r.Regions != 4 {
		t.Errorf("row %+v", r)
	}
	if !strings.Contains(strings.Join(diags, "\n"), "pid 3000") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestAnOutputDirectoryIsRequired(t *testing.T) {
	if _, err := Run(sFixture(t).Context()); !errors.Is(err, ErrNoOutputDir) {
		t.Errorf("Run: %v, want %v", err, ErrNoOutputDir)
	}
}

type memoryReader = memory.MemoryReader
