package minidump

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/extract"
)

type stream struct {
	typ       StreamType
	size, rva uint32
}

func directory(t *testing.T, d []byte) []stream {
	t.Helper()
	n, rva := binary.LittleEndian.Uint32(d[8:]), binary.LittleEndian.Uint32(d[12:])
	var out []stream
	for i := range n {
		e := d[rva+12*i:]
		out = append(out, stream{StreamType(binary.LittleEndian.Uint32(e)), binary.LittleEndian.Uint32(e[4:]), binary.LittleEndian.Uint32(e[8:])})
	}
	return out
}

func body(t *testing.T, d []byte, typ StreamType) []byte {
	t.Helper()
	for _, s := range directory(t, d) {
		if s.typ == typ {
			return d[s.rva : s.rva+s.size]
		}
	}
	t.Fatalf("no %s", typ)
	return nil
}

func text(t *testing.T, d []byte, rva uint32) string {
	t.Helper()
	n := binary.LittleEndian.Uint32(d[rva:])
	units := make([]uint16, n/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(d[int(rva)+4+2*i:])
	}
	if binary.LittleEndian.Uint16(d[int(rva)+4+int(n):]) != 0 {
		t.Errorf("string at 0x%x has no terminator", rva)
	}
	return string(utf16.Decode(units))
}

func u32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
func u64(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }

type memory map[uint64]byte

func (m memory) read(base, size uint64) ([]byte, extract.GapMap) {
	out := make([]byte, size)
	var gaps extract.GapMap
	for i := uint64(0); i < size; i += 0x1000 {
		v, ok := m[(base+i)&^0xFFF]
		if !ok {
			gaps = append(gaps, extract.Gap{Start: base + i, Length: min(0x1000, size-i)})
			continue
		}
		for j := i; j < min(i+0x1000, size); j++ {
			out[j] = v
		}
	}
	return out, gaps
}

func fullInput() Input {
	ctx := AMD64Context{Flags: ContextAMD64 | ContextControl, Rip: 0x7ff612340000, Rsp: 0x5000ff8}
	return Input{
		System: SystemInfo{ProcessorArchitecture: ProcessorArchitectureAMD64, NumberOfProcessors: 4, ProductType: 1,
			MajorVersion: 10, BuildNumber: 19045, PlatformID: 2, SuiteMask: 0x100},
		Modules: []Module{
			{Base: 0x7ff612340000, Size: 0x3000, Name: `C:\Windows\notepad.exe`, TimeDateStamp: 7, CheckSum: 9},
			{Base: 0x7ffa00000000, Size: 0x2000, Name: `C:\Windows\System32\ntdll.dll`},
		},
		Threads: []Thread{
			{ID: 100, Teb: 0x3000, StackBase: 0x5000000, StackSize: 0x2000, Context: ctx.Bytes(), CreateTime: 5, StartAddress: 0x7ff612341000},
			{ID: 104, StackBase: 0x9000000, StackSize: 0x1000, ExitTime: 6},
		},
		Handles: []Handle{
			{Handle: 4, TypeName: "File", ObjectName: `\Device\HarddiskVolume3\x`, GrantedAccess: 0x12019F},
			{Handle: 8, TypeName: "File"},
			{Handle: 12},
		},
		Regions: []Region{
			{BaseAddress: 0x7ff612340000, AllocationBase: 0x7ff612340000, Size: 0x3000, Protect: 0x20, AllocationProtect: 0x80, State: MemCommit, Type: MemImage, Dumpable: true},
			{BaseAddress: 0x5000000, AllocationBase: 0x5000000, Size: 0x2000, Protect: 0x04, AllocationProtect: 0x04, State: MemCommit, Type: MemPrivate, Dumpable: true},
			{BaseAddress: 0x6000000, AllocationBase: 0x6000000, Size: 0x100000, State: MemReserve, Type: MemPrivate},
			{BaseAddress: 0x5002000, AllocationBase: 0x5002000, Size: 0x1000, Protect: 0x04, State: MemCommit, Type: MemMapped, Dumpable: true},
		},
		ReadMemory:    memory{0x7ff612340000: 0xA1, 0x7ff612342000: 0xA3, 0x5000000: 0xB0, 0x5001000: 0xB1, 0x5002000: 0xB2}.read,
		TimeDateStamp: 0x5F000000,
	}
}

func write(t *testing.T, in Input) ([]byte, Result) {
	t.Helper()
	var buf bytes.Buffer
	res, err := Write(&buf, in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Size != uint64(buf.Len()) {
		t.Errorf("Result.Size %d, file %d bytes", res.Size, buf.Len())
	}
	if a := Validate(buf.Bytes()); !a.OK() {
		t.Fatalf("written dump fails validation: %q", a.Problems)
	}
	return buf.Bytes(), res
}

func TestHeaderAndDirectory(t *testing.T) {
	d, res := write(t, fullInput())
	if u32(d, 0) != Signature || u32(d, 4) != VersionLow || u32(d, 12) != headerSize || u32(d, 16) != 0 || u32(d, 20) != 0x5F000000 {
		t.Errorf("header % x", d[:24])
	}
	want := MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo
	if f := u64(d, 24); f != want {
		t.Errorf("flags 0x%x, want 0x%x", f, want)
	}
	order := []StreamType{StreamSystemInfo, StreamModuleList, StreamThreadList, StreamThreadInfoList, StreamHandleData, StreamMemoryInfoList, StreamMemory64List}
	dir := directory(t, d)
	if len(dir) != len(order) || len(res.Streams) != len(order) {
		t.Fatalf("%d streams, want %d", len(dir), len(order))
	}
	for i, s := range dir {
		if s.typ != order[i] || res.Streams[i] != (StreamRecord{s.typ, s.rva, s.size}) {
			t.Errorf("stream %d: %v, result %v", i, s, res.Streams[i])
		}
		if s.rva%streamAlign != 0 {
			t.Errorf("%s at 0x%x is not %d-aligned", s.typ, s.rva, streamAlign)
		}
	}
}

func TestEmptyInputStillHasTheRequiredStreams(t *testing.T) {
	d, res := write(t, Input{System: SystemInfo{ProcessorArchitecture: ProcessorArchitectureAMD64}})
	dir := directory(t, d)
	if len(dir) != 5 || dir[3].typ != StreamThreadInfoList || dir[4].typ != StreamMemory64List {
		t.Fatalf("streams %v", dir)
	}
	if u64(d, 24) != MiniDumpWithFullMemory|MiniDumpWithThreadInfo {
		t.Errorf("flags 0x%x", u64(d, 24))
	}
	if res.MemoryBytes != 0 || len(res.MemoryGaps) != 0 {
		t.Errorf("result %+v", res)
	}
}

func TestNoThreadsGetsThePlaceholderThread(t *testing.T) {
	in := fullInput()
	in.Threads = nil
	d, _ := write(t, in)
	b := body(t, d, StreamThreadList)
	if u32(b, 0) != 1 || !bytes.Equal(b[listCountSize:], make([]byte, threadSize)) {
		t.Errorf("thread list % x", b)
	}
	info := body(t, d, StreamThreadInfoList)
	if u32(info, 8) != 1 || u32(info, threadInfoHeaderSize) != 0 {
		t.Fatalf("thread info % x", info)
	}
	if f := u32(info, threadInfoHeaderSize+4); f != threadInfoErrorThread|threadInfoInvalidContext|threadInfoInvalidTEB {
		t.Errorf("placeholder flags 0x%x", f)
	}
}

func TestSystemInfo(t *testing.T) {
	in := fullInput()
	in.System.CSDVersion = "Service Pack 1"
	d, _ := write(t, in)
	b := body(t, d, StreamSystemInfo)
	if len(b) != systemInfoSize {
		t.Fatalf("%d bytes", len(b))
	}
	if binary.LittleEndian.Uint16(b) != 9 || b[6] != 4 || b[7] != 1 || u32(b, 8) != 10 || u32(b, 16) != 19045 || u32(b, 20) != 2 || binary.LittleEndian.Uint16(b[28:]) != 0x100 {
		t.Errorf("system info % x", b)
	}
	if s := text(t, d, u32(b, 24)); s != "Service Pack 1" {
		t.Errorf("CSDVersion %q", s)
	}
	if !bytes.Equal(b[30:], make([]byte, 26)) {
		t.Errorf("reserved and cpu bytes % x", b[30:])
	}
}

func TestEmptyCSDVersionIsAnEmptyString(t *testing.T) {
	d, _ := write(t, fullInput())
	if s := text(t, d, u32(body(t, d, StreamSystemInfo), 24)); s != "" {
		t.Errorf("%q", s)
	}
}

func TestModules(t *testing.T) {
	in := fullInput()
	d, _ := write(t, in)
	b := body(t, d, StreamModuleList)
	if u32(b, 0) != 2 || len(b) != listCountSize+2*moduleSize {
		t.Fatalf("%d modules in %d bytes", u32(b, 0), len(b))
	}
	for i, m := range in.Modules {
		e := b[listCountSize+i*moduleSize:]
		if u64(e, 0) != m.Base || uint64(u32(e, 8)) != m.Size || u32(e, 12) != m.CheckSum || u32(e, 16) != m.TimeDateStamp {
			t.Errorf("module %d % x", i, e[:20])
		}
		if s := text(t, d, u32(e, 20)); s != m.Name {
			t.Errorf("module %d name %q", i, s)
		}
		if !bytes.Equal(e[24:moduleSize], make([]byte, moduleSize-24)) {
			t.Errorf("module %d version, records and reserved not zero", i)
		}
	}
}

func TestThreadsContextsAndStacks(t *testing.T) {
	in := fullInput()
	d, _ := write(t, in)
	b := body(t, d, StreamThreadList)
	if u32(b, 0) != 2 {
		t.Fatalf("%d threads", u32(b, 0))
	}
	e := b[listCountSize:]
	if u32(e, 0) != 100 || u64(e, 16) != 0x3000 || u64(e, 24) != 0x5000000 {
		t.Errorf("thread 0 % x", e[:32])
	}
	size, rva := u32(e, 32), u32(e, 36)
	if size != 0x2000 || d[rva] != 0xB0 || d[rva+0x1000] != 0xB1 {
		t.Errorf("stack descriptor 0x%x at 0x%x", size, rva)
	}
	csize, crva := u32(e, 40), u32(e, 44)
	if csize != ContextAMD64Size || !bytes.Equal(d[crva:crva+csize], in.Threads[0].Context) {
		t.Errorf("context 0x%x at 0x%x", csize, crva)
	}
	e = b[listCountSize+threadSize:]
	if u64(e, 24) != 0x9000000 || u32(e, 32) != 0 || u32(e, 36) != 0 || u32(e, 40) != 0 || u32(e, 44) != 0 {
		t.Errorf("thread 1 with an unwritten stack and no context % x", e)
	}
}

func TestStackSpanningContiguousRanges(t *testing.T) {
	in := fullInput()
	in.Threads[0].StackSize = 0x3000
	d, _ := write(t, in)
	e := body(t, d, StreamThreadList)[listCountSize:]
	if rva := u32(e, 36); u32(e, 32) != 0x3000 || d[rva+0x2000] != 0xB2 {
		t.Errorf("stack over two ranges: 0x%x at 0x%x", u32(e, 32), rva)
	}
	in.Threads[0].StackSize = 0x4000
	d, _ = write(t, in)
	if e := body(t, d, StreamThreadList)[listCountSize:]; u32(e, 32) != 0 || u32(e, 36) != 0 {
		t.Errorf("stack past the written ranges kept a location")
	}
}

func TestThreadInfo(t *testing.T) {
	in := fullInput()
	in.Threads[1].DumpError, in.Threads[1].ExitStatus, in.Threads[1].Affinity = 0x80004005, 0x103, 0xF
	d, _ := write(t, in)
	b := body(t, d, StreamThreadInfoList)
	if u32(b, 0) != threadInfoHeaderSize || u32(b, 4) != threadInfoSize || u32(b, 8) != 2 {
		t.Fatalf("header % x", b[:12])
	}
	e := b[threadInfoHeaderSize:]
	if u32(e, 0) != 100 || u32(e, 4) != 0 || u64(e, 16) != 5 || u64(e, 48) != 0x7ff612341000 {
		t.Errorf("entry 0 % x", e[:threadInfoSize])
	}
	e = b[threadInfoHeaderSize+threadInfoSize:]
	if u32(e, 4) != threadInfoExited|threadInfoInvalidContext|threadInfoInvalidTEB {
		t.Errorf("entry 1 flags 0x%x", u32(e, 4))
	}
	if u32(e, 8) != 0x80004005 || u32(e, 12) != 0x103 || u64(e, 24) != 6 || u64(e, 56) != 0xF {
		t.Errorf("entry 1 % x", e[:threadInfoSize])
	}
}

func TestHandles(t *testing.T) {
	d, _ := write(t, fullInput())
	b := body(t, d, StreamHandleData)
	if u32(b, 0) != handleHeaderSize || u32(b, 4) != handleDescriptorSize || u32(b, 8) != 3 || u32(b, 12) != 0 {
		t.Fatalf("header % x", b[:16])
	}
	e0, e1, e2 := b[16:], b[16+32:], b[16+64:]
	if text(t, d, u32(e0, 8)) != "File" || text(t, d, u32(e0, 12)) != `\Device\HarddiskVolume3\x` || u32(e0, 20) != 0x12019F {
		t.Errorf("handle 0 % x", e0[:32])
	}
	if u32(e1, 8) != u32(e0, 8) || u32(e1, 12) != 0 {
		t.Errorf("handle 1: type rva 0x%x (handle 0 0x%x), object rva 0x%x", u32(e1, 8), u32(e0, 8), u32(e1, 12))
	}
	if u64(e2, 0) != 12 || u32(e2, 8) != 0 || u32(e2, 12) != 0 {
		t.Errorf("handle 2 % x", e2[:32])
	}
}

func TestMemoryInfoAndMemory64(t *testing.T) {
	in := fullInput()
	d, res := write(t, in)
	b := body(t, d, StreamMemoryInfoList)
	if u32(b, 0) != memoryInfoHeaderSize || u32(b, 4) != memoryInfoSize || u64(b, 8) != 4 {
		t.Fatalf("header % x", b[:16])
	}
	wantBases := []uint64{0x5000000, 0x5002000, 0x6000000, 0x7ff612340000}
	for i, base := range wantBases {
		e := b[memoryInfoHeaderSize+i*memoryInfoSize:]
		if u64(e, 0) != base {
			t.Errorf("entry %d at 0x%x, want 0x%x (ascending)", i, u64(e, 0), base)
		}
	}
	e := b[memoryInfoHeaderSize+3*memoryInfoSize:]
	if u64(e, 8) != 0x7ff612340000 || u32(e, 16) != 0x80 || u64(e, 24) != 0x3000 || u32(e, 32) != MemCommit || u32(e, 36) != 0x20 || u32(e, 40) != MemImage {
		t.Errorf("image entry % x", e[:memoryInfoSize])
	}

	m := body(t, d, StreamMemory64List)
	if u64(m, 0) != 3 {
		t.Fatalf("%d ranges, want the three committed dumpable regions", u64(m, 0))
	}
	cursor := u64(m, 8)
	dir := directory(t, d)
	if last := dir[len(dir)-1]; cursor != uint64(last.rva+last.size) {
		t.Errorf("BaseRva 0x%x, list ends at 0x%x", cursor, last.rva+last.size)
	}
	fills := [][]byte{{0xB0, 0xB1}, {0xB2}, {0xA1, 0, 0xA3}}
	for i, want := range fills {
		start, size := u64(m, 16+16*i), u64(m, 24+16*i)
		if start != []uint64{0x5000000, 0x5002000, 0x7ff612340000}[i] || size != uint64(len(want))*0x1000 {
			t.Errorf("range %d 0x%x+0x%x", i, start, size)
		}
		for p, v := range want {
			if got := d[cursor+uint64(p)*0x1000]; got != v {
				t.Errorf("range %d page %d holds 0x%x, want 0x%x", i, p, got, v)
			}
		}
		cursor += size
	}
	if cursor != uint64(len(d)) {
		t.Errorf("memory data ends at 0x%x, file 0x%x", cursor, len(d))
	}
	if res.MemoryBytes != 5*0x1000 || len(res.MemoryGaps) != 1 || res.MemoryGaps[0] != (extract.Gap{Start: 0x7ff612341000, Length: 0x1000}) {
		t.Errorf("result %d bytes, gaps %v", res.MemoryBytes, res.MemoryGaps)
	}
}

func TestReaderThatReturnsTheWrongLength(t *testing.T) {
	for _, n := range []int{0x800, 0x2000} {
		in := fullInput()
		in.Regions = in.Regions[1:2]
		in.Threads = nil
		in.ReadMemory = func(base, size uint64) ([]byte, extract.GapMap) { return bytes.Repeat([]byte{0xCC}, n), nil }
		d, res := write(t, in)
		got := d[len(d)-0x2000:]
		keep := min(n, 0x2000)
		if !bytes.Equal(got[:keep], bytes.Repeat([]byte{0xCC}, keep)) || !bytes.Equal(got[keep:], make([]byte, 0x2000-keep)) {
			t.Errorf("reader returning %d bytes: data not cut or padded to the range", n)
		}
		wantGap := uint64(0x2000 - keep)
		if res.MemoryGaps.PaddedBytes() != wantGap || res.MemoryBytes != 0x2000-wantGap {
			t.Errorf("reader returning %d bytes: gaps %v, %d bytes", n, res.MemoryGaps, res.MemoryBytes)
		}
	}
}

func TestLargeRegionIsReadInChunks(t *testing.T) {
	var calls, biggest uint64
	in := Input{
		Regions: []Region{{BaseAddress: 0x10000000, Size: 3*readChunk + 0x1000, State: MemCommit, Type: MemPrivate, Dumpable: true}},
		ReadMemory: func(base, size uint64) ([]byte, extract.GapMap) {
			calls++
			biggest = max(biggest, size)
			return make([]byte, size), nil
		},
	}
	_, res := write(t, in)
	if calls != 4 || biggest != readChunk || res.MemoryBytes != 3*readChunk+0x1000 {
		t.Errorf("%d reads, largest 0x%x, %d bytes", calls, biggest, res.MemoryBytes)
	}
}

func TestInputRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Input)
		want error
	}{
		{"module over 32 bits", func(in *Input) { in.Modules[0].Size = 1 << 32 }, ErrModuleTooLarge},
		{"empty region", func(in *Input) { in.Regions[0].Size = 0 }, ErrRegionRange},
		{"region wraps", func(in *Input) { in.Regions[0].BaseAddress, in.Regions[0].Size = ^uint64(0)-0xFFF, 0x2000 }, ErrRegionRange},
		{"overlap", func(in *Input) { in.Regions[3].BaseAddress = 0x5001000 }, ErrRegionOverlap},
		{"zero state", func(in *Input) { in.Regions[0].State = 0 }, ErrRegionAttributes},
		{"zero type", func(in *Input) { in.Regions[0].Type = 0 }, ErrRegionAttributes},
		{"no reader", func(in *Input) { in.ReadMemory = nil }, ErrNoMemoryReader},
	}
	for _, c := range cases {
		in := fullInput()
		c.edit(&in)
		var buf bytes.Buffer
		if _, err := Write(&buf, in); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
		if buf.Len() != 0 {
			t.Errorf("%s: %d bytes written before the refusal", c.name, buf.Len())
		}
	}
}

func TestFreeRegionNeedsNoType(t *testing.T) {
	in := fullInput()
	in.Regions = append(in.Regions, Region{BaseAddress: 0x10000, Size: 0x10000, State: MemFree})
	write(t, in)
}

func TestNotDumpableAndUncommittedRegionsAreListedOnly(t *testing.T) {
	in := fullInput()
	in.Regions[1].Dumpable = false
	in.Regions[2].Dumpable = true
	in.Threads = nil
	d, _ := write(t, in)
	if n := u64(body(t, d, StreamMemory64List), 0); n != 2 {
		t.Errorf("%d ranges, want 2", n)
	}
	if n := u64(body(t, d, StreamMemoryInfoList), 8); n != 4 {
		t.Errorf("%d info entries, want 4", n)
	}
}

type failWriter struct{ after int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("disk full")
	}
	f.after--
	return len(p), nil
}

func TestWriteErrorsAbort(t *testing.T) {
	for after := range 3 {
		if _, err := Write(&failWriter{after: after}, fullInput()); err == nil {
			t.Errorf("write failing after %d calls: no error", after)
		}
	}
}

func TestStackRVAEdges(t *testing.T) {
	written := []span{{address: 0x1000, size: 0x1000, rva: 0x100}, {address: 0x2000, size: 0x1000, rva: 0x1100}, {address: 0x4000, size: 0x1000, rva: 0x2100}}
	for _, c := range []struct {
		base, size, rva uint64
		ok              bool
	}{
		{0x1000, 0x1000, 0x100, true},
		{0x1800, 0x1000, 0x900, true},
		{0x1800, 0x2000, 0, false},
		{0x3000, 0x100, 0, false},
		{0x4800, 0x800, 0x2900, true},
		{0x4800, 0x801, 0, false},
		{0x500, 0x100, 0, false},
		{0x1000, 0, 0, false},
		{0x1000, 1 << 32, 0, false},
	} {
		rva, ok := stackRVA(c.base, c.size, written)
		if ok != c.ok || rva != c.rva {
			t.Errorf("stack 0x%x+0x%x: 0x%x %v, want 0x%x %v", c.base, c.size, rva, ok, c.rva, c.ok)
		}
	}
	if _, ok := stackRVA(0x1000, 0x1000, []span{{address: 0x1000, size: 0x1000, rva: maxRVA - 0x800}}); ok {
		t.Error("stack past the 32-bit rva limit kept a location")
	}
}

func TestStreamTypeNames(t *testing.T) {
	if StreamMemory64List.String() != "Memory64ListStream" || StreamType(0x8000).String() != "stream type 32768" {
		t.Errorf("%s, %s", StreamMemory64List, StreamType(0x8000))
	}
}
