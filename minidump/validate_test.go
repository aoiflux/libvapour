package minidump

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func valid(t *testing.T) []byte {
	t.Helper()
	d, _ := write(t, fullInput())
	return d
}

func at(t *testing.T, d []byte, typ StreamType) int {
	t.Helper()
	for _, s := range directory(t, d) {
		if s.typ == typ {
			return int(s.rva)
		}
	}
	t.Fatalf("no %s", typ)
	return 0
}

func dirEntry(t *testing.T, d []byte, typ StreamType) int {
	t.Helper()
	for i, s := range directory(t, d) {
		if s.typ == typ {
			return headerSize + i*directoryEntry
		}
	}
	t.Fatalf("no %s", typ)
	return 0
}

func put32(d []byte, off int, v uint32) { binary.LittleEndian.PutUint32(d[off:], v) }
func put64(d []byte, off int, v uint64) { binary.LittleEndian.PutUint64(d[off:], v) }

func TestValidateFlagsEachRule(t *testing.T) {
	cases := []struct {
		name string
		edit func(t *testing.T, d []byte) []byte
		want string
	}{
		{"short header", func(t *testing.T, d []byte) []byte { return d[:20] }, "under 32"},
		{"signature", func(t *testing.T, d []byte) []byte { d[0] = 'X'; return d }, "signature"},
		{"version", func(t *testing.T, d []byte) []byte { put32(d, 4, 0xA0F10001); return d }, "version low word 0x0001"},
		{"directory", func(t *testing.T, d []byte) []byte { put32(d, 8, 1<<28); return d }, "directory"},
		{"stream location", func(t *testing.T, d []byte) []byte {
			put32(d, dirEntry(t, d, StreamModuleList)+4, uint32(len(d)))
			return d
		}, "ModuleListStream at"},
		{"duplicate", func(t *testing.T, d []byte) []byte {
			put32(d, dirEntry(t, d, StreamThreadInfoList), uint32(StreamThreadList))
			return d
		}, "second stream of this type"},
		{"overlap", func(t *testing.T, d []byte) []byte {
			put32(d, dirEntry(t, d, StreamHandleData)+8, uint32(at(t, d, StreamThreadInfoList)))
			return d
		}, "overlaps"},
		{"no system info", func(t *testing.T, d []byte) []byte {
			put32(d, dirEntry(t, d, StreamSystemInfo), 0x10000)
			return d
		}, "no SystemInfoStream"},
		{"short system info", func(t *testing.T, d []byte) []byte {
			put32(d, dirEntry(t, d, StreamSystemInfo)+4, 40)
			return d
		}, "under 56"},
		{"odd string", func(t *testing.T, d []byte) []byte {
			rva := binary.LittleEndian.Uint32(d[at(t, d, StreamModuleList)+4+20:])
			put32(d, int(rva), 3)
			return d
		}, "odd length"},
		{"unterminated string", func(t *testing.T, d []byte) []byte {
			rva := binary.LittleEndian.Uint32(d[at(t, d, StreamModuleList)+4+20:])
			n := binary.LittleEndian.Uint32(d[rva:])
			d[rva+4+n] = 'x'
			return d
		}, "no terminating NUL"},
		{"string past the end", func(t *testing.T, d []byte) []byte {
			put32(d, at(t, d, StreamModuleList)+4+20, uint32(len(d)-2))
			return d
		}, "passes the end of the file"},
		{"module count", func(t *testing.T, d []byte) []byte { put32(d, at(t, d, StreamModuleList), 3); return d }, "do not fit"},
		{"no thread", func(t *testing.T, d []byte) []byte {
			off := at(t, d, StreamThreadList)
			put32(d, off, 0)
			put32(d, dirEntry(t, d, StreamThreadInfoList), 0x10001)
			return d
		}, "no thread"},
		{"context size", func(t *testing.T, d []byte) []byte {
			put32(d, at(t, d, StreamThreadList)+4+40, 0x100)
			return d
		}, "under 1232"},
		{"context flags", func(t *testing.T, d []byte) []byte {
			rva := binary.LittleEndian.Uint32(d[at(t, d, StreamThreadList)+4+44:])
			put32(d, int(rva)+ctxFlags, ContextControl)
			return d
		}, "lack 0x100000"},
		{"context location", func(t *testing.T, d []byte) []byte {
			put32(d, at(t, d, StreamThreadList)+4+44, uint32(len(d)-8))
			return d
		}, "thread 100 context"},
		{"stack address", func(t *testing.T, d []byte) []byte {
			off := at(t, d, StreamThreadList) + 4 + 36
			put32(d, off, binary.LittleEndian.Uint32(d[off:])+0x1000)
			return d
		}, "holds another address"},
		{"stack location", func(t *testing.T, d []byte) []byte {
			put32(d, at(t, d, StreamThreadList)+4+36, uint32(len(d)-0x100))
			return d
		}, "stack at 0x5000000"},
		{"thread info header", func(t *testing.T, d []byte) []byte { put32(d, at(t, d, StreamThreadInfoList)+4, 56); return d }, "under 12 and 64"},
		{"thread info id", func(t *testing.T, d []byte) []byte { put32(d, at(t, d, StreamThreadInfoList)+12, 999); return d }, "thread 999 is not in the thread list"},
		{"handle descriptor", func(t *testing.T, d []byte) []byte { put32(d, at(t, d, StreamHandleData)+4, 36); return d }, "not 32 or 40"},
		{"handle reserved", func(t *testing.T, d []byte) []byte { put32(d, at(t, d, StreamHandleData)+12, 1); return d }, "reserved 0x1"},
		{"handle name", func(t *testing.T, d []byte) []byte {
			put32(d, at(t, d, StreamHandleData)+16+12, uint32(len(d)))
			return d
		}, "handle 0 object"},
		{"memory info state", func(t *testing.T, d []byte) []byte {
			put32(d, at(t, d, StreamMemoryInfoList)+16+2*48+32, 0)
			return d
		}, "state 0x0"},
		{"memory info type", func(t *testing.T, d []byte) []byte {
			put32(d, at(t, d, StreamMemoryInfoList)+16+2*48+40, 0)
			return d
		}, "type 0x0"},
		{"memory info order", func(t *testing.T, d []byte) []byte {
			put64(d, at(t, d, StreamMemoryInfoList)+16+48, 0x5000000)
			return d
		}, "below the end"},
		{"memory info size", func(t *testing.T, d []byte) []byte {
			put64(d, at(t, d, StreamMemoryInfoList)+16+24, 0)
			return d
		}, "empty or passes"},
		{"memory info count", func(t *testing.T, d []byte) []byte { put64(d, at(t, d, StreamMemoryInfoList)+8, 1<<60); return d }, "do not fit"},
		{"memory64 count", func(t *testing.T, d []byte) []byte { put64(d, at(t, d, StreamMemory64List), 4); return d }, "ranges do not fit"},
		{"memory64 order", func(t *testing.T, d []byte) []byte {
			put64(d, at(t, d, StreamMemory64List)+16+16, 0x5000000)
			return d
		}, "below the end"},
		{"memory64 wrap", func(t *testing.T, d []byte) []byte {
			put64(d, at(t, d, StreamMemory64List)+16+2*16, ^uint64(0)-0x10)
			return d
		}, "end of the address space"},
		{"memory64 data", func(t *testing.T, d []byte) []byte { return d[:len(d)-1] }, "passes the end of the file"},
		{"memory64 base", func(t *testing.T, d []byte) []byte {
			put64(d, at(t, d, StreamMemory64List)+8, uint64(at(t, d, StreamSystemInfo)))
			return d
		}, "overlaps"},
		{"flags", func(t *testing.T, d []byte) []byte {
			put64(d, 24, MiniDumpWithHandleData|MiniDumpWithThreadInfo|MiniDumpWithFullMemoryInfo)
			return d
		}, "lack 0x2 for Memory64ListStream"},
		{"uncommitted memory", func(t *testing.T, d []byte) []byte {
			put32(d, at(t, d, StreamMemoryInfoList)+16+32, MemReserve)
			return d
		}, "not in a committed memory info entry"},
	}
	for _, c := range cases {
		d := c.edit(t, valid(t))
		a := Validate(d)
		if a.OK() || !strings.Contains(strings.Join(a.Problems, "\n"), c.want) {
			t.Errorf("%s: problems %q, want one containing %q", c.name, a.Problems, c.want)
		}
	}
}

func TestValidateReportsTheDirectory(t *testing.T) {
	d := valid(t)
	a := Validate(d)
	if a.Size != uint64(len(d)) || a.NumberOfStreams != 7 || len(a.Streams) != 7 || a.Streams[6].Type != StreamMemory64List {
		t.Errorf("audit %+v", a)
	}
	if b := ValidateReaderAt(bytes.NewReader(d), int64(len(d))); !b.OK() || len(b.Streams) != 7 {
		t.Errorf("reader audit %+v", b)
	}
}

func TestRepeatedProblemsAreCounted(t *testing.T) {
	d := valid(t)
	for i := range 2 {
		put32(d, at(t, d, StreamModuleList)+4+i*moduleSize+20, uint32(len(d)))
	}
	a := Validate(d)
	if len(a.Problems) != 1 || !strings.HasSuffix(a.Problems[0], "(and 1 more)") {
		t.Errorf("problems %q", a.Problems)
	}
}

func TestUnknownAndUnusedStreamsAreAccepted(t *testing.T) {
	d := valid(t)
	put32(d, dirEntry(t, d, StreamThreadInfoList), 0x10001)
	put64(d, 24, binary.LittleEndian.Uint64(d[24:])&^MiniDumpWithThreadInfo)
	if a := Validate(d); !a.OK() {
		t.Errorf("unknown stream type: %q", a.Problems)
	}
	put32(d, dirEntry(t, d, StreamHandleData), uint32(StreamUnused))
	if a := Validate(d); len(a.Problems) != 0 {
		t.Errorf("unused stream: %q", a.Problems)
	}
}
