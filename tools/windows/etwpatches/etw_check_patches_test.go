package etwpatches

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
)

type flat struct {
	base uint64
	buf  []byte
}

func (f flat) Size() uint64 { return ^uint64(0) }

func (f flat) ReadAt(at, n uint64) ([]byte, error) {
	if at < f.base || at-f.base+n > uint64(len(f.buf)) {
		return nil, fmt.Errorf("0x%x not mapped", at)
	}
	return f.buf[at-f.base : at-f.base+n], nil
}

const base = uint64(0x7ffc0000000)

func image(path string) (flat, memoryranges.Mapping) {
	return flat{base: base, buf: make([]byte, 0x4000)},
		memoryranges.Mapping{PID: 42, Process: "victim.exe", Start: base, End: base + 0x3fff, Path: path}
}

func TestReturnsAndJumpsOutOfTheImageArePatches(t *testing.T) {
	space, m := image(`\Windows\System32\ntdll.dll`)
	put := func(rva uint64, b ...byte) { copy(space.buf[rva:], b) }
	put(0x100, 0xC3)
	put(0x200, 0xE9, 0x10, 0x00, 0x00, 0x00)
	put(0x300, 0xE9, 0x00, 0x00, 0x00, 0x10)
	put(0x400, 0xEB, 0x10)
	put(0x500, 0xFF, 0x25, 0x00, 0x10, 0x00, 0x00)
	binary.LittleEndian.PutUint64(space.buf[0x1506:], 0x1234560000)
	put(0x600, 0x4C, 0x8B, 0xDC)
	put(0x700, 0xC2, 0x08, 0x00)
	exports := []pe.Export{
		{Name: "EtwEventWrite", RVA: 0x100}, {Name: "EtwpGetCpuSpeed", RVA: 0x200}, {Name: "EtwFar", RVA: 0x300},
		{Name: "EtwShort", RVA: 0x400}, {Name: "NtTraceEvent", RVA: 0x500}, {Name: "EtwClean", RVA: 0x600},
		{Name: "ZwTraceControl", RVA: 0x700}, {Name: "NtClose", RVA: 0x100},
		{Name: "EtwForward", RVA: 0x800, Forwarder: "x.y"},
	}
	var c tally
	rows := check(space, m, exports, &c)
	want := map[string]uint64{"EtwEventWrite": 0, "EtwFar": base + 0x305 + 0x10000000, "NtTraceEvent": 0x1234560000,
		"ZwTraceControl": 0}
	if len(rows) != len(want) || c.checked != 7 {
		t.Fatalf("rows = %+v, checked %d", rows, c.checked)
	}
	for _, r := range rows {
		target, ok := want[r.Function]
		if !ok || r.Target != target || r.PID != 42 || r.Module != "ntdll.dll" || r.Offset < base {
			t.Errorf("row %+v", r)
		}
	}
	if rows[0].OpcodeString() != "c3 (RET)" {
		t.Errorf("OpcodeString = %q", rows[0].OpcodeString())
	}
}

func TestAWow64ImageReadsAnAbsoluteSlot(t *testing.T) {
	const low = uint64(0x77000000)
	space := flat{base: low, buf: make([]byte, 0x4000)}
	m := memoryranges.Mapping{PID: 7, Process: "w.exe", Start: low, End: low + 0x3fff, Path: `\Windows\SysWOW64\ntdll.dll`}
	copy(space.buf[0x100:], []byte{0xFF, 0x25})
	binary.LittleEndian.PutUint32(space.buf[0x102:], uint32(low+0x2000))
	binary.LittleEndian.PutUint32(space.buf[0x2000:], 0x50000000)
	var c tally
	rows := check(space, m, []pe.Export{{Name: "EtwEventWrite", RVA: 0x100}}, &c)
	if len(rows) != 1 || rows[0].Target != 0x50000000 {
		t.Errorf("rows = %+v", rows)
	}
}

func TestETWFunctionNames(t *testing.T) {
	for name, want := range map[string]bool{"EtwEventWrite": true, "NtTraceEvent": true, "ZwTraceControl": true,
		"NtClose": false, "etwEventWrite": false} {
		if IsETWFunction(name) != want {
			t.Errorf("IsETWFunction(%q) != %v", name, want)
		}
	}
}

func FuzzClassify(f *testing.F) {
	f.Add([]byte{0xE9, 1, 2, 3, 4, 5}, true)
	space, m := image(`\Windows\System32\ntdll.dll`)
	f.Fuzz(func(t *testing.T, code []byte, wide bool) {
		if len(code) == 0 {
			return
		}
		r, patched := classify(space, base+0x100, code, m, wide)
		if r.Opcode != code[0] {
			t.Errorf("opcode %x", r.Opcode)
		}
		if patched && r.Target != 0 && r.Target >= m.Start && r.Target <= m.End {
			t.Errorf("a jump inside the image is a patch: %+v", r)
		}
		if _, known := Opcodes[code[0]]; patched && !known {
			t.Errorf("patched with opcode %x", code[0])
		}
	})
}
