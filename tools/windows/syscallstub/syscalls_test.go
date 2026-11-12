package syscallstub

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
)

const (
	ntdllPath  = `\Windows\System32\ntdll.dll`
	win32uPath = `\Windows\System32\win32u.dll`
	ntdllBase  = uint64(0x7FFA00000000)
	win32uBase = uint64(0x7FFA10000000)
)

type fakeImages struct {
	exportsOf map[string][]pe.Export
	failed    map[string]bool
	memory    map[uint64]sparse
	noOffset  bool
}

func (f fakeImages) exports(im image) ([]pe.Export, error) {
	if f.failed[im.path] {
		return nil, errors.New("export directory paged out")
	}
	return f.exportsOf[im.path], nil
}

func (f fakeImages) read(im image, address, n uint64) ([]byte, error) {
	b, err := f.memory[im.dtb].ReadAt(address, n)
	if err != nil || uint64(len(b)) < n {
		return nil, errors.New("unread")
	}
	return b, nil
}

func (f fakeImages) systemCallOffset() (uint64, bool) { return systemCallOffset, !f.noOffset }

type stubWorld struct {
	images []image
	src    fakeImages
}

func newWorld(processes int) *stubWorld {
	w := &stubWorld{src: fakeImages{
		exportsOf: map[string][]pe.Export{
			ntdllPath: {{Name: "NtClose", RVA: 0x1000}, {Name: "ZwClose", RVA: 0x1000}, {Name: "NtOpenFile", RVA: 0x1020},
				{Name: "RtlAllocateHeap", RVA: 0x2000}, {Name: "NtForwarded", RVA: 0x3000, Forwarder: "x.y"}},
			win32uPath: {{Name: "NtUserGetDC", RVA: 0x1000}},
		},
		failed: map[string]bool{},
		memory: map[uint64]sparse{},
	}}
	for i := 0; i < processes; i++ {
		dtb := uint64(0x1000 * (i + 1))
		mem := sparse{}
		mem.write(ntdllBase+0x1000, stub(0x0F))
		mem.write(ntdllBase+0x1020, stub(0x33))
		mem.write(win32uBase+0x1000, stub(0x100A))
		w.src.memory[dtb] = mem
		pid := uint64(100 + 4*i)
		w.images = append(w.images,
			image{pid: pid, process: "p" + string(rune('a'+i)), dtb: dtb, path: ntdllPath, base: ntdllBase, size: 0x200000, sequence: 2 * i},
			image{pid: pid, process: "p" + string(rune('a'+i)), dtb: dtb, path: win32uPath, base: win32uBase, size: 0x100000, sequence: 2*i + 1})
	}
	return w
}

func (w *stubWorld) run(t *testing.T) ([]Row, []string) {
	t.Helper()
	var diags []string
	rows, err := compare(contextFor(nil, &diags), w.images, w.src)
	if err != nil {
		t.Fatal(err)
	}
	return rows, diags
}

func rowFor(rows []Row, fn string) Row {
	for _, r := range rows {
		if r.Function == fn {
			return r
		}
	}
	return Row{}
}

func TestIdenticalStubsAgree(t *testing.T) {
	rows, diags := newWorld(3).run(t)
	if len(rows) != 3 || len(diags) != 0 {
		t.Fatalf("rows %+v diagnostics %v", rows, diags)
	}
	want := []string{"NtClose", "NtOpenFile", "NtUserGetDC"}
	for i, r := range rows {
		if r.Function != want[i] || r.Variants != 1 || r.Agreeing != 3 || r.Processes != 3 || r.Form != FormSyscall ||
			len(r.Differing) != 0 || r.Tie {
			t.Errorf("row %d = %+v", i, r)
		}
	}
	if c := rowFor(rows, "NtClose"); !reflect.DeepEqual(c.Aliases, []string{"ZwClose"}) || c.Number != 0x0F ||
		c.Address != ntdllBase+0x1000 || c.RVA != 0x1000 || c.Module != ntdllPath {
		t.Errorf("NtClose = %+v", c)
	}
}

func TestAHookedStubNamesItsProcess(t *testing.T) {
	w := newWorld(3)
	w.src.memory[0x2000].write(ntdllBase+0x1020, []byte{0xE9, 0x10, 0x20, 0x30, 0x40})
	rows, _ := w.run(t)
	r := rowFor(rows, "NtOpenFile")
	if r.Variants != 2 || r.Agreeing != 2 || r.Form != FormSyscall || r.Number != 0x33 ||
		!reflect.DeepEqual(r.Differing, []string{"pb (104)"}) || r.DifferingText() != "pb (104)" {
		t.Errorf("hooked row = %+v", r)
	}
}

func TestATieNamesNoProcess(t *testing.T) {
	w := newWorld(2)
	w.src.memory[0x2000].write(ntdllBase+0x1000, []byte{0xE9, 0, 0, 0, 0})
	r := rowFor(func() []Row { rows, _ := w.run(t); return rows }(), "NtClose")
	if !r.Tie || len(r.Differing) != 0 || r.Variants != 2 || r.Agreeing != 1 || r.Form != FormSyscall {
		t.Errorf("tie row = %+v", r)
	}
}

func TestAnUnreadStubIsCountedNotCompared(t *testing.T) {
	w := newWorld(2)
	delete(w.src.memory[0x1000], (ntdllBase+0x1000)&^0xFFF)
	rows, _ := w.run(t)
	r := rowFor(rows, "NtClose")
	if r.Processes != 1 || r.Unread != 1 || r.Variants != 1 || len(r.Differing) != 0 {
		t.Errorf("row = %+v", r)
	}
}

func TestAnExportTableThatDoesNotReadIsADiagnostic(t *testing.T) {
	w := newWorld(2)
	w.src.failed[win32uPath] = true
	rows, diags := w.run(t)
	if len(rows) != 2 || len(diags) != 1 || !strings.Contains(diags[0], "export table not read") {
		t.Errorf("rows %d diagnostics %v", len(rows), diags)
	}
}

func TestClassify(t *testing.T) {
	tails := testTemplates(fakeImages{})
	bare := append([]byte{0x4C, 0x8B, 0xD1, 0xB8, 7, 0, 0, 0}, 0x0F, 0x05, 0xC3)
	x86 := []byte{0xB8, 0x26, 0, 0x01, 0, 0xBA, 0x10, 0x20, 0x30, 0x40, 0xFF, 0xD2, 0xC2, 0x0C, 0}
	cases := []struct {
		b      []byte
		form   Form
		number uint32
	}{
		{stub(0x55), FormSyscall, 0x55},
		{bare, FormSyscall, 7},
		{x86, FormX86Call, 0x10026},
		{[]byte{0xE9, 1, 2, 3, 4}, FormJump, 0},
		{[]byte{0xFF, 0x25, 0, 0, 0, 0}, FormJump, 0},
		{[]byte{0x48, 0x8B, 0xC4}, FormOther, 0},
		{nil, FormOther, 0},
	}
	for i, c := range cases {
		if f, n := classify(c.b, tails); f != c.form || n != c.number {
			t.Errorf("case %d: %s %d, want %s %d", i, f, n, c.form, c.number)
		}
	}
	if f, _ := classify(stub(1), testTemplates(fakeImages{noOffset: true})); f != FormOther {
		t.Errorf("without the SystemCall member the tested stub is %s", f)
	}
}

func TestStubImagesKeepOnlyNtdllAndWin32uImages(t *testing.T) {
	mappings := []memoryranges.Mapping{
		{PID: 4, Start: 0x1000, End: 0x1FFF, Type: memoryranges.KindImage, Path: `\Windows\System32\NTDLL.DLL`},
		{PID: 4, Start: 0x3000, End: 0x3FFF, Type: memoryranges.KindMapped, Path: `\Windows\System32\ntdll.dll`},
		{PID: 4, Start: 0x5000, End: 0x5FFF, Type: memoryranges.KindImage, Path: `\Windows\System32\kernel32.dll`},
		{PID: 4, Start: 0x7000, End: 0x8FFF, Type: memoryranges.KindImage, Path: `\Windows\SysWOW64\win32u.dll`},
	}
	got := stubImages(mappings)
	if len(got) != 2 || got[0].size != 0x1000 || got[1].size != 0x2000 || got[1].sequence != 1 {
		t.Errorf("images = %+v", got)
	}
}

func FuzzClassify(f *testing.F) {
	f.Add(stub(3))
	f.Add([]byte{0xB8, 1, 2, 3, 4, 0xBA, 1, 2, 3, 4, 0xFF, 0xD2})
	tails := testTemplates(fakeImages{})
	f.Fuzz(func(t *testing.T, b []byte) {
		form, number := classify(b, tails)
		switch form {
		case FormSyscall:
			if !bytes.HasPrefix(b, []byte{0x4C, 0x8B, 0xD1, 0xB8}) {
				t.Fatalf("syscall form without the preamble: % x", b)
			}
		case FormX86Call, FormJump, FormOther:
		default:
			t.Fatalf("form %q", form)
		}
		if (form == FormJump || form == FormOther) && number != 0 {
			t.Fatalf("number %d on form %s", number, form)
		}
	})
}

func TestAStubWindowEndsAtTheNextStub(t *testing.T) {
	const wowPath = `\Windows\SysWOW64\ntdll.dll`
	const wowBase = uint64(0x77000000)
	x86 := func(n byte) []byte {
		return []byte{0xB8, n, 0, 0, 0, 0xBA, 0, 0x10, 0, 0x77, 0xFF, 0xD2, 0xC2, 0x08, 0, 0x90}
	}
	w := &stubWorld{src: fakeImages{
		exportsOf: map[string][]pe.Export{wowPath: {{Name: "NtClose", RVA: 0x1000}, {Name: "NtOpen", RVA: 0x1010}}},
		failed:    map[string]bool{},
		memory:    map[uint64]sparse{},
	}}
	for i := 0; i < 3; i++ {
		dtb := uint64(0x1000 * (i + 1))
		mem := sparse{}
		mem.write(wowBase+0x1000, append(x86(1), x86(2)...))
		w.src.memory[dtb] = mem
		w.images = append(w.images, image{pid: uint64(8 + 4*i), process: "wow.exe", dtb: dtb, path: wowPath,
			base: wowBase, size: 0x10000, sequence: i})
	}
	w.src.memory[0x3000].write(wowBase+0x1010, []byte{0xE9, 0, 0, 0, 0})
	rows, _ := w.run(t)
	if len(rows) != 2 || rows[0].Variants != 1 || rows[0].Form != FormX86Call || rows[0].Number != 1 ||
		rows[1].Variants != 2 || !reflect.DeepEqual(rows[1].Differing, []string{"wow.exe (16)"}) {
		t.Errorf("rows = %+v", rows)
	}
}
