package syscallstub

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/disasm"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
)

const (
	privateExec = uint64(0x20000)
	appImage    = uint64(0x7FF600000000)
	syscallRVA  = 0x1012
)

type blockWorld struct {
	spaces   map[uint64]sparse
	mappings []memoryranges.Mapping
}

func (w *blockWorld) process(pid, dtb uint64, name, exe string) sparse {
	mem := sparse{}
	mem.write(ntdllBase+0x1000, stub(0x0F))
	w.spaces[dtb] = mem
	w.mappings = append(w.mappings,
		memoryranges.Mapping{PID: pid, Process: name, DirectoryTableBase: dtb, Start: appImage, End: appImage + 0xFFFF,
			Type: memoryranges.KindImage, Path: exe, Protection: "PAGE_EXECUTE_WRITECOPY"},
		memoryranges.Mapping{PID: pid, Process: name, DirectoryTableBase: dtb, Start: ntdllBase, End: ntdllBase + 0x1FFFFF,
			Type: memoryranges.KindImage, Path: ntdllPath, Protection: "PAGE_EXECUTE_WRITECOPY"},
		memoryranges.Mapping{PID: pid, Process: name, DirectoryTableBase: dtb, Start: privateExec, End: privateExec + 0x1FFF,
			Type: memoryranges.KindPrivate, Protection: "PAGE_EXECUTE_READWRITE"},
		memoryranges.Mapping{PID: pid, Process: name, DirectoryTableBase: dtb, Start: 0x40000, End: 0x40FFF,
			Type: memoryranges.KindPrivate, Protection: "PAGE_READWRITE"})
	for _, base := range []uint64{appImage, privateExec, 0x40000} {
		mem.write(base, make([]byte, 0x1000))
	}
	mem.write(privateExec+0x1000, make([]byte, 0x1000))
	return mem
}

func newBlockWorld() *blockWorld {
	return &blockWorld{spaces: map[uint64]sparse{}}
}

func (w *blockWorld) scan(t *testing.T, kind blockKind) ([]Finding, Coverage) {
	t.Helper()
	var diags []string
	return scanProcesses(contextFor(w.spaces, &diags), kind, w.mappings)
}

func directBlock(number uint32) []byte {
	b := []byte{0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0x0F, 0x05, 0xC3}
	binary.LittleEndian.PutUint32(b[4:], number)
	return b
}

func TestADirectBlockOutsideNtdllIsFound(t *testing.T) {
	w := newBlockWorld()
	mem := w.process(8, 0x1000, "app.exe", `\Users\a\app.exe`)
	mem.write(privateExec+0x100, directBlock(0x18))
	mem.write(privateExec+0xFFE, stub(0x19))
	found, cov := w.scan(t, direct)
	if len(found) != 2 {
		t.Fatalf("found %+v", found)
	}
	f := found[0]
	if f.PID != 8 || f.Process != "app.exe" || f.Address != privateExec+0x100 || f.Number != 0x18 ||
		f.SyscallAt != privateExec+0x108 || f.Path != "" || f.Defender ||
		f.Instructions != "mov r10, rcx; mov eax, 0x18; syscall; ret" {
		t.Errorf("finding = %+v", f)
	}
	if found[1].Address != privateExec+0xFFE || found[1].Number != 0x19 {
		t.Errorf("page-straddling stub = %+v", found[1])
	}
	if cov.Processes != 1 || cov.Mappings != 2 || cov.Blocks != 2 || cov.Bytes != 0x3000 {
		t.Errorf("coverage = %+v", cov)
	}
}

func TestTheMoveOrderDoesNotMatter(t *testing.T) {
	w := newBlockWorld()
	mem := w.process(8, 0x1000, "app.exe", `\Users\a\app.exe`)
	mem.write(privateExec+0x200, []byte{0xB8, 0x22, 0, 0, 0, 0x4C, 0x8B, 0xD1, 0x0F, 0x05, 0xC3})
	found, _ := w.scan(t, direct)
	if len(found) != 1 || found[0].Address != privateExec+0x200 || found[0].Number != 0x22 {
		t.Errorf("found %+v", found)
	}
}

func TestBlocksThatBreakTheShapeAreNotFound(t *testing.T) {
	cases := map[string][]byte{
		"call before syscall": {0x4C, 0x8B, 0xD1, 0xB8, 1, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0x0F, 0x05, 0xC3},
		"no ret after":        {0x4C, 0x8B, 0xD1, 0xB8, 1, 0, 0, 0, 0x0F, 0x05, 0x90},
		"no mov eax":          {0x4C, 0x8B, 0xD1, 0x90, 0x0F, 0x05, 0xC3},
		"jump in a direct":    {0x4C, 0x8B, 0xD1, 0xB8, 1, 0, 0, 0, 0xEB, 0x00, 0x0F, 0x05, 0xC3},
	}
	for name, code := range cases {
		w := newBlockWorld()
		mem := w.process(8, 0x1000, "app.exe", `\Users\a\app.exe`)
		mem.write(privateExec+0x300, code)
		if found, _ := w.scan(t, direct); len(found) != 0 {
			t.Errorf("%s: found %+v", name, found)
		}
	}
}

func TestNtdllItselfAndDataMappingsAreNotScanned(t *testing.T) {
	w := newBlockWorld()
	mem := w.process(8, 0x1000, "app.exe", `\Users\a\app.exe`)
	mem.write(0x40000+0x10, directBlock(1))
	found, cov := w.scan(t, direct)
	if len(found) != 0 || cov.Mappings != 2 {
		t.Errorf("found %+v coverage %+v", found, cov)
	}
}

func TestIndirectBlocks(t *testing.T) {
	w := newBlockWorld()
	mem := w.process(8, 0x1000, "app.exe", `\Users\a\app.exe`)
	target := ntdllBase + syscallRVA
	slot := privateExec + 0x800
	viaSlot := []byte{0x4C, 0x8B, 0xD1, 0xB8, 0x30, 0, 0, 0, 0xFF, 0x25, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(viaSlot[10:], uint32(slot-(privateExec+0x100+uint64(len(viaSlot)))))
	mem.write(privateExec+0x100, viaSlot)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], target)
	mem.write(slot, b[:])
	viaReg := append([]byte{0x4C, 0x8B, 0xD1, 0xB8, 0x31, 0, 0, 0, 0x49, 0xBB}, b[:]...)
	viaReg = append(viaReg, 0x41, 0xFF, 0xE3)
	mem.write(privateExec+0x200, viaReg)
	wrong := []byte{0x4C, 0x8B, 0xD1, 0xB8, 0x32, 0, 0, 0, 0x49, 0xBB, 0, 0x10, 0, 0, 0xFA, 0x7F, 0, 0, 0x41, 0xFF, 0xE3}
	mem.write(privateExec+0x300, wrong)
	found, _ := w.scan(t, indirect)
	if len(found) != 2 {
		t.Fatalf("found %+v", found)
	}
	for i, n := range []uint32{0x30, 0x31} {
		if found[i].Number != n || found[i].SyscallAt != target {
			t.Errorf("finding %d = %+v", i, found[i])
		}
	}
	if !strings.HasSuffix(found[1].Instructions, "jmp r11") {
		t.Errorf("instructions %q", found[1].Instructions)
	}
	if direct, _ := w.scan(t, direct); len(direct) != 0 {
		t.Errorf("indirect blocks found as direct: %+v", direct)
	}
}

func TestASharedImageIsScannedOnceAndDefenderIsMarkedByPath(t *testing.T) {
	w := newBlockWorld()
	for i, p := range []struct {
		name, exe string
	}{
		{"MsMpEng.exe", `\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MsMpEng.exe`},
		{"MsMpEng.exe", `\Users\a\MsMpEng.exe`},
	} {
		mem := w.process(uint64(8+4*i), uint64(0x1000*(i+1)), p.name, p.exe)
		mem.write(appImage+0x40, directBlock(9))
	}
	found, cov := w.scan(t, direct)
	if cov.Shared != 0 {
		t.Errorf("two different executables shared: %+v", cov)
	}
	if len(found) != 2 || !found[0].Defender || found[1].Defender || found[0].Path == "" {
		t.Errorf("found %+v", found)
	}
	w2 := newBlockWorld()
	for i := 0; i < 2; i++ {
		mem := w2.process(uint64(8+4*i), uint64(0x1000*(i+1)), "app.exe", `\Users\a\app.exe`)
		mem.write(appImage+0x40, directBlock(9))
	}
	found, cov = w2.scan(t, direct)
	if cov.Shared != 1 || len(found) != 1 || found[0].PID != 8 {
		t.Errorf("shared image: found %+v coverage %+v", found, cov)
	}
}

func TestUnreadPagesAreCounted(t *testing.T) {
	w := newBlockWorld()
	mem := w.process(8, 0x1000, "app.exe", `\Users\a\app.exe`)
	delete(mem, privateExec+0x1000)
	_, cov := w.scan(t, direct)
	if cov.Unread != 0x10000 {
		t.Errorf("coverage = %+v", cov)
	}
}

func TestDefenderPaths(t *testing.T) {
	for path, want := range map[string]bool{
		`\Program Files\Windows Defender\MsMpEng.exe`:                              true,
		`\ProgramData\Microsoft\Windows Defender\Platform\4.18.2\MsMpEng.exe`:      true,
		`C:/PROGRAMDATA/Microsoft/Windows Defender/Platform/4.18.2/NisSrv.exe`:     true,
		`\Users\x\Windows Defender\MsMpEng.exe`:                                    false,
		`\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\a.exe`: false,
		``: false,
	} {
		if got := isDefenderPath(path); got != want {
			t.Errorf("%q: %v, want %v", path, got, want)
		}
	}
}

func FuzzDecodeBlock(f *testing.F) {
	f.Add(directBlock(1), false)
	f.Add([]byte{0x4C, 0x8B, 0xD1, 0xB8, 0x30, 0, 0, 0, 0xFF, 0x25, 0, 0, 0, 0}, true)
	f.Fuzz(func(t *testing.T, code []byte, indirectKind bool) {
		w := newBlockWorld()
		mem := w.process(8, 0x1000, "app.exe", `\Users\a\app.exe`)
		mem.write(privateExec+0x10, code)
		kind := direct
		if indirectKind {
			kind = indirect
		}
		found, cov := w.scan(t, kind)
		if cov.Blocks != len(found) {
			t.Fatalf("coverage %+v for %d findings", cov, len(found))
		}
		for _, fd := range found {
			b, err := mem.ReadAt(fd.SyscallAt, 16)
			inst, ok := disasm.Decode(b, fd.SyscallAt, disasm.Mode64)
			if err != nil || !ok || !inst.IsSyscall() {
				t.Fatalf("finding %+v does not point at a SYSCALL", fd)
			}
			if kind == direct && (fd.SyscallAt < fd.Address || fd.SyscallAt >= fd.Address+stubWindow) {
				t.Fatalf("direct finding %+v outside its window", fd)
			}
		}
	})
}
