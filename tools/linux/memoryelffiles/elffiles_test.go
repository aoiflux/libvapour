package memoryelffiles

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	imageBase = uint64(0x555500000000)
	vdsoBase  = uint64(0x7ffff7fc0000)
)

type elfCase struct {
	k     *lt.Kernel
	fs    *lt.RootFS
	procs *lt.Processes
	tasks []uint64
}

func newELFCase() *elfCase {
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	return &elfCase{k: k, fs: k.NewRootFS(), procs: k.NewProcesses()}
}

// The image's two segments sit at file offsets 0 and 0x2000 and p_vaddr 0 and
// 0x3000, so the rebuilt file differs from the memory layout.
var segments = []lt.Segment{
	{Type: 1, Offset: 0, Vaddr: 0, Filesz: 0x1100, Memsz: 0x1100},
	{Type: 1, Offset: 0x2000, Vaddr: 0x3000, Filesz: 0x80, Memsz: 0x1000},
}

func (c *elfCase) process(pid int32) *lt.Memory {
	file := c.fs.File("/usr/bin/tool", 1, 0x2080)
	task, _, space := c.procs.Add(lt.Task{PID: pid, TGID: pid, Comm: "tool"}, lt.MM{VMAs: []lt.VMA{
		{Start: imageBase, End: imageBase + 0x2000, File: file},
		{Start: imageBase + 0x3000, End: imageBase + 0x4000, File: file, Pgoff: 2},
		{Start: imageBase + 0x8000, End: imageBase + 0x9000},
		{Start: vdsoBase, End: vdsoBase + 0x1000},
	}})
	c.fs.Enter(task)
	lt.ELF64(space, imageBase, segments, 0, 0)
	space.Write(imageBase+0x1000, bytes.Repeat([]byte{0xcc}, 0x100))
	space.Write(imageBase+0x3000, bytes.Repeat([]byte{0xdd}, 0x80))
	space.Write(imageBase+0x8000, []byte("data"))
	lt.ELF64(space, vdsoBase, []lt.Segment{{Type: 1, Filesz: 0x100, Memsz: 0x100}}, 0, 0)
	c.tasks = append(c.tasks, task)
	return space
}

func (c *elfCase) run(t *testing.T, options map[string]any) ([]ELF, []string, error) {
	t.Helper()
	c.k.LinkTasks(c.tasks...)
	ctx, diags := c.procs.Context(options)
	rows, err := Run(ctx)
	return rows, *diags, err
}

func TestAreasThatBeginWithAnELFHeaderAreListed(t *testing.T) {
	c := newELFCase()
	c.process(100)
	rows, diags, err := c.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []ELF{
		{PID: 100, Process: "tool", StartAddress: imageBase, EndAddress: imageBase + 0x2000, Path: "/usr/bin/tool", PathRead: true},
		{PID: 100, Process: "tool", StartAddress: vdsoBase, EndAddress: vdsoBase + 0x1000, PathRead: true},
	}
	if !slices.Equal(rows, want) {
		t.Errorf("rows\n %+v\nwant\n %+v", rows, want)
	}
	if len(diags) != 0 {
		t.Errorf("diagnostics %q", diags)
	}
	if _, _, err := c.run(t, map[string]any{OptionDump: true}); err != ErrNoOutputDir {
		t.Errorf("dump without a directory: %v", err)
	}
}

func TestADumpPlacesEachSegmentAtItsFileOffset(t *testing.T) {
	c := newELFCase()
	space := c.process(100)
	space.Unmap(imageBase + 0x1000)
	dir := t.TempDir()
	rows, diags, err := c.run(t, map[string]any{OptionDump: true, tools.OptionOutputDir: dir})
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if rows[0].Artefact != "image.pid100.0x0000555500000000.tool.elf" {
		t.Errorf("artefact %q", rows[0].Artefact)
	}
	b, err := os.ReadFile(filepath.Join(dir, rows[0].Artefact))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0x2080 || !bytes.HasPrefix(b, []byte("\x7fELF")) {
		t.Fatalf("file of %#x bytes", len(b))
	}
	if !bytes.Equal(b[0x1000:0x1100], make([]byte, 0x100)) || !bytes.Equal(b[0x2000:], bytes.Repeat([]byte{0xdd}, 0x80)) {
		t.Error("segment bytes are not at their file offsets")
	}
	if len(diags) != 1 || !strings.Contains(diags[0], "zero-filled") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestAnImageOverTheDumpLimitIsNotWritten(t *testing.T) {
	c := newELFCase()
	c.process(100)
	dir := t.TempDir()
	rows, diags, err := c.run(t, map[string]any{OptionDump: true, tools.OptionOutputDir: dir,
		tools.OptionMaxDumpSize: uint64(0x1000)})
	if err != nil || len(rows) != 2 || rows[0].Artefact != "" || rows[1].Artefact == "" {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if len(diags) != 1 || !strings.Contains(diags[0], "1 images not written") {
		t.Errorf("diagnostics %q", diags)
	}
}

func FuzzLayout(f *testing.F) {
	f.Add(uint64(0), uint64(0), uint64(0x1100), uint64(0x2000), uint64(0x3000), uint64(0x80), uint16(56))
	f.Add(^uint64(0), uint64(0), uint64(2), uint64(0), uint64(0), uint64(0), uint16(0))
	f.Fuzz(func(t *testing.T, off1, va1, size1, off2, va2, size2 uint64, phent uint16) {
		m := lt.NewMemory()
		lt.ELF64(m, imageBase, []lt.Segment{{Type: 1, Offset: off1, Vaddr: va1, Filesz: size1},
			{Type: 1, Offset: off2, Vaddr: va2, Filesz: size2}}, 0, 0)
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], phent)
		m.Write(imageBase+54, b[:])
		e, ok, err := linuxobj.ParseELF(m, imageBase)
		if err != nil || !ok {
			return
		}
		p, err := layout(e, 16)
		if err != nil {
			return
		}
		for _, s := range p.segments {
			if s.offset+s.size > p.size || s.offset+s.size < s.offset {
				t.Fatalf("segment %+v outside a file of %#x bytes", s, p.size)
			}
		}
	})
}
