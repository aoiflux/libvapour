package memoryranges

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

type namedCase struct {
	k     *lt.Kernel
	fs    *lt.RootFS
	mm    uint64
	task  uint64
	namer uint64
}

func newNamedCase(t *testing.T, vmas []lt.VMA, files func(fs *lt.RootFS) []uint64) *namedCase {
	t.Helper()
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	c := &namedCase{k: k, fs: k.NewRootFS(), namer: lt.AddAreaOperations(k)}
	if files != nil {
		for i, f := range files(c.fs) {
			vmas[i].File = f
		}
	}
	c.mm = k.AddMM(lt.MM{StartBrk: 0x600000, Brk: 0x621000, StartStack: 0x7ffd1000, VMAs: vmas})
	c.task = k.AddTask(lt.Task{PID: 42, TGID: 42, Comm: "app", MM: c.mm})
	k.LinkTasks(c.task)
	c.fs.Enter(c.task)
	return c
}

func describeAreas(rows []Mapping) []string {
	var out []string
	for _, m := range rows {
		path := m.Path
		if m.PathUnreadable {
			path = "(not built)"
		}
		out = append(out, fmt.Sprintf("%d %#x-%#x %s %s %#x %d %d:%d %s", m.PID, m.Start, m.End, m.Protection, m.Type,
			m.PageOffset, m.Inode, m.Major, m.Minor, path))
	}
	return out
}

func TestLinuxAreasAreNamedAsTheMapsFileNamesThem(t *testing.T) {
	c := newNamedCase(t, []lt.VMA{
		{Start: 0x400000, End: 0x402000, Flags: 5, Pgoff: 2},
		{Start: 0x500000, End: 0x501000, Flags: 3},
		{Start: 0x600000, End: 0x621000, Flags: 3},
		{Start: 0x7f000000, End: 0x7f001000, Flags: 7},
		{Start: 0x7f002000, End: 0x7f003000, Flags: 3},
		{Start: 0x7ffd0000, End: 0x7ffd2000, Flags: 3},
		{Start: 0x7fff0000, End: 0x7fff2000, Flags: 5},
		{Start: 0x7fff4000, End: 0x7fff5000, Flags: 1},
	}, func(fs *lt.RootFS) []uint64 {
		return []uint64{fs.File("/usr/bin/app", 1, 0x10000), fs.File("/dev/shm/x", 1, 0x1000)}
	})
	c.k.NameAnonArea(c.mm, 0x500000, "pool")
	c.k.NameAnonArea(c.mm, 0x7f000000, "jit")
	c.k.NameSpecialArea(c.mm, 0x7fff0000, c.namer, "[vdso]")
	c.k.NameSpecialArea(c.mm, 0x7fff4000, c.k.Alloc(0x10), "[other]")
	ctx, diags := c.k.Context(nil)
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"42 0x400000-0x401fff r-x file 0x2000 103 8:1 /usr/bin/app",
		"42 0x500000-0x500fff rw- file 0x0 106 8:1 [anon_shmem:pool]",
		"42 0x600000-0x620fff rw- anonymous 0x0 0 0:0 [heap]",
		"42 0x7f000000-0x7f000fff rwx anonymous 0x0 0 0:0 [anon:jit]",
		"42 0x7f002000-0x7f002fff rw- anonymous 0x0 0 0:0 ",
		"42 0x7ffd0000-0x7ffd1fff rw- anonymous 0x0 0 0:0 [stack]",
		"42 0x7fff0000-0x7fff1fff r-x anonymous 0x0 0 0:0 [vdso]",
		"42 0x7fff4000-0x7fff4fff r-- anonymous 0x0 0 0:0 (not built)",
	}
	if got := describeAreas(rows); !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s\ndiags %q", strings.Join(got, "\n"), strings.Join(want, "\n"), *diags)
	}
	if !strings.Contains(strings.Join(*diags, " "), "1 memory areas whose name was not built") {
		t.Errorf("diags %q", *diags)
	}
}

func TestAnAreaWhosePathDoesNotBuildIsListedWithoutIt(t *testing.T) {
	c := newNamedCase(t, []lt.VMA{{Start: 0x400000, End: 0x401000, Flags: 5}}, func(fs *lt.RootFS) []uint64 {
		return []uint64{fs.File("/usr/bin/app", 1, 0x1000)}
	})
	file := read64(c.k, read64(c.k, c.mm+lt.FSMMMmap)+lt.FSVMAFile)
	dentry := read64(c.k, file+lt.FSFilePath+8)
	c.k.Mem.U64(dentry+lt.FSDentName+lt.FSQstrName, lt.Base+0x7400000)
	ctx, diags := c.k.Context(nil)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || !rows[0].PathUnreadable || rows[0].Path != "" || rows[0].Inode == 0 {
		t.Errorf("rows %+v, %v, diags %q", rows, err, *diags)
	}
	ctx, _ = c.k.Context(map[string]any{"strict": true})
	if _, err := Run(ctx); err != nil {
		t.Errorf("strict mode: %v; a name that does not build stays a diagnostic", err)
	}
}

func TestAreaLossesAreDiagnosticsUnlessStrict(t *testing.T) {
	c := newNamedCase(t, []lt.VMA{{Start: 0x400000, End: 0x401000, Flags: 5}, {Start: 0x300000, End: 0x301000, Flags: 5}}, nil)
	ctx, diags := c.k.Context(nil)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || !strings.Contains(strings.Join(*diags, " "), lossOrder) {
		t.Errorf("rows %d, %v, diags %q", len(rows), err, *diags)
	}
	ctx, _ = c.k.Context(map[string]any{"strict": true})
	if _, err := Run(ctx); err == nil || !strings.Contains(err.Error(), "pid 42") {
		t.Errorf("strict mode: %v", err)
	}
}

func TestOpenFilesAndMountPointsAreNamedFromTheTasksRoot(t *testing.T) {
	tr := lt.NewTree()
	ctx, _ := tr.K.Context(nil)
	lw, err := NewLinuxWalker(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := lw.OpenFileName(tr.Task, tr.XFile, false); err != nil || p != "/tmp/x" {
		t.Errorf("x = %q, %v", p, err)
	}
	for mnt, want := range map[uint64]string{tr.RootMnt: "/", tr.TmpMnt: "/tmp"} {
		if p, err := lw.MountPointPath(tr.Task, mnt); err != nil || p != want {
			t.Errorf("mount point of %#x = %q, %v; want %q", mnt, p, err, want)
		}
	}
	tr.K.Mem.U64(tr.TmpMnt+lt.FSMntParent, tr.TmpMnt)
	if p, err := lw.MountPointPath(tr.Task, tr.TmpMnt); err != nil || p != "" {
		t.Errorf("a mount the root does not reach = %q, %v", p, err)
	}

	ops := tr.K.Alloc(0x80)
	pipe := tr.K.Alloc(0x10)
	tr.K.Table.AddSymbol(symbols.Symbol{Name: "pipefs_dname", Address: pipe})
	tr.K.Mem.U64(ops+0x48, pipe)
	d := tr.K.AddDentry("", 0, tr.XInode)
	tr.K.Mem.U64(d+lt.FSDentOp, ops)
	f := tr.K.AddFile(d, tr.RootMnt+lt.FSMntVfs, tr.XInode)
	if p, err := lw.OpenFileName(tr.Task, f, false); err != nil || p != "pipe:[5]" {
		t.Errorf("pipe = %q, %v", p, err)
	}
	if p, err := lw.OpenFileName(tr.Task, f, true); err != nil || p != "" {
		t.Errorf("pipe with walkedOnly = %q, %v", p, err)
	}
	fs := read64(tr.K, tr.Task+lt.FSTaskFS)
	tr.K.Mem.U64(fs+lt.FSStructRoot+8, lt.Base+0x7500000)
	if _, err := lw.OpenFileName(tr.Task, tr.XFile, false); !IsPathUnresolved(err) {
		t.Errorf("a root that does not read: %v", err)
	}
	if IsPathUnresolved(linuxobj.ErrUnsupported) {
		t.Error("a layout error is not a path failure")
	}
}
