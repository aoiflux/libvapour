package librarylist

import (
	"slices"
	"strings"
	"testing"

	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	exeBase = uint64(0x555500000000)
	libBase = uint64(0x7f0000000000)
	debugAt = uint64(0x555500100000)
	mapAt   = uint64(0x555500200000)
)

type libraryCase struct {
	k     *lt.Kernel
	fs    *lt.RootFS
	procs *lt.Processes
	tasks []uint64
}

func newLibraryCase() *libraryCase {
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	lt.AddExeFile(k)
	return &libraryCase{k: k, fs: k.NewRootFS(), procs: k.NewProcesses()}
}

func (c *libraryCase) process(pid int32, comm string, areas ...lt.VMA) *lt.Memory {
	task, _, space := c.procs.Add(lt.Task{PID: pid, TGID: pid, Comm: comm}, lt.MM{VMAs: areas})
	c.fs.Enter(task)
	c.tasks = append(c.tasks, task)
	return space
}

func (c *libraryCase) run(t *testing.T, options map[string]any) ([]Library, []string, error) {
	t.Helper()
	c.k.LinkTasks(c.tasks...)
	ctx, diags := c.procs.Context(options)
	rows, err := Run(ctx)
	return rows, *diags, err
}

var exeSegments = []lt.Segment{{Type: 1, Filesz: 0x1000, Memsz: 0x1000}}

func TestTheLinkerListGivesEachNamedObjectOnce(t *testing.T) {
	c := newLibraryCase()
	space := c.process(100, "bash",
		lt.VMA{Start: exeBase, End: exeBase + 0x3000}, lt.VMA{Start: libBase, End: libBase + 0x1000})
	lt.ELF64(space, exeBase, exeSegments, 0x2000, debugAt)
	lt.ELF64(space, libBase, exeSegments, 0x800, debugAt)
	lt.LinkMap(space, debugAt, []lt.LinkEntry{
		{At: mapAt, Base: exeBase, Name: ""},
		{At: mapAt + 0x1000, Base: libBase, Name: "/lib/x86_64-linux-gnu/libc.so.6"},
		{At: mapAt + 0x2000, Base: 0, Name: "/opt/prelinked.so"},
		{At: mapAt + 0x3000, Base: 0x7f2000000000, Name: "/lib64/ld-linux-x86-64.so.2"},
	})
	other := c.process(200, "static", lt.VMA{Start: exeBase, End: exeBase + 0x1000})
	lt.ELF64(other, exeBase, exeSegments, 0, 0)
	rows, diags, err := c.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Library{
		{Process: "bash", PID: 100, BaseAddress: libBase, Path: "/lib/x86_64-linux-gnu/libc.so.6", Route: RouteLinkerList},
		{Process: "bash", PID: 100, BaseAddress: 0, Path: "/opt/prelinked.so", Route: RouteLinkerList},
		{Process: "bash", PID: 100, BaseAddress: 0x7f2000000000, Path: "/lib64/ld-linux-x86-64.so.2", Route: RouteLinkerList},
	}
	if !slices.Equal(rows, want) {
		t.Errorf("rows\n %+v\nwant\n %+v", rows, want)
	}
	if len(diags) != 0 {
		t.Errorf("diagnostics %q", diags)
	}
	if rows, _, _ := c.run(t, map[string]any{"pid": []uint64{200}}); len(rows) != 0 {
		t.Errorf("pid 200: %+v", rows)
	}
}

func TestAListCutByAReadIsSaid(t *testing.T) {
	c := newLibraryCase()
	space := c.process(100, "bash", lt.VMA{Start: exeBase, End: exeBase + 0x3000})
	lt.ELF64(space, exeBase, exeSegments, 0x2000, debugAt)
	lt.LinkMap(space, debugAt, []lt.LinkEntry{
		{At: mapAt, Base: exeBase},
		{At: mapAt + 0x1000, Base: libBase, Name: "/lib/libc.so.6"},
	})
	space.U64(mapAt+0x1000+24, 0x7f9900000000)
	rows, diags, err := c.run(t, nil)
	if err != nil || len(rows) != 1 || rows[0].Path != "/lib/libc.so.6" {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	if len(diags) != 1 || !strings.HasPrefix(diags[0], Name+": 1 library lists cut short, first: task_struct at 0x") {
		t.Errorf("diagnostics %q", diags)
	}
	if _, _, err := c.run(t, map[string]any{"strict": true}); err == nil {
		t.Error("strict mode passed a cut list")
	}
}

// The executable's header is not in the capture, so no DT_DEBUG is found and
// the images mapped from file offset 0 stand in. The library's first PT_LOAD
// sits at p_vaddr 0x1000 and offset 0, so its base is one page below the
// area.
func TestWithoutALinkerListTheMappedImagesAreListed(t *testing.T) {
	c := newLibraryCase()
	exe := c.fs.File("/usr/bin/daemon", 1, 0x4000)
	libc := c.fs.File("/usr/lib/libc.so.6", 1, 0x8000)
	data := c.fs.File("/usr/share/locale.bin", 1, 0x1000)
	lib2 := c.fs.File("/usr/lib/libz.so.1", 1, 0x2000)
	areas := []lt.VMA{
		{Start: exeBase, End: exeBase + 0x1000, File: exe},
		{Start: libBase, End: libBase + 0x2000, File: libc},
		{Start: libBase + 0x2000, End: libBase + 0x3000, File: libc, Pgoff: 2},
		{Start: libBase + 0x10000, End: libBase + 0x11000, File: data},
		{Start: libBase + 0x20000, End: libBase + 0x21000},
		{Start: libBase + 0x30000, End: libBase + 0x31000, File: lib2},
	}
	task, mm, space := c.procs.Add(lt.Task{PID: 300, TGID: 300, Comm: "daemon"}, lt.MM{VMAs: areas})
	c.fs.Enter(task)
	c.tasks = append(c.tasks, task)
	c.k.Mem.U64(mm+lt.MMExeFile, exe)
	lt.ELF64(space, libBase, []lt.Segment{{Type: 1, Vaddr: 0x1000, Filesz: 0x1000, Memsz: 0x1000}}, 0, 0)
	lt.ELF64(space, libBase+0x2000, exeSegments, 0, 0)
	space.Write(libBase+0x10000, []byte("not an image"))
	lt.ELF64(space, libBase+0x20000, exeSegments, 0, 0)
	lt.ELF64(space, libBase+0x30000, exeSegments, 0, 0)
	rows, diags, err := c.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Library{
		{Process: "daemon", PID: 300, BaseAddress: libBase - 0x1000, Path: "/usr/lib/libc.so.6", Route: RouteMappedImage},
		{Process: "daemon", PID: 300, BaseAddress: libBase + 0x30000, Path: "/usr/lib/libz.so.1", Route: RouteMappedImage},
	}
	if !slices.Equal(rows, want) {
		t.Errorf("rows\n %+v\nwant\n %+v", rows, want)
	}
	if len(diags) != 0 {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestALinkerListThatGivesNoRowFallsBackToTheMappedImages(t *testing.T) {
	c := newLibraryCase()
	lib := c.fs.File("/usr/lib/libc.so.6", 1, 0x2000)
	space := c.process(100, "bash",
		lt.VMA{Start: exeBase, End: exeBase + 0x3000}, lt.VMA{Start: libBase, End: libBase + 0x1000, File: lib})
	lt.ELF64(space, exeBase, exeSegments, 0x2000, debugAt)
	lt.ELF64(space, libBase, exeSegments, 0, 0)
	lt.LinkMap(space, debugAt, []lt.LinkEntry{{At: mapAt, Base: exeBase}})
	rows, _, err := c.run(t, nil)
	want := []Library{{Process: "bash", PID: 100, BaseAddress: libBase, Path: "/usr/lib/libc.so.6", Route: RouteMappedImage}}
	if err != nil || !slices.Equal(rows, want) {
		t.Errorf("rows %+v err %v, want %+v", rows, err, want)
	}
}

// earlyEndCase maps the executable, libc (on the list) and libz (past the
// list's end), each from its file at offset 0 (S61 4.10 step 5, O14).
func earlyEndCase(t *testing.T) (*libraryCase, *lt.Memory) {
	t.Helper()
	c := newLibraryCase()
	exe := c.fs.File("/usr/bin/daemon", 1, 0x4000)
	libc := c.fs.File("/usr/lib/libc.so.6", 1, 0x2000)
	libz := c.fs.File("/usr/lib/libz.so.1", 1, 0x2000)
	areas := []lt.VMA{
		{Start: exeBase, End: exeBase + 0x3000, File: exe},
		{Start: libBase, End: libBase + 0x1000, File: libc},
		{Start: libBase + 0x10000, End: libBase + 0x11000, File: libz},
	}
	task, mm, space := c.procs.Add(lt.Task{PID: 100, TGID: 100, Comm: "daemon"}, lt.MM{VMAs: areas})
	c.fs.Enter(task)
	c.tasks = append(c.tasks, task)
	c.k.Mem.U64(mm+lt.MMExeFile, exe)
	lt.ELF64(space, exeBase, exeSegments, 0x2000, debugAt)
	lt.ELF64(space, libBase, exeSegments, 0, 0)
	lt.ELF64(space, libBase+0x10000, exeSegments, 0, 0)
	return c, space
}

var earlyEndRows = []Library{
	{Process: "daemon", PID: 100, BaseAddress: libBase, Path: "/lib/libc.so.6", Route: RouteLinkerList},
	{Process: "daemon", PID: 100, BaseAddress: libBase + 0x10000, Path: "/usr/lib/libz.so.1", Route: RouteMappedImage},
}

func TestAListCutShortAlsoReadsTheMappedImages(t *testing.T) {
	c, space := earlyEndCase(t)
	lt.LinkMap(space, debugAt, []lt.LinkEntry{
		{At: mapAt, Base: exeBase},
		{At: mapAt + 0x1000, Base: libBase, Name: "/lib/libc.so.6"},
	})
	space.U64(mapAt+0x1000+24, 0x7f9900000000)
	rows, diags, err := c.run(t, nil)
	if err != nil || !slices.Equal(rows, earlyEndRows) {
		t.Errorf("rows\n %+v\nwant\n %+v (err %v)", rows, earlyEndRows, err)
	}
	if len(diags) != 1 || !strings.Contains(diags[0], "library lists cut short") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestAListEndingAtAZeroEntryAlsoReadsTheMappedImages(t *testing.T) {
	c, space := earlyEndCase(t)
	zero := mapAt + 0x2000
	lt.LinkMap(space, debugAt, []lt.LinkEntry{
		{At: mapAt, Base: exeBase},
		{At: mapAt + 0x1000, Base: libBase, Name: "/lib/libc.so.6"},
		{At: zero},
	})
	space.U64(zero+8, 0)
	rows, diags, err := c.run(t, nil)
	if err != nil || !slices.Equal(rows, earlyEndRows) {
		t.Errorf("rows\n %+v\nwant\n %+v (err %v)", rows, earlyEndRows, err)
	}
	if len(diags) != 0 {
		t.Errorf("diagnostics %q", diags)
	}
}

// A list that ends where the linker's list ends gives its rows alone.
func TestACompleteListLeavesTheMappedImagesUnread(t *testing.T) {
	c, space := earlyEndCase(t)
	lt.LinkMap(space, debugAt, []lt.LinkEntry{
		{At: mapAt, Base: exeBase},
		{At: mapAt + 0x1000, Base: libBase, Name: "/lib/libc.so.6"},
	})
	rows, _, err := c.run(t, nil)
	if err != nil || !slices.Equal(rows, earlyEndRows[:1]) {
		t.Errorf("rows %+v err %v", rows, err)
	}
}
