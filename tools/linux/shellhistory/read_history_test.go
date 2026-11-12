package shellhistory

import (
	"errors"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/tools"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	vmRead = 0x1
	rw     = vmRead | vmWrite
)

type fixture struct {
	k     *lt.Kernel
	us    *lt.UserSpaces
	fs    *lt.RootFS
	files map[string]uint64
	tasks []uint64
}

func newFixture() *fixture {
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	lt.AddExeFile(k)
	return &fixture{k: k, us: k.NewUserSpaces(16 << 20), fs: k.NewRootFS(), files: map[string]uint64{}}
}

func (f *fixture) file(path string) uint64 {
	if path == "" {
		return 0
	}
	if at, ok := f.files[path]; ok {
		return at
	}
	at := f.fs.File(path, 1, 0x1000)
	f.files[path] = at
	return at
}

const libraryArea = 0x7f0000000000

// process maps m as the heap and each library as a read-only file area.
func (f *fixture) process(pid int32, comm, exe string, m *image, flags uint64, libraries ...string) uint64 {
	pgd, as := f.us.New()
	end := m.base + uint64(len(m.buf))
	vmas := []lt.VMA{{Start: m.base, End: end, Flags: flags}}
	for i, l := range libraries {
		at := libraryArea + uint64(i)*0x10000
		vmas = append(vmas, lt.VMA{Start: at, End: at + pageSize, Flags: vmRead, File: f.file(l)})
	}
	mm := f.k.AddMM(lt.MM{PGD: pgd, StartBrk: m.base, Brk: end, VMAs: vmas})
	f.k.Mem.U64(mm+lt.MMExeFile, f.file(exe))
	for off := 0; off < len(m.buf); off += pageSize {
		pa := as.MapPageFlags(m.base+uint64(off), 0)
		f.us.PM.WriteAt(pa, m.buf[off:off+pageSize])
	}
	task := f.k.AddTask(lt.Task{PID: pid, TGID: pid, Comm: comm, MM: mm})
	f.fs.Enter(task)
	f.tasks = append(f.tasks, task)
	f.k.LinkTasks(f.tasks...)
	return task
}

func (f *fixture) run(t *testing.T, opts map[string]any) ([]Command, *[]string, error) {
	return f.runWithin(t, opts, limits.Limits{})
}

func (f *fixture) runWithin(t *testing.T, opts map[string]any, lim limits.Limits) ([]Command, *[]string, error) {
	t.Helper()
	ctx, diags := f.us.Context(opts)
	ctx.Limits = lim
	rows, err := Run(ctx)
	return rows, diags, err
}

func history() *image {
	m := newImage(2)
	a := m.entry("sudo insmod rk.ko", "#1700000000")
	b := m.entry("unset HISTFILE", "#1700000060")
	m.list(a, b)
	return m
}

func TestProcessesAreChosenByTheirFilesNotTheirNames(t *testing.T) {
	f := newFixture()
	f.process(100, "bash", "/usr/bin/bash", history(), rw)
	f.process(101, "fish", "/usr/bin/fish", history(), rw)
	f.process(102, "sh", "/usr/bin/bash", history(), rw|vmShared)
	f.process(103, "sh", "/bin/sh", history(), rw)
	f.process(104, "bash", "/usr/bin/fish", history(), rw)
	f.process(105, "kworker/0:1", "/tmp/bash", history(), rw)
	f.process(106, "python3", "/usr/bin/python3.12", history(), rw, "/usr/lib/libc.so.6", "/usr/lib64/libreadline.so.8.2")
	f.process(107, "gdb", "/usr/bin/gdb", history(), rw, "/usr/lib64/libhistory.so.8")
	f.process(108, "vim", "/usr/bin/vim", history(), rw, "/usr/lib/libreadlinex.so")
	rows, diags, err := f.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1700000000, 0).UTC()
	var want []Command
	for _, p := range []struct {
		pid                int64
		comm, exe, library string
	}{
		{100, "bash", "/usr/bin/bash", ""},
		{103, "sh", "/bin/sh", ""},
		{105, "kworker/0:1", "/tmp/bash", ""},
		{106, "python3", "/usr/bin/python3.12", "/usr/lib64/libreadline.so.8.2"},
		{107, "gdb", "/usr/bin/gdb", "/usr/lib64/libhistory.so.8"},
	} {
		want = append(want,
			Command{PID: p.pid, Process: p.comm, Executable: p.exe, Library: p.library, Index: 0,
				Command: "sudo insmod rk.ko", Timestamp: "#1700000000", CommandTime: stamp, CommandTimeOK: true},
			Command{PID: p.pid, Process: p.comm, Executable: p.exe, Library: p.library, Index: 1,
				Command: "unset HISTFILE", Timestamp: "#1700000060", CommandTime: stamp.Add(time.Minute), CommandTimeOK: true})
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v, diagnostics %q", rows, *diags)
	}
	for i := range want {
		got := rows[i]
		if got.EntryAddress < heapStart || got.EntryAddress >= heapStart+2*pageSize {
			t.Errorf("row %d entry at %#x", i, got.EntryAddress)
		}
		got.EntryAddress = 0
		if got != want[i] {
			t.Errorf("row %d\n got %+v\nwant %+v", i, got, want[i])
		}
	}
	if len(*diags) != 0 {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestADeletedBashIsStillBash(t *testing.T) {
	f := newFixture()
	exe := f.fs.File("/usr/bin/bash", 0, 0x1000)
	f.files["/usr/bin/bash"] = exe
	f.process(100, "bash", "/usr/bin/bash", history(), rw)
	rows, _, err := f.run(t, nil)
	if err != nil || len(rows) != 2 || rows[0].Executable != "/usr/bin/bash (deleted)" {
		t.Fatalf("rows %+v, %v", rows, err)
	}
}

func TestATableWithoutExeFileFallsBackToTheLibraries(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	f := &fixture{k: k, us: k.NewUserSpaces(16 << 20), fs: k.NewRootFS(), files: map[string]uint64{}}
	lt.AddExeFile(k)
	f.process(100, "bash", "/usr/bin/bash", history(), rw)
	f.process(101, "bc", "/usr/bin/bc", history(), rw, "/usr/lib/libreadline.so.8")
	mm, _ := k.Table.Struct("mm_struct")
	kept := mm.Fields[:0]
	for _, fl := range mm.Fields {
		if fl.Name != "exe_file" {
			kept = append(kept, fl)
		}
	}
	mm.Fields = kept
	k.Table.AddStruct(mm)
	rows, diags, err := f.run(t, nil)
	if err != nil || len(rows) != 2 || rows[0].PID != 101 || rows[0].Executable != "" {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	found := false
	for _, d := range *diags {
		found = found || contains(d, "exe_file not in the symbol table")
	}
	if !found {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestThePIDFilterAndTheScanCapApply(t *testing.T) {
	f := newFixture()
	f.process(100, "bash", "/usr/bin/bash", history(), rw)
	f.process(200, "bash", "/usr/bin/bash", history(), rw)
	rows, _, err := f.run(t, map[string]any{"pid": []uint64{200}})
	if err != nil || len(rows) != 2 || rows[0].PID != 200 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	f = newFixture()
	m := newImage(2)
	a := m.entry("id", "#1")
	m.next = heapStart + pageSize
	m.list(a)
	f.process(300, "bash", "/usr/bin/bash", m, rw)
	small := limits.Limits{MaxRegionScanBytes: pageSize}
	capped := map[string]any{}
	rows, diags, err := f.runWithin(t, capped, small)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range *diags {
		found = found || contains(d, "search stops at Limits.MaxRegionScanBytes")
	}
	if !found || len(rows) != 0 {
		t.Errorf("rows %+v, diagnostics %q", rows, *diags)
	}
	capped["strict"] = true
	if _, _, err := f.runWithin(t, capped, small); err == nil {
		t.Error("strict mode accepts a capped search")
	}
}

func TestOnlyLinuxIsRead(t *testing.T) {
	f := newFixture()
	ctx, _ := f.us.Context(nil)
	ctx.Profile = profiles.WindowsX64Profile{}
	if _, err := Run(ctx); !errors.Is(err, ErrNotLinux) {
		t.Errorf("a Windows profile: %v", err)
	}
	if _, err := tools.Get(Name); err != nil {
		t.Errorf("%s is not registered: %v", Name, err)
	}
}

func contains(s, part string) bool {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
