package processidentity

import (
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const areaAt = uint64(0x7ffc0000)

type identityCase struct {
	k     *lt.Kernel
	fs    *lt.RootFS
	procs *lt.Processes
	tasks []uint64
}

func newIdentityCase() *identityCase {
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	lt.AddExeFile(k)
	return &identityCase{k: k, fs: k.NewRootFS(), procs: k.NewProcesses()}
}

func (c *identityCase) process(pid int32, comm string, exe uint64, area string) uint64 {
	end := areaAt + uint64(len(area))
	task, mm, space := c.procs.Add(lt.Task{PID: pid, TGID: pid, Comm: comm},
		lt.MM{ArgStart: areaAt, ArgEnd: end, EnvStart: end, EnvEnd: end + 8})
	space.Write(areaAt, []byte(area))
	space.Write(end, make([]byte, 8))
	c.k.Mem.U64(mm+lt.MMExeFile, exe)
	c.fs.Enter(task)
	c.tasks = append(c.tasks, task)
	return task
}

func (c *identityCase) run(t *testing.T, options map[string]any) (map[int64]Process, []string, error) {
	t.Helper()
	c.k.LinkTasks(c.tasks...)
	ctx, diags := c.procs.Context(options)
	rows, err := Run(ctx)
	byPID := map[int64]Process{}
	for _, r := range rows {
		byPID[r.PID] = r
	}
	return byPID, *diags, err
}

func TestTheThreeNamesAreComparedWithTheExecutable(t *testing.T) {
	c := newIdentityCase()
	bash := c.fs.File("/usr/bin/bash", 1, 100)
	gdm := c.fs.File("/usr/libexec/gdm-session-worker", 1, 100)
	gone := c.fs.File("/tmp/dropper", 0, 100)
	c.process(10, "bash", bash, "/usr/bin/bash\x00-l\x00")
	c.process(11, "kworker", bash, "sshd\x00")
	c.process(12, "gdm-session-wor", gdm, "gdm-session-worker\x00")
	c.process(13, "dropper", gone, "dropper\x00")
	c.process(14, "bash", bash, "\x00")
	rows, diags, err := c.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int64]Process{
		10: {PID: 10, Comm: "bash", ExePath: "/usr/bin/bash", ExeName: "bash", ExeRead: true,
			ArgumentName: "bash", ArgumentRead: true},
		11: {PID: 11, Comm: "kworker", ExePath: "/usr/bin/bash", ExeName: "bash", ExeRead: true,
			ArgumentName: "sshd", ArgumentRead: true, CommDiffers: true, ArgumentDiffers: true},
		12: {PID: 12, Comm: "gdm-session-wor", ExePath: "/usr/libexec/gdm-session-worker", ExeName: "gdm-session-worker",
			ExeRead: true, ArgumentName: "gdm-session-worker", ArgumentRead: true},
		13: {PID: 13, Comm: "dropper", ExePath: "/tmp/dropper (deleted)", ExeName: "dropper", ExeRead: true,
			ExeDeleted: true, ArgumentName: "dropper", ArgumentRead: true},
		14: {PID: 14, Comm: "bash", ExePath: "/usr/bin/bash", ExeName: "bash", ExeRead: true, ArgumentRead: true},
	}
	for pid, w := range want {
		if got := rows[pid]; got != w {
			t.Errorf("pid %d:\n got %+v\nwant %+v", pid, got, w)
		}
	}
	if len(diags) != 0 {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestATitleAndAKernelThreadAreShownForWhatTheyAre(t *testing.T) {
	c := newIdentityCase()
	sshd := c.fs.File("/usr/sbin/sshd", 1, 100)
	c.process(20, "sshd", sshd, "sshd\x00-D\x00")
	kthread := c.k.AddTask(lt.Task{PID: 2, TGID: 2, Comm: "kthreadd", Flags: linuxobj.PFKThread})
	c.tasks = append(c.tasks, kthread)
	rows, _, err := c.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := rows[2]; r.ExeRead || r.ArgumentRead || r.CommDiffers || r.ArgumentDiffers || r.Comm != "kthreadd" {
		t.Errorf("kernel thread %+v", r)
	}
	if r := rows[20]; r.ArgumentTitle || r.ArgumentName != "sshd" {
		t.Errorf("sshd %+v", r)
	}
}

func TestASetTitleIsMarked(t *testing.T) {
	c := newIdentityCase()
	sshd := c.fs.File("/usr/sbin/sshd", 1, 100)
	c.process(20, "sshd", sshd, "sshd: listener\x01")
	rows, _, err := c.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := rows[20]; !r.ArgumentTitle || r.ArgumentName != "sshd: listener\x01" || !r.ArgumentDiffers {
		t.Errorf("title %+v", r)
	}
}

func TestMissingPathsAndAreasAreCounted(t *testing.T) {
	c := newIdentityCase()
	bash := c.fs.File("/usr/bin/bash", 1, 100)
	c.process(30, "bash", bash, "bash\x00")
	c.process(31, "lost", c.k.Alloc(0x40)+0x100000000, "lost\x00")
	rows, diags, err := c.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := rows[31]; r.ExeRead || !r.ArgumentRead {
		t.Errorf("pid 31 %+v", r)
	}
	if len(diags) != 1 || !strings.HasPrefix(diags[0], Name+": 1 executable paths not built, first: task_struct at 0x") {
		t.Errorf("diagnostics %q", diags)
	}
}

func FuzzBaseName(f *testing.F) {
	for _, s := range []string{"/usr/bin/bash", "bash", "dir/", "", "/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		b := baseName(path)
		if strings.Contains(b, "/") || !strings.HasSuffix(path, b) {
			t.Fatalf("baseName(%q) = %q", path, b)
		}
	})
}
