package processarguments

import (
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const areaAt = uint64(0x7ffd0000)

type linuxCase struct {
	k     *lt.Kernel
	procs *lt.Processes
	tasks []uint64
}

func newLinuxCase() *linuxCase {
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	return &linuxCase{k: k, procs: k.NewProcesses()}
}

// process lays the area out at areaAt with envp starting right after it.
func (c *linuxCase) process(pid int32, area []byte) (task, mm uint64, space *lt.Memory) {
	end := areaAt + uint64(len(area))
	task, mm, space = c.procs.Add(lt.Task{PID: pid, TGID: pid, Comm: "p"},
		lt.MM{ArgStart: areaAt, ArgEnd: end, EnvStart: end, EnvEnd: end + 8})
	space.Write(areaAt, area)
	space.Write(end, make([]byte, 8))
	c.tasks = append(c.tasks, task)
	return task, mm, space
}

func (c *linuxCase) run(t *testing.T, options map[string]any) ([]ProcessCmdline, []string, error) {
	t.Helper()
	c.k.LinkTasks(c.tasks...)
	ctx, diags := c.procs.Context(options)
	rows, err := Run(ctx)
	return rows, *diags, err
}

func rowFor(rows []ProcessCmdline, pid uint64) (ProcessCmdline, bool) {
	for _, r := range rows {
		if r.PID == pid {
			return r, true
		}
	}
	return ProcessCmdline{}, false
}

func TestALinuxCommandLineIsTheArgumentAreaSplitAtNUL(t *testing.T) {
	c := newLinuxCase()
	c.process(100, []byte("bash\x00-c\x00echo hi\x00"))
	c.process(101, []byte("\xffbad\x00"))
	rows, diags, err := c.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := rowFor(rows, 100)
	if !ok || !slices.Equal(r.Arguments, []string{"bash", "-c", "echo hi"}) || r.Cmdline != "bash -c echo hi" ||
		r.CmdlineUnreadable {
		t.Errorf("pid 100: %+v", r)
	}
	if r, _ := rowFor(rows, 101); !slices.Equal(r.Arguments, []string{"�bad"}) {
		t.Errorf("pid 101: %+v", r)
	}
	if len(diags) != 0 {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestATitleOverwritingTheLastNULIsReadToItsFirstNUL(t *testing.T) {
	c := newLinuxCase()
	_, _, space := c.process(100, []byte("orig\x00arg\x00"))
	space.Write(areaAt, []byte("daemon: busy now\x00"))
	rows, _, err := c.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := rowFor(rows, 100)
	if !slices.Equal(r.Arguments, []string{"daemon: busy now"}) || r.CmdlineUnreadable {
		t.Errorf("title: %+v", r)
	}
}

func TestTasksWithoutAnArgumentAreaHaveAnEmptyCommandLine(t *testing.T) {
	c := newLinuxCase()
	kthread := c.k.AddTask(lt.Task{PID: 2, TGID: 2, Comm: "kthreadd", Flags: linuxobj.PFKThread})
	c.tasks = append(c.tasks, kthread)
	_, mm, _ := c.process(100, []byte("a\x00"))
	c.k.Mem.U64(mm+lt.FSMMEnvEnd, 0)
	_, mm, _ = c.process(101, []byte("b\x00"))
	c.k.Mem.U64(mm+lt.FSMMArgEnd, areaAt)
	rows, diags, err := c.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range []uint64{2, 100, 101} {
		if r, ok := rowFor(rows, pid); !ok || r.Cmdline != "" || r.Arguments != nil || r.CmdlineUnreadable {
			t.Errorf("pid %d: %+v (found %v)", pid, r, ok)
		}
	}
	if len(diags) != 0 {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestAnAreaThatDoesNotReadIsSaidToBeUnread(t *testing.T) {
	c := newLinuxCase()
	area := append([]byte(strings.Repeat("x", 0x1000-1)), 0)
	area = append(area, []byte("second\x00")...)
	_, _, space := c.process(100, area)
	space.Unmap(areaAt + 0x1000)
	_, mm, big := c.process(101, []byte("big\x00"))
	c.k.Mem.U64(mm+lt.FSMMArgEnd, areaAt+MaxLinuxExecArea+1)
	big.Write(areaAt+MaxLinuxExecArea, []byte{0})
	_, mm, _ = c.process(102, []byte("c\x00"))
	c.k.Mem.U64(mm+lt.FSMMPgd, c.k.Alloc(0x1000))
	rows, diags, err := c.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range []uint64{100, 101, 102} {
		if r, _ := rowFor(rows, pid); !r.CmdlineUnreadable {
			t.Errorf("pid %d not marked unread: %+v", pid, r)
		}
	}
	if len(diags) != 1 || !strings.HasPrefix(diags[0], Name+": 3 command lines not read, first: task_struct at 0x") {
		t.Errorf("diagnostics %q", diags)
	}
	if _, _, err := c.run(t, map[string]any{"strict": true}); err == nil ||
		!strings.Contains(err.Error(), "strict mode: 3 command lines not read") {
		t.Errorf("strict: %v", err)
	}
}

func TestAPartlyReadAreaKeepsTheWordsBeforeTheGap(t *testing.T) {
	c := newLinuxCase()
	area := append([]byte(strings.Repeat("y", 0x1000-3)), []byte("\x00ab")...)
	area = append(area, make([]byte, 0x1000)...)
	area = append(area, []byte("cd\x00e\x00")...)
	task, _, space := c.process(100, area)
	space.Unmap(areaAt + 0x1000)
	ctx, _ := c.procs.Context(nil)
	args, held, why, err := ReadLinuxArguments(linuxobj.New(ctx), linuxobj.Task{Addr: task})
	if err != nil || !held || why == nil || !args.Partial || len(args.Words) != 2 || args.Words[1] != "ab" {
		t.Errorf("args %+v held %v why %v err %v", args, held, why, err)
	}
}

func TestThePIDOptionNarrowsTheLinuxRows(t *testing.T) {
	c := newLinuxCase()
	c.process(100, []byte("a\x00"))
	c.process(200, []byte("b\x00"))
	rows, _, err := c.run(t, map[string]any{"pid": []uint64{200}})
	if err != nil || len(rows) != 1 || rows[0].PID != 200 || rows[0].Cmdline != "b" {
		t.Errorf("rows %+v err %v", rows, err)
	}
}

func FuzzArgumentArea(f *testing.F) {
	f.Add([]byte("bash\x00-c\x00ls\x00"), uint16(0), uint16(12), true)
	f.Add([]byte("title"), uint16(0), uint16(5), false)
	f.Fuzz(func(t *testing.T, data []byte, start, end uint16, env bool) {
		c := newLinuxCase()
		task, mm, space := c.process(100, data)
		c.k.Mem.U64(mm+lt.FSMMArgStart, areaAt+uint64(start))
		c.k.Mem.U64(mm+lt.FSMMArgEnd, areaAt+uint64(end))
		if !env {
			c.k.Mem.U64(mm+lt.FSMMEnvEnd, 0)
		}
		if len(data) > 0x1000 {
			space.Unmap(areaAt + 0x1000)
		}
		ctx, _ := c.procs.Context(nil)
		args, held, why, err := ReadLinuxArguments(linuxobj.New(ctx), linuxobj.Task{Addr: task})
		if err != nil {
			t.Fatal(err)
		}
		if !held && (why != nil || args.Words != nil) {
			t.Fatalf("no area but %+v %v", args, why)
		}
		total := 0
		for _, w := range args.Words {
			total += len(w)
		}
		if limit := 4 * (int(end) + 0x1000); total > limit {
			t.Fatalf("%d bytes of words from an area of %d", total, int(end)-int(start))
		}
	})
}
