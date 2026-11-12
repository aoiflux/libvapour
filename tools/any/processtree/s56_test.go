package processtree

import (
	"fmt"
	"strings"
	"testing"
	"time"

	ts "github.com/aoiflux/libvapour/internal/testsupport"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const second = uint64(10_000_000)

var boot = uint64(134_000_000_000_000_000)

func shape(roots []*Entry) string {
	var b strings.Builder
	for _, e := range Flatten(roots) {
		fmt.Fprintf(&b, "%s%d ", strings.Repeat(".", e.Depth), e.PID)
	}
	return strings.TrimSpace(b.String())
}

func windowsTree(t *testing.T, procs []ts.S56Process, options map[string]any) ([]*Entry, *ts.S56Image) {
	t.Helper()
	img := ts.BuildS56Image(procs)
	for k, v := range options {
		img.Options[k] = v
	}
	roots, err := RunAny(img.Context())
	if err != nil {
		t.Fatalf("RunAny: %v", err)
	}
	return roots.([]*Entry), img
}

func proc(pid, ppid uint64, created uint64) ts.S56Process {
	return ts.S56Process{PID: pid, PPID: ppid, Name: fmt.Sprintf("p%d.exe", pid), CreateTime: created}
}

func TestChildrenHangUnderTheirParentInPIDOrder(t *testing.T) {
	roots, _ := windowsTree(t, []ts.S56Process{
		proc(4, 0, boot+50*second), proc(500, 4, boot+2*second), proc(900, 500, boot+3*second),
		proc(700, 500, boot+4*second), proc(800, 4, boot+5*second),
	}, nil)
	if got := shape(roots); got != "4 .500 ..700 ..900 .800" {
		t.Errorf("tree %q", got)
	}
}

func TestAParentCreatedAfterTheChildIsAReusedPID(t *testing.T) {
	roots, _ := windowsTree(t, []ts.S56Process{
		proc(4, 0, boot), proc(944, 4, boot+20*second), proc(1276, 944, boot+10*second),
	}, nil)
	if got := shape(roots); got != "4 .944 1276" {
		t.Fatalf("tree %q", got)
	}
	for _, e := range Flatten(roots) {
		if e.ParentPIDReused != (e.PID == 1276) {
			t.Errorf("pid %d: reused %v", e.PID, e.ParentPIDReused)
		}
		if e.PID == 1276 && (e.PPID != 944 || e.PPIDUnreadable) {
			t.Errorf("the recorded parent PID was changed: %+v", e)
		}
	}
}

func TestTheInitialSystemProcessKeepsTheChildrenTheKernelStartedBeforeIt(t *testing.T) {
	roots, _ := windowsTree(t, []ts.S56Process{proc(4, 0, boot+50*second), proc(276, 4, boot)}, nil)
	if got := shape(roots); got != "4 .276" {
		t.Errorf("tree %q", got)
	}
}

func TestASelfParentedProcessIsARootWithoutChildren(t *testing.T) {
	roots, _ := windowsTree(t, []ts.S56Process{proc(0, 0, 0), proc(4, 0, boot), proc(8, 4, boot+second)}, nil)
	if got := shape(roots); got != "0 4 .8" {
		t.Errorf("tree %q", got)
	}
}

func TestAMissingParentMakesARoot(t *testing.T) {
	roots, _ := windowsTree(t, []ts.S56Process{proc(632, 620, boot), proc(4, 0, boot)}, nil)
	if got := shape(roots); got != "4 632" {
		t.Errorf("tree %q", got)
	}
}

func TestWithTwoHoldersOfAPIDTheOneAliveAtTheChildsCreationIsTheParent(t *testing.T) {
	old := proc(100, 4, boot)
	old.ExitTime = boot + 5*second
	young := proc(100, 4, boot+20*second)
	roots, img := windowsTree(t, []ts.S56Process{proc(4, 0, boot), old, young, proc(200, 100, boot+2*second), proc(300, 100, boot+30*second)}, nil)
	var parents []uint64
	for _, e := range Flatten(roots) {
		for _, c := range e.Children {
			if c.PID == 200 || c.PID == 300 {
				parents = append(parents, e.EPROCESS)
			}
		}
	}
	want := []uint64{img.Procs[1].EPROCESS, img.Procs[2].EPROCESS}
	if len(parents) != 2 || parents[0] != want[0] || parents[1] != want[1] {
		t.Errorf("parents %x, want %x", parents, want)
	}
}

func TestACycleOfParentLinksIsBrokenAtItsFirstListedMember(t *testing.T) {
	nodes := []node{{pid: 10, ppid: 30, ppidKnown: true}, {pid: 20, ppid: 10, ppidKnown: true}, {pid: 30, ppid: 20, ppidKnown: true}}
	placed := place(nodes)
	if placed[0].parent != -1 || placed[1].parent != 0 || placed[2].parent != 1 || placed[2].depth != 2 {
		t.Errorf("placement %+v", placed)
	}
}

func TestAnUnreadableParentPIDIsARoot(t *testing.T) {
	placed := place([]node{{pid: 4, ppid: 0, ppidKnown: true}, {pid: 8, ppid: 4}})
	if placed[1].parent != -1 {
		t.Errorf("placement %+v", placed)
	}
}

func TestThePIDSetKeepsTheChainAboveASelectedProcess(t *testing.T) {
	roots, _ := windowsTree(t, []ts.S56Process{
		proc(4, 0, boot), proc(500, 4, boot+second), proc(600, 500, boot+2*second), proc(700, 4, boot+3*second),
	}, map[string]any{"pid": []uint64{600}})
	if got := shape(roots); got != "4 .500 ..600" {
		t.Errorf("tree %q", got)
	}
}

func TestWindowsDetailsComeFromTheAuditInfoAndTheProcessParameters(t *testing.T) {
	p := proc(500, 4, boot)
	p.AuditName = `\Device\HarddiskVolume3\Windows\System32\svchost.exe`
	p.ImagePath = `C:\Windows\System32\svchost.exe`
	p.CommandLine = `C:\Windows\System32\svchost.exe -k netsvcs`
	system := proc(4, 0, boot)
	system.NoPeb = true
	paged := proc(600, 4, boot+second)
	_, img := windowsTree(t, []ts.S56Process{system, p, paged}, nil)
	img.UserOf(600).Unmap(ts.S56PebVA)
	roots, err := Run(img.Context())
	if err != nil {
		t.Fatal(err)
	}
	byPID := map[uint64]*Entry{}
	for _, e := range Flatten(roots) {
		byPID[e.PID] = e
	}
	e := byPID[500]
	if e.AuditImageName != p.AuditName || e.AuditImageNameUnreadable || e.ImagePathName != p.ImagePath ||
		e.CommandLine != p.CommandLine || e.ParametersUnreadable || e.CommandLineUnreadable || e.ImagePathNameUnreadable {
		t.Errorf("details %+v", e)
	}
	if s := byPID[4]; s.AuditImageName != "" || s.AuditImageNameUnreadable || s.ParametersUnreadable {
		t.Errorf("a process without a PEB or audit name was flagged: %+v", s)
	}
	if !byPID[600].ParametersUnreadable || !byPID[600].CommandLineUnreadable {
		t.Errorf("a paged-out PEB was not flagged: %+v", byPID[600])
	}
}

func TestRowsKeepTheProcessListColumns(t *testing.T) {
	roots, img := windowsTree(t, []ts.S56Process{proc(4, 0, boot)}, nil)
	e := roots[0]
	want := time.Unix(int64(boot/second)-11644473600, 0).UTC()
	if e.EPROCESS != img.Procs[0].EPROCESS || e.Name != "p4.exe" || !e.CreateTime.Equal(want) {
		t.Errorf("row %+v", e)
	}
}

func TestLinuxTasksHangUnderTheirRealParent(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	initProc := k.AddTask(lt.Task{PID: 1, TGID: 1, Comm: "systemd"})
	leader := k.AddTask(lt.Task{PID: 100, TGID: 100, Comm: "leader", Parent: initProc})
	thread := k.AddTask(lt.Task{PID: 150, TGID: 100, Comm: "leader", Parent: initProc})
	child := k.AddTask(lt.Task{PID: 200, TGID: 200, Comm: "child", Parent: thread})
	k.LinkTasks(initProc, leader, child)
	ctx, _ := k.Context(map[string]any{"pid": []uint64{200}})
	roots, err := Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := shape(roots); got != "1 .100 ..200" {
		t.Errorf("tree %q", got)
	}
	if c := Flatten(roots)[2]; c.PPID != 100 || c.PPIDUnreadable || c.Name != "child" {
		t.Errorf("child %+v", c)
	}
}

func FuzzTree(f *testing.F) {
	f.Add([]byte{4, 0, 8, 4, 12, 8})
	f.Add([]byte{1, 2, 2, 1})
	f.Add([]byte{0, 0, 4, 0, 4, 4})
	f.Fuzz(func(t *testing.T, data []byte) {
		var nodes []node
		for i := 0; i+2 < len(data); i += 3 {
			nodes = append(nodes, node{pid: uint64(data[i]), ppid: uint64(data[i+1]), ppidKnown: data[i+2]&1 == 0,
				created: time.Unix(int64(data[i+2]>>1), 0)})
		}
		placed := place(nodes)
		seen := make([]int, len(nodes))
		var walk func(i, depth int)
		walk = func(i, depth int) {
			seen[i]++
			if placed[i].depth != depth {
				t.Fatalf("node %d at depth %d, want %d", i, placed[i].depth, depth)
			}
			if nodes[i].selfParented() && len(placed[i].children) > 0 {
				t.Fatalf("self-parented node %d has children", i)
			}
			for _, c := range placed[i].children {
				if placed[c].parent != i {
					t.Fatalf("child %d does not name %d as parent", c, i)
				}
				walk(c, depth+1)
			}
		}
		for i := range placed {
			if placed[i].parent < 0 {
				walk(i, 0)
			}
		}
		for i, n := range seen {
			if n != 1 {
				t.Fatalf("node %d placed %d times", i, n)
			}
		}
	})
}
