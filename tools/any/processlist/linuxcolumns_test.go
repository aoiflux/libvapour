package processlist

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const unmapped = 0xffff888300000000

type linuxTasks struct {
	k                          *lt.Kernel
	init, kthread, srv, worker uint64
}

func newLinuxTasks() linuxTasks {
	k := lt.NewKernel(1700000000, 0)
	mm := k.Alloc(0x100)
	cred := k.AddCred(lt.Cred{UID: 1000, GID: 1000, EUID: 0, EGID: 27})
	var s linuxTasks
	s.k = k
	s.init = k.AddTask(lt.Task{PID: 1, TGID: 1, Comm: "systemd", MM: k.Alloc(0x100), StartNS: 2e9})
	s.kthread = k.AddTask(lt.Task{PID: 2, TGID: 2, Comm: "kthreadd", Flags: linuxobj.PFKThread})
	s.srv = k.AddTask(lt.Task{PID: 300, TGID: 300, Comm: "server", Parent: s.init, Cred: cred, MM: mm, StartNS: 5_000_001_500})
	s.worker = k.AddTask(lt.Task{PID: 301, TGID: 300, Comm: "worker", Parent: s.init, Cred: cred, MM: mm})
	k.LinkTasks(s.init, s.kthread, s.srv)
	k.LinkThreads(s.srv, s.worker)
	return s
}

func (s linuxTasks) rows() []Process {
	return []Process{
		{PID: 1, Name: "systemd", EPROCESS: s.init},
		{PID: 2, Name: "kthreadd", EPROCESS: s.kthread},
		{PID: 300, Name: "server", EPROCESS: s.srv},
	}
}

func TestLinuxColumnsComeFromEachTask(t *testing.T) {
	s := newLinuxTasks()
	ctx, diags := s.k.Context(nil)
	rows, err := linuxTool(ctx, s.rows())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || len(*diags) != 0 {
		t.Fatalf("rows %+v, diagnostics %q; want the three processes, no diagnostics", rows, *diags)
	}
	c := rows[2].Linux
	if !c.Read || c.PID != 300 || c.TID != 300 || c.PPID != 1 || c.Comm != "server" || c.Thread {
		t.Errorf("server columns %+v", c)
	}
	if !c.CredsRead || c.UID != 1000 || c.GID != 1000 || c.EUID != 0 || c.EGID != 27 {
		t.Errorf("server IDs %+v", c)
	}
	if want := time.Date(2023, 11, 14, 22, 13, 25, 1500, time.UTC); !c.CreationTime.Equal(want) || c.CreationTimeErr != nil {
		t.Errorf("server created %v (%v), want %v", c.CreationTime, c.CreationTimeErr, want)
	}
	if rows[0].Linux.PPID != 0 || rows[1].Linux.Comm != "kthreadd" {
		t.Errorf("systemd %+v, kthreadd %+v", rows[0].Linux, rows[1].Linux)
	}
}

func TestThreadsFollowTheirProcessAndDecorationMarksRoles(t *testing.T) {
	s := newLinuxTasks()
	ctx, _ := s.k.Context(map[string]any{OptionThreads: true, OptionDecorateComm: "true"})
	rows, err := linuxTool(ctx, s.rows())
	if err != nil {
		t.Fatal(err)
	}
	var comms []string
	var pids []uint64
	for _, r := range rows {
		comms = append(comms, r.Linux.Comm)
		pids = append(pids, r.PID)
	}
	if !slices.Equal(comms, []string{"systemd", "[kthreadd]", "server", "{worker}"}) || !slices.Equal(pids, []uint64{1, 2, 300, 301}) {
		t.Errorf("comms %q pids %v", comms, pids)
	}
	if w := rows[3]; !w.Linux.Thread || w.Linux.PID != 300 || w.Linux.TID != 301 || w.Linux.PPID != 1 ||
		w.Name != "worker" || w.EPROCESS != s.worker {
		t.Errorf("worker row %+v", w)
	}
}

func TestAnOptionOfTheWrongTypeIsRefused(t *testing.T) {
	s := newLinuxTasks()
	for _, key := range []string{OptionThreads, OptionDecorateComm} {
		ctx, _ := s.k.Context(map[string]any{key: "maybe"})
		if _, err := linuxTool(ctx, s.rows()); err == nil || !strings.Contains(err.Error(), Name) {
			t.Errorf("%s = maybe: %v", key, err)
		}
	}
}

func TestMarkedFailuresAreDiagnosticsEvenInStrictMode(t *testing.T) {
	s := newLinuxTasks()
	for _, task := range []uint64{s.init, s.srv} {
		s.k.Mem.U64(task+lt.TaskRealCred, unmapped)
	}
	ctx, diags := s.k.Context(map[string]any{"strict": true})
	rows, err := linuxTool(ctx, s.rows())
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Linux.CredsRead || rows[2].Linux.CredsRead || !rows[1].Linux.CredsRead || !rows[2].Linux.Read {
		t.Errorf("rows %+v", rows)
	}
	want := []string{
		Name + ": task at 0x" + hex(s.init) + ": credentials do not read: ",
		Name + ": 1 more tasks: credentials do not read",
	}
	if len(*diags) != 2 || !strings.HasPrefix((*diags)[0], want[0]) || (*diags)[1] != want[1] {
		t.Errorf("diagnostics %q, want %q", *diags, want)
	}
}

func TestAnUnreadParentIsMarkedInTheRow(t *testing.T) {
	s := newLinuxTasks()
	s.k.Mem.U64(s.srv+lt.TaskRealParent, unmapped)
	ctx, diags := s.k.Context(map[string]any{"strict": true})
	rows, err := linuxTool(ctx, s.rows())
	if err != nil {
		t.Fatal(err)
	}
	if r := rows[2].Linux; !r.Read || r.PPIDRead || r.PPID != 0 {
		t.Errorf("srv row %+v", r)
	}
	if r := rows[0].Linux; !r.PPIDRead || r.PPID != 0 {
		t.Errorf("init row %+v: a parent of 0 that read is marked read", r)
	}
	if len(*diags) != 1 || !strings.HasPrefix((*diags)[0], Name+": task at 0x"+hex(s.srv)+": parent does not read: ") {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestUnmarkedFailuresAreReportedAndRefusedInStrictMode(t *testing.T) {
	s := newLinuxTasks()
	rows := append(s.rows(), Process{PID: 9, Name: "gone", EPROCESS: unmapped})

	ctx, diags := s.k.Context(nil)
	got, err := linuxTool(ctx, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[3].Linux.Read || got[3].Linux.Unread == nil || got[3].Linux.PPIDRead {
		t.Errorf("rows %+v", got)
	}
	if joined := strings.Join(*diags, "\n"); !strings.Contains(joined, "task at 0x"+hex(unmapped)+": columns do not read") {
		t.Errorf("diagnostics %q", *diags)
	}

	ctx, _ = s.k.Context(map[string]any{"strict": true})
	if _, err := linuxTool(ctx, rows); err == nil || !strings.HasPrefix(err.Error(), Name+": strict mode: task at 0x"+hex(unmapped)+": columns do not read") {
		t.Errorf("strict: %v", err)
	}
}

func TestABrokenThreadListIsReported(t *testing.T) {
	s := newLinuxTasks()
	s.k.Mem.U64(s.worker+lt.TaskThreadNode, unmapped)
	ctx, diags := s.k.Context(map[string]any{OptionThreads: true})
	rows, err := linuxTool(ctx, s.rows())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 || !strings.Contains(strings.Join(*diags, "\n"), "task at 0x"+hex(s.srv)+": thread list ends early: after 2 threads") {
		t.Errorf("rows %d, diagnostics %q", len(rows), *diags)
	}
	ctx, _ = s.k.Context(map[string]any{OptionThreads: true, "strict": true})
	if _, err := linuxTool(ctx, s.rows()); err == nil {
		t.Error("strict mode took a broken thread list")
	}
}

func hex(v uint64) string { return strconv.FormatUint(v, 16) }
