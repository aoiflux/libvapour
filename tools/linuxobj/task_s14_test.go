package linuxobj_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func taskKernel(t *testing.T, k *lt.Kernel) *linuxobj.Kernel {
	t.Helper()
	ctx, _ := k.Context(nil)
	return linuxobj.New(ctx)
}

func TestIdentityIsPIDTGIDAndTheRealParentsTGID(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	parent := k.AddTask(lt.Task{PID: 812, TGID: 800, Comm: "worker"})
	child := k.AddTask(lt.Task{PID: 4242, TGID: 4240, Comm: "child", Parent: parent})
	orphan := k.AddTask(lt.Task{PID: 7, TGID: 7, Comm: "orphan"})
	k.Mem.U64(orphan+lt.TaskRealParent, 0)
	lost := k.AddTask(lt.Task{PID: 8, TGID: 8, Comm: "lost"})
	k.Mem.U64(lost+lt.TaskRealParent, 0xffff888300000000)
	k.Mem.U32(k.InitTask+lt.TaskTGID, 0)
	kern := taskKernel(t, k)

	task := linuxobj.Task{Addr: child}
	if tid, err := kern.PID(task); err != nil || tid != 4242 {
		t.Errorf("PID = %d, %v; want the task's pid 4242", tid, err)
	}
	if pid, err := kern.TGID(task); err != nil || pid != 4240 {
		t.Errorf("TGID = %d, %v; want 4240", pid, err)
	}
	if ppid, err := kern.ParentPID(task); err != nil || ppid != 800 {
		t.Errorf("ParentPID = %d, %v; want the parent's tgid 800, not its pid 812", ppid, err)
	}
	if ppid, err := kern.ParentPID(linuxobj.Task{Addr: parent}); err != nil || ppid != 0 {
		t.Errorf("a child of init_task: ParentPID = %d, %v; want 0", ppid, err)
	}
	if ppid, err := kern.ParentPID(linuxobj.Task{Addr: orphan}); err != nil || ppid != 0 {
		t.Errorf("a null real_parent: ParentPID = %d, %v; want 0 and no error", ppid, err)
	}
	if _, err := kern.ParentPID(linuxobj.Task{Addr: lost}); err == nil {
		t.Error("a real_parent that does not read gave no error")
	}
	if _, err := kern.PID(linuxobj.Task{Addr: 0xffff888300000000}); err == nil {
		t.Error("an unmapped task read a pid")
	}
}

func TestATaskFoundElsewhereReadsItsOwnMembersThroughItsReader(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	parent := k.AddTask(lt.Task{PID: 50, TGID: 50, Comm: "parent"})
	task := k.AddTask(lt.Task{PID: 60, TGID: 60, Comm: "scanned", Parent: parent})
	raw, err := k.Mem.ReadAt(task, lt.TaskSize)
	if err != nil {
		t.Fatal(err)
	}
	phys := &lt.Flat{Buf: append(make([]byte, 0x1000), raw...)}
	k.Mem.U32(task+lt.TaskPID, 61)
	f, err := taskKernel(t, k).TaskFields(linuxobj.Task{Addr: 0x1000, In: phys}, false)
	if err != nil {
		t.Fatal(err)
	}
	if f.Offset != 0x1000 || f.TID != 60 || f.PID != 60 || f.PPID != 50 || f.Comm != "scanned" {
		t.Errorf("got %+v, want offset 0x1000, tid 60 from the physical copy, ppid 50 through kernel space", f)
	}
}

func TestCommStopsAtTheFirstNUL(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	kern := taskKernel(t, k)
	task := k.AddTask(lt.Task{PID: 9, TGID: 9})
	for _, c := range []struct {
		raw  string
		want string
	}{
		{"bash\x00", "bash"},
		{"sh\x00old-name\x00\x00\x00\x00", "sh"},
		{"\x00stale", ""},
		{"0123456789abcdef", "0123456789abcdef"},
		{"\xff\x01tab\tx\x00", "\xff\x01tab\tx"},
	} {
		comm := make([]byte, linuxobj.TaskCommLen)
		copy(comm, c.raw)
		k.Mem.Write(task+lt.TaskComm, comm)
		got, err := kern.Comm(linuxobj.Task{Addr: task})
		if err != nil || got != c.want {
			t.Errorf("comm bytes %q: got %q, %v; want %q", c.raw, got, err, c.want)
		}
	}
}

func TestKernelThreadIsTheFlagNotAMissingMM(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	mm := k.AddMM(lt.MM{PGD: k.Alloc(0x1000)})
	adopted := k.AddTask(lt.Task{PID: 30, TGID: 30, Comm: "kworker", Flags: linuxobj.PFKThread, MM: mm})
	exiting := k.AddTask(lt.Task{PID: 31, TGID: 31, Comm: "exiting", Flags: 0x4})
	kern := taskKernel(t, k)
	if kt, err := kern.IsKernelThread(linuxobj.Task{Addr: adopted}); err != nil || !kt {
		t.Errorf("a kernel thread holding an mm: %v, %v", kt, err)
	}
	if kt, err := kern.IsKernelThread(linuxobj.Task{Addr: exiting}); err != nil || kt {
		t.Errorf("an exiting user task with no mm: %v, %v", kt, err)
	}
}

func TestDecorationMarksKernelThreadsAndNonLeaders(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	kthread := k.AddTask(lt.Task{PID: 2, TGID: 2, Comm: "kthreadd", Flags: linuxobj.PFKThread})
	leader := k.AddTask(lt.Task{PID: 70, TGID: 70, Comm: "server"})
	thread := k.AddTask(lt.Task{PID: 71, TGID: 70, Comm: "pool"})
	kern := taskKernel(t, k)
	for _, c := range []struct {
		task       uint64
		plain, dec string
	}{{kthread, "kthreadd", "[kthreadd]"}, {leader, "server", "server"}, {thread, "pool", "{pool}"}} {
		for _, decorate := range []bool{false, true} {
			f, err := kern.TaskFields(linuxobj.Task{Addr: c.task}, decorate)
			want := c.plain
			if decorate {
				want = c.dec
			}
			if err != nil || f.Name != want || f.Comm != c.plain {
				t.Errorf("decorate %v: name %q comm %q (%v); want %q and %q", decorate, f.Name, f.Comm, err, want, c.plain)
			}
		}
	}
}

func TestColumnCredentialsAreTheObjectiveOnes(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	acting := k.AddCred(lt.Cred{UID: 0, GID: 0, EUID: 0, EGID: 0})
	real := k.AddCred(lt.Cred{UID: 1000, GID: 1001, EUID: 0xfffffffe, EGID: 27})
	task := k.AddTask(lt.Task{PID: 40, TGID: 40, Comm: "su", Cred: acting})
	k.Mem.U64(task+lt.TaskRealCred, real)
	nullCreds := k.AddTask(lt.Task{PID: 41, TGID: 41, Comm: "a"})
	k.Mem.U64(nullCreds+lt.TaskRealCred, 0)
	lostCreds := k.AddTask(lt.Task{PID: 42, TGID: 42, Comm: "b"})
	k.Mem.U64(lostCreds+lt.TaskRealCred, 0xffff888300000000)
	kern := taskKernel(t, k)

	f, err := kern.TaskFields(linuxobj.Task{Addr: task}, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := (linuxobj.CredIDs{UID: 1000, GID: 1001, EUID: 0xfffffffe, EGID: 27}); !f.CredsRead || f.Creds != want || f.CredsErr != nil {
		t.Errorf("creds %+v read %v (%v), want %+v from real_cred, unsigned", f.Creds, f.CredsRead, f.CredsErr, want)
	}
	if cred, ok, err := kern.TaskCred(linuxobj.Task{Addr: task}); err != nil || !ok || cred != acting {
		t.Errorf("TaskCred = %#x %v %v, want the subjective cred %#x", cred, ok, err, acting)
	}
	if v, err := kern.CredValue(real, "egid"); err != nil || v != 27 {
		t.Errorf("CredValue egid = %d, %v", v, err)
	}

	n, err := kern.TaskFields(linuxobj.Task{Addr: nullCreds}, false)
	if err != nil || n.CredsRead || !errors.Is(n.CredsErr, linuxobj.ErrNoCredentials) || n.Creds != (linuxobj.CredIDs{}) {
		t.Errorf("a null real_cred: %+v, %v", n, err)
	}
	l, err := kern.TaskFields(linuxobj.Task{Addr: lostCreds}, false)
	if err != nil || l.CredsRead || l.CredsErr == nil || l.TID != 42 {
		t.Errorf("a real_cred that does not read must still give the task: %+v, %v", l, err)
	}
	k.Mem.U64(lostCreds+lt.TaskCred, 0xffff888300000000)
	if _, ok, err := kern.TaskCred(linuxobj.Task{Addr: lostCreds}); ok || err != nil {
		t.Errorf("an unreadable cred: ok %v err %v; want not usable, no error", ok, err)
	}
	k.Mem.U64(lostCreds+lt.TaskCred, 0)
	if _, ok, err := kern.TaskCred(linuxobj.Task{Addr: lostCreds}); ok || err != nil {
		t.Errorf("a null cred: ok %v err %v", ok, err)
	}
}

func TestAnIDTypedAsAPlainIntegerIsReadDirectly(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	st, err := k.Table.Struct("cred")
	if err != nil {
		t.Fatal(err)
	}
	for i := range st.Fields {
		if st.Fields[i].Name == "uid" {
			st.Fields[i].Type = symbols.TypeRef{Name: "unsigned int"}
		}
	}
	k.Table.AddStruct(st)
	cred := k.AddCred(lt.Cred{UID: 0x80000001, GID: 5})
	kern := taskKernel(t, k)
	if v, err := kern.CredValue(cred, "uid"); err != nil || v != 0x80000001 {
		t.Errorf("plain uid = %#x, %v", v, err)
	}
	if v, err := kern.CredValue(cred, "gid"); err != nil || v != 5 {
		t.Errorf("kgid_t gid = %d, %v", v, err)
	}
	if _, err := kern.CredValue(cred, "fsuid"); err == nil {
		t.Error("a member the table lacks gave a value")
	}
}

func TestSummaryKeepsTheTaskWhenItsParentDoesNotRead(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	task := k.AddTask(lt.Task{PID: 5, TGID: 5, Comm: "x"})
	k.Mem.U64(task+lt.TaskRealParent, 0xffff888300000000)
	f, err := taskKernel(t, k).TaskFields(linuxobj.Task{Addr: task}, false)
	if err != nil || f.ParentErr == nil || f.PPID != 0 || f.TID != 5 || !f.CredsRead {
		t.Errorf("got %+v, %v", f, err)
	}
	if _, err := taskKernel(t, k).TaskFields(linuxobj.Task{Addr: 0xffff888300000000}, false); err == nil {
		t.Error("a task that does not read gave a summary")
	}
}

func spaceKernel() (*lt.Kernel, uint64) {
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	return k, k.Alloc(0x1000)
}

func withTables(k *lt.Kernel, tables map[uint64]uint64) *linuxobj.Kernel {
	ctx, _ := k.Context(nil)
	ctx.Memory = &lt.Translating{Memory: k.Mem, Tables: tables}
	ctx.ProcessMemory = func(dtb uint64) (memory.MemoryReader, error) {
		if dtb == 0x9000 {
			return nil, errors.New("no space here")
		}
		return lt.NewMemory(), nil
	}
	return linuxobj.New(ctx)
}

func TestTheRootIsWhereThePGDTranslates(t *testing.T) {
	k, pgd := spaceKernel()
	mm := k.AddMM(lt.MM{PGD: pgd})
	user := k.AddTask(lt.Task{PID: 1, TGID: 1, Comm: "init", MM: mm})
	kern := withTables(k, map[uint64]uint64{pgd: 0x5000})
	if dtb, ok, why, err := kern.TaskDTB(linuxobj.Task{Addr: user}); err != nil || !ok || why != nil || dtb != 0x5000 {
		t.Errorf("TaskDTB = %#x %v %v %v", dtb, ok, why, err)
	}
	layer, ok, why, err := kern.ProcessLayer(linuxobj.Task{Addr: user})
	if err != nil || !ok || why != nil || layer.DTB != 0x5000 || layer.Reader == nil {
		t.Errorf("ProcessLayer = %+v %v %v %v", layer, ok, why, err)
	}
}

func TestTasksWithNoAddressSpaceOfTheirOwnAreSilent(t *testing.T) {
	k, pgd := spaceKernel()
	mm := k.AddMM(lt.MM{PGD: pgd})
	kthread := k.AddTask(lt.Task{PID: 2, TGID: 2, Comm: "kthreadd", Flags: linuxobj.PFKThread})
	adopted := k.AddTask(lt.Task{PID: 3, TGID: 3, Comm: "kworker", Flags: linuxobj.PFKThread, MM: mm})
	exiting := k.AddTask(lt.Task{PID: 4, TGID: 4, Comm: "gone", Flags: 0x4})
	ctx, _ := k.Context(nil)
	plain := linuxobj.New(ctx)
	kern := withTables(k, map[uint64]uint64{pgd: 0x5000})
	for _, task := range []uint64{kthread, adopted, exiting} {
		for _, kk := range []*linuxobj.Kernel{kern, plain} {
			if _, ok, why, err := kk.ProcessLayer(linuxobj.Task{Addr: task}); ok || why != nil || err != nil {
				t.Errorf("task %#x: %v %v %v, want none, silently, with or without a translator", task, ok, why, err)
			}
		}
	}
}

func TestARootThatCannotBeReachedHasAReason(t *testing.T) {
	k, pgd := spaceKernel()
	unaligned := k.Alloc(0x1000)
	noSpace := k.Alloc(0x1000)
	cases := []struct {
		name string
		pgd  uint64
		want error
		text string
	}{
		{"does not translate", 0xffff888400000000, memory.ErrUnmapped, "does not translate"},
		{"misaligned", unaligned, linuxobj.ErrRootMisaligned, "root 0x5010"},
		{"null pgd", 0, nil, "pgd is null"},
		{"no process space", noSpace, nil, "no space here"},
	}
	kern := withTables(k, map[uint64]uint64{pgd: 0x5000, unaligned: 0x5010, noSpace: 0x9000})
	for _, c := range cases {
		task := k.AddTask(lt.Task{PID: 10, TGID: 10, Comm: "p", MM: k.AddMM(lt.MM{PGD: c.pgd})})
		_, ok, why, err := kern.ProcessLayer(linuxobj.Task{Addr: task})
		if ok || err != nil || why == nil || (c.want != nil && !errors.Is(why, c.want)) || !strings.Contains(why.Error(), c.text) {
			t.Errorf("%s: %v %v %v", c.name, ok, why, err)
		}
	}
	task := k.AddTask(lt.Task{PID: 11, TGID: 11, Comm: "q"})
	k.Mem.U64(task+lt.TaskMM, 0xffff888300000000)
	if _, ok, why, err := kern.ProcessLayer(linuxobj.Task{Addr: task}); ok || err != nil || why == nil {
		t.Errorf("an mm that does not read: %v %v %v", ok, why, err)
	}
}

func TestNoTranslatorIsAnErrorOnlyForATaskWithAnMM(t *testing.T) {
	k, pgd := spaceKernel()
	user := k.AddTask(lt.Task{PID: 1, TGID: 1, Comm: "init", MM: k.AddMM(lt.MM{PGD: pgd})})
	kern := taskKernel(t, k)
	if _, _, _, err := kern.ProcessLayer(linuxobj.Task{Addr: user}); !errors.Is(err, linuxobj.ErrNoTranslator) {
		t.Errorf("ProcessLayer: %v", err)
	}
	if _, _, _, err := kern.TaskDTB(linuxobj.Task{Addr: user}); !errors.Is(err, linuxobj.ErrNoTranslator) {
		t.Errorf("TaskDTB: %v", err)
	}
}

func TestPIDSkipKeepsTheProcessesInTheSet(t *testing.T) {
	k := lt.NewKernel(1700000000, 0)
	a := k.AddTask(lt.Task{PID: 100, TGID: 100, Comm: "a"})
	b := k.AddTask(lt.Task{PID: 200, TGID: 200, Comm: "b"})
	k.LinkTasks(a, b)
	ctx, _ := k.Context(map[string]any{"pid": []uint64{200}})
	kern := linuxobj.New(ctx)
	list, err := kern.Walker().Tasks(false, kern.PIDSkip(ctx.PIDs()))
	if err != nil || len(list.Tasks) != 1 || list.Tasks[0] != b {
		t.Errorf("filtered walk %+v, %v; want only pid 200", list.Tasks, err)
	}
	all, _ := k.Context(nil)
	if kern.PIDSkip(all.PIDs()) != nil {
		t.Error("an empty PID set built a filter")
	}
}
