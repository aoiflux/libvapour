package mountlist

import (
	"strings"
	"testing"

	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func run(t *testing.T, tr *lt.Tree, options map[string]any) ([]Mount, []string, error) {
	t.Helper()
	ctx, diags := tr.K.Context(options)
	rows, err := Run(ctx)
	return rows, *diags, err
}

func TestEachNamespaceIsReadOnceFromItsFirstHolder(t *testing.T) {
	tr := lt.NewTree()
	other := tr.K.AddTask(lt.Task{PID: 7, TGID: 7, Comm: "sh"})
	tr.K.LinkTasks(tr.Task, other)
	tr.K.SetTaskFS(other, tr.RootMnt+lt.FSMntVfs, tr.RootDentry, tr.NS)
	rows, diags, err := run(t, tr, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Mount{
		{MntNsID: 4026531840, MntNsIDOK: true, MountAddress: tr.RootMnt, MountID: 1, ParentID: 1, MajorMinor: "8:1",
			Root: "/", MountPoint: "/", MountOptions: "rw", FSType: "ext4", FSTypeOK: true, MountSource: "/dev/sda1",
			SBOptions: "rw"},
		{MntNsID: 4026531840, MntNsIDOK: true, MountAddress: tr.TmpMnt, MountID: 2, ParentID: 1, MajorMinor: "0:30",
			Root: "/", MountPoint: "/tmp", MountOptions: "rw,nosuid,nodev", Fields: "shared:1", FSType: "tmpfs",
			FSTypeOK: true, MountSource: "tmpfs", SBOptions: "rw"},
	}
	if len(rows) != len(want) || len(diags) != 0 {
		t.Fatalf("rows %+v, diagnostics %q", rows, diags)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d %+v\nwant %+v", i, rows[i], want[i])
		}
	}
}

func TestAPIDSelectionReadsEveryTasksView(t *testing.T) {
	tr := lt.NewTree()
	other := tr.K.AddTask(lt.Task{PID: 7, TGID: 7, Comm: "sh"})
	tr.K.LinkTasks(tr.Task, other)
	tr.K.SetTaskFS(other, tr.RootMnt+lt.FSMntVfs, tr.RootDentry, tr.NS)
	rows, _, err := run(t, tr, map[string]any{"pid": "1,7"})
	if err != nil || len(rows) != 4 || !rows[0].PIDShown || rows[0].PID != 1 || rows[2].PID != 7 {
		t.Errorf("pids 1,7: %+v %v", rows, err)
	}
}

func TestAChrootedReaderSeesOnlyTheMountsBelowItsRoot(t *testing.T) {
	tr := lt.NewTree()
	tr.K.SetTaskFS(tr.Task, tr.TmpMnt+lt.FSMntVfs, tr.TmpRoot, tr.NS)
	rows, _, err := run(t, tr, nil)
	if err != nil || len(rows) != 1 || rows[0].MountID != 2 || rows[0].MountPoint != "/" {
		t.Errorf("chrooted at /tmp: %+v %v; want only the tmpfs mount, at /", rows, err)
	}
}

func TestTasksWithoutFSOrNamespaceHoldNoView(t *testing.T) {
	tr := lt.NewTree()
	tr.K.Mem.U64(tr.Task+lt.FSTaskFS, 0)
	if rows, diags, err := run(t, tr, nil); err != nil || len(rows) != 0 || len(diags) != 0 {
		t.Errorf("fs null: %+v %q %v", rows, diags, err)
	}
	tr = lt.NewTree()
	tr.K.Mem.U64(tr.Task+lt.TaskNsproxy, 0)
	if rows, diags, err := run(t, tr, nil); err != nil || len(rows) != 0 || len(diags) != 0 {
		t.Errorf("nsproxy null: %+v %q %v", rows, diags, err)
	}
}

func TestTheNamespaceFilter(t *testing.T) {
	tr := lt.NewTree()
	if rows, _, err := run(t, tr, map[string]any{OptionMntNS: "4026531841"}); err != nil || len(rows) != 0 {
		t.Errorf("another namespace: %+v %v", rows, err)
	}
	if rows, _, err := run(t, tr, map[string]any{OptionMntNS: "4026531840"}); err != nil || len(rows) != 2 {
		t.Errorf("this namespace: %+v %v", rows, err)
	}
	if _, _, err := run(t, tr, map[string]any{OptionMntNS: "x"}); err == nil || !strings.Contains(err.Error(), OptionMntNS) {
		t.Errorf("a filter that is not a number: %v", err)
	}
}

func TestTheMountsForm(t *testing.T) {
	tr := lt.NewTree()
	tr.K.Mem.U64(tr.TmpSB+lt.FSSBFlags, 1|1<<4)
	rows, _, err := run(t, tr, map[string]any{OptionMountFormat: true})
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %+v %v", rows, err)
	}
	if r := rows[1]; !r.MountFormat || r.MntOpts != "ro,sync,nosuid,nodev" || r.MountOptions != "rw,nosuid,nodev" ||
		r.SBOptions != "ro,sync" {
		t.Errorf("mounts form: %+v; want ro from the superblock, its options, then the mount's", r)
	}
	plain, _, _ := run(t, tr, nil)
	if plain[1].MountFormat || plain[1].MntOpts != "" {
		t.Errorf("mountinfo form: %+v", plain[1])
	}
	if _, _, err := run(t, tr, map[string]any{OptionMountFormat: "maybe"}); err == nil {
		t.Error("mount_format of the wrong type accepted")
	}
}

func TestPropagationTags(t *testing.T) {
	tr := lt.NewTree()
	slave := tr.K.AddMount(lt.Mount{Parent: tr.RootMnt, Mountpoint: tr.Etc, Root: tr.TmpRoot, SB: tr.TmpSB,
		Devname: "", ID: 3, Master: tr.TmpMnt})
	ns := tr.K.AddMountNamespace(4026531840, tr.RootMnt, tr.TmpMnt, slave)
	tr.K.SetTaskFS(tr.Task, tr.RootMnt+lt.FSMntVfs, tr.RootDentry, ns)
	rows, _, err := run(t, tr, nil)
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows %+v %v", rows, err)
	}
	if s := rows[2]; s.Fields != "master:1" || s.MountPoint != "/etc" || s.MountSource != "none" {
		t.Errorf("slave %+v: want master:1 alone (its dominating group is its master's), /etc, none", s)
	}
}

func TestAMountThatDoesNotReadIsCounted(t *testing.T) {
	tr := lt.NewTree()
	tr.K.Mem.U64(tr.TmpMnt+lt.FSMntVfs+lt.FSVfsSB, lt.Base+0x7300000)
	rows, diags, err := run(t, tr, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v %v", rows, err)
	}
	if len(diags) != 1 || !strings.HasPrefix(diags[0], Name+": mount at 0x") {
		t.Errorf("diagnostics %q", diags)
	}
	if _, _, err := run(t, tr, map[string]any{"strict": true}); err == nil {
		t.Error("strict mode accepted a mount that does not read")
	}
	tr = lt.NewTree()
	tr.K.Mem.U64(tr.TmpMnt+lt.FSMntVfs+lt.FSVfsSB, 0)
	if _, diags, _ := run(t, tr, nil); len(diags) != 1 || !strings.Contains(diags[0], "mnt_sb is null") {
		t.Errorf("null superblock: %q", diags)
	}
}

func TestAReaderRootThatDoesNotReadIsCounted(t *testing.T) {
	tr := lt.NewTree()
	tr.K.SetTaskFS(tr.Task, tr.RootMnt+lt.FSMntVfs, lt.Base+0x7400000, tr.NS)
	rows, diags, err := run(t, tr, nil)
	if err != nil || len(rows) != 0 || len(diags) != 1 || !strings.Contains(diags[0], "fs root") {
		t.Errorf("rows %+v, diags %q, err %v", rows, diags, err)
	}
}

func FuzzMountRecord(f *testing.F) {
	f.Add(make([]byte, 0x40))
	f.Fuzz(func(t *testing.T, b []byte) {
		tr := lt.NewTree()
		if len(b) > lt.FSMntSize {
			b = b[:lt.FSMntSize]
		}
		tr.K.Mem.Write(tr.TmpMnt, b)
		rows, _, err := run(t, tr, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 2 {
			t.Fatalf("%d rows from two mounts", len(rows))
		}
	})
}
