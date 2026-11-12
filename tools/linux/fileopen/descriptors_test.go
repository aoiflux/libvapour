package fileopen

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/profiles"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func run(t *testing.T, tr *lt.Tree, options map[string]any) ([]File, []string, error) {
	t.Helper()
	ctx, diags := tr.K.Context(options)
	rows, err := Run(ctx)
	return rows, *diags, err
}

func word(t *testing.T, k *lt.Kernel, at uint64) uint64 {
	t.Helper()
	b, err := k.Mem.ReadAt(at, 8)
	if err != nil {
		t.Fatal(err)
	}
	return binary.LittleEndian.Uint64(b)
}

func TestEachSlotGivesARowWithItsPathAndStatFacts(t *testing.T) {
	tr := lt.NewTree()
	rows, diags, err := run(t, tr, nil)
	if err != nil || len(rows) != 2 || len(diags) != 0 {
		t.Fatalf("rows %+v, diags %q, err %v", rows, diags, err)
	}
	want := File{PID: 1, TID: 1, Process: "init", FD: 0, FileAddress: tr.PasswdFile, Path: "/etc/passwd",
		Device: "8:1", DeviceOK: true, InodeOK: true, Inode: 12, Type: "REG", TypeOK: true, Mode: "-rw-r--r--",
		Changed: time.Unix(1700003000, 0).UTC(), Modified: time.Unix(1700002000, 0).UTC(),
		Accessed: time.Unix(1700001000, 0).UTC(), ChangedOK: true, ModifiedOK: true, AccessedOK: true, Size: 0x1800}
	if rows[0] != want {
		t.Errorf("fd 0: %+v\nwant %+v", rows[0], want)
	}
	x := rows[1]
	if x.FD != 1 || x.Path != "/tmp/x" || x.Device != "0:30" || x.Mode != "-rw-------" || x.Size != 10 || x.PathUnresolved {
		t.Errorf("fd 1: %+v", x)
	}
}

func TestNullSlotsAreNotFiles(t *testing.T) {
	tr := lt.NewTree()
	tr.K.SetTaskFiles(tr.Task, 8, map[uint64]uint64{2: tr.XFile, 5: tr.PasswdFile})
	rows, _, err := run(t, tr, nil)
	if err != nil || len(rows) != 2 || rows[0].FD != 2 || rows[1].FD != 5 {
		t.Errorf("rows %+v, err %v; want fds 2 and 5 in slot order", rows, err)
	}
}

func TestATaskWithoutATableHasNoRows(t *testing.T) {
	tr := lt.NewTree()
	tr.K.Mem.U64(tr.Task+lt.FSTaskFiles, 0)
	rows, diags, err := run(t, tr, nil)
	if err != nil || len(rows) != 0 || len(diags) != 0 {
		t.Errorf("rows %+v, diags %q, err %v", rows, diags, err)
	}
}

func TestStatFactsAreWholeOrAbsent(t *testing.T) {
	tr := lt.NewTree()
	tr.K.Mem.U64(tr.XFile+lt.FSFileInode, lt.Base+0x7100000)
	rows, diags, err := run(t, tr, nil)
	if err != nil || len(rows) != 2 || rows[1].InodeOK || rows[1].DeviceOK || rows[1].Path != "/tmp/x" || len(diags) != 0 {
		t.Errorf("unreadable inode: rows %+v, diags %q, err %v", rows, diags, err)
	}

	tr = lt.NewTree()
	tr.K.Mem.U64(tr.XInode+lt.FSInodeSB, lt.Base+0x7200000)
	rows, diags, err = run(t, tr, nil)
	if err != nil || len(rows) != 2 || len(diags) != 0 {
		t.Fatalf("rows %+v, diags %q, err %v", rows, diags, err)
	}
	if r := rows[1]; !r.InodeOK || r.DeviceOK || r.Device != "" || r.Inode != 5 {
		t.Errorf("superblock that does not read: %+v; want the inode without a device", r)
	}
}

func TestAPathThatIsNotBuiltIsFlaggedAndCounted(t *testing.T) {
	tr := lt.NewTree()
	page := lt.Base + 0x6000000
	tr.K.Mem.Map(page, 0x1000)
	dentry := page + 0x1000 - 0x20
	tr.K.Mem.U64(dentry+lt.FSDentParent, tr.Etc)
	broken := tr.K.AddFile(dentry, tr.RootMnt+lt.FSMntVfs, tr.PasswdInode)
	tr.K.SetTaskFiles(tr.Task, 4, map[uint64]uint64{0: tr.PasswdFile, 1: broken, 2: tr.XFile})
	rows, diags, err := run(t, tr, nil)
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
	if rows[0].Path != "/etc/passwd" || rows[1].Path != "" || !rows[1].PathUnresolved || !rows[1].InodeOK || rows[2].Path != "/tmp/x" {
		t.Errorf("rows %+v; want fd 1 kept with no path and its inode", rows)
	}
	if len(diags) != 1 || !strings.HasPrefix(diags[0], Name+": file at 0x") {
		t.Errorf("diagnostics %q", diags)
	}
	if _, _, err := run(t, tr, map[string]any{"strict": true}); err == nil || !strings.Contains(err.Error(), "1 paths not built") {
		t.Errorf("strict: %v", err)
	}
}

func TestARootThatDoesNotReadLeavesEveryPathUnbuilt(t *testing.T) {
	tr := lt.NewTree()
	fs := word(t, tr.K, tr.Task+lt.FSTaskFS)
	tr.K.Mem.U64(fs+lt.FSStructRoot+8, lt.Base+0x7000000)
	rows, diags, err := run(t, tr, nil)
	if err != nil || len(rows) != 2 || !rows[0].PathUnresolved || !rows[1].PathUnresolved || len(diags) != 2 {
		t.Errorf("rows %+v, diags %q, err %v", rows, diags, err)
	}
}

func TestSlotsThatDoNotReadKeepTheRowsBeforeThem(t *testing.T) {
	tr := lt.NewTree()
	array := tr.K.SetTaskFiles(tr.Task, 0x400, map[uint64]uint64{0: tr.PasswdFile})
	tr.K.Mem.Unmap(array + 0x1000)
	rows, diags, err := run(t, tr, nil)
	if err != nil || len(rows) != 1 || rows[0].FD != 0 {
		t.Fatalf("rows %+v, err %v", rows, err)
	}
	if len(diags) != 1 || !strings.Contains(diags[0], "descriptor slots") {
		t.Errorf("diagnostics %q", diags)
	}
}

func TestEveryThreadListsItsTable(t *testing.T) {
	tr := lt.NewTree()
	thread := tr.K.AddTask(lt.Task{PID: 2, TGID: 1, Comm: "init:w"})
	tr.K.LinkThreads(tr.Task, thread)
	tr.K.Mem.U64(thread+lt.FSTaskFiles, word(t, tr.K, tr.Task+lt.FSTaskFiles))
	tr.K.Mem.U64(thread+lt.FSTaskFS, word(t, tr.K, tr.Task+lt.FSTaskFS))
	rows, _, err := run(t, tr, nil)
	if err != nil || len(rows) != 4 || rows[2].TID != 2 || rows[2].PID != 1 || rows[2].Path != "/etc/passwd" {
		t.Errorf("rows %+v, err %v", rows, err)
	}
}

func TestOptions(t *testing.T) {
	tr := lt.NewTree()
	if rows, _, err := run(t, tr, map[string]any{"pid": uint64(2)}); err != nil || len(rows) != 0 {
		t.Errorf("pid 2: %+v, err %v", rows, err)
	}
	if rows, _, err := run(t, tr, map[string]any{OptionFilesOnly: true}); err != nil || len(rows) != 2 || rows[0].Path != "/etc/passwd" {
		t.Errorf("files_only on walked paths: %+v, err %v", rows, err)
	}
	if _, _, err := run(t, tr, map[string]any{OptionFilesOnly: "maybe"}); err == nil || !strings.Contains(err.Error(), OptionFilesOnly) {
		t.Errorf("files_only of the wrong type: %v", err)
	}
}

func TestOtherProfilesAreRefused(t *testing.T) {
	tr := lt.NewTree()
	ctx, _ := tr.K.Context(nil)
	ctx.Profile = profiles.WindowsX64Profile{}
	if _, err := Run(ctx); !errors.Is(err, ErrNotLinux) {
		t.Errorf("windows profile: %v", err)
	}
}

func FuzzDescriptorSlots(f *testing.F) {
	f.Add([]byte{}, uint16(4))
	f.Add(make([]byte, 64), uint16(8))
	f.Fuzz(func(t *testing.T, slots []byte, maxFDs uint16) {
		tr := lt.NewTree()
		if maxFDs == 0 || maxFDs > 512 {
			maxFDs = 512
		}
		array := tr.K.SetTaskFiles(tr.Task, uint32(maxFDs), nil)
		if len(slots) > int(maxFDs)*8 {
			slots = slots[:int(maxFDs)*8]
		}
		tr.K.Mem.Write(array, slots)
		rows, _, err := run(t, tr, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > int(maxFDs) {
			t.Fatalf("%d rows from %d slots", len(rows), maxFDs)
		}
		for i := 1; i < len(rows); i++ {
			if rows[i].FD <= rows[i-1].FD {
				t.Fatalf("slots out of order: %+v", rows)
			}
		}
	})
}
