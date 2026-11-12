package linuxobj_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

func newFSKernel() *lt.Kernel {
	k := lt.NewKernel(1700000000, 0)
	lt.AddFS(k)
	return k
}

func field(name string, off uint64, typ symbols.TypeRef) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: typ}
}

func pointer(name string) symbols.TypeRef {
	return symbols.TypeRef{IsPointer: true, Element: &symbols.TypeRef{Name: name}}
}

func addMembers(t *testing.T, k *lt.Kernel, typ string, fields ...symbols.Field) {
	t.Helper()
	st, err := k.Table.Struct(typ)
	if err != nil {
		t.Fatal(err)
	}
	st.Fields = append(st.Fields, fields...)
	k.Table.AddStruct(st)
}

func TestModesAreNamedAndRenderedByTheStatBits(t *testing.T) {
	for mode, want := range map[uint64]string{
		0o100644: "-rw-r--r--", 0o104755: "-rwsr-xr-x", 0o104644: "-rwSr--r--", 0o102755: "-rwxr-sr-x",
		0o102644: "-rw-r-Sr--", 0o041777: "drwxrwxrwt", 0o041776: "drwxrwxrwT", 0o120777: "lrwxrwxrwx",
		0o140755: "srwxr-xr-x", 0o020620: "crw--w----", 0o060660: "brw-rw----", 0o010644: "prw-r--r--",
		0o000644: "?rw-r--r--", 0o170644: "?rw-r--r--",
	} {
		if got := linuxobj.FileMode(mode); got != want {
			t.Errorf("FileMode(%#o) = %q, want %q", mode, got, want)
		}
	}
	for mode, want := range map[uint64]string{0o040000: "DIR", 0o100000: "REG", 0o120000: "LNK", 0o010000: "FIFO",
		0o140000: "SOCK", 0o020000: "CHR", 0o060000: "BLK"} {
		if got, ok := linuxobj.InodeType(mode); !ok || got != want {
			t.Errorf("InodeType(%#o) = %q, %v; want %q", mode, got, ok, want)
		}
	}
	if got, ok := linuxobj.InodeType(0o170000); ok {
		t.Errorf("InodeType(0o170000) = %q, want none", got)
	}
}

func FuzzFileMode(f *testing.F) {
	for _, m := range []uint64{0, 0o100644, 0o177777, 1 << 40} {
		f.Add(m)
	}
	f.Fuzz(func(t *testing.T, mode uint64) {
		s := linuxobj.FileMode(mode)
		if len(s) != 10 {
			t.Fatalf("FileMode(%#o) = %q, want ten characters", mode, s)
		}
		if _, ok := linuxobj.InodeType(mode); ok == (s[0] == '?') {
			t.Fatalf("FileMode(%#o) = %q disagrees with InodeType", mode, s)
		}
	})
}

func TestDescriptorTablesKeepTheirOpenSlots(t *testing.T) {
	k := newFSKernel()
	task := k.AddTask(lt.Task{PID: 10, TGID: 10, Comm: "cat"})
	f0, f2 := k.AddFile(0, 0, 0), k.AddFile(0, 0, 0)
	array := k.SetTaskFiles(task, 4, map[uint64]uint64{0: f0, 2: f2})
	ctx, _ := k.Context(nil)
	kk := linuxobj.New(ctx)
	tab, ok, err := kk.TaskFDs(linuxobj.Task{Addr: task})
	if err != nil || !ok || tab.Array != array || tab.Count != 4 {
		t.Fatalf("TaskFDs = %+v, %v, %v", tab, ok, err)
	}
	files, err := kk.OpenFiles(tab)
	if want := []linuxobj.OpenFile{{FD: 0, File: f0}, {FD: 2, File: f2}}; err != nil || !slices.Equal(files, want) {
		t.Errorf("OpenFiles = %+v, %v; want %+v", files, err, want)
	}
	files, err = kk.OpenFiles(linuxobj.FDTable{Array: array, Count: 0x2000})
	if err == nil || len(files) != 2 {
		t.Errorf("a table past its memory: %d files, %v; want the 2 before the failed slot and an error", len(files), err)
	}
	bare := k.AddTask(lt.Task{PID: 11, TGID: 11, Comm: "idle"})
	if _, ok, err := kk.TaskFDs(linuxobj.Task{Addr: bare}); ok || err != nil {
		t.Errorf("no files_struct: ok %v, %v", ok, err)
	}
}

func TestInodeTimesReadBothLayouts(t *testing.T) {
	k := newFSKernel()
	in := k.AddInode(lt.Inode{Ino: 3, Mode: 0o100600, ATime: [2]int64{100, 5}, MTime: [2]int64{200, 0},
		CTime: [2]int64{300, 2_000_000_000}})
	ctx, _ := k.Context(nil)
	got, err := linuxobj.New(ctx).InodeTimes(in)
	if err != nil || !got.AccessedOK || !got.Accessed.Equal(time.Unix(100, 5)) || !got.ModifiedOK || got.ChangedOK {
		t.Errorf("timespec64 times = %+v, %v; want a and m, c rejected for its nanoseconds", got, err)
	}

	split := newFSKernel()
	st, err := split.Table.Struct("inode")
	if err != nil {
		t.Fatal(err)
	}
	var kept []symbols.Field
	for _, f := range st.Fields {
		if !strings.HasSuffix(f.Name, "time") {
			kept = append(kept, f)
		}
	}
	u64 := symbols.TypeRef{Name: "long long int"}
	u32 := symbols.TypeRef{Name: "unsigned int"}
	st.Fields = append(kept, field("i_atime_sec", 0x58, u64), field("i_mtime_sec", 0x60, u64),
		field("i_ctime_sec", 0x68, u64), field("i_atime_nsec", 0x70, u32), field("i_mtime_nsec", 0x74, u32),
		field("i_ctime_nsec", 0x78, u32))
	split.Table.AddStruct(st)
	inode := split.Alloc(lt.FSInodeSize)
	split.Mem.U64(inode+0x68, 1700000000)
	split.Mem.U32(inode+0x78, 1<<31|7)
	ctx, _ = split.Context(nil)
	got, err = linuxobj.New(ctx).InodeTimes(inode)
	if err != nil || !got.ChangedOK || !got.Changed.Equal(time.Unix(1700000000, 7)) {
		t.Errorf("split times = %+v, %v; want the change time with I_CTIME_QUERIED masked", got, err)
	}
}

func TestSuperBlocksGiveDeviceTypeAndFlags(t *testing.T) {
	k := newFSKernel()
	sb := k.AddSuperBlock(lt.SuperBlock{Dev: 8<<20 | 1, Flags: 1 | 16 | 1<<25, Type: "fuse", Subtype: "sshfs"})
	ctx, _ := k.Context(nil)
	kk := linuxobj.New(ctx)
	if s, err := kk.SuperBlockDeviceString(sb); err != nil || s != "8:1" {
		t.Errorf("device = %q, %v", s, err)
	}
	if s, ok, err := kk.SuperBlockType(sb); err != nil || !ok || s != "fuse.sshfs" {
		t.Errorf("type = %q, %v, %v", s, ok, err)
	}
	if access, opts, err := kk.SuperBlockFlags(sb); err != nil || access != "ro" || !slices.Equal(opts, []string{"sync", "lazytime"}) {
		t.Errorf("flags = %q %q, %v", access, opts, err)
	}
	if _, ok, err := kk.SuperBlockType(k.AddSuperBlock(lt.SuperBlock{})); ok || err != nil {
		t.Errorf("no s_type: ok %v, %v", ok, err)
	}
	access, opts := linuxobj.MountFlagStrings(0x40 | 0x01 | 0x04 | 0x20 | 0x80 | 0x1000)
	if access != "ro" || !slices.Equal(opts, []string{"nosuid", "noexec", "relatime", "nosymfollow"}) {
		t.Errorf("mount flags = %q %q", access, opts)
	}
}

type pathCase struct {
	tr   *lt.Tree
	kk   *linuxobj.Kernel
	root linuxobj.PathPoint
}

func newPathCase(t *testing.T, edit func(*lt.Tree)) *pathCase {
	t.Helper()
	tr := lt.NewTree()
	if edit != nil {
		edit(tr)
	}
	ctx, _ := tr.K.Context(nil)
	kk := linuxobj.New(ctx)
	root, err := kk.TaskFSRoot(linuxobj.Task{Addr: tr.Task})
	if err != nil {
		t.Fatal(err)
	}
	return &pathCase{tr: tr, kk: kk, root: root}
}

func (c *pathCase) show(t *testing.T, file uint64) linuxobj.ShownPath {
	t.Helper()
	at, err := c.kk.FileLocation(file)
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.kk.ShowPath(at, c.root)
	if err != nil {
		t.Fatalf("ShowPath: %v", err)
	}
	return s
}

func TestAPathCrossesMountsUpToTheReadersRoot(t *testing.T) {
	c := newPathCase(t, nil)
	if s := c.show(t, c.tr.PasswdFile); s.Text != "/etc/passwd" || s.End != linuxobj.EndAtRoot || s.Deleted {
		t.Errorf("passwd = %+v", s)
	}
	if s := c.show(t, c.tr.XFile); s.Text != "/tmp/x" || s.End != linuxobj.EndAtRoot || s.Mount != c.tr.RootMnt {
		t.Errorf("x on the tmpfs mount = %+v", s)
	}
	if s, err := c.kk.WalkPath(c.root, c.root); err != nil || s.Text != "/" {
		t.Errorf("the root itself = %+v, %v", s, err)
	}
	if p, err := c.kk.DentryPath(c.tr.X); err != nil || p != "/x" {
		t.Errorf("x inside its own filesystem = %q, %v", p, err)
	}
}

func TestAPathFromAChrootEndsAtThatRoot(t *testing.T) {
	c := newPathCase(t, nil)
	chroot := linuxobj.PathPoint{Mount: c.tr.RootMnt, Dentry: c.tr.Etc}
	at, _ := c.kk.FileLocation(c.tr.PasswdFile)
	if s, err := c.kk.ShowPath(at, chroot); err != nil || s.Text != "/passwd" || s.End != linuxobj.EndAtRoot {
		t.Errorf("under the chroot = %+v, %v", s, err)
	}
	at, _ = c.kk.FileLocation(c.tr.XFile)
	s, err := c.kk.ShowPath(at, chroot)
	if err != nil || s.Text != "/tmp/x" || s.End != linuxobj.EndOutsideRoot || s.Namespace != c.tr.NS {
		t.Errorf("outside the chroot = %+v, %v", s, err)
	}
}

func TestAPathEndsDetachedOrEscaped(t *testing.T) {
	c := newPathCase(t, func(tr *lt.Tree) { tr.K.Mem.U64(tr.TmpMnt+lt.FSMntParent, tr.TmpMnt) })
	c.tr.K.Mem.U64(c.tr.TmpMnt+lt.FSMntNS, 0)
	if s := c.show(t, c.tr.XFile); s.Text != "/x" || s.End != linuxobj.EndDetached {
		t.Errorf("a mount in no namespace = %+v", s)
	}
	c.tr.K.Mem.U64(c.tr.TmpMnt+lt.FSMntNS, ^uint64(21))
	if s := c.show(t, c.tr.XFile); s.End != linuxobj.EndDetached {
		t.Errorf("MNT_NS_INTERNAL = %+v", s)
	}
	addMembers(t, c.tr.K, "mnt_namespace", field("seq", 0x30, symbols.TypeRef{Name: "long long unsigned int"}))
	anon := c.tr.K.AddMountNamespace(9)
	c.tr.K.Mem.U64(c.tr.TmpMnt+lt.FSMntNS, anon)
	ctx, _ := c.tr.K.Context(nil)
	c.kk = linuxobj.New(ctx)
	if s := c.show(t, c.tr.XFile); s.End != linuxobj.EndDetached {
		t.Errorf("an anonymous namespace = %+v", s)
	}
	c.tr.K.Mem.U64(anon+0x30, 4)
	if s := c.show(t, c.tr.XFile); s.End != linuxobj.EndOutsideRoot || s.Namespace != anon {
		t.Errorf("another namespace = %+v", s)
	}

	c = newPathCase(t, nil)
	c.tr.K.Mem.U64(c.tr.Etc+lt.FSDentParent, c.tr.Etc)
	if s := c.show(t, c.tr.PasswdFile); s.Text != "/" || s.End != linuxobj.EndEscaped {
		t.Errorf("escaped = %+v", s)
	}
}

func TestAnUnhashedDentryIsShownDeleted(t *testing.T) {
	c := newPathCase(t, nil)
	c.tr.K.Mem.U64(c.tr.Passwd+lt.FSDentHash+8, 0)
	if s := c.show(t, c.tr.PasswdFile); s.Text != "/etc/passwd (deleted)" || !s.Deleted {
		t.Errorf("unhashed = %+v", s)
	}
	c.tr.K.Mem.U64(c.tr.RootDentry+lt.FSDentHash+8, 0)
	if s, err := c.kk.ShowPath(c.root, c.root); err != nil || s.Deleted {
		t.Errorf("an unhashed root = %+v, %v; a root is never unlinked", s, err)
	}
}

func addNamer(t *testing.T, k *lt.Kernel, name string) uint64 {
	t.Helper()
	fn := k.Alloc(0x10)
	k.Table.AddSymbol(symbols.Symbol{Name: name, Address: fn})
	return fn
}

func (c *pathCase) pseudo(t *testing.T, name string, inode uint64, dentry string) (uint64, uint64) {
	t.Helper()
	k := c.tr.K
	ops := k.Alloc(0x80)
	k.Mem.U64(ops+0x48, addNamer(t, k, name))
	d := k.AddDentry(dentry, 0, inode)
	k.Mem.U64(d+lt.FSDentOp, ops)
	return d, k.AddFile(d, c.tr.TmpMnt+lt.FSMntVfs, inode)
}

func TestPseudoFilesAreNamedByTheirOperation(t *testing.T) {
	c := newPathCase(t, nil)
	k := c.tr.K
	k.Table.AddStruct(symbols.StructType{Name: "proc_ns_operations", Size: 0x40, Fields: []symbols.Field{
		field("name", 0, pointer("char"))}})
	k.Table.AddStruct(symbols.StructType{Name: "dma_buf", Size: 0x60, Fields: []symbols.Field{
		field("name", 0x48, pointer("char"))}})
	inode := k.AddInode(lt.Inode{Ino: 4321, Mode: 0o10600})
	ctx, _ := k.Context(nil)
	c.kk = linuxobj.New(ctx)

	for name, want := range map[string]string{"pipefs_dname": "pipe:[4321]", "sockfs_dname": "socket:[4321]",
		"anon_inodefs_dname": "anon_inode:[eventfd]", "pidfs_dname": "anon_inode:[pidfd]",
		"simple_dname": "/[eventfd] (deleted)"} {
		_, f := c.pseudo(t, name, inode, "[eventfd]")
		if s := c.show(t, f); s.Text != want || s.Pseudo != name {
			t.Errorf("%s = %+v, want %q", name, s, want)
		}
	}

	ns := k.Alloc(0x18)
	nsOps := k.Alloc(0x40)
	k.Mem.U64(nsOps, k.Str("net"))
	k.Mem.U64(ns+8, nsOps)
	k.Mem.U64(inode+0x200, ns)
	if _, f := c.pseudo(t, "ns_dname", inode, ""); c.show(t, f).Text != "net:[4321]" {
		t.Errorf("ns_dname = %+v", c.show(t, f))
	}

	buf := k.Alloc(0x60)
	k.Mem.U64(buf+0x48, k.Str("frame"))
	d, f := c.pseudo(t, "dmabuffs_dname", inode, "dmabuf")
	k.Mem.U64(d+lt.FSDentOp+8, buf)
	if s := c.show(t, f); s.Text != "/dmabuf:frame" {
		t.Errorf("dmabuffs_dname = %+v", s)
	}

	_, f = c.pseudo(t, "anon_inodefs_dname", inode, strings.Repeat("n", 60))
	if _, err := c.kk.ShowPath(mustLocate(t, c.kk, f), c.root); !errors.Is(err, linuxobj.ErrPathLength) {
		t.Errorf("a name past dynamic_dname's buffer: %v", err)
	}
	_, f = c.pseudo(t, "some_other_dname", inode, "x")
	if _, err := c.kk.ShowPath(mustLocate(t, c.kk, f), c.root); !errors.Is(err, linuxobj.ErrPseudoUnknown) {
		t.Errorf("an unknown d_dname: %v", err)
	}

	d, _ = c.pseudo(t, "pipefs_dname", inode, "/")
	mounted := k.AddMount(lt.Mount{Parent: c.tr.RootMnt, Mountpoint: c.tr.TmpDir, Root: d, ID: 9})
	k.Mem.U64(mounted+lt.FSMntNS, c.tr.NS)
	s, err := c.kk.ShowPath(linuxobj.PathPoint{Mount: mounted, Dentry: d}, c.root)
	if err != nil || s.Pseudo != "" || s.Text != "/tmp" {
		t.Errorf("a mounted pseudo root = %+v, %v; want the walked mount point", s, err)
	}
}

func mustLocate(t *testing.T, kk *linuxobj.Kernel, file uint64) linuxobj.PathPoint {
	t.Helper()
	at, err := kk.FileLocation(file)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestPathWalksStopAtTheirLimits(t *testing.T) {
	c := newPathCase(t, nil)
	k := c.tr.K
	parent := c.tr.RootDentry
	for range 17 {
		parent = k.AddDentry(strings.Repeat("d", 255), parent, 0)
	}
	_, err := c.kk.WalkPath(linuxobj.PathPoint{Mount: c.tr.RootMnt, Dentry: parent}, c.root)
	if !errors.Is(err, linuxobj.ErrPathLength) {
		t.Errorf("a path past PATH_MAX: %v", err)
	}
	empty := k.AddDentry("", c.tr.RootDentry, 0)
	if _, err := c.kk.WalkPath(linuxobj.PathPoint{Mount: c.tr.RootMnt, Dentry: empty}, c.root); !errors.Is(err, linuxobj.ErrName) {
		t.Errorf("an empty name: %v", err)
	}
	ctx, _ := k.Context(nil)
	ctx.Limits = limits.Limits{MaxPathSteps: 1}
	kk := linuxobj.New(ctx)
	at := mustLocate(t, kk, c.tr.PasswdFile)
	if _, err := kk.WalkPath(at, c.root); !errors.Is(err, linuxobj.ErrWalkBound) || !linuxobj.IsPathFailure(err) {
		t.Errorf("two steps at MaxPathSteps 1: %v", err)
	}
	k.Mem.U64(c.tr.Etc+lt.FSDentName+lt.FSQstrName, lt.Base+0x7300000)
	if _, err := c.kk.WalkPath(at, c.root); !errors.Is(err, linuxobj.ErrPathUnread) {
		t.Errorf("a name that does not read: %v", err)
	}
}

func FuzzPathWalk(f *testing.F) {
	f.Add(make([]byte, 0x400), uint8(0), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, from, to uint8) {
		k := newFSKernel()
		region := k.Alloc(0x1000)
		if len(data) > 0x1000 {
			data = data[:0x1000]
		}
		k.Mem.Write(region, data)
		at := func(b uint8) uint64 { return region + uint64(b)*8 }
		ctx, _ := k.Context(nil)
		ctx.Limits = limits.Limits{MaxPathSteps: 64, MaxNameBytes: 300}
		kk := linuxobj.New(ctx)
		s, err := kk.ShowPath(linuxobj.PathPoint{Mount: at(from), Dentry: at(to)},
			linuxobj.PathPoint{Mount: at(to), Dentry: at(from)})
		if err == nil && (s.Steps > 64 || s.Text == "") {
			t.Fatalf("walk = %+v", s)
		}
		if err != nil && !linuxobj.IsPathFailure(err) && !errors.Is(err, linuxobj.ErrUnsupported) {
			t.Fatalf("unclassified failure: %v", err)
		}
	})
}

func (c *pathCase) treeNamespace(t *testing.T, mounts ...uint64) uint64 {
	t.Helper()
	k := c.tr.K
	addMembers(t, k, "mnt_namespace", field("mounts", 0x40, symbols.TypeRef{Name: "rb_root"}))
	ns := k.AddMountNamespace(4026531841)
	nodes := make([]uint64, len(mounts))
	for i, m := range mounts {
		nodes[i] = m + lt.FSMntNode
	}
	var build func(lo, hi int, parent uint64) uint64
	build = func(lo, hi int, parent uint64) uint64 {
		if lo > hi {
			return 0
		}
		mid := (lo + hi) / 2
		n := nodes[mid]
		k.Mem.U64(n, parent)
		k.Mem.U64(n+0x10, build(lo, mid-1, n))
		k.Mem.U64(n+8, build(mid+1, hi, n))
		return n
	}
	k.Mem.U64(ns+0x40, build(0, len(nodes)-1, 0))
	ctx, _ := k.Context(nil)
	c.kk = linuxobj.New(ctx)
	return ns
}

func TestMountTreesAreWalkedInOrder(t *testing.T) {
	c := newPathCase(t, nil)
	k := c.tr.K
	var mounts []uint64
	for i := range 6 {
		mounts = append(mounts, k.AddMount(lt.Mount{Root: c.tr.RootDentry, ID: int32(i + 1)}))
	}
	ns := c.treeNamespace(t, mounts...)
	w, err := c.kk.MountPoints(ns)
	if err != nil || !w.Tree || w.Broken() || !slices.Equal(w.Mounts, mounts) {
		t.Fatalf("tree walk = %+v, %v; want %x", w, err, mounts)
	}
	k.Mem.U64(mounts[0]+lt.FSMntNode, mounts[5]+lt.FSMntNode)
	if w, err := c.kk.MountPoints(ns); err != nil || w.End != linuxobj.TreeParentMismatch {
		t.Errorf("a child naming another parent = %+v, %v", w, err)
	}

	c = newPathCase(t, nil)
	if w, err := c.kk.MountPoints(c.tr.NS); err != nil || w.Tree || !slices.Equal(w.Mounts, []uint64{c.tr.RootMnt, c.tr.TmpMnt}) {
		t.Errorf("list walk = %+v, %v", w, err)
	}
	if inum, ok, err := c.kk.MountNamespaceInode(c.tr.NS); err != nil || !ok || inum != 4026531840 {
		t.Errorf("inum = %d, %v, %v", inum, ok, err)
	}
}

func TestPropagationAndTheDominatingPeerGroup(t *testing.T) {
	c := newPathCase(t, nil)
	k := c.tr.K
	tr := c.tr
	if shared, unbindable, err := c.kk.MountPropagation(tr.TmpMnt, 0x1000|0x2000); err != nil || !shared || !unbindable {
		t.Errorf("mnt_flags propagation = %v %v, %v", shared, unbindable, err)
	}
	otherNS := k.AddMountNamespace(77)
	outside := k.AddMount(lt.Mount{Root: tr.RootDentry, ID: 30, GroupID: 3, NS: otherNS})
	master := k.AddMount(lt.Mount{Parent: tr.RootMnt, Mountpoint: tr.TmpDir, Root: tr.TmpRoot, ID: 31, GroupID: 7, Master: outside, NS: tr.NS})
	peer := k.AddMount(lt.Mount{Parent: tr.RootMnt, Mountpoint: tr.Etc, Root: tr.TmpRoot, ID: 32, GroupID: 7, NS: tr.NS})
	slave := k.AddMount(lt.Mount{Parent: tr.RootMnt, Mountpoint: tr.TmpDir, Root: tr.TmpRoot, ID: 33, Master: outside, NS: tr.NS})
	k.Circle(outside+lt.FSMntShare, master+lt.FSMntShare, peer+lt.FSMntShare)
	if id, err := c.kk.DominatingID(slave, c.root); err != nil || id != 7 {
		t.Errorf("dominating = %d, %v; want 7, a peer of the master in the slave's namespace", id, err)
	}
	chroot := linuxobj.PathPoint{Mount: tr.TmpMnt, Dentry: tr.TmpRoot}
	if id, err := c.kk.DominatingID(slave, chroot); err != nil || id != 0 {
		t.Errorf("from a root no peer sits under = %d, %v; want 0", id, err)
	}

	addMembers(t, k, "mount", field("mnt_t_flags", 0x130, symbols.TypeRef{Name: "int"}))
	k.Mem.U32(tr.TmpMnt+0x130, 2)
	ctx, _ := k.Context(nil)
	kk := linuxobj.New(ctx)
	if shared, unbindable, err := kk.MountPropagation(tr.TmpMnt, 0x1000); err != nil || shared || !unbindable {
		t.Errorf("mnt_t_flags propagation = %v %v, %v", shared, unbindable, err)
	}
	if name, err := kk.MountDevname(tr.TmpMnt); err != nil || name != "tmpfs" {
		t.Errorf("devname = %q, %v", name, err)
	}
}
