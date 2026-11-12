package linuxobj

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

func (k *Kernel) mountOf(vfs uint64) (uint64, error) {
	f, err := k.Member("mount", "mnt")
	if err != nil {
		return 0, fmt.Errorf("%w: struct mount has no mnt", ErrUnsupported)
	}
	if vfs == 0 {
		return 0, nil
	}
	return k.Canonical(vfs - f.Offset), nil
}

func (k *Kernel) vfsmountOf(mnt uint64) (uint64, error) {
	f, err := k.Member("mount", "mnt")
	if err != nil {
		return 0, fmt.Errorf("%w: struct mount has no mnt", ErrUnsupported)
	}
	return k.Canonical(mnt + f.Offset), nil
}

func (k *Kernel) TaskFSRoot(t Task) (PathPoint, error) {
	fs, err := k.Pointer(k.in(t), t.Addr, "task_struct", "fs")
	if err != nil {
		return PathPoint{}, err
	}
	if fs == 0 {
		return PathPoint{}, ErrNoRoot
	}
	root, err := k.Member("fs_struct", "root")
	if err != nil {
		return PathPoint{}, fmt.Errorf("%w: fs_struct has no root", ErrUnsupported)
	}
	at, err := k.pathAt(fs + root.Offset)
	if err != nil {
		return PathPoint{}, err
	}
	if !k.Readable(at.Dentry, k.PointerSize()) || !k.Readable(at.Mount, k.PointerSize()) {
		return PathPoint{}, fmt.Errorf("%w: task root at %#x: mount %#x, dentry %#x", ErrPathUnread,
			k.Masked(fs), k.Masked(at.Mount), k.Masked(at.Dentry))
	}
	return at, nil
}

var ErrNoRoot = errors.New("linuxobj: task has no fs_struct")

func (k *Kernel) MountNamespaceInode(ns uint64) (uint64, bool, error) {
	f, err := k.Member("mnt_namespace", "ns")
	if err != nil || !k.Has(f.Type.Name, "inum") {
		return 0, false, nil
	}
	inum, err := k.Uint(k.mem, ns+f.Offset, f.Type.Name, "inum")
	if err != nil {
		return 0, false, err
	}
	return inum, true, nil
}

type MountTreeEnd uint8

const (
	TreeComplete MountTreeEnd = iota
	TreeLinkUnread
	TreeParentMismatch
	TreeRevisited
	TreeCapped
)

func (e MountTreeEnd) String() string {
	switch e {
	case TreeComplete:
		return "every node was visited"
	case TreeLinkUnread:
		return "a node does not read"
	case TreeParentMismatch:
		return "a child does not name its parent"
	case TreeRevisited:
		return "a node was reached twice"
	case TreeCapped:
		return "it reached Limits.MaxListEntries"
	}
	return fmt.Sprintf("MountTreeEnd(%d)", uint8(e))
}

// One of Tree and List is used, by the namespace's layout (S39 N1).
type MountWalk struct {
	Mounts []uint64
	Tree   bool
	End    MountTreeEnd
	At     uint64
	List   linuxwalk.List
}

func (w MountWalk) Broken() bool {
	if w.Tree {
		return w.End != TreeComplete
	}
	return w.List.Broken()
}

func (k *Kernel) MountPoints(ns uint64) (MountWalk, error) {
	if f, err := k.Member("mnt_namespace", "mounts"); err == nil {
		return k.mountTree(ns + f.Offset)
	}
	list, err := k.Member("mnt_namespace", "list")
	if err != nil {
		return MountWalk{}, fmt.Errorf("%w: mnt_namespace has neither mounts nor list", ErrUnsupported)
	}
	l, err := k.Walker().List(ns+list.Offset, "mount", "mnt_list", linuxwalk.Forward)
	if err != nil {
		return MountWalk{}, err
	}
	return MountWalk{Mounts: l.Entries, List: l}, nil
}

type rbLinks struct{ parent, left, right, node uint64 }

func (k *Kernel) rbLinks() (rbLinks, error) {
	node, err := k.Member("mount", "mnt_node")
	if err != nil {
		return rbLinks{}, fmt.Errorf("%w: struct mount has no mnt_node", ErrUnsupported)
	}
	var l rbLinks
	l.node = node.Offset
	for _, m := range []struct {
		name string
		at   *uint64
	}{{"__rb_parent_color", &l.parent}, {"rb_left", &l.left}, {"rb_right", &l.right}} {
		f, err := k.Member("rb_node", m.name)
		if err != nil {
			return rbLinks{}, fmt.Errorf("%w: rb_node has no %s", ErrUnsupported, m.name)
		}
		*m.at = f.Offset
	}
	return l, nil
}

// The in-order walk gives mounts by mnt_id_unique, the tree's key (S39 N1).
func (k *Kernel) mountTree(root uint64) (MountWalk, error) {
	links, err := k.rbLinks()
	if err != nil {
		return MountWalk{}, err
	}
	w := MountWalk{Tree: true}
	top, err := k.PointerAt(k.mem, root)
	if err != nil {
		w.End, w.At = TreeLinkUnread, root
		return w, nil
	}
	limit := k.ctx.Bounds().MaxListEntries
	seen := map[uint64]bool{}
	type frame struct{ node, parent uint64 }
	var stack []frame
	cur := frame{node: top}
	for cur.node != 0 || len(stack) > 0 {
		for cur.node != 0 {
			if seen[cur.node] {
				w.End, w.At = TreeRevisited, cur.node
				return w, nil
			}
			if len(seen) >= limit {
				w.End, w.At = TreeCapped, cur.node
				return w, nil
			}
			seen[cur.node] = true
			pc, err := k.PointerAt(k.mem, cur.node+links.parent)
			if err != nil {
				w.End, w.At = TreeLinkUnread, cur.node
				return w, nil
			}
			if k.Canonical(pc&^3) != cur.parent {
				w.End, w.At = TreeParentMismatch, cur.node
				return w, nil
			}
			stack = append(stack, cur)
			left, err := k.PointerAt(k.mem, cur.node+links.left)
			if err != nil {
				w.End, w.At = TreeLinkUnread, cur.node
				return w, nil
			}
			cur = frame{node: left, parent: cur.node}
		}
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		w.Mounts = append(w.Mounts, k.Canonical(top.node-links.node))
		right, err := k.PointerAt(k.mem, top.node+links.right)
		if err != nil {
			w.End, w.At = TreeLinkUnread, top.node
			return w, nil
		}
		cur = frame{node: right, parent: top.node}
	}
	return w, nil
}

func (k *Kernel) vfsMember(mnt uint64, member string) (uint64, error) {
	vfs, err := k.vfsmountOf(mnt)
	if err != nil {
		return 0, err
	}
	return k.Pointer(k.mem, vfs, "vfsmount", member)
}

func (k *Kernel) MountRoot(mnt uint64) (uint64, error) { return k.vfsMember(mnt, "mnt_root") }

func (k *Kernel) MountSuperBlock(mnt uint64) (uint64, error) { return k.vfsMember(mnt, "mnt_sb") }

func (k *Kernel) MountFlags(mnt uint64) (int64, error) {
	vfs, err := k.vfsmountOf(mnt)
	if err != nil {
		return 0, err
	}
	return k.Int(k.mem, vfs, "vfsmount", "mnt_flags")
}

const (
	mntReadOnly     = 0x40
	mntShared       = 0x1000
	mntUnbindable   = 0x2000
	mountShared     = 1
	mountUnbindable = 2
)

var mountOptions = []struct {
	bit  int64
	name string
}{
	{0x01, "nosuid"}, {0x02, "nodev"}, {0x04, "noexec"}, {0x08, "noatime"}, {0x10, "nodiratime"},
	{0x20, "relatime"}, {0x80, "nosymfollow"},
}

func MountFlagStrings(flags int64) (string, []string) {
	access := "rw"
	if flags&mntReadOnly != 0 {
		access = "ro"
	}
	var opts []string
	for _, o := range mountOptions {
		if flags&o.bit != 0 {
			opts = append(opts, o.name)
		}
	}
	return access, opts
}

func (k *Kernel) MountPropagation(mnt uint64, flags int64) (shared, unbindable bool, err error) {
	if !k.Has("mount", "mnt_t_flags") {
		return flags&mntShared != 0, flags&mntUnbindable != 0, nil
	}
	t, err := k.Int(k.mem, mnt, "mount", "mnt_t_flags")
	if err != nil {
		return false, false, err
	}
	return t&mountShared != 0, t&mountUnbindable != 0, nil
}

func (k *Kernel) MountID(mnt uint64) (int64, error) { return k.Int(k.mem, mnt, "mount", "mnt_id") }

func (k *Kernel) MountGroupID(mnt uint64) (int64, error) {
	return k.Int(k.mem, mnt, "mount", "mnt_group_id")
}

func (k *Kernel) MountParent(mnt uint64) (uint64, error) {
	return k.Pointer(k.mem, mnt, "mount", "mnt_parent")
}

func (k *Kernel) MountMaster(mnt uint64) (uint64, error) {
	return k.Pointer(k.mem, mnt, "mount", "mnt_master")
}

func (k *Kernel) MountDevname(mnt uint64) (string, error) {
	p, err := k.Pointer(k.mem, mnt, "mount", "mnt_devname")
	if err != nil || p == 0 {
		return "", err
	}
	s, err := k.StringAt(p, pathMax)
	if err != nil {
		return "", fmt.Errorf("linuxobj: mount at %#x: mnt_devname: %w", k.Masked(mnt), err)
	}
	return s, nil
}

func (k *Kernel) mountNamespace(mnt uint64) (uint64, error) {
	return k.Pointer(k.mem, mnt, "mount", "mnt_ns")
}

// A slave's dominating peer group is the first master, or a peer of one,
// that sits in the slave's namespace below the reader's root (S39 N6).
func (k *Kernel) DominatingID(mnt uint64, root PathPoint) (int64, error) {
	ns, err := k.mountNamespace(mnt)
	if err != nil {
		return 0, err
	}
	limit := k.ctx.Bounds().MaxListEntries
	master, err := k.MountMaster(mnt)
	if err != nil {
		return 0, err
	}
	for chain := 0; master != 0; chain++ {
		if chain >= limit {
			return 0, fmt.Errorf("linuxobj: mount at %#x: master chain passes Limits.MaxListEntries %d: %w",
				k.Masked(mnt), limit, ErrWalkBound)
		}
		peers, err := k.Walker().List(master+k.mntShareOffset(), "mount", "mnt_share", linuxwalk.Forward)
		if err != nil {
			return 0, err
		}
		for _, peer := range append([]uint64{master}, peers.Entries...) {
			pns, err := k.mountNamespace(peer)
			if err != nil {
				return 0, err
			}
			if pns != ns {
				continue
			}
			under, err := k.mountUnderRoot(peer, root)
			if err != nil {
				return 0, err
			}
			if under {
				return k.MountGroupID(peer)
			}
		}
		if master, err = k.MountMaster(master); err != nil {
			return 0, err
		}
	}
	return 0, nil
}

func (k *Kernel) mntShareOffset() uint64 {
	f, err := k.Member("mount", "mnt_share")
	if err != nil {
		return 0
	}
	return f.Offset
}

// The mount's root counts when climbing its mount chain reaches the root's
// mount at a dentry that descends from the root's dentry (S39 N6).
func (k *Kernel) mountUnderRoot(mnt uint64, root PathPoint) (bool, error) {
	dentry, err := k.MountRoot(mnt)
	if err != nil {
		return false, err
	}
	steps := k.ctx.Bounds().MaxPathSteps
	for i := 0; mnt != root.Mount; i++ {
		if i >= steps {
			return false, k.stepBound(mnt)
		}
		parent, err := k.MountParent(mnt)
		if err != nil {
			return false, err
		}
		if parent == mnt {
			return false, nil
		}
		if dentry, err = k.Pointer(k.mem, mnt, "mount", "mnt_mountpoint"); err != nil {
			return false, err
		}
		mnt = parent
	}
	for i := 0; ; i++ {
		if dentry == root.Dentry {
			return true, nil
		}
		if i >= steps {
			return false, k.stepBound(dentry)
		}
		parent, err := k.Pointer(k.mem, dentry, "dentry", "d_parent")
		if err != nil {
			return false, err
		}
		if parent == dentry {
			return false, nil
		}
		dentry = parent
	}
}

func (k *Kernel) stepBound(at uint64) error {
	return fmt.Errorf("linuxobj: %#x: walk passes Limits.MaxPathSteps %d: %w", k.Masked(at),
		k.ctx.Bounds().MaxPathSteps, ErrWalkBound)
}

type PathEnd uint8

const (
	EndAtRoot PathEnd = iota
	EndOutsideRoot
	EndDetached
	EndEscaped
)

func (e PathEnd) String() string {
	switch e {
	case EndAtRoot:
		return "at the root"
	case EndOutsideRoot:
		return "outside the root"
	case EndDetached:
		return "detached"
	case EndEscaped:
		return "escaped"
	}
	return fmt.Sprintf("PathEnd(%d)", uint8(e))
}

// Mount and Namespace are where the walk stopped, which for an end outside
// the root is not the reader's namespace.
type WalkedPath struct {
	Text      string
	End       PathEnd
	Mount     uint64
	Namespace uint64
	Steps     int
}

const errorPointers = 4095

func (k *Kernel) isErrorPointer(p uint64) bool {
	return k.Masked(p) >= k.Masked(^uint64(0))-errorPointers+1
}

func (k *Kernel) attachedNamespace(ns uint64) (bool, error) {
	if ns == 0 || k.isErrorPointer(ns) {
		return false, nil
	}
	if !k.Has("mnt_namespace", "seq") {
		return true, nil
	}
	seq, err := k.Uint(k.mem, ns, "mnt_namespace", "seq")
	if err != nil {
		return false, err
	}
	return seq != 0, nil
}

// WalkPath climbs from at to root as the kernel's prepend_path does, crossing
// each mount at its root to the dentry it is mounted on (S39 4.3).
func (k *Kernel) WalkPath(at, root PathPoint) (WalkedPath, error) {
	var names []string
	size := 1
	steps := k.ctx.Bounds().MaxPathSteps
	d, m := at.Dentry, at.Mount
	out := WalkedPath{End: EndAtRoot}
	for d != root.Dentry || m != root.Mount {
		out.Steps++
		if out.Steps > steps {
			return WalkedPath{}, k.stepBound(at.Dentry)
		}
		mntRoot, err := k.MountRoot(m)
		if err != nil {
			return WalkedPath{}, unreadPath("mount", m, err)
		}
		if d == mntRoot {
			parent, err := k.MountParent(m)
			if err != nil {
				return WalkedPath{}, unreadPath("mount", m, err)
			}
			if parent != m {
				if d, err = k.Pointer(k.mem, m, "mount", "mnt_mountpoint"); err != nil {
					return WalkedPath{}, unreadPath("mount", m, err)
				}
				m = parent
				continue
			}
			ns, err := k.mountNamespace(m)
			if err != nil {
				return WalkedPath{}, unreadPath("mount", m, err)
			}
			attached, err := k.attachedNamespace(ns)
			if err != nil {
				return WalkedPath{}, unreadPath("mnt_namespace", ns, err)
			}
			out.End, out.Namespace = EndDetached, ns
			if attached {
				out.End = EndOutsideRoot
			}
			break
		}
		parent, err := k.Pointer(k.mem, d, "dentry", "d_parent")
		if err != nil {
			return WalkedPath{}, unreadPath("dentry", d, err)
		}
		if parent == d {
			names, size = nil, 1
			out.End = EndEscaped
			break
		}
		name, err := k.DentryName(d)
		if err != nil {
			return WalkedPath{}, err
		}
		size += len(name) + 1
		if size > pathMax {
			return WalkedPath{}, fmt.Errorf("linuxobj: dentry at %#x: path passes PATH_MAX: %w", k.Masked(at.Dentry), ErrPathLength)
		}
		names = append(names, name)
		d = parent
	}
	out.Mount = m
	if out.End == EndAtRoot {
		ns, err := k.mountNamespace(m)
		if err != nil {
			return WalkedPath{}, unreadPath("mount", m, err)
		}
		out.Namespace = ns
	}
	out.Text = joinReversed(names)
	return out, nil
}

func joinReversed(names []string) string {
	if len(names) == 0 {
		return "/"
	}
	var b strings.Builder
	for i := len(names) - 1; i >= 0; i-- {
		b.WriteByte('/')
		b.WriteString(names[i])
	}
	return b.String()
}
