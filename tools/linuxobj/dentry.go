package linuxobj

import (
	"errors"
	"fmt"
)

var (
	ErrWalkBound     = errors.New("linuxobj: walk limit reached")
	ErrPathUnread    = errors.New("linuxobj: path: a dentry or mount on the way does not read")
	ErrName          = errors.New("linuxobj: dentry name is empty or longer than NAME_MAX")
	ErrPathLength    = errors.New("linuxobj: name does not fit the kernel's buffer")
	ErrPseudoUnknown = errors.New("linuxobj: pseudo file named by an operation that is not run")
)

func unreadPath(kind string, at uint64, err error) error {
	return fmt.Errorf("%w: %s at %#x: %w", ErrPathUnread, kind, at, err)
}

// IsPathFailure reports an error that leaves one path unbuilt, as against a
// layout the tool cannot work with.
func IsPathFailure(err error) bool {
	for _, e := range []error{ErrWalkBound, ErrPathUnread, ErrName, ErrPathLength, ErrPseudoUnknown} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

const nameMax = 255

func (k *Kernel) DentryName(dentry uint64) (string, error) {
	f, err := k.Member("dentry", "d_name")
	if err != nil {
		return "", fmt.Errorf("%w: dentry has no d_name", ErrUnsupported)
	}
	at := dentry + f.Offset
	n, err := k.Uint(k.mem, at, f.Type.Name, "len")
	if err != nil {
		return "", unreadPath("dentry", dentry, err)
	}
	if limit := k.ctx.Bounds().MaxNameBytes; int64(n) > limit {
		return "", fmt.Errorf("linuxobj: dentry at %#x: %d-byte name passes Limits.MaxNameBytes %d: %w",
			k.Masked(dentry), n, limit, ErrWalkBound)
	}
	if n == 0 || n > nameMax {
		return "", fmt.Errorf("linuxobj: dentry at %#x: %d-byte name: %w", k.Masked(dentry), n, ErrName)
	}
	p, err := k.Pointer(k.mem, at, f.Type.Name, "name")
	if err != nil {
		return "", unreadPath("dentry", dentry, err)
	}
	b, err := k.mem.ReadAt(p, n)
	if err != nil {
		return "", unreadPath("dentry name", p, err)
	}
	return string(b), nil
}

// DentryPath is the path inside the dentry's own filesystem, from its root.
func (k *Kernel) DentryPath(dentry uint64) (string, error) {
	var names []string
	steps := k.ctx.Bounds().MaxPathSteps
	size := 1
	for d := dentry; ; {
		parent, err := k.Pointer(k.mem, d, "dentry", "d_parent")
		if err != nil {
			return "", unreadPath("dentry", d, err)
		}
		if parent == d {
			break
		}
		if len(names) >= steps {
			return "", k.stepBound(dentry)
		}
		name, err := k.DentryName(d)
		if err != nil {
			return "", err
		}
		if size += len(name) + 1; size > pathMax {
			return "", fmt.Errorf("linuxobj: dentry at %#x: path passes PATH_MAX: %w", k.Masked(dentry), ErrPathLength)
		}
		names = append(names, name)
		d = parent
	}
	return joinReversed(names), nil
}

// ShownPath is the text the kernel's d_path gives: a pseudo file's own name,
// or the walked path with " (deleted)" for an unlinked dentry (S39 4.4).
type ShownPath struct {
	WalkedPath
	Pseudo  string
	Deleted bool
}

const deletedSuffix = " (deleted)"

func (k *Kernel) ShowPath(at, root PathPoint) (ShownPath, error) {
	namer, err := k.dentryNamer(at)
	if err != nil {
		return ShownPath{}, err
	}
	if namer != 0 {
		return k.pseudoName(at, namer)
	}
	walked, err := k.WalkPath(at, root)
	if err != nil {
		return ShownPath{}, err
	}
	out := ShownPath{WalkedPath: walked}
	if out.Deleted, err = k.unlinked(at.Dentry); err != nil {
		return ShownPath{}, err
	}
	if out.Deleted {
		if len(out.Text)+len(deletedSuffix)+1 > pathMax {
			return ShownPath{}, fmt.Errorf("linuxobj: dentry at %#x: path passes PATH_MAX: %w", k.Masked(at.Dentry), ErrPathLength)
		}
		out.Text += deletedSuffix
	}
	return out, nil
}

func (k *Kernel) dentryNamer(at PathPoint) (uint64, error) {
	if !k.Has("dentry", "d_op") || !k.Has("dentry_operations", "d_dname") {
		return 0, nil
	}
	ops, err := k.Pointer(k.mem, at.Dentry, "dentry", "d_op")
	if err != nil {
		return 0, unreadPath("dentry", at.Dentry, err)
	}
	if ops == 0 {
		return 0, nil
	}
	namer, err := k.Pointer(k.mem, ops, "dentry_operations", "d_dname")
	if err != nil {
		return 0, unreadPath("dentry_operations", ops, err)
	}
	if namer == 0 {
		return 0, nil
	}
	parent, err := k.Pointer(k.mem, at.Dentry, "dentry", "d_parent")
	if err != nil {
		return 0, unreadPath("dentry", at.Dentry, err)
	}
	if parent == at.Dentry {
		root, err := k.MountRoot(at.Mount)
		if err != nil {
			return 0, unreadPath("mount", at.Mount, err)
		}
		if root == at.Dentry {
			return 0, nil
		}
	}
	return namer, nil
}

func (k *Kernel) unlinked(dentry uint64) (bool, error) {
	hash, err := k.Member("dentry", "d_hash")
	if err != nil || !k.Has(hash.Type.Name, "pprev") {
		return false, nil
	}
	pprev, err := k.Pointer(k.mem, dentry+hash.Offset, hash.Type.Name, "pprev")
	if err != nil {
		return false, unreadPath("dentry", dentry, err)
	}
	if pprev != 0 {
		return false, nil
	}
	parent, err := k.Pointer(k.mem, dentry, "dentry", "d_parent")
	if err != nil {
		return false, unreadPath("dentry", dentry, err)
	}
	return parent != dentry, nil
}

const (
	dynamicNameBuffer = 64
	dmaBufNameLen     = 32
)

var pseudoNamers = []string{"pipefs_dname", "sockfs_dname", "anon_inodefs_dname", "ns_dname", "simple_dname",
	"dmabuffs_dname", "pidfs_dname"}

func (k *Kernel) namerName(addr uint64) string {
	addr = k.Canonical(addr)
	for _, name := range pseudoNamers {
		if s, err := k.Symbol(name); err == nil && s.Address == addr {
			return name
		}
	}
	return ""
}

func (k *Kernel) pseudoName(at PathPoint, namer uint64) (ShownPath, error) {
	fn := k.namerName(namer)
	out := ShownPath{Pseudo: fn, WalkedPath: WalkedPath{Mount: at.Mount}}
	inodeNumber := func() (uint64, error) {
		inode, err := k.Pointer(k.mem, at.Dentry, "dentry", "d_inode")
		if err != nil {
			return 0, unreadPath("dentry", at.Dentry, err)
		}
		n, err := k.Uint(k.mem, inode, "inode", "i_ino")
		if err != nil {
			return 0, unreadPath("inode", inode, err)
		}
		return n, nil
	}
	var text string
	switch fn {
	case "pipefs_dname", "sockfs_dname":
		ino, err := inodeNumber()
		if err != nil {
			return ShownPath{}, err
		}
		prefix := "pipe"
		if fn == "sockfs_dname" {
			prefix = "socket"
		}
		text = fmt.Sprintf("%s:[%d]", prefix, ino)
	case "pidfs_dname":
		text = "anon_inode:[pidfd]"
	case "anon_inodefs_dname":
		name, err := k.DentryName(at.Dentry)
		if err != nil {
			return ShownPath{}, err
		}
		text = "anon_inode:" + name
	case "ns_dname":
		ino, err := inodeNumber()
		if err != nil {
			return ShownPath{}, err
		}
		kind, err := k.namespaceKind(at.Dentry)
		if err != nil {
			return ShownPath{}, err
		}
		text = fmt.Sprintf("%s:[%d]", kind, ino)
	case "simple_dname":
		name, err := k.DentryName(at.Dentry)
		if err != nil {
			return ShownPath{}, err
		}
		out.Text, out.Deleted = "/"+name+deletedSuffix, true
		return out, nil
	case "dmabuffs_dname":
		name, err := k.DentryName(at.Dentry)
		if err != nil {
			return ShownPath{}, err
		}
		label, err := k.dmaBufName(at.Dentry)
		if err != nil {
			return ShownPath{}, err
		}
		text = "/" + name + ":" + label
	default:
		return ShownPath{}, fmt.Errorf("linuxobj: dentry at %#x: d_dname %#x: %w", k.Masked(at.Dentry), k.Masked(namer), ErrPseudoUnknown)
	}
	if len(text)+1 > dynamicNameBuffer {
		return ShownPath{}, fmt.Errorf("linuxobj: dentry at %#x: %s name of %d bytes: %w", k.Masked(at.Dentry), fn, len(text), ErrPathLength)
	}
	out.Text = text
	return out, nil
}

// nsfs keeps the namespace in the inode's i_private at every tag; its ops
// name the kind (S39 Q3).
func (k *Kernel) namespaceKind(dentry uint64) (string, error) {
	inode, err := k.Pointer(k.mem, dentry, "dentry", "d_inode")
	if err != nil {
		return "", unreadPath("dentry", dentry, err)
	}
	ns, err := k.Pointer(k.mem, inode, "inode", "i_private")
	if err != nil {
		return "", unreadPath("inode", inode, err)
	}
	ops, err := k.Pointer(k.mem, ns, "ns_common", "ops")
	if err != nil {
		return "", unreadPath("ns_common", ns, err)
	}
	p, err := k.Pointer(k.mem, ops, "proc_ns_operations", "name")
	if err != nil {
		return "", unreadPath("proc_ns_operations", ops, err)
	}
	name, err := k.StringAt(p, dynamicNameBuffer)
	if err != nil {
		return "", unreadPath("namespace kind", p, err)
	}
	return name, nil
}

func (k *Kernel) dmaBufName(dentry uint64) (string, error) {
	buf, err := k.Pointer(k.mem, dentry, "dentry", "d_fsdata")
	if err != nil {
		return "", unreadPath("dentry", dentry, err)
	}
	p, err := k.Pointer(k.mem, buf, "dma_buf", "name")
	if err != nil {
		return "", unreadPath("dma_buf", buf, err)
	}
	if p == 0 {
		return "", nil
	}
	name, err := k.StringAt(p, dmaBufNameLen-1)
	if err != nil {
		return "", unreadPath("dma_buf name", p, err)
	}
	return name, nil
}
