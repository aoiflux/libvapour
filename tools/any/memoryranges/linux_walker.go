package memoryranges

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

var ErrAreaNameUnread = errors.New("memoryranges: an area's name does not read")

// IsPathUnresolved reports an error that leaves one name or path unbuilt;
// the caller lists the object without it.
func IsPathUnresolved(err error) bool {
	return err != nil && (linuxobj.IsPathFailure(err) || errors.Is(err, linuxobj.ErrNoRoot) ||
		errors.Is(err, ErrAreaNamerUnknown) || errors.Is(err, ErrAreaNameUnread))
}

type LinuxWalker struct {
	k     *linuxobj.Kernel
	shape areaShape
}

func NewLinuxWalker(ctx tools.Context) (*LinuxWalker, error) {
	k := linuxobj.New(ctx)
	shape, err := resolveAreaShape(k)
	if err != nil {
		return nil, err
	}
	if _, err := k.Member("mount", "mnt"); err != nil {
		return nil, fmt.Errorf("%w: struct mount has no mnt", linuxobj.ErrUnsupported)
	}
	return &LinuxWalker{k: k, shape: shape}, nil
}

type LinuxVMA struct {
	Addr             uint64
	Start, End, File uint64
}

// TaskVMAs returns the areas kept in address order; err is an AreaLosses
// when candidates were dropped or the count differs from map_count.
func (lw *LinuxWalker) TaskVMAs(task uint64) (mm uint64, vmas []LinuxVMA, err error) {
	k := lw.k
	if mm, err = k.Pointer(k.Memory(), task, "task_struct", "mm"); err != nil {
		return 0, nil, fmt.Errorf("task_struct at %#x: mm: %w", k.Masked(task), err)
	}
	if mm == 0 {
		return 0, nil, nil
	}
	if !k.Readable(mm, lw.shape.mmSize) {
		return mm, nil, fmt.Errorf("mm_struct at %#x: does not read", k.Masked(mm))
	}
	vmas, losses := lw.walkAreas(mm)
	if losses.Total() > 0 || losses.Mismatch() {
		return mm, vmas, losses
	}
	return mm, vmas, nil
}

func (lw *LinuxWalker) AreaWalk(mm uint64) ([]LinuxVMA, AreaLosses) { return lw.walkAreas(mm) }

// OpenFileName is the target the kernel gives /proc/<pid>/fd/<n> for the
// file, built from the task's own root. With walkedOnly a pseudo file has no
// name.
func (lw *LinuxWalker) OpenFileName(task, file uint64, walkedOnly bool) (string, error) {
	shown, err := lw.ShowOpenFile(task, file)
	if walkedOnly && (errors.Is(err, linuxobj.ErrPseudoUnknown) || err == nil && shown.Pseudo != "") {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return shown.Text, nil
}

func (lw *LinuxWalker) ShowOpenFile(task, file uint64) (linuxobj.ShownPath, error) {
	k := lw.k
	root, err := k.TaskFSRoot(linuxobj.Task{Addr: task})
	if err != nil {
		return linuxobj.ShownPath{}, err
	}
	at, err := k.FileLocation(file)
	if err != nil && !errors.Is(err, linuxobj.ErrUnsupported) {
		return linuxobj.ShownPath{}, fmt.Errorf("%w: %w", linuxobj.ErrPathUnread, err)
	}
	if err != nil {
		return linuxobj.ShownPath{}, err
	}
	return k.ShowPath(at, root)
}

// MountPointPath is the mount point mountinfo shows for the task: empty when
// the mount is not reachable from the task's root (S39 N5).
func (lw *LinuxWalker) MountPointPath(task, mnt uint64) (string, error) {
	k := lw.k
	root, err := k.TaskFSRoot(linuxobj.Task{Addr: task})
	if err != nil {
		return "", err
	}
	dentry, err := k.MountRoot(mnt)
	if err != nil {
		return "", err
	}
	walked, err := k.WalkPath(linuxobj.PathPoint{Mount: k.Canonical(mnt), Dentry: dentry}, root)
	if err != nil || walked.End != linuxobj.EndAtRoot {
		return "", err
	}
	return walked.Text, nil
}
