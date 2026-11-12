package mountlist

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.mount.list"

const (
	OptionMntNS       = "linux.mount.list.mntns"
	OptionMountFormat = "linux.mount.list.mount_format"
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the mounts of each Linux mount namespace as /proc/<pid>/mountinfo shows them from a task's root",
		},
		RunAny,
	)
}

var ErrNotLinux = errors.New("mountlist: the profile is not linux")

type Mount struct {
	MntNsID      uint64
	MntNsIDOK    bool
	PID          int64
	PIDShown     bool
	MountFormat  bool
	MountAddress uint64

	MountID, ParentID int64
	MajorMinor        string
	Root              string
	MountPoint        string
	MountOptions      string
	Fields            string
	FSType            string
	FSTypeOK          bool
	MountSource       string
	SBOptions         string
	MntOpts           string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type view struct {
	task      linuxobj.Task
	namespace uint64
}

func Run(ctx tools.Context) ([]Mount, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: %w", Name, ErrNotLinux)
	}
	only, err := ctx.UintListOption(OptionMntNS)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	mountsForm, err := ctx.BoolOption(OptionMountFormat)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	k := linuxobj.New(ctx)
	pids := ctx.PIDs()
	perTask := !pids.All()
	walk, err := k.Walker().Tasks(false, k.PIDSkip(pids))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)

	l := &lister{k: k, diag: ctx.AddDiagnostic, mountsForm: mountsForm}
	views, err := l.views(walk.Tasks, perTask)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	var out []Mount
	unfiltered := 0
	for _, v := range views {
		number, known, err := k.MountNamespaceInode(v.namespace)
		if err != nil {
			if err := l.failed("mnt_namespace", v.namespace, "ns.inum", err); err != nil {
				return nil, fmt.Errorf("%s: %w", Name, err)
			}
		}
		if len(only) > 0 {
			if !known {
				unfiltered++
			} else if !slices.Contains(only, number) {
				continue
			}
		}
		rows, err := l.namespace(v, perTask)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		for i := range rows {
			rows[i].MntNsID, rows[i].MntNsIDOK = number, known
		}
		out = append(out, rows...)
	}
	if unfiltered > 0 {
		ctx.AddDiagnostic("%s: %d mount namespaces have no number that reads; listed without the %s filter",
			Name, unfiltered, OptionMntNS)
	}
	if l.lost > 0 && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: %d mounts, namespaces or task roots read in part", Name, l.lost)
	}
	return out, nil
}

type lister struct {
	k          *linuxobj.Kernel
	diag       func(string, ...any)
	mountsForm bool
	lost       int
}

func (l *lister) failed(object string, at uint64, what string, err error) error {
	if errors.Is(err, linuxobj.ErrUnsupported) || linuxobj.TableGap(err) {
		return fmt.Errorf("%s at %#x: %s: %w", object, l.k.Canonical(at), what, err)
	}
	l.lost++
	l.diag("%s: %s at %#x: %s: %v", Name, object, l.k.Canonical(at), what, err)
	return nil
}

// Without a PID selection each namespace is read once, from the first task
// that holds it: every holder sees the same mounts, and only a chrooted
// holder would see fewer of them.
func (l *lister) views(tasks []uint64, perTask bool) ([]view, error) {
	k := l.k
	var out []view
	seen := map[uint64]bool{}
	for _, addr := range tasks {
		t := linuxobj.Task{Addr: addr}
		fs, err := k.Pointer(k.Memory(), addr, "task_struct", "fs")
		if err != nil {
			if err := l.failed("task_struct", addr, "fs", err); err != nil {
				return nil, err
			}
			continue
		}
		nsproxy, err := k.Pointer(k.Memory(), addr, "task_struct", "nsproxy")
		if err != nil {
			if err := l.failed("task_struct", addr, "nsproxy", err); err != nil {
				return nil, err
			}
			continue
		}
		if fs == 0 || nsproxy == 0 {
			continue
		}
		ns, err := k.Pointer(k.Memory(), nsproxy, "nsproxy", "mnt_ns")
		if err != nil {
			if err := l.failed("nsproxy", nsproxy, "mnt_ns", err); err != nil {
				return nil, err
			}
			continue
		}
		if ns == 0 || !perTask && seen[ns] {
			continue
		}
		seen[ns] = true
		out = append(out, view{task: t, namespace: ns})
	}
	return out, nil
}

func (l *lister) namespace(v view, perTask bool) ([]Mount, error) {
	k := l.k
	root, err := k.TaskFSRoot(v.task)
	if err != nil {
		return nil, l.failed("task_struct", v.task.Addr, "fs root", err)
	}
	var pid int64
	if perTask {
		if pid, err = k.PID(v.task); err != nil {
			return nil, l.failed("task_struct", v.task.Addr, "pid", err)
		}
	}
	walk, err := k.MountPoints(v.namespace)
	if err != nil {
		return nil, l.failed("mnt_namespace", v.namespace, "mounts", err)
	}
	if walk.Broken() {
		l.lost++
		at, end, read := walk.At, walk.End.String(), len(walk.Mounts)
		if !walk.Tree {
			at, end = walk.List.At, walk.List.End.String()
		}
		l.diag("%s: mnt_namespace at %#x: mounts: walk ends after %d mounts at %#x: %s", Name,
			k.Canonical(v.namespace), read, k.Canonical(at), end)
	}
	var out []Mount
	for _, mnt := range walk.Mounts {
		row, shown, err := l.record(mnt, root)
		if err != nil {
			if err := l.failed("mount", mnt, "record", err); err != nil {
				return nil, err
			}
			continue
		}
		if !shown {
			continue
		}
		row.PID, row.PIDShown = pid, perTask
		out = append(out, row)
	}
	return out, nil
}
