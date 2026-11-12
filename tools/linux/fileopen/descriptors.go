package fileopen

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.file.list_open"

const OptionFilesOnly = "linux.file.list_open.files_only"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List each Linux task's open descriptors with the name /proc/<pid>/fd gives them and the stat facts of their inodes",
		},
		RunAny,
	)
}

var ErrNotLinux = errors.New("fileopen: the profile is not linux")

type File struct {
	PID, TID                          int64
	Process                           string
	FD                                uint64
	FileAddress                       uint64
	Path                              string
	PathUnresolved                    bool
	Device                            string
	DeviceOK                          bool
	InodeOK                           bool
	Inode                             uint64
	Type                              string
	TypeOK                            bool
	Mode                              string
	Changed, Modified, Accessed       time.Time
	ChangedOK, ModifiedOK, AccessedOK bool
	Size                              int64
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]File, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: %w", Name, ErrNotLinux)
	}
	filesOnly, err := ctx.BoolOption(OptionFilesOnly)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	k := linuxobj.New(ctx)
	paths, err := memoryranges.NewLinuxWalker(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk, err := k.Walker().Tasks(true, k.PIDSkip(ctx.PIDs()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)

	l := &lister{k: k, paths: paths, filesOnly: filesOnly, diag: ctx.AddDiagnostic}
	var out []File
	for _, task := range walk.Tasks {
		rows, err := l.task(task)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		out = append(out, rows...)
	}
	if l.lost.any() && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: %s", Name, l.lost)
	}
	return out, nil
}

type losses struct {
	tables, paths, inodes int
}

func (l losses) any() bool { return l.tables+l.paths+l.inodes > 0 }

func (l losses) String() string {
	return fmt.Sprintf("%d descriptor tables read in part, %d paths not built, %d inodes not read",
		l.tables, l.paths, l.inodes)
}

type lister struct {
	k         *linuxobj.Kernel
	paths     *memoryranges.LinuxWalker
	filesOnly bool
	diag      func(string, ...any)
	lost      losses
}

// A layout the readers do not recognise would fail every task the same way,
// so it ends the tool instead of being counted per task.
func layoutGap(err error) bool {
	return errors.Is(err, linuxobj.ErrUnsupported) || linuxobj.TableGap(err)
}

func (l *lister) failed(count *int, object string, at uint64, what string, err error) error {
	if layoutGap(err) {
		return fmt.Errorf("%s at %#x: %s: %w", object, l.k.Canonical(at), what, err)
	}
	*count++
	l.diag("%s: %s at %#x: %s: %v", Name, object, l.k.Canonical(at), what, err)
	return nil
}

func (l *lister) task(addr uint64) ([]File, error) {
	k := l.k
	t := linuxobj.Task{Addr: addr}
	table, held, err := k.TaskFDs(t)
	if err != nil {
		return nil, l.failed(&l.lost.tables, "task_struct", addr, "descriptor table", err)
	}
	if !held {
		return nil, nil
	}
	open, slotErr := k.OpenFiles(table)
	if len(open) > 0 {
		base, err := l.identity(t)
		if err != nil {
			return nil, l.failed(&l.lost.tables, "task_struct", addr, "identity", err)
		}
		rows := make([]File, 0, len(open))
		for _, f := range open {
			row := base
			row.FD, row.FileAddress = f.FD, k.Canonical(f.File)
			if err := l.name(addr, f.File, &row); err != nil {
				return nil, err
			}
			if err := l.inode(f.File, &row); err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
		if slotErr != nil {
			return rows, l.failed(&l.lost.tables, "fdtable", table.Array, "descriptor slots", slotErr)
		}
		return rows, nil
	}
	if slotErr != nil {
		return nil, l.failed(&l.lost.tables, "fdtable", table.Array, "descriptor slots", slotErr)
	}
	return nil, nil
}

func (l *lister) identity(t linuxobj.Task) (File, error) {
	var f File
	var err error
	if f.PID, err = l.k.TGID(t); err != nil {
		return f, err
	}
	if f.TID, err = l.k.PID(t); err != nil {
		return f, err
	}
	f.Process, err = l.k.Comm(t)
	return f, err
}

func (l *lister) name(task, file uint64, row *File) error {
	path, err := l.paths.OpenFileName(task, file, l.filesOnly)
	if err == nil {
		row.Path = path
		return nil
	}
	if memoryranges.IsPathUnresolved(err) {
		row.PathUnresolved = true
		l.lost.paths++
		l.diag("%s: file at %#x: path: %v", Name, l.k.Canonical(file), err)
		return nil
	}
	row.PathUnresolved = true
	return l.failed(&l.lost.paths, "file", file, "path", err)
}
