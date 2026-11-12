package processidentity

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processarguments"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.process.check_identity"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Compare each Linux process's comm and first argument with the name of its executable",
		},
		RunAny,
	)
}

// S61 I3: d_path marks an unlinked file this way.
const deletedMark = " (deleted)"

var errNotRead = errors.New("processidentity: structure does not read")

type Process struct {
	PID, PPID       int64
	Comm            string
	ExePath         string
	ExeName         string
	ExeRead         bool
	ExeDeleted      bool
	ArgumentName    string
	ArgumentRead    bool
	ArgumentTitle   bool
	CommDiffers     bool
	ArgumentDiffers bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type tally struct {
	count int
	first string
}

func (t *tally) add(addr uint64, why error) {
	if t.count == 0 {
		t.first = fmt.Sprintf("task_struct at %#x: %v", addr, why)
	}
	t.count++
}

func Run(ctx tools.Context) ([]Process, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	k := linuxobj.New(ctx)
	lw, err := memoryranges.NewLinuxWalker(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk, err := k.Walker().Tasks(false, k.PIDSkip(ctx.PIDs()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)

	var out []Process
	var skipped, noPath, noArgs tally
	for _, addr := range walk.Tasks {
		t := linuxobj.Task{Addr: addr}
		p, err := identity(k, t)
		if err != nil {
			skipped.add(addr, err)
			continue
		}
		kernelThread, err := k.IsKernelThread(t)
		if err != nil {
			skipped.add(addr, err)
			continue
		}
		if !kernelThread {
			if why := executable(k, lw, t, &p); why != nil {
				noPath.add(addr, why)
			}
			args, held, why, err := processarguments.ReadLinuxArguments(k, t)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", Name, err)
			}
			if why != nil {
				noArgs.add(addr, why)
			}
			if held && len(args.Words) > 0 {
				p.ArgumentName, p.ArgumentRead, p.ArgumentTitle = baseName(args.Words[0]), true, args.Title
			}
		}
		compare(&p)
		out = append(out, p)
	}
	if skipped.count > 0 {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: strict mode: %d processes not read, first: %s", Name, skipped.count, skipped.first)
		}
		ctx.AddDiagnostic("%s: %d processes not read, first: %s", Name, skipped.count, skipped.first)
	}
	if noPath.count > 0 {
		ctx.AddDiagnostic("%s: %d executable paths not built, first: %s", Name, noPath.count, noPath.first)
	}
	if noArgs.count > 0 {
		ctx.AddDiagnostic("%s: %d argument areas not read, first: %s", Name, noArgs.count, noArgs.first)
	}
	return out, nil
}

func identity(k *linuxobj.Kernel, t linuxobj.Task) (Process, error) {
	var p Process
	var err error
	if p.PID, err = k.TGID(t); err != nil {
		return p, err
	}
	if p.PPID, err = k.ParentPID(t); err != nil {
		return p, err
	}
	p.Comm, err = k.Comm(t)
	return p, err
}

// S61 I1: /proc/<pid>/exe is the f_path of mm->exe_file.
func executable(k *linuxobj.Kernel, lw *memoryranges.LinuxWalker, t linuxobj.Task, p *Process) error {
	mm, ok, err := k.Deref(k.Memory(), t.Addr, "task_struct", "mm")
	if err != nil || mm == 0 {
		return err
	}
	if !ok {
		return fmt.Errorf("mm_struct at %#x: %w", mm, errNotRead)
	}
	file, ok, err := k.Deref(k.Memory(), mm, "mm_struct", "exe_file")
	if err != nil {
		return fmt.Errorf("mm_struct at %#x: exe_file: %w", mm, err)
	}
	if file == 0 {
		return nil
	}
	if !ok {
		return fmt.Errorf("file at %#x: %w", file, errNotRead)
	}
	path, err := lw.OpenFileName(t.Addr, file, false)
	if err != nil {
		return fmt.Errorf("file at %#x: %w", file, err)
	}
	p.ExePath, p.ExeRead = path, true
	p.ExeDeleted = strings.HasSuffix(path, deletedMark)
	p.ExeName = baseName(strings.TrimSuffix(path, deletedMark))
	return nil
}

// S61 I2: kbasename, the part after the last slash.
func baseName(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// S61 I4: exec writes at most TASK_COMM_LEN - 1 bytes of the name into comm.
// An empty first argument has no name to compare (S61 M22).
func compare(p *Process) {
	if !p.ExeRead || p.ExeName == "" {
		return
	}
	name := p.ExeName
	if n := linuxobj.TaskCommLen - 1; len(name) > n {
		name = name[:n]
	}
	p.CommDiffers = p.Comm != name
	p.ArgumentDiffers = p.ArgumentRead && p.ArgumentName != "" && p.ArgumentName != p.ExeName
}
