package shellhistory

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.shell.read_history"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "Command lines held in the writable memory of running Bash shells and other programs that use the GNU History Library"},
		RunAny,
	)
}

var (
	ErrNotLinux  = errors.New("shellhistory: profile is not linux")
	ErrNoExeFile = errors.New("shellhistory: mm_struct.exe_file not in the symbol table")
	ErrUnread    = errors.New("shellhistory: structure does not read")
)

type Command struct {
	PID           int64
	Process       string
	Executable    string
	Library       string
	EntryAddress  uint64
	Index         int
	Command       string
	Timestamp     string
	CommandTime   time.Time
	CommandTimeOK bool
}

// S15c 4.1: Bash, also when its file is named sh (H7), holds the library
// itself unless built against the installed one (H8).
var shells = map[string]bool{"bash": true, "sh": true}

// S15c H9: the shared library files are lib<name>.so.<version>.
var historyLibraries = []string{"libreadline.so", "libhistory.so"}

const deletedMark = " (deleted)"

// S15c K2.
const (
	vmWrite  = 0x2
	vmShared = 0x8
)

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Command, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: %w", Name, ErrNotLinux)
	}
	k := linuxobj.New(ctx)
	vmas, err := memoryranges.NewLinuxWalker(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk, err := k.Walker().Tasks(false, k.PIDSkip(ctx.PIDs()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)
	r := &reader{ctx: ctx, k: k, vmas: vmas, lim: ctx.Bounds()}
	var out []Command
	for _, task := range walk.Tasks {
		rows, err := r.task(task)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		out = append(out, rows...)
	}
	if r.unreadPages > 0 {
		ctx.AddDiagnostic("%s: %d pages of searched memory do not read", Name, r.unreadPages)
	}
	if r.unnamed.count > 0 {
		ctx.AddDiagnostic("%s: %d processes whose executable or mapped file names do not all read were chosen by the names that read, first: %s",
			Name, r.unnamed.count, r.unnamed.first)
	}
	if r.lossy && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: processes or memory areas were left out", Name)
	}
	return out, nil
}

type reader struct {
	ctx         tools.Context
	k           *linuxobj.Kernel
	vmas        *memoryranges.LinuxWalker
	lim         limits.Limits
	unreadPages int
	unnamed     tally
	lossy       bool
}

type tally struct {
	count int
	first string
}

func (t *tally) add(format string, args ...any) {
	if t.count == 0 {
		t.first = fmt.Sprintf(format, args...)
	}
	t.count++
}

func (r *reader) skip(task uint64, pid int64, format string, args ...any) {
	r.lossy = true
	r.ctx.AddDiagnostic("%s: process %d at %#x: "+format, append([]any{Name, pid, task}, args...)...)
}

func (r *reader) task(task uint64) ([]Command, error) {
	k := r.k
	t := linuxobj.Task{Addr: task}
	pid, err := k.PID(t)
	if err != nil {
		r.skip(task, -1, "pid does not read: %v", err)
		return nil, nil
	}
	comm, err := k.Comm(t)
	if err != nil {
		r.skip(task, pid, "comm does not read: %v", err)
		return nil, nil
	}
	mm, vmas, walkErr := r.vmas.TaskVMAs(task)
	if mm == 0 {
		if walkErr != nil {
			r.skip(task, pid, "memory areas not walked: %v", walkErr)
		}
		return nil, nil
	}
	exe, lib, chosen := r.choose(task, pid, mm, vmas)
	if !chosen {
		return nil, nil
	}
	if walkErr != nil {
		r.skip(task, pid, "memory areas walked in part: %v", walkErr)
	}
	layer, ok, why, err := k.ProcessLayer(t)
	if err != nil {
		return nil, err
	}
	if !ok {
		if why != nil {
			r.skip(task, pid, "no address space: %v", why)
		}
		return nil, nil
	}
	sp := r.memory(task, pid, layer, vmas)
	list, others := findList(sp, uint64(r.lim.MaxTextBytes))
	if others > 0 {
		r.ctx.AddDiagnostic("%s: process %d at %#x: %d shorter or later entry arrays are not the history list", Name, pid, task, others)
	}
	out := make([]Command, 0, len(list.entries))
	for i, e := range list.entries {
		c := Command{PID: pid, Process: comm, Executable: exe, Library: lib, EntryAddress: e.at, Index: i,
			Command: e.line, Timestamp: e.stamp}
		c.CommandTime, c.CommandTimeOK = parseStamp(e.digits)
		out = append(out, c)
	}
	return out, nil
}

// S15c 4.1: the executable file and the mapped files choose the process; comm
// is the process's own to change (O4).
func (r *reader) choose(task uint64, pid int64, mm uint64, vmas []memoryranges.LinuxVMA) (exe, lib string, chosen bool) {
	var why string
	defer func() {
		if why != "" {
			r.unnamed.add("process %d at %#x: %s", pid, task, why)
		}
	}()
	exe, err := r.executable(task, mm)
	if err != nil {
		why = fmt.Sprintf("executable: %v", err)
	}
	if shells[baseName(exe)] {
		return exe, "", true
	}
	names := map[uint64]bool{}
	for _, v := range vmas {
		if v.File == 0 || names[v.File] {
			continue
		}
		names[v.File] = true
		path, named, err := r.vmas.AreaName(task, mm, v)
		if err != nil || !named {
			if err != nil && why == "" {
				why = fmt.Sprintf("vm_area_struct at %#x: %v", v.Addr, err)
			}
			continue
		}
		name := baseName(path)
		for _, l := range historyLibraries {
			if strings.HasPrefix(name, l) {
				return exe, path, true
			}
		}
	}
	return exe, "", false
}

// S61 I1: /proc/<pid>/exe is the f_path of mm->exe_file.
func (r *reader) executable(task, mm uint64) (string, error) {
	k := r.k
	if !k.Has("mm_struct", "exe_file") {
		return "", ErrNoExeFile
	}
	file, ok, err := k.Deref(k.Memory(), mm, "mm_struct", "exe_file")
	if err != nil {
		return "", fmt.Errorf("mm_struct at %#x: exe_file: %w", mm, err)
	}
	if file == 0 {
		return "", nil
	}
	if !ok {
		return "", fmt.Errorf("file at %#x: %w", file, ErrUnread)
	}
	return r.vmas.OpenFileName(task, file, false)
}

func baseName(path string) string {
	path = strings.TrimSuffix(path, deletedMark)
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

func (r *reader) memory(task uint64, pid int64, layer linuxobj.ProcessLayer, vmas []memoryranges.LinuxVMA) *space {
	k := r.k
	sp := newSpace(k.PointerSize())
	budget := uint64(r.lim.MaxRegionScanBytes)
	var flagErrs int
	for _, v := range vmas {
		flags, err := k.Uint(k.Memory(), v.Addr, "vm_area_struct", "vm_flags")
		if err != nil {
			flagErrs++
			continue
		}
		if flags&vmWrite == 0 || flags&vmShared != 0 {
			continue
		}
		for page := v.Start &^ (pageSize - 1); page < v.End; page += pageSize {
			if budget < pageSize {
				r.skip(task, pid, "search stops at Limits.MaxRegionScanBytes")
				return sp
			}
			budget -= pageSize
			b, err := layer.Reader.ReadAt(page, pageSize)
			if err != nil || len(b) < pageSize {
				r.unreadPages++
				continue
			}
			sp.add(page, b)
		}
	}
	if flagErrs > 0 {
		r.skip(task, pid, "%d memory areas whose vm_flags do not read are not searched", flagErrs)
	}
	return sp
}
