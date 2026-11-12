package processlist

import (
	"fmt"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const OptionThreads = "any.process.list.threads"

const OptionDecorateComm = "any.process.list.decorate_comm"

const FileOutputDisabled = "Disabled"

type LinuxColumns struct {
	Read                 bool
	Unread               error
	PID, TID, PPID       int64
	PPIDRead             bool
	Comm                 string
	Thread               bool
	UID, GID, EUID, EGID int64
	CredsRead            bool
	CreationTime         time.Time
	CreationTimeErr      error
}

type taskFailure struct {
	what  string
	at    uint64
	err   error
	count int
}

// Each kind is reported once with its first task, so a cause shared by every
// task (a missing member) gives two lines, not one per task.
type taskFailures struct {
	kinds []*taskFailure
	// Kinds with no mark in the row; strict mode refuses the result on these.
	unmarked *taskFailure
}

func (f *taskFailures) add(what string, at uint64, err error, marked bool) {
	for _, k := range f.kinds {
		if k.what == what {
			k.count++
			return
		}
	}
	k := &taskFailure{what: what, at: at, err: err, count: 1}
	f.kinds = append(f.kinds, k)
	if !marked && f.unmarked == nil {
		f.unmarked = k
	}
}

func (f *taskFailures) report(ctx tools.Context) error {
	if f.unmarked != nil && ctx.StrictMode() {
		return failureError(Name+": strict mode", f.unmarked)
	}
	for _, k := range f.kinds {
		ctx.AddDiagnostic("%v", failureError(Name, k))
		if k.count > 1 {
			ctx.AddDiagnostic("%s: %d more tasks: %s", Name, k.count-1, k.what)
		}
	}
	return nil
}

func failureError(prefix string, k *taskFailure) error {
	if k.err == nil {
		return fmt.Errorf("%s: task at %#x: %s", prefix, k.at, k.what)
	}
	return fmt.Errorf("%s: task at %#x: %s: %w", prefix, k.at, k.what, k.err)
}

func readLinuxColumns(k *linuxobj.Kernel, addr uint64, decorate, thread bool, fails *taskFailures) (LinuxColumns, string) {
	f, err := k.TaskFields(linuxobj.Task{Addr: addr}, decorate)
	if err != nil {
		fails.add("columns do not read", addr, err, false)
		return LinuxColumns{Unread: err, Thread: thread}, ""
	}
	if f.ParentErr != nil {
		fails.add("parent does not read", addr, f.ParentErr, true)
	}
	if f.CredsErr != nil {
		fails.add("credentials do not read", addr, f.CredsErr, true)
	}
	return LinuxColumns{
		Read: true, PID: f.PID, TID: f.TID, PPID: f.PPID, PPIDRead: f.ParentErr == nil, Comm: f.Name, Thread: thread,
		UID: f.Creds.UID, GID: f.Creds.GID, EUID: f.Creds.EUID, EGID: f.Creds.EGID, CredsRead: f.CredsRead,
		CreationTime: f.CreationTime, CreationTimeErr: f.CreationTimeErr,
	}, f.Comm
}

func appendThreads(k *linuxobj.Kernel, out []Process, leader uint64, decorate bool, fails *taskFailures) []Process {
	list, err := k.Walker().Threads(leader)
	if err != nil {
		fails.add("thread list does not read", leader, err, false)
		return out
	}
	if w := list.Walks[0]; w.Broken() {
		fails.add("thread list ends early", leader,
			fmt.Errorf("after %d threads at %#x: %s", len(w.Entries), w.At, w.End), false)
	}
	for _, why := range list.Reasons() {
		fails.add("threads left out", leader, fmt.Errorf("%d: %s", list.Invalid[why], why), false)
	}
	for _, addr := range list.Tasks {
		cols, comm := readLinuxColumns(k, addr, decorate, true, fails)
		if !cols.Read {
			continue
		}
		out = append(out, Process{PID: uint64(cols.TID), Name: comm, EPROCESS: addr, Linux: cols})
	}
	return out
}

func linuxTool(ctx tools.Context, rows []Process) ([]Process, error) {
	threads, err := ctx.BoolOption(OptionThreads)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	decorate, err := ctx.BoolOption(OptionDecorateComm)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	k := linuxobj.New(ctx)
	var fails taskFailures
	out := make([]Process, 0, len(rows))
	for _, p := range rows {
		p.Linux, _ = readLinuxColumns(k, p.EPROCESS, decorate, false, &fails)
		out = append(out, p)
		if threads {
			out = appendThreads(k, out, p.EPROCESS, decorate, &fails)
		}
	}
	if err := fails.report(ctx); err != nil {
		return nil, err
	}
	return out, nil
}
