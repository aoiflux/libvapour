package linuxobj

import (
	"bytes"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const (
	PFKThread   = 0x00200000
	TaskCommLen = 16
)

// In is set for a task found in another layer, such as a physical scan. Only
// the task's own members are read through it; its pointers lead into kernel
// space.
type Task struct {
	Addr uint64
	In   memory.MemoryReader
}

func (k *Kernel) in(t Task) memory.MemoryReader {
	if t.In != nil {
		return t.In
	}
	return k.mem
}

func (k *Kernel) PID(t Task) (int64, error) { return k.Int(k.in(t), t.Addr, "task_struct", "pid") }

func (k *Kernel) TGID(t Task) (int64, error) { return k.Int(k.in(t), t.Addr, "task_struct", "tgid") }

// getppid reports the real parent's tgid; init_task is its own real parent,
// so a null pointer can only mean the parent is gone, which /proc shows as 0.
func (k *Kernel) ParentPID(t Task) (int64, error) {
	parent, err := k.Pointer(k.in(t), t.Addr, "task_struct", "real_parent")
	if err != nil {
		return 0, err
	}
	if parent == 0 {
		return 0, nil
	}
	return k.Int(k.mem, parent, "task_struct", "tgid")
}

// A kernel thread can hold a user mm for a while (kthread_use_mm), so the
// flag, not a null mm, decides.
func (k *Kernel) IsKernelThread(t Task) (bool, error) {
	flags, err := k.Uint(k.in(t), t.Addr, "task_struct", "flags")
	if err != nil {
		return false, err
	}
	return flags&PFKThread != 0, nil
}

func (k *Kernel) Comm(t Task) (string, error) {
	f, err := k.sym.Field("task_struct", "comm")
	if err != nil {
		return "", fmt.Errorf("linuxobj: task_struct.comm: %w", err)
	}
	n := f.Type.ArrayLength
	if n == 0 {
		n = TaskCommLen
	}
	raw, err := k.in(t).ReadAt(t.Addr+f.Offset, n)
	if err == nil && uint64(len(raw)) < n {
		err = memory.ErrUnmapped
	}
	if err != nil {
		return "", fmt.Errorf("linuxobj: task_struct.comm at %#x: %w", t.Addr+f.Offset, err)
	}
	return commName(raw), nil
}

// The kernel always leaves a NUL in comm, so one without is damage; keeping
// all of it keeps the task visible instead of dropping it.
func commName(raw []byte) string {
	if end := bytes.IndexByte(raw, 0); end >= 0 {
		raw = raw[:end]
	}
	return string(raw)
}

func decorateComm(comm string, kernelThread bool, tid, pid int64) string {
	switch {
	case kernelThread:
		return "[" + comm + "]"
	case tid != pid:
		return "{" + comm + "}"
	}
	return comm
}

func (k *Kernel) PIDSkip(pids tools.PIDSet) linuxwalk.TaskFilter {
	if pids.All() {
		return nil
	}
	return func(task uint64) (bool, error) {
		pid, err := k.TGID(Task{Addr: task})
		if err != nil {
			return false, err
		}
		return pid < 0 || !pids.Keep(uint64(pid)), nil
	}
}
