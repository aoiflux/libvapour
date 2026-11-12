package linuxobj

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

// S46 R1, R2: PT_OPT_FLAG_SHIFT moves PTRACE_O_* option bits into the
// task's ptrace word.
const ptraceOptionShift = 3

const ptracePtraced = 1 << 0

// S46 R1: bits 1, 30 and 31 are named at v4.19 only; later kernels do not
// set them.
var ptraceBits = []struct {
	bit  uint
	name string
}{
	{0, "PT_PTRACED"},
	{1, "PT_DTRACE"},
	{ptraceOptionShift + 0, "PT_TRACESYSGOOD"},
	{ptraceOptionShift + 1, "PT_TRACE_FORK"},
	{ptraceOptionShift + 2, "PT_TRACE_VFORK"},
	{ptraceOptionShift + 3, "PT_TRACE_CLONE"},
	{ptraceOptionShift + 4, "PT_TRACE_EXEC"},
	{ptraceOptionShift + 5, "PT_TRACE_VFORK_DONE"},
	{ptraceOptionShift + 6, "PT_TRACE_EXIT"},
	{ptraceOptionShift + 7, "PT_TRACE_SECCOMP"},
	{16, "PT_SEIZED"},
	{ptraceOptionShift + 20, "PT_EXITKILL"},
	{ptraceOptionShift + 21, "PT_SUSPEND_SECCOMP"},
	{30, "PT_BLOCKSTEP"},
	{31, "PT_SINGLESTEP"},
}

func PtraceFlagNames(v uint64) (names string, rest uint64) {
	var out []string
	rest = v
	for _, b := range ptraceBits {
		if v&(1<<b.bit) != 0 {
			out = append(out, b.name)
			rest &^= 1 << b.bit
		}
	}
	return strings.Join(out, "|"), rest
}

func (k *Kernel) ptraceWord(t Task) (uint64, error) {
	return k.Uint(k.in(t), t.Addr, "task_struct", "ptrace")
}

// S46 R3: ptrace attach sets PT_PTRACED and unlink clears the whole word.
func (k *Kernel) IsBeingPtraced(t Task) (bool, error) {
	v, err := k.ptraceWord(t)
	if err != nil {
		return false, err
	}
	return v&ptracePtraced != 0, nil
}

// S46 R4: a tracer's ptraced list holds its tracees; an empty list points
// back at itself.
func (k *Kernel) IsPtracing(t Task) (bool, error) {
	f, err := k.Member("task_struct", "ptraced")
	if err != nil {
		return false, fmt.Errorf("linuxobj: task_struct.ptraced: %w", err)
	}
	head := t.Addr + f.Offset
	next, err := k.Pointer(k.in(t), head, "list_head", "next")
	if err != nil {
		return false, err
	}
	return k.Canonical(next) != k.Canonical(head), nil
}

// S46 R4: the tracer is the tracee's parent while it is traced.
func (k *Kernel) PtraceTracerTID(t Task) (tid int64, ok bool, err error) {
	traced, err := k.IsBeingPtraced(t)
	if err != nil || !traced {
		return 0, false, err
	}
	parent, err := k.Pointer(k.in(t), t.Addr, "task_struct", "parent")
	if err != nil {
		return 0, false, err
	}
	if parent == 0 {
		return 0, false, nil
	}
	tid, err = k.Int(k.mem, parent, "task_struct", "pid")
	if err != nil {
		return 0, false, err
	}
	return tid, true, nil
}

func (k *Kernel) PtraceTraceeTIDs(t Task) ([]int64, linuxwalk.List, error) {
	f, err := k.Member("task_struct", "ptraced")
	if err != nil {
		return nil, linuxwalk.List{}, fmt.Errorf("linuxobj: task_struct.ptraced: %w", err)
	}
	walk, err := k.Walker().List(t.Addr+f.Offset, "task_struct", "ptrace_entry", linuxwalk.Forward)
	if err != nil {
		return nil, walk, err
	}
	tids := make([]int64, 0, len(walk.Entries))
	for _, tracee := range walk.Entries {
		tid, err := k.Int(k.mem, tracee, "task_struct", "pid")
		if err != nil {
			return tids, walk, fmt.Errorf("linuxobj: tracee at %#x: %w", tracee, err)
		}
		tids = append(tids, tid)
	}
	return tids, walk, nil
}

func (k *Kernel) PtraceFlags(t Task) (names string, rest uint64, traced bool, err error) {
	v, err := k.ptraceWord(t)
	if err != nil {
		return "", 0, false, err
	}
	names, rest = PtraceFlagNames(v)
	return names, rest, v != 0, nil
}
