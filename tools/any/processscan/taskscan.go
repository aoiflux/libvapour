package processscan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

var (
	ErrNoTaskMember = errors.New("processscan: symbol table lacks a task_struct member the scan needs")
	ErrNoDirectMap  = errors.New("processscan: page_offset_base does not resolve or read")
	ErrPointerSize  = errors.New("processscan: task scan needs 8-byte pointers")
)

type ExitState string

const (
	ExitNone   ExitState = ""
	ExitZombie ExitState = "EXIT_ZOMBIE"
	ExitDead   ExitState = "EXIT_DEAD"
	ExitTrace  ExitState = "EXIT_TRACE"
)

// include/linux/sched.h; exit_state holds no other value (S65 K7).
var exitStates = map[uint32]ExitState{0: ExitNone, 0x10: ExitDead, 0x20: ExitZombie, 0x30: ExitTrace}

// PID_MAX_LIMIT when long is 8 bytes (include/linux/threads.h); alloc_pid
// hands out numbers below it (S65 K6).
const pidLimit = 4 * 1024 * 1024

const sweepWindow = 1 << 20

type LinuxTask struct {
	Offset         uint64
	Address        uint64
	PID, TID, PPID int64
	Comm           string
	ExitState      ExitState
}

type taskShape struct {
	ptraced, ptraceEntry, pid, tgid, leader, realParent, parent, exitState, comm uint64
}

func resolveTaskShape(k *linuxobj.Kernel) (taskShape, error) {
	var s taskShape
	for _, m := range []struct {
		at   *uint64
		name string
	}{
		{&s.ptraced, "ptraced"}, {&s.ptraceEntry, "ptrace_entry"}, {&s.pid, "pid"}, {&s.tgid, "tgid"},
		{&s.leader, "group_leader"}, {&s.realParent, "real_parent"}, {&s.parent, "parent"},
		{&s.exitState, "exit_state"}, {&s.comm, "comm"},
	} {
		f, err := k.Member("task_struct", m.name)
		if err != nil {
			return s, fmt.Errorf("%s: task_struct.%s: %w: %w", Name, m.name, ErrNoTaskMember, err)
		}
		*m.at = f.Offset
	}
	return s, nil
}

type refusal int

const (
	refusedIDs refusal = iota
	refusedLeader
	refusedParents
	refusedExitState
	refusedName
	refusalKinds
)

var refusalNames = [refusalKinds]string{"ids", "group leader", "parents", "exit state", "name"}

// Every new task starts with both ptrace heads empty, each pointing at its
// own direct-map address (S65 K2 to K4); the scan anchors on that pair.
func ownAddressHeads(phys memory.MemoryReader, base uint64) ([]uint64, memory.Coverage) {
	var heads []uint64
	cov := memory.ScanWindows(phys, sweepWindow, 8, func(off uint64, w []byte) bool {
		start := int((8 - off%8) % 8)
		for i := start; i+16 <= len(w) && i < sweepWindow; i += 8 {
			at := off + uint64(i)
			v := binary.LittleEndian.Uint64(w[i:])
			if v == base+at && binary.LittleEndian.Uint64(w[i+8:]) == v {
				heads = append(heads, at)
			}
		}
		return false
	})
	slices.Sort(heads)
	return slices.Compact(heads), cov
}

func read32(r memory.MemoryReader, at uint64) (uint32, bool) {
	b, err := r.ReadAt(at, 4)
	if err != nil || len(b) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}

func read64(r memory.MemoryReader, at uint64) (uint64, bool) {
	b, err := r.ReadAt(at, 8)
	if err != nil || len(b) < 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

func kernelHalf(addr uint64) bool { return addr>>63 == 1 }

func judgeTask(phys memory.MemoryReader, s taskShape, task, address uint64) (ExitState, refusal, bool) {
	pid, ok1 := read32(phys, task+s.pid)
	tgid, ok2 := read32(phys, task+s.tgid)
	if !ok1 || !ok2 || int32(pid) < 1 || int32(tgid) < 1 || pid >= pidLimit || tgid >= pidLimit {
		return "", refusedIDs, false
	}
	leader, ok := read64(phys, task+s.leader)
	if !ok || leader == address && pid != tgid || leader != address && (!kernelHalf(leader) || pid == tgid) {
		return "", refusedLeader, false
	}
	realParent, ok1 := read64(phys, task+s.realParent)
	parent, ok2 := read64(phys, task+s.parent)
	if !ok1 || !ok2 || !kernelHalf(realParent) || !kernelHalf(parent) {
		return "", refusedParents, false
	}
	raw, ok := read32(phys, task+s.exitState)
	state, known := exitStates[raw]
	if !ok || !known {
		return "", refusedExitState, false
	}
	comm, err := phys.ReadAt(task+s.comm, linuxobj.TaskCommLen)
	if err != nil || uint64(len(comm)) < linuxobj.TaskCommLen || bytes.IndexByte(comm, 0) < 0 {
		return "", refusedName, false
	}
	return state, 0, true
}

func RunLinux(ctx tools.Context) ([]LinuxTask, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	phys := ctx.PhysicalMemory()
	if phys == nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPhysicalMemory)
	}
	k := linuxobj.New(ctx)
	if k.PointerSize() != 8 {
		return nil, fmt.Errorf("%s: %w", Name, ErrPointerSize)
	}
	s, err := resolveTaskShape(k)
	if err != nil {
		return nil, err
	}
	base, err := directMapBase(k)
	if err != nil {
		return nil, err
	}
	heads, cov := ownAddressHeads(phys, base)
	if err := cov.Incomplete(); err != nil {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: physical sweep incomplete: %w", Name, err)
		}
		ctx.AddDiagnostic("%s: physical sweep incomplete: %v", Name, err)
	}
	pids := ctx.PIDs()
	var out []LinuxTask
	var refused [refusalKinds]int
	candidates := 0
	for _, h := range heads {
		if h < s.ptraced {
			continue
		}
		task := h - s.ptraced
		if _, found := slices.BinarySearch(heads, task+s.ptraceEntry); !found {
			continue
		}
		candidates++
		address := base + task
		state, why, ok := judgeTask(phys, s, task, address)
		if !ok {
			refused[why]++
			continue
		}
		f, err := k.TaskFields(linuxobj.Task{Addr: task, In: phys}, false)
		if err != nil {
			if ctx.StrictMode() {
				return nil, fmt.Errorf("%s: task at 0x%x: summary does not read: %w", Name, task, err)
			}
			ctx.AddDiagnostic("%s: task at 0x%x: summary does not read: %v", Name, task, err)
			continue
		}
		if !pids.Keep(uint64(f.PID)) {
			continue
		}
		out = append(out, LinuxTask{Offset: task, Address: address, PID: f.PID, TID: f.TID, PPID: f.PPID, Comm: f.Comm, ExitState: state})
	}
	parts := make([]string, 0, refusalKinds)
	for i, n := range refused {
		parts = append(parts, fmt.Sprintf("%s %d", refusalNames[i], n))
	}
	ctx.AddDiagnostic("%s: %d tasks from %d own-address list heads, %d candidates; refused: %s", Name, len(out), len(heads),
		candidates, strings.Join(parts, ", "))
	return out, nil
}

func directMapBase(k *linuxobj.Kernel) (uint64, error) {
	sym, err := k.Symbol("page_offset_base")
	if err != nil {
		return 0, fmt.Errorf("%s: %w: %w", Name, ErrNoDirectMap, err)
	}
	v, err := k.PointerAt(k.Memory(), sym.Address)
	if err != nil {
		return 0, fmt.Errorf("%s: %w: %w", Name, ErrNoDirectMap, err)
	}
	if v == 0 {
		return 0, fmt.Errorf("%s: %w: it reads 0", Name, ErrNoDirectMap)
	}
	return v, nil
}
