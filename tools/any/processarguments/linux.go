package processarguments

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	"github.com/aoiflux/libvapour/util"
)

// S61 A5: bprm_stack_limits holds argv and envp of one exec to three quarters
// of _STK_LIM (8 MiB); a larger area was set later through prctl.
const MaxLinuxExecArea = (8 << 20) / 4 * 3

const linuxPage = 4096

var (
	ErrArgumentArea    = errors.New("processarguments: argument area is larger than one exec builds")
	ErrArgumentsUnread = errors.New("processarguments: argument area does not read")
)

type LinuxArguments struct {
	Words   []string
	Title   bool
	Partial bool
}

// held is false when the task has no argument area; why is set when it has
// one that does not read whole, and err only for a session that cannot reach
// any process space.
func ReadLinuxArguments(k *linuxobj.Kernel, t linuxobj.Task) (args LinuxArguments, held bool, why, err error) {
	layer, ok, why, err := k.ProcessLayer(t)
	if err != nil {
		return args, false, nil, err
	}
	if !ok {
		return args, why != nil, why, nil
	}
	mm, rerr := k.Pointer(k.Memory(), t.Addr, "task_struct", "mm")
	if rerr != nil {
		return args, true, rerr, nil
	}
	var bounds [3]uint64
	for i, m := range []string{"arg_start", "arg_end", "env_end"} {
		if bounds[i], rerr = k.Uint(k.Memory(), mm, "mm_struct", m); rerr != nil {
			return args, true, fmt.Errorf("mm_struct at %#x: %s: %w", mm, m, rerr), nil
		}
	}
	start, end, envEnd := bounds[0], bounds[1], bounds[2]
	if envEnd == 0 || start >= end {
		return args, false, nil, nil
	}
	last, rerr := layer.Reader.ReadAt(end-1, 1)
	if rerr != nil || len(last) != 1 {
		return args, true, fmt.Errorf("byte at %#x: %w", end-1, ErrArgumentsUnread), nil
	}
	if last[0] != 0 {
		raw := readPages(layer.Reader, start, linuxPage)
		if len(raw) == 0 {
			return args, true, fmt.Errorf("title at %#x: %w", start, ErrArgumentsUnread), nil
		}
		if i := bytes.IndexByte(raw, 0); i >= 0 {
			raw = raw[:i]
		}
		return LinuxArguments{Words: []string{util.DecodeUTF8Replace(raw)}, Title: true}, true, nil, nil
	}
	if end-start > MaxLinuxExecArea {
		return args, true, fmt.Errorf("area %#x-%#x: %w", start, end, ErrArgumentArea), nil
	}
	raw := readPages(layer.Reader, start, end-start)
	args.Words = splitArguments(raw)
	if uint64(len(raw)) < end-start {
		args.Partial = true
		return args, true, fmt.Errorf("area %#x-%#x: %d of %d bytes: %w", start, end, len(raw), end-start,
			ErrArgumentsUnread), nil
	}
	return args, true, nil, nil
}

// The kernel's own read stops at the first page that does not read and
// returns what came before it.
func readPages(r memory.MemoryReader, addr, size uint64) []byte {
	out := make([]byte, 0, size)
	for uint64(len(out)) < size {
		at := addr + uint64(len(out))
		n := min(linuxPage-at%linuxPage, size-uint64(len(out)))
		b, err := r.ReadAt(at, n)
		if err != nil || uint64(len(b)) != n {
			break
		}
		out = append(out, b...)
	}
	return out
}

func splitArguments(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	raw = bytes.TrimSuffix(raw, []byte{0})
	parts := bytes.Split(raw, []byte{0})
	words := make([]string, len(parts))
	for i, p := range parts {
		words[i] = util.DecodeUTF8Replace(p)
	}
	return words
}

func runLinux(ctx tools.Context) ([]ProcessCmdline, error) {
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	k := linuxobj.New(ctx)
	pids := ctx.PIDs()
	out := make([]ProcessCmdline, 0, len(procs))
	var missed unread
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		args, _, why, err := ReadLinuxArguments(k, linuxobj.Task{Addr: p.EPROCESS})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		if why != nil {
			missed.add("task_struct", p.EPROCESS, why)
		}
		out = append(out, ProcessCmdline{PID: p.PID, Name: p.Name, Address: p.EPROCESS,
			Cmdline: strings.Join(args.Words, " "), Arguments: args.Words, CmdlineUnreadable: why != nil})
	}
	if err := missed.report(ctx); err != nil {
		return nil, err
	}
	return out, nil
}
