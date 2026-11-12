package socketlist

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.socket.list"

const OptionNetNS = "linux.socket.list.netns"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the sockets each Linux process holds open, with family, addresses, state and filter",
		},
		RunAny,
	)
}

type Socket struct {
	PID     int64
	TID     int64
	Process string
	FD      uint64
	Inode   uint64
	Sock    uint64
	Decoded
}

var (
	ErrNoSocketFileOps = errors.New("socketlist: symbol table has no socket_file_ops")
	ErrBackLink        = errors.New("socketlist: link does not lead back")
	ErrNullPointer     = errors.New("socketlist: null pointer")
)

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Socket, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	netns, _, err := ctx.UintOption(OptionNetNS)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	k := linuxobj.New(ctx)
	if !k.Has("task_struct", "files") {
		return nil, fmt.Errorf("%s: %w: task_struct has no files", Name, linuxobj.ErrUnsupported)
	}
	ops, err := k.Symbol("socket_file_ops")
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", Name, ErrNoSocketFileOps, err)
	}
	dec, err := NewDecoder(k)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	tasks, err := k.Walker().Tasks(true, k.PIDSkip(ctx.PIDs()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	tasks.Report(ctx.AddDiagnostic, Name)
	w := &walk{k: k, dec: dec, ops: ops.Address, netns: netns, tables: map[uint64]bool{}, lost: map[string]int{},
		first: map[string]string{}}
	for _, t := range tasks.Tasks {
		if err := w.task(linuxobj.Task{Addr: t}); err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
	}
	dec.Report(ctx.AddDiagnostic, Name)
	for _, why := range sortedKeys(w.lost) {
		ctx.AddDiagnostic("%s: %d %s, first: %s", Name, w.lost[why], why, w.first[why])
	}
	if ctx.StrictMode() {
		if len(tasks.Invalid)+tasks.ThreadListsBroken > 0 || tasks.Walks[0].Broken() || tasks.Walks[1].Broken() {
			return nil, fmt.Errorf("%s: strict mode: the task walk left tasks out", Name)
		}
		if len(w.lost) > 0 || dec.Lossy() {
			return nil, fmt.Errorf("%s: strict mode: sockets or socket fields were left out", Name)
		}
	}
	return w.out, nil
}

type walk struct {
	k      *linuxobj.Kernel
	dec    *Decoder
	ops    uint64
	netns  uint64
	tables map[uint64]bool
	out    []Socket
	lost   map[string]int
	first  map[string]string
}

func (w *walk) lose(why string, err error) {
	if w.lost[why] == 0 {
		w.first[why] = err.Error()
	}
	w.lost[why]++
}

// Threads made with CLONE_FILES share one files_struct (S13 T2), so each
// table is listed once, under the first task that holds it: the leader, as
// the task walk gives a leader before its threads.
func (w *walk) task(t linuxobj.Task) error {
	k := w.k
	files, err := k.Pointer(k.Memory(), t.Addr, "task_struct", "files")
	if err != nil {
		w.lose("tasks whose files pointer does not read", fmt.Errorf("task at %#x: %w", k.Masked(t.Addr), err))
		return nil
	}
	if files == 0 || w.tables[files] {
		return nil
	}
	w.tables[files] = true
	tab, ok, err := k.TaskFDs(t)
	if err != nil {
		return err
	}
	if !ok {
		w.lose("descriptor tables that do not read or are over Limits.MaxTableEntries",
			fmt.Errorf("task at %#x: files at %#x", k.Masked(t.Addr), k.Masked(files)))
		return nil
	}
	open, err := k.OpenFiles(tab)
	if err != nil {
		w.lose("descriptor tables cut at a slot that does not read", fmt.Errorf("task at %#x: %w", k.Masked(t.Addr), err))
	}
	var process string
	var pid, tid int64
	named := false
	for _, f := range open {
		sock, ok := w.socket(f)
		if !ok {
			continue
		}
		if !named {
			named = true
			if process, err = k.Comm(t); err != nil {
				w.lose("tasks whose comm does not read", fmt.Errorf("task at %#x: %w", k.Masked(t.Addr), err))
			}
			if pid, err = k.TGID(t); err != nil {
				return err
			}
			if tid, err = k.PID(t); err != nil {
				return err
			}
		}
		sock.PID, sock.TID, sock.Process, sock.FD = pid, tid, process, f.FD
		if w.netns != 0 && (!sock.NetNSKnown || sock.NetNS != w.netns) {
			continue
		}
		w.out = append(w.out, sock)
	}
	return nil
}

// socket follows a socket file to its sock (S13 F1-F3): f_op is
// socket_file_ops, private_data is the struct socket, and each link must
// point back.
func (w *walk) socket(f linuxobj.OpenFile) (Socket, bool) {
	k, mem := w.k, w.k.Memory()
	op, err := k.Pointer(mem, f.File, "file", "f_op")
	if err != nil {
		w.lose("open files whose f_op does not read", fmt.Errorf("file at %#x: f_op: %w", k.Masked(f.File), err))
		return Socket{}, false
	}
	if op != w.ops {
		return Socket{}, false
	}
	socket, err := k.Pointer(mem, f.File, "file", "private_data")
	if err == nil && socket == 0 {
		err = ErrNullPointer
	}
	if err != nil {
		w.lose("socket files with no socket", fmt.Errorf("file at %#x: private_data: %w", k.Masked(f.File), err))
		return Socket{}, false
	}
	if back, err := k.Pointer(mem, socket, "socket", "file"); err != nil || back != f.File {
		w.lose("sockets whose file does not lead back to the open file", backLink("socket", socket, "file", back, err))
		return Socket{}, false
	}
	sk, err := k.Pointer(mem, socket, "socket", "sk")
	if err == nil && sk == 0 {
		err = ErrNullPointer
	}
	if err != nil {
		w.lose("sockets with no sock", fmt.Errorf("socket at %#x: sk: %w", k.Masked(socket), err))
		return Socket{}, false
	}
	if back, err := k.Pointer(mem, sk, "sock", "sk_socket"); err != nil || back != socket {
		w.lose("socks whose sk_socket does not lead back to the socket", backLink("sock", sk, "sk_socket", back, err))
		return Socket{}, false
	}
	d, err := w.dec.Decode(mem, sk)
	if err != nil {
		w.lose("socks that do not read", fmt.Errorf("sock at %#x: %w", k.Masked(sk), err))
		return Socket{}, false
	}
	return Socket{Sock: k.Masked(sk), Inode: w.inode(socket), Decoded: d}, true
}

func backLink(object string, at uint64, member string, got uint64, err error) error {
	if err == nil {
		err = fmt.Errorf("%w: it holds %#x", ErrBackLink, got)
	}
	return fmt.Errorf("%s at %#x: %s: %w", object, at, member, err)
}

// inode is SOCK_INODE(socket)->i_ino; sockfs never gives inode number 0
// (S13 F5), so 0 means it did not read.
func (w *walk) inode(socket uint64) uint64 {
	k := w.k
	s, err1 := k.Member("socket_alloc", "socket")
	in, err2 := k.Member("socket_alloc", "vfs_inode")
	if err1 != nil || err2 != nil || socket < s.Offset {
		w.dec.Misses["socket_alloc.vfs_inode"]++
		return 0
	}
	ino, err := k.Uint(k.Memory(), socket-s.Offset+in.Offset, "inode", "i_ino")
	if err != nil {
		w.dec.Misses["inode.i_ino"]++
		return 0
	}
	return ino
}
