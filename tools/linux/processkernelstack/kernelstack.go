package processkernelstack

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.process.read_kernel_stack"

const OptionUnresolved = "linux.process.read_kernel_stack.unresolved"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the words on each Linux task's kernel stack, from its saved stack pointer up, that name kernel symbols",
		},
		RunAny,
	)
}

type Entry struct {
	TID         int64
	Process     string
	Slot        int64
	SlotAddress uint64
	Value       uint64
	Named       bool
	Symbol      string
	Offset      uint64
	SymbolType  string
	Module      string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

// S61 K1, K2: THREAD_SIZE is PAGE_SIZE << (2 + KASAN_STACK_ORDER), and
// KASAN_STACK_ORDER is 1 exactly when the kernel is built with KASAN, whose
// generic runtime defines __asan_load8.
const (
	pageSize        = 4096
	stackOrder      = 2
	kasanStackOrder = 1
	kasanSymbol     = "__asan_load8"
)

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

func ThreadSize(k *linuxobj.Kernel) uint64 {
	if k.HasSymbol(kasanSymbol) {
		return pageSize << (stackOrder + kasanStackOrder)
	}
	return pageSize << stackOrder
}

func Run(ctx tools.Context) ([]Entry, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	unresolved, err := ctx.BoolOption(OptionUnresolved)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	k := linuxobj.New(ctx)
	thread, err := k.Member("task_struct", "thread")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !k.Has(thread.Type.Name, "sp") || !k.Has("task_struct", "stack") {
		return nil, fmt.Errorf("%s: symbol table has no thread_struct.sp or task_struct.stack: %w", Name, linuxobj.ErrUnsupported)
	}
	ks, err := k.NewKallsyms()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	size := ThreadSize(k)
	walk, err := k.Walker().Tasks(true, k.PIDSkip(ctx.PIDs()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)

	var out []Entry
	var skipped, outside, cut tally
	for _, addr := range walk.Tasks {
		t := linuxobj.Task{Addr: addr}
		s, err := stackOf(k, t, thread.Offset, thread.Type.Name)
		if err != nil {
			skipped.add("task_struct at %#x: %v", addr, err)
			continue
		}
		if s.base == 0 {
			continue
		}
		if s.sp < s.base || s.sp-s.base >= size {
			outside.add("tid %d: sp %#x, stack %#x-%#x", s.tid, s.sp, s.base, s.base+size)
			continue
		}
		words, full := readWords(k.Memory(), s.sp, s.base+size, k.PointerSize())
		if !full {
			cut.add("tid %d: stack %#x-%#x: read stops at %#x", s.tid, s.base, s.base+size, s.sp+uint64(len(words))*k.PointerSize())
		}
		for i, v := range words {
			if v == 0 {
				continue
			}
			e := Entry{TID: s.tid, Process: s.comm, Slot: int64(i), SlotAddress: s.sp + uint64(i)*k.PointerSize(), Value: v}
			// S38 names the canonical form, which would name a non-canonical
			// word by its low bits; such a word is no address (S61 K7).
			if sym, ok := ks.SymbolAt(v); ok && k.Canonical(v) == v {
				e.Named, e.Symbol, e.Offset, e.SymbolType = true, sym.Name, sym.Offset, sym.Type
				if sym.ModuleKnown {
					e.Module = sym.Module
				}
			} else if !unresolved {
				continue
			}
			out = append(out, e)
		}
	}
	if ctx.StrictMode() {
		for _, t := range []tally{skipped, outside} {
			if t.count > 0 {
				return nil, fmt.Errorf("%s: strict mode: %d tasks not read and %d with sp outside the stack, first: %s",
					Name, skipped.count, outside.count, t.first)
			}
		}
	}
	for _, f := range []struct {
		what string
		t    tally
	}{
		{"tasks not read", skipped},
		{"tasks whose saved sp is outside their stack", outside},
		{"stacks cut at a page that does not read", cut},
	} {
		if f.t.count > 0 {
			ctx.AddDiagnostic("%s: %d %s, first: %s", Name, f.t.count, f.what, f.t.first)
		}
	}
	report := ks.Report()
	reasons := make([]string, 0, len(report))
	for why := range report {
		reasons = append(reasons, why)
	}
	sort.Strings(reasons)
	for _, why := range reasons {
		ctx.AddDiagnostic("%s: %d symbol lookups failed and were left unnamed: %s", Name, report[why].Count, report[why].First)
	}
	return out, nil
}

type stack struct {
	tid      int64
	comm     string
	base, sp uint64
}

// S61 K3, K4: the stack is task->stack, in kernel memory for every task, and a
// task that is not running saved its stack pointer in thread.sp.
func stackOf(k *linuxobj.Kernel, t linuxobj.Task, threadOff uint64, threadType string) (stack, error) {
	var s stack
	var err error
	if s.tid, err = k.PID(t); err != nil {
		return s, err
	}
	if s.comm, err = k.Comm(t); err != nil {
		return s, err
	}
	if s.base, err = k.Pointer(k.Memory(), t.Addr, "task_struct", "stack"); err != nil {
		return s, err
	}
	if s.sp, err = k.Uint(k.Memory(), t.Addr+threadOff, threadType, "sp"); err != nil {
		return s, err
	}
	s.base, s.sp = k.Canonical(s.base), k.Canonical(s.sp)
	return s, nil
}

// full is false when a page did not read; the words stop before it.
func readWords(r memory.MemoryReader, sp, end, width uint64) ([]uint64, bool) {
	if width != 4 && width != 8 || end <= sp {
		return nil, true
	}
	var words []uint64
	var carry []byte
	for at := sp; at < end; {
		n := min(pageSize-at%pageSize, end-at)
		b, err := r.ReadAt(at, n)
		if err != nil || uint64(len(b)) != n {
			return words, false
		}
		carry = append(carry, b...)
		for uint64(len(carry)) >= width {
			if width == 8 {
				words = append(words, binary.LittleEndian.Uint64(carry))
			} else {
				words = append(words, uint64(binary.LittleEndian.Uint32(carry)))
			}
			carry = carry[width:]
		}
		at += n
	}
	return words, true
}
