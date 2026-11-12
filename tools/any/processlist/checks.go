package processlist

import (
	"encoding/binary"
	"errors"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

var (
	ErrCheckUnusable = errors.New("processlist: symbol table lacks a member the check needs")
	ErrMemberUnread  = errors.New("processlist: candidate member does not read")
	ErrNoImageName   = errors.New("processlist: image name is empty")
	ErrBadID         = errors.New("processlist: id is 0, not a multiple of 4, or wider than a dword")
	ErrCreateTime    = errors.New("processlist: creation time outside the capture window")
	ErrExitTime      = errors.New("processlist: exit time outside the capture window or before creation")
	ErrPageTableRoot = errors.New("processlist: page-table root outside physical memory")
	ErrThreadLinks   = errors.New("processlist: thread list links outside system space")
)

const (
	// The largest multiple of 4 that a DWORD holds (S17 4.2 step 2).
	maxID = uint64(0xFFFFFFFC)
	// FileTimeToSystemTime refuses values from 2^63 on (S17 F2).
	maxFileTime = uint64(1)<<63 - 1
	// S17 4.4 and open point O1.
	captureAllowance = uint64(24 * 60 * 60 * 10_000_000)
	// CR3 bits 11:0 never hold address bits, and MAXPHYADDR is at most 52 (S17 F7).
	pageTableFlagBits = uint64(0xFFF)
	maxPhysicalBits   = 52
)

type TimeWindow struct {
	Earliest uint64
	Latest   uint64
}

func (w TimeWindow) Holds(ft uint64) bool { return w.Earliest <= ft && ft <= w.Latest }

func ReadTimeWindow(ctx tools.Context) TimeWindow {
	w := TimeWindow{Earliest: 1, Latest: maxFileTime}
	if ctx.Symbols == nil || ctx.Memory == nil {
		return w
	}
	if f, err := ctx.Symbols.Field("_KUSER_SHARED_DATA", "SystemTime"); err == nil {
		if now, ok := readU64(ctx.Memory, winkernel.SharedDataAddress(ctx.Symbols)+f.Offset); ok && now != 0 {
			if now <= maxFileTime-captureAllowance {
				w.Latest = now + captureAllowance
			}
		}
	}
	boot, okBoot := readGlobal(ctx, "KeBootTime")
	bias, okBias := readGlobal(ctx, "KeBootTimeBias")
	if okBoot && okBias {
		magnitude := bias
		if int64(bias) < 0 {
			magnitude = uint64(-int64(bias))
		}
		if boot > magnitude {
			w.Earliest = boot - magnitude
		}
	}
	return w
}

func readGlobal(ctx tools.Context, name string) (uint64, bool) {
	sym, err := ctx.Symbols.LookupSymbol(name)
	if err != nil {
		return 0, false
	}
	return readU64(ctx.Memory, sym.Address)
}

func readU64(r memory.MemoryReader, at uint64) (uint64, bool) {
	b, err := r.ReadAt(at, 8)
	if err != nil || len(b) < 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

type member struct {
	at    uint64
	width uint64
	ok    bool
}

func memberOf(table symbols.SymbolTable, path ...string) member {
	var at uint64
	for i := 0; i+1 < len(path); i += 2 {
		f, err := table.Field(path[i], path[i+1])
		if err != nil {
			return member{}
		}
		at += f.Offset
	}
	width := uint64(table.PointerSize())
	if sizer, ok := table.(symbols.FieldSizer); ok && len(path) >= 2 {
		if n, err := sizer.FieldSize(path[len(path)-2], path[len(path)-1]); err == nil && (n == 4 || n == 8) {
			width = n
		}
	}
	return member{at: at, width: width, ok: true}
}

func (m member) read(r memory.MemoryReader, base uint64) (uint64, error) {
	b, err := r.ReadAt(base+m.at, m.width)
	if err != nil || uint64(len(b)) < m.width {
		return 0, ErrMemberUnread
	}
	if m.width == 4 {
		return uint64(binary.LittleEndian.Uint32(b)), nil
	}
	return binary.LittleEndian.Uint64(b), nil
}

func validID(id uint64) bool { return id != 0 && id%4 == 0 && id <= maxID }

type ProcessIdentity struct {
	PID  uint64
	Name string
}

type ProcessCheck struct {
	name        symbols.CharArrayField
	pid         member
	created     member
	exited      member
	root        member
	threadLinks [2]member
	pointer     uint64
	frameLimit  uint64
	window      TimeWindow
	usable      bool
}

func NewProcessCheck(ctx tools.Context) ProcessCheck {
	c := ProcessCheck{window: ReadTimeWindow(ctx)}
	if ctx.Symbols == nil {
		return c
	}
	t := ctx.Symbols
	c.pointer = uint64(t.PointerSize())
	name, err := symbols.ResolveCharArray(t, "_EPROCESS", "ImageFileName", WindowsImageNameLength)
	c.pid = memberOf(t, "_EPROCESS", "UniqueProcessId")
	c.pid.width = c.pointer
	c.usable = err == nil && c.pid.ok
	c.name = name
	c.created = memberOf(t, "_EPROCESS", "CreateTime")
	c.created.width = 8
	c.exited = memberOf(t, "_EPROCESS", "ExitTime")
	c.exited.width = 8
	c.root = memberOf(t, "_EPROCESS", "Pcb", "_KPROCESS", "DirectoryTableBase")
	head := memberOf(t, "_EPROCESS", "ThreadListHead")
	flink, blink := memberOf(t, "_LIST_ENTRY", "Flink"), memberOf(t, "_LIST_ENTRY", "Blink")
	if head.ok && flink.ok && blink.ok {
		c.threadLinks = [2]member{
			{at: head.at + flink.at, width: c.pointer, ok: true},
			{at: head.at + blink.at, width: c.pointer, ok: true},
		}
	}
	c.frameLimit = uint64(1) << maxPhysicalBits
	if phys := ctx.PhysicalMemory(); phys != nil && phys.Size() > 0 {
		c.frameLimit = phys.Size()
	}
	return c
}

func (c ProcessCheck) Usable() bool { return c.usable }

func (c ProcessCheck) Window() TimeWindow { return c.window }

func (c ProcessCheck) Check(r memory.MemoryReader, eprocess uint64) (ProcessIdentity, error) {
	if !c.usable {
		return ProcessIdentity{}, ErrCheckUnusable
	}
	name, err := c.name.Read(r, eprocess)
	if err != nil {
		return ProcessIdentity{}, ErrMemberUnread
	}
	if name == "" {
		return ProcessIdentity{}, ErrNoImageName
	}
	pid, err := c.pid.read(r, eprocess)
	if err != nil {
		return ProcessIdentity{}, err
	}
	if !validID(pid) {
		return ProcessIdentity{}, ErrBadID
	}
	if err := c.times(r, eprocess); err != nil {
		return ProcessIdentity{}, err
	}
	if err := c.pageTableRoot(r, eprocess); err != nil {
		return ProcessIdentity{}, err
	}
	if err := c.threadList(r, eprocess); err != nil {
		return ProcessIdentity{}, err
	}
	return ProcessIdentity{PID: pid, Name: name}, nil
}

func (c ProcessCheck) times(r memory.MemoryReader, eprocess uint64) error {
	if !c.created.ok {
		return nil
	}
	created, err := c.created.read(r, eprocess)
	if err != nil {
		return err
	}
	if !c.window.Holds(created) {
		return ErrCreateTime
	}
	if !c.exited.ok {
		return nil
	}
	exited, err := c.exited.read(r, eprocess)
	if err != nil {
		return err
	}
	if exited != 0 && (!c.window.Holds(exited) || exited < created) {
		return ErrExitTime
	}
	return nil
}

func (c ProcessCheck) pageTableRoot(r memory.MemoryReader, eprocess uint64) error {
	if !c.root.ok {
		return nil
	}
	root, err := c.root.read(r, eprocess)
	if err != nil {
		return err
	}
	frame := root &^ pageTableFlagBits
	if frame == 0 || frame >= c.frameLimit {
		return ErrPageTableRoot
	}
	return nil
}

func (c ProcessCheck) threadList(r memory.MemoryReader, eprocess uint64) error {
	for _, m := range c.threadLinks {
		if !m.ok {
			return nil
		}
		link, err := m.read(r, eprocess)
		if err != nil {
			return err
		}
		if link != eprocess+c.threadLinks[0].at && !inSystemSpace(link, c.pointer) {
			return ErrThreadLinks
		}
	}
	return nil
}

// S17 4.2 step 6: user space ends at 0x7FFF'FFFFFFFF on 64-bit Windows and at
// 2 GB on 32-bit Windows.
func inSystemSpace(addr, pointer uint64) bool {
	if pointer == 4 {
		return addr >= 0x80000000 && addr <= 0xFFFFFFFF
	}
	return addr>>63 == 1
}

type ThreadCheck struct {
	tid     member
	owner   member
	created member
	window  TimeWindow
	usable  bool
}

func NewThreadCheck(ctx tools.Context) ThreadCheck {
	c := ThreadCheck{window: ReadTimeWindow(ctx)}
	if ctx.Symbols == nil {
		return c
	}
	t := ctx.Symbols
	pointer := uint64(t.PointerSize())
	c.tid = memberOf(t, "_ETHREAD", "Cid", "_CLIENT_ID", "UniqueThread")
	c.owner = memberOf(t, "_ETHREAD", "Cid", "_CLIENT_ID", "UniqueProcess")
	c.tid.width, c.owner.width = pointer, pointer
	c.created = memberOf(t, "_ETHREAD", "CreateTime")
	c.created.width = 8
	c.usable = c.tid.ok && c.owner.ok
	return c
}

func (c ThreadCheck) Usable() bool { return c.usable }

func (c ThreadCheck) Check(r memory.MemoryReader, ethread uint64) error {
	if !c.usable {
		return ErrCheckUnusable
	}
	tid, err := c.tid.read(r, ethread)
	if err != nil {
		return err
	}
	owner, err := c.owner.read(r, ethread)
	if err != nil {
		return err
	}
	if !validID(tid) || !validID(owner) {
		return ErrBadID
	}
	if !c.created.ok {
		return nil
	}
	created, err := c.created.read(r, ethread)
	if err != nil {
		return err
	}
	// The System process's first threads start before the clock is set (S17 M4).
	if created > c.window.Latest || owner != systemPID && created < c.window.Earliest {
		return ErrCreateTime
	}
	return nil
}
