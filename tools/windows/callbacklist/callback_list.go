package callbacklist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/tools/winkernel"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.callback.list"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List kernel callback registrations and the module that holds each routine",
		},
		RunAny,
	)
}

var (
	ErrNot64Bit      = errors.New("callbacklist: kernel is not 64-bit")
	ErrSymbolMissing = errors.New("callbacklist: kernel symbol missing")
	ErrRecordUnread  = errors.New("callbacklist: record does not read")
	ErrStringUnread  = errors.New("callbacklist: name string does not read")
	ErrNotDevice     = errors.New("callbacklist: object is not a device object")
	ErrNotDriver     = errors.New("callbacklist: object is not a driver object")
	ErrOtherType     = errors.New("callbacklist: entry names another object type")
	ErrNullRoutine   = errors.New("callbacklist: routine is null")
)

type Kind string

const (
	KindProcessCreate      Kind = "process_create"
	KindThreadCreate       Kind = "thread_create"
	KindImageLoad          Kind = "image_load"
	KindRegistry           Kind = "registry"
	KindBugCheck           Kind = "bugcheck"
	KindBugCheckReason     Kind = "bugcheck_reason"
	KindShutdown           Kind = "shutdown"
	KindShutdownLastChance Kind = "shutdown_last_chance"
	KindFileSystemChange   Kind = "filesystem_change"
	KindPowerSetting       Kind = "power_setting"
	KindObjectHandle       Kind = "object_handle"
)

type Entry struct {
	Kind             Kind
	Routine          uint64
	Module           string
	ModuleUnreadable bool
	Symbol           string
	Record           uint64
	Detail           string
	Damage           string
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

func Run(ctx tools.Context) ([]Entry, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	if ctx.Symbols.PointerSize() != 8 {
		return nil, fmt.Errorf("%s: %w", Name, ErrNot64Bit)
	}
	mods, err := modulelist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: loaded modules: %w", Name, err)
		}
		ctx.AddDiagnostic("%s: loaded modules not read, so no routine has an owner: %v", Name, err)
	}
	return collect(ctx, modulelist.Placed(ctx, Name, mods))
}

type collector struct {
	ctx     tools.Context
	mem     memory.MemoryReader
	strict  bool
	owners  modulelist.Attributor
	walker  winkernel.ListWalker
	private privateLayout
	rows    []Entry
}

func collect(ctx tools.Context, mods []modulelist.Module) ([]Entry, error) {
	c := &collector{ctx: ctx, mem: ctx.Memory, strict: ctx.StrictMode(), owners: modulelist.NewAttributor(ctx, mods)}
	layout, err := winkernel.NativeListLayout(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	c.walker = winkernel.ListWalker{Tool: Name, Memory: ctx.Memory, Layout: layout, Limit: ctx.Bounds().MaxListEntries,
		Strict: c.strict, Report: ctx.AddDiagnostic}

	build := winkernel.ReadBuild(Name, ctx.Memory, ctx.Symbols)
	var privateErr error
	c.private, privateErr = c.privateFor(build)

	type source struct {
		run     func() error
		private bool
	}
	sources := []source{
		{func() error { return c.notifyArray(KindProcessCreate, "PspCreateProcessNotifyRoutine") }, true},
		{func() error { return c.notifyArray(KindThreadCreate, "PspCreateThreadNotifyRoutine") }, true},
		{func() error { return c.notifyArray(KindImageLoad, "PspLoadImageNotifyRoutine") }, true},
		{c.registry, true},
		{func() error {
			return c.bugChecks(KindBugCheck, "KeBugCheckCallbackListHead", "_KBUGCHECK_CALLBACK_RECORD", wdkBugCheck)
		}, false},
		{func() error {
			return c.bugChecks(KindBugCheckReason, "KeBugCheckReasonCallbackListHead", "_KBUGCHECK_REASON_CALLBACK_RECORD",
				wdkBugCheckReason)
		}, false},
		{func() error { return c.shutdowns(KindShutdown, "IopNotifyShutdownQueueHead") }, true},
		{func() error { return c.shutdowns(KindShutdownLastChance, "IopNotifyLastChanceShutdownQueueHead") }, true},
		{c.fileSystemChanges, true},
		{c.powerSettings, true},
		{c.objectHandles, true},
	}
	for _, s := range sources {
		if s.private && privateErr != nil {
			continue
		}
		if err := s.run(); err != nil {
			// Strict mode is about reads; a kernel that lacks a symbol has no
			// such registrations to misread.
			if c.strict && !errors.Is(err, ErrSymbolMissing) {
				return nil, err
			}
			ctx.AddDiagnostic("%v", err)
		}
	}
	return c.rows, nil
}

func (c *collector) privateFor(build winkernel.Build) (privateLayout, error) {
	if build.KernelErr != nil {
		c.ctx.AddDiagnostic("%s: kernel build not read, so only the wdm.h bug-check records are listed: %v", Name,
			build.KernelErr)
		return privateLayout{}, build.KernelErr
	}
	l, err := privateLayoutFor(build.Kernel)
	if err != nil {
		c.ctx.AddDiagnostic("%s: only the wdm.h bug-check records are listed: %v", Name, err)
	}
	return l, err
}

func (c *collector) symbol(name string) (uint64, error) {
	sym, err := c.ctx.Symbols.LookupSymbol(name)
	if err != nil {
		return 0, fmt.Errorf("%s: %s: %w: %w", Name, name, ErrSymbolMissing, err)
	}
	return sym.Address, nil
}

// A broken record is a row, so that the registration stays visible, and in
// strict mode the first one is the error.
func (c *collector) add(e Entry, damage error) error {
	if damage == nil && e.Routine == 0 {
		damage = fmt.Errorf("%s: %s record at 0x%x: %w", Name, e.Kind, e.Record, ErrNullRoutine)
	}
	if damage != nil {
		if c.strict {
			return damage
		}
		c.ctx.AddDiagnostic("%v", damage)
		e.Damage = damageText(damage)
	}
	if e.Routine != 0 {
		if owners := c.owners.At(e.Routine); len(owners) > 0 {
			e.Module, e.Symbol, e.ModuleUnreadable = owners[0].Module, owners[0].Symbol, owners[0].ModuleUnreadable
		}
	}
	c.rows = append(c.rows, e)
	return nil
}

func damageText(err error) string {
	for _, sentinel := range []error{ErrRecordUnread, ErrStringUnread, ErrNotDevice, ErrNotDriver, ErrOtherType, ErrNullRoutine} {
		if errors.Is(err, sentinel) {
			return strings.TrimPrefix(sentinel.Error(), "callbacklist: ")
		}
	}
	return err.Error()
}

func (c *collector) pointer(at uint64) (uint64, error) {
	b, err := c.mem.ReadAt(at, 8)
	if err != nil {
		return 0, err
	}
	if len(b) < 8 {
		return 0, fmt.Errorf("read 8 bytes, got %d", len(b))
	}
	return binary.LittleEndian.Uint64(b), nil
}

func (c *collector) unread(what string, at uint64, err error) error {
	return fmt.Errorf("%s: %s at 0x%x: %w: %w", Name, what, at, ErrRecordUnread, err)
}

func (c *collector) stringUnread(what string, at uint64, err error) error {
	return fmt.Errorf("%s: %s at 0x%x: %w: %w", Name, what, at, ErrStringUnread, err)
}

func (c *collector) unicode(at uint64) (string, error) {
	layout := util.ResolveUnicodeStringLayout(c.ctx.Symbols)
	s, err := util.ReadUnicodeString(c.mem, at, layout, uint64(c.ctx.Bounds().MaxNameBytes))
	if err != nil {
		return "", err
	}
	return util.CountedText(s.Value), nil
}

// Component is a NUL-terminated ANSI string (KeRegisterBugCheckCallback); it
// is read a page at most at a time so that a string near a page end reads.
func (c *collector) ansi(at uint64) (string, error) {
	limit := uint64(c.ctx.Bounds().MaxNameBytes)
	var out []byte
	for uint64(len(out)) < limit {
		n := 0x1000 - (at+uint64(len(out)))&0xFFF
		if rest := limit - uint64(len(out)); n > rest {
			n = rest
		}
		b, err := c.mem.ReadAt(at+uint64(len(out)), n)
		if err != nil {
			if len(out) > 0 {
				return string(out), nil
			}
			return "", err
		}
		for i, ch := range b {
			if ch == 0 {
				return string(append(out, b[:i]...)), nil
			}
		}
		out = append(out, b...)
		if uint64(len(b)) < n {
			break
		}
	}
	return string(out), nil
}

func (c *collector) walk(head uint64, label string) ([]uint64, error) {
	w, err := c.walker.Walk(head, label)
	if err != nil {
		return nil, err
	}
	return w.Entries, nil
}
