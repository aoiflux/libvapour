package ttycheck

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const Name = "linux.tty.check"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "List the receive handlers of each Linux tty's line discipline and the module or kernel code that holds them"},
		RunAny,
	)
}

var ErrNoDrivers = errors.New("ttycheck: tty_drivers not in the symbol table")

type Handler string

const (
	HandlerReceive  Handler = "receive_buf"
	HandlerReceive2 Handler = "receive_buf2"
)

type Row struct {
	TTY           string
	TTYAddress    uint64
	Driver        string
	DriverAddress uint64
	Discipline    string
	OpsAddress    uint64
	Handler       Handler
	Address       uint64
	Module        string
	Symbol        string
	ModuleAddress uint64
	ModuleFound   bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	k, err := linuxkern.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	head, err := k.Symbol("tty_drivers")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoDrivers)
	}
	c, err := newCheck(k)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	list, err := k.Walker().List(head, "tty_driver", "tty_drivers", linuxwalk.Forward)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if list.Broken() {
		c.lossy = true
		ctx.AddDiagnostic("%s: tty_drivers at %#x: list ends %s at %#x after %d drivers", Name, head, list.End,
			list.At, len(list.Entries))
	}
	c.owners = newOwners(k, ctx.AddDiagnostic)
	var out []Row
	for _, drv := range list.Entries {
		out = append(out, c.driver(drv)...)
	}
	if (c.lossy || c.owners.lossy) && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: drivers, ttys or module views were read in part", Name)
	}
	return out, nil
}

type check struct {
	k         *linuxkern.Kernel
	diag      func(string, ...any)
	owners    *owners
	nameBytes uint64
	handlers  []Handler
	maxSlots  uint64
	lossy     bool
}

// TT6: tty_line_name writes the driver's name into the tty's name array, so
// that array's length bounds both names.
func newCheck(k *linuxkern.Kernel) (*check, error) {
	for _, m := range [][2]string{
		{"tty_driver", "name"}, {"tty_driver", "num"}, {"tty_driver", "ttys"}, {"tty_struct", "index"},
		{"tty_struct", "driver"}, {"tty_struct", "ldisc"}, {"tty_ldisc", "ops"}, {"tty_ldisc_ops", "name"},
		{"tty_ldisc_ops", string(HandlerReceive)},
	} {
		if _, err := k.Member(m[0], m[1]); err != nil {
			return nil, err
		}
	}
	m, err := k.Member("tty_struct", "name")
	if err != nil {
		return nil, err
	}
	n, err := linuxkern.ByteArrayLength(k.Sym, m.Parent, m.Field)
	if err != nil {
		return nil, err
	}
	c := &check{k: k, diag: k.Diag, nameBytes: n, handlers: []Handler{HandlerReceive},
		maxSlots: uint64(k.Context().Bounds().MaxTableEntries)}
	if k.HasMember("tty_ldisc_ops", string(HandlerReceive2)) {
		c.handlers = append(c.handlers, HandlerReceive2)
	}
	return c, nil
}

type slotCounts struct {
	unread, foreign int
}

func (c *check) driver(drv uint64) []Row {
	k := c.k
	name, err := c.pointedString(drv, "tty_driver", "name")
	if err != nil {
		c.diag("%s: tty_driver at %#x: name: %v", Name, drv, err)
	}
	num, err1 := k.Uint(drv, "tty_driver", "num")
	ttys, err2 := k.Ptr(drv, "tty_driver", "ttys")
	if err := errors.Join(err1, err2); err != nil {
		c.lossy = true
		c.diag("%s: tty_driver at %#x: tty table: %v", Name, drv, err)
		return nil
	}
	if ttys == 0 {
		return nil
	}
	if num > c.maxSlots {
		c.lossy = true
		c.diag("%s: tty_driver at %#x: %d slots, only the first %d are read (Limits.MaxTableEntries)", Name, drv,
			num, c.maxSlots)
		num = c.maxSlots
	}
	var counts slotCounts
	var out []Row
	for i := range num {
		tty, err := k.ReadPointer(ttys + i*k.PtrSize)
		if err != nil {
			counts.unread++
			continue
		}
		if tty == 0 {
			continue
		}
		out = append(out, c.tty(drv, name, tty, i, &counts)...)
	}
	if counts.unread > 0 {
		c.lossy = true
		c.diag("%s: tty_driver at %#x: %d of %d slots or their ttys do not read", Name, drv, counts.unread, num)
	}
	if counts.foreign > 0 {
		c.diag("%s: tty_driver at %#x: %d slots hold a tty whose index or driver is not this slot's", Name, drv,
			counts.foreign)
	}
	return out
}

func (c *check) tty(drv uint64, driverName string, tty, slot uint64, counts *slotCounts) []Row {
	k := c.k
	index, err1 := k.Int(tty, "tty_struct", "index")
	back, err2 := k.Ptr(tty, "tty_struct", "driver")
	ldisc, err3 := k.Ptr(tty, "tty_struct", "ldisc")
	if errors.Join(err1, err2, err3) != nil {
		counts.unread++
		return nil
	}
	if index < 0 || uint64(index) != slot || back != drv {
		counts.foreign++
		return nil
	}
	if ldisc == 0 {
		return nil
	}
	name, err := k.MemberString(tty, "tty_struct", "name")
	if err != nil {
		c.diag("%s: tty_struct at %#x: name: %v", Name, tty, err)
	}
	ops, err := k.Ptr(ldisc, "tty_ldisc", "ops")
	if err != nil {
		counts.unread++
		return nil
	}
	if ops == 0 {
		return nil
	}
	discipline, err := c.pointedString(ops, "tty_ldisc_ops", "name")
	if err != nil {
		c.diag("%s: tty_ldisc_ops at %#x: name: %v", Name, ops, err)
	}
	var out []Row
	for _, h := range c.handlers {
		fn, err := k.Ptr(ops, "tty_ldisc_ops", string(h))
		if err != nil {
			c.lossy = true
			c.diag("%s: tty_ldisc_ops at %#x: %s: %v", Name, ops, h, err)
			continue
		}
		if fn == 0 {
			continue
		}
		o := c.owners.of(fn)
		out = append(out, Row{TTY: name, TTYAddress: tty, Driver: driverName, DriverAddress: drv,
			Discipline: discipline, OpsAddress: ops, Handler: h, Address: fn, Module: o.module, Symbol: o.symbol,
			ModuleAddress: o.moduleAddress, ModuleFound: o.found})
	}
	return out
}

func (c *check) pointedString(addr uint64, typ, member string) (string, error) {
	p, err := c.k.Ptr(addr, typ, member)
	if err != nil || p == 0 {
		return "", err
	}
	return c.k.StringAt(p, c.nameBytes)
}
