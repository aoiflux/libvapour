package interruptcheck

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const Name = "linux.interrupt.check"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "Check every Linux interrupt descriptor table gate and where its handler lies"},
		RunAny,
	)
}

type Placement string

const (
	InKernel     Placement = "kernel"
	InKernelInit Placement = "kernel_init"
	InModule     Placement = "module"
	Unowned      Placement = "unowned"
	NoHandler    Placement = "none"
)

type Source string

const (
	FromLoaded Source = "loaded"
	FromTable  Source = "idt_table"
)

type Row struct {
	Index     uint64
	Address   uint64
	Module    string
	Symbol    string
	Placement Placement
	Type      GateType
	Selector  uint16
	DPL       uint8
	IST       uint8
	Present   bool
	Source    Source
	Differs   bool
}

const vectors = 256

var (
	ErrNoTable     = errors.New("interruptcheck: no idt_table symbol")
	ErrUnsupported = errors.New("interruptcheck: gate layout not supported")
)

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	k, err := linuxkern.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	size := gateSize(k.PtrSize)
	if k.HasType("gate_struct") {
		if n, err := k.TypeSize("gate_struct"); err == nil && n != size {
			return nil, fmt.Errorf("%s: gate_struct is %d bytes, not %d: %w", Name, n, size, ErrUnsupported)
		}
	}
	table, err := k.Symbol("idt_table")
	if err != nil {
		return nil, fmt.Errorf("%s: %v: %w", Name, err, ErrNoTable)
	}
	loaded, haveLoaded := loadedTable(k, size)
	p, err := newPlacer(k)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	var out []Row
	unread, differ := 0, 0
	for v := range uint64(vectors) {
		own, ownOK := readEntry(k, table+v*size, size)
		raw, src := own, FromTable
		var row Row
		if haveLoaded && loaded != table {
			if cpu, ok := readEntry(k, loaded+v*size, size); ok {
				raw, src = cpu, FromLoaded
				row.Differs = ownOK && !bytes.Equal(own, cpu)
			}
		} else if haveLoaded {
			src = FromLoaded
		}
		if raw == nil {
			unread++
			continue
		}
		g, err := DecodeGate(raw, size)
		if err != nil {
			return nil, fmt.Errorf("%s: gate %d at %#x: %w", Name, v, table+v*size, err)
		}
		if row.Differs {
			differ++
		}
		row.Index, row.Source = v, src
		row.Type, row.Selector, row.DPL, row.IST, row.Present = g.Type, g.Selector, g.DPL, g.IST, g.Present
		row.Address = g.Offset & k.Mask
		if err := p.place(&row); err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		out = append(out, row)
	}
	if differ > 0 {
		k.Diag("%s: idt_table at %#x: %d gates differ from the table the CPUs load at %#x", Name, table, differ, loaded)
	}
	if unread > 0 {
		k.Diag("%s: idt_table at %#x: %d gates unreadable and left out", Name, table, unread)
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: strict mode: %d gates unreadable", Name, unread)
		}
	}
	return out, nil
}

func readEntry(k *linuxkern.Kernel, at, size uint64) ([]byte, bool) {
	b, err := k.Read(at, size)
	if err != nil {
		return nil, false
	}
	return b, true
}

// The CPUs index the table idt_descr names, which on x86-64 is a read-only
// alias of idt_table's page (S10 K5), so a rewrite of either shows here.
func loadedTable(k *linuxkern.Kernel, size uint64) (uint64, bool) {
	at, err := k.Symbol("idt_descr")
	if err != nil {
		k.Diag("%s: no idt_descr symbol: gates come from idt_table only", Name)
		return 0, false
	}
	sizeOff, addrOff := uint64(0), uint64(2)
	if m, err := k.Member("desc_ptr", "size"); err == nil {
		sizeOff = m.Offset
	}
	if m, err := k.Member("desc_ptr", "address"); err == nil {
		addrOff = m.Offset
	}
	limit, err := k.ReadUint(at+sizeOff, 2)
	if err == nil && limit != vectors*size-1 {
		k.Diag("%s: idt_descr at %#x: limit %#x, not %#x", Name, at, limit, vectors*size-1)
	}
	base, err := k.ReadPointer(at + addrOff)
	if err != nil {
		k.Diag("%s: idt_descr at %#x: address unreadable: %v", Name, at, err)
		return 0, false
	}
	return base, true
}

type placer struct {
	k         *linuxkern.Kernel
	model     *linuxmodule.Model
	names     linuxmodule.KernelNamer
	initStart uint64
	initEnd   uint64
	gathered  bool
	known     []linuxmodule.Module
}

func newPlacer(k *linuxkern.Kernel) (*placer, error) {
	model, err := k.Modules()
	if err != nil {
		return nil, err
	}
	p := &placer{k: k, model: model, names: func(a uint64) []string {
		names, _ := k.SymbolsAt(a)
		return names
	}}
	start, err1 := k.Symbol("_sinittext")
	end, err2 := k.Symbol("_einittext")
	if err1 == nil && err2 == nil && start < end {
		p.initStart, p.initEnd = start, end
	}
	return p, nil
}

func (p *placer) place(row *Row) error {
	if row.Type == GateTask {
		row.Placement = NoHandler
		return nil
	}
	if o := p.model.Lookup(nil, row.Address, p.names); o.Found {
		row.Module, row.Symbol = o.Names()
		row.Placement = InKernel
		return nil
	}
	if row.Address >= p.initStart && row.Address < p.initEnd {
		row.Module, row.Placement = linuxmodule.KernelOwner, InKernelInit
		if names := p.names(row.Address); len(names) > 0 {
			row.Symbol = names[0]
		}
		return nil
	}
	if err := p.gather(); err != nil {
		return err
	}
	if o := p.model.Lookup(p.known, row.Address, p.names); o.Found && !o.Kernel {
		row.Module, row.Symbol = o.Names()
		row.Placement = InModule
		return nil
	}
	row.Placement = Unowned
	return nil
}

// Modules are gathered only when a handler is outside the kernel image, which
// a clean kernel never has (S10 M3), so a clean run skips the module scan.
func (p *placer) gather() error {
	if p.gathered {
		return nil
	}
	p.gathered = true
	vs, err := p.model.Views()
	vs.Report(p.k.Diag, Name)
	if err != nil {
		if p.k.Context().StrictMode() {
			return fmt.Errorf("strict mode: no module view: %w", err)
		}
		return nil
	}
	if vs.Lossy() && p.k.Context().StrictMode() {
		return errors.New("strict mode: the module views left modules out")
	}
	p.known = vs.Known()
	return nil
}
