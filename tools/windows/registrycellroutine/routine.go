package registrycellroutine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
)

const Name = "windows.registry.check_cell_routine"

var (
	ErrLayout     = errors.New("registrycellroutine: _HHIVE has no cell routine members")
	ErrNoHive     = errors.New("registrycellroutine: no hive found")
	ErrUnreadable = errors.New("registrycellroutine: routine pointer does not read")
)

type Placement string

const (
	InKernelImage Placement = "kernel_image"
	InOtherModule Placement = "other_module"
	InNoModule    Placement = "no_module"
	NullRoutine   Placement = "null"
	NotRead       Placement = "unreadable"
)

var routineMembers = []string{"GetCellRoutine", "ReleaseCellRoutine"}

type Routine struct {
	HiveAddress      uint64
	HivePath         string
	Member           string
	Address          uint64
	Placement        Placement
	Module           string
	ModuleUnreadable bool
	Symbol           string
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Show where each registry hive's GetCellRoutine and ReleaseCellRoutine point: the kernel image, another module or no module",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Routine, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	members, err := loadMembers(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	hives := registryhive.GatherHives(ctx)
	if len(hives) == 0 {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoHive)
	}
	mods, err := modulelist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: loaded modules: %w", Name, err)
	}
	p := newPlacer(ctx, modulelist.Placed(ctx, Name, mods))
	return check(ctx, members, hives, p)
}

type member struct {
	name   string
	offset uint64
}

func loadMembers(table symbols.SymbolTable) ([]member, error) {
	hive, err := table.Field("_CMHIVE", "Hive")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLayout, err)
	}
	var out []member
	for _, n := range routineMembers {
		if f, err := table.Field("_HHIVE", n); err == nil {
			out = append(out, member{name: n, offset: hive.Offset + f.Offset})
		}
	}
	if len(out) == 0 {
		return nil, ErrLayout
	}
	return out, nil
}

type placer struct {
	mods    []modulelist.Module
	kernel  modulelist.Module
	known   bool
	locator symbols.SymbolLocator
}

// CmpHiveListHead is kernel data, so the module that holds it is the kernel
// image whatever base the session assumed.
func newPlacer(ctx tools.Context, mods []modulelist.Module) placer {
	p := placer{mods: mods}
	p.locator, _ = ctx.Symbols.(symbols.SymbolLocator)
	if head, err := ctx.Symbols.LookupSymbol("CmpHiveListHead"); err == nil {
		if in := modulelist.Containing(mods, head.Address); len(in) > 0 {
			p.kernel, p.known = in[0], true
		}
	}
	if base, ok := ctx.KernelBase(); !p.known && ok && base != 0 {
		for _, m := range mods {
			if m.Base == base {
				p.kernel, p.known = m, true
			}
		}
	}
	if !p.known {
		ctx.AddDiagnostic("%s: kernel image not among the loaded modules: no routine is placed in it", Name)
	}
	return p
}

func (p placer) place(r *Routine) {
	if r.Address == 0 {
		r.Placement = NullRoutine
		return
	}
	in := modulelist.Containing(p.mods, r.Address)
	if len(in) == 0 {
		r.Placement = InNoModule
		return
	}
	m := in[0]
	r.Module, r.ModuleUnreadable = modulelist.DisplayName(m), m.NameUnreadable
	if !p.known || m.Base != p.kernel.Base {
		r.Placement = InOtherModule
		return
	}
	r.Placement = InKernelImage
	if p.locator != nil {
		if names := symbols.NamesAt(p.locator, r.Address); len(names) > 0 {
			r.Symbol = names[0]
		}
	}
}

func hivePath(h registryhive.Hive) string {
	if h.FileFullPath != "" {
		return h.FileFullPath
	}
	return h.Name
}

func check(ctx tools.Context, members []member, hives []registryhive.Hive, p placer) ([]Routine, error) {
	var out []Routine
	var firstErr error
	outside := 0
	for _, h := range hives {
		for _, m := range members {
			r := Routine{HiveAddress: h.Address, HivePath: hivePath(h), Member: m.name}
			v, err := ctx.Symbols.ReadPointer(ctx.Memory, h.Address+m.offset)
			if err != nil {
				r.Placement = NotRead
				ctx.AddDiagnostic("%s: hive at 0x%x: %s not read: %v", Name, h.Address, m.name, fmt.Errorf("%w: %w", ErrUnreadable, err))
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: hive at 0x%x: %s: %w", Name, h.Address, m.name, ErrUnreadable)
				}
				out = append(out, r)
				continue
			}
			r.Address = v
			p.place(&r)
			if r.Placement != InKernelImage {
				outside++
			}
			out = append(out, r)
		}
	}
	if outside > 0 {
		ctx.AddDiagnostic("%s: %d of %d routines are not inside the kernel image", Name, outside, len(out))
	}
	if firstErr != nil && ctx.StrictMode() {
		return out, firstErr
	}
	return out, nil
}
