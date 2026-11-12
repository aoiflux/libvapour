package modulelist

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

func (m Module) RangeKnown() bool { return !m.BaseUnreadable && !m.SizeUnreadable }

func (m Module) holds(address uint64) bool {
	if m.SeparateRegions {
		for _, r := range m.Regions {
			if address >= r.Base && address-r.Base < r.Size {
				return true
			}
		}
		return false
	}
	return m.RangeKnown() && address >= m.Base && address-m.Base < m.Size
}

func Placed(ctx tools.Context, tool string, mods []Module) []Module {
	placed := make([]Module, 0, len(mods))
	var unplaced []string
	for _, m := range mods {
		if m.RangeKnown() {
			placed = append(placed, m)
		} else {
			unplaced = append(unplaced, fmt.Sprintf("0x%x", m.Entry))
		}
	}
	if len(unplaced) > 0 {
		ctx.AddDiagnostic("%s: loader entries at %s: base or size does not read: no address is attributed to them",
			tool, strings.Join(unplaced, ", "))
	}
	return placed
}

func Containing(mods []Module, address uint64) []Module {
	var out []Module
	for _, m := range mods {
		if m.holds(address) {
			out = append(out, m)
		}
	}
	return out
}

// Both separators count: the loader writes \ and a caller may pass /. A name
// of dots alone keeps its dots, so no name becomes empty.
func DisplayName(mod Module) string {
	name := mod.Name
	start := strings.LastIndexAny(name, `\/`) + 1
	dot := strings.LastIndexByte(name, '.')
	if dot <= start || strings.Trim(name[start:dot], ".") == "" {
		return name
	}
	return name[:dot]
}

type Attribution struct {
	Module           string
	Symbol           string
	ModuleUnreadable bool
}

// The kernel table names only addresses inside the kernel image: applied to a
// driver it would name whichever kernel symbol happens to lie below.
type Attributor struct {
	mods    []Module
	kernel  Module
	known   bool
	locator symbols.SymbolLocator
}

func NewAttributor(ctx tools.Context, mods []Module) Attributor {
	return NewAttributorAnchoredAt(ctx, mods, 0)
}

// An anchor is an address the caller read from the kernel's own data, such
// as a service table: the module that holds it is the kernel image whatever
// base the session assumed.
func NewAttributorAnchoredAt(ctx tools.Context, mods []Module, anchor uint64) Attributor {
	a := Attributor{mods: mods}
	a.locator, _ = ctx.Symbols.(symbols.SymbolLocator)
	a.kernel, a.known = kernelImage(ctx, mods, anchor)
	return a
}

func kernelImage(ctx tools.Context, mods []Module, anchor uint64) (Module, bool) {
	if anchor != 0 {
		if owners := Containing(mods, anchor); len(owners) > 0 {
			return owners[0], true
		}
	}
	if base, ok := ctx.KernelBase(); ok && base != 0 {
		for _, m := range mods {
			if m.RangeKnown() && m.Base == base {
				return m, true
			}
		}
	}
	if head, err := ctx.Symbols.LookupSymbol("PsLoadedModuleList"); err == nil && head.Address != 0 {
		if owners := Containing(mods, head.Address); len(owners) > 0 {
			return owners[0], true
		}
	}
	return Module{}, false
}

func (a Attributor) SymbolModuleKnown() bool { return a.known }

func (a Attributor) At(address uint64) []Attribution {
	var out []Attribution
	for _, m := range Containing(a.mods, address) {
		names := []string{""}
		if a.known && a.locator != nil && m.Base == a.kernel.Base {
			if found := symbols.NamesAt(a.locator, address); len(found) > 0 {
				names = found
			}
		}
		for _, n := range names {
			out = append(out, Attribution{Module: DisplayName(m), Symbol: n, ModuleUnreadable: m.NameUnreadable})
		}
	}
	return out
}
