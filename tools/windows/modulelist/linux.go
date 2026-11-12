package modulelist

import (
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

// The Linux module model owns the list walk and the checks on each struct
// module (S06, S07); this side only maps its list view onto Module.
func linuxModules(ctx tools.Context) ([]Module, error) {
	mask, width := AddressMask(ctx), ctx.Symbols.PointerSize()
	model, err := linuxmodule.New(linuxwalk.Reader{
		Mem:     ctx.Memory,
		Sym:     ctx.Symbols,
		Address: func(a uint64) uint64 { return CanonicalAddress(a, mask, width) },
		Limits:  ctx.Bounds(),
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	view, err := model.List()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	view.Report(ctx.AddDiagnostic, Name)
	if view.Lossy() && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: the module list view left modules out", Name)
	}
	separate := model.SeparateRegions()
	mods := make([]Module, 0, len(view.Modules))
	for _, m := range view.Modules {
		mod := Module{
			Base:            m.Base(),
			Size:            m.CoreSize(),
			InitSize:        m.InitSize(),
			Name:            m.Name,
			Entry:           m.Address,
			Regions:         make([]Region, 0, len(m.Regions)),
			SeparateRegions: separate,
		}
		// S55 4.2: separate regions make [Base, Base + Size) the text alone.
		if separate {
			mod.Size = m.TextSize()
		}
		for _, r := range m.Regions {
			mod.Regions = append(mod.Regions, Region{Kind: r.Kind.String(), Base: r.Base, Size: r.Size})
		}
		mods = append(mods, mod)
	}
	return mods, nil
}
