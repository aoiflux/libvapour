package driverunbacked

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/driverscan"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const Name = "windows.driver.find_unbacked"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the driver objects whose DriverStart lies in no loaded kernel module",
		},
		RunAny,
	)
}

type Driver struct {
	driverscan.Driver
	NoImage bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Driver, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	mods, err := modulelist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		// Without the module list every driver would look unbacked.
		return nil, fmt.Errorf("%s: loaded modules: %w", Name, err)
	}
	placed := modulelist.Placed(ctx, Name, mods)
	drivers, err := driverscan.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	var out []Driver
	for _, d := range drivers {
		if d.Start != 0 && len(modulelist.Containing(placed, d.Start)) > 0 {
			continue
		}
		// A driver object with neither DriverStart nor DriverSize has no
		// image to back it; \FileSystem\RAW is one on every capture (S64 D4).
		out = append(out, Driver{Driver: d, NoImage: d.Start == 0 && d.Size == 0})
	}
	return out, nil
}
