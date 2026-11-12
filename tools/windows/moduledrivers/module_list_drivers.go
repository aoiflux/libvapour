package moduledrivers

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

const Name = "windows.module.list_drivers"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Placeholder: the loaded kernel modules whose name ends in .sys; windows.driver.scan reads driver objects",
		},
		RunAny,
	)
}

type Driver struct {
	Base           uint64
	Size           uint64
	Name           string
	NameUnreadable bool
	BaseUnreadable bool
	SizeUnreadable bool
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

func Run(ctx tools.Context) ([]Driver, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	mods, err := modulelist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	var out []Driver
	for _, m := range mods {
		// File names compare without case on Windows; a name that did not
		// read is kept rather than hidden.
		if !m.NameUnreadable && !strings.HasSuffix(strings.ToLower(m.Name), ".sys") {
			continue
		}
		out = append(out, Driver{Base: m.Base, Size: m.Size, Name: m.Name, NameUnreadable: m.NameUnreadable,
			BaseUnreadable: m.BaseUnreadable, SizeUnreadable: m.SizeUnreadable})
	}
	return out, nil
}
