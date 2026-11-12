package modulehidden

import (
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linux/modulelist"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const Name = "linux.module.find_hidden"

const OptionDump = "linux.module.find_hidden.dump"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "Scan Linux module memory for modules that are not on the module list"},
		RunAny,
	)
}

type Row = linuxmodule.Row

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	model, o, err := modulelist.Open(ctx, Name, OptionDump)
	if err != nil {
		return nil, err
	}
	list, err := model.List()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if err := modulelist.Checked(ctx, Name, list); err != nil {
		return nil, err
	}
	scan, err := model.Scan()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if err := modulelist.Checked(ctx, Name, scan); err != nil {
		return nil, err
	}
	rows, err := model.Rows(linuxmodule.Missing(scan, list), linuxmodule.FromScan, o)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	return rows, nil
}
