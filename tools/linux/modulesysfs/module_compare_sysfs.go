package modulesysfs

import (
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linux/modulelist"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const Name = "linux.module.compare_sysfs"

const OptionDump = "linux.module.compare_sysfs.dump"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "Show Linux modules that are on the module list or in sysfs but not both"},
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
	sysfs, err := model.Sysfs()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if err := modulelist.Checked(ctx, Name, sysfs); err != nil {
		return nil, err
	}
	rows, err := model.Rows(linuxmodule.Missing(list, sysfs), linuxmodule.FromList, o)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	more, err := model.Rows(linuxmodule.Missing(sysfs, list), linuxmodule.FromSysfs, o)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	return append(rows, more...), nil
}
