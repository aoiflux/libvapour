package modulecompare

import (
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linux/modulelist"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const Name = "linux.module.compare"

const OptionPlainTaints = "linux.module.compare.plain_taints"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "Show which of the module list, sysfs and a module-memory scan hold each Linux module, with its taints"},
		RunAny,
	)
}

type Row struct {
	Address      uint64
	Name         string
	InList       bool
	InSysfs      bool
	InScan       bool
	Taints       string
	TaintsUnread bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	plain, err := ctx.BoolOption(OptionPlainTaints)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	model, _, err := modulelist.Open(ctx, Name, "")
	if err != nil {
		return nil, err
	}
	vs, err := model.Views()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	vs.Report(ctx.AddDiagnostic, Name)
	if vs.Lossy() && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: a view failed or left modules out", Name)
	}
	known := vs.Known()
	out := make([]Row, 0, len(known))
	for _, mod := range known {
		row := Row{Address: mod.Address, Name: mod.Name, InList: vs.List.Has(mod.Address),
			InSysfs: vs.Sysfs.Has(mod.Address), InScan: vs.Scan.Has(mod.Address), TaintsUnread: mod.TaintsUnread}
		if mod.HasTaints && !mod.TaintsUnread {
			ts := model.Taints(mod.Taints)
			if plain {
				row.Taints = linuxmodule.TaintLetters(ts)
			} else {
				row.Taints = linuxmodule.TaintNames(ts)
			}
		}
		out = append(out, row)
	}
	return out, nil
}
