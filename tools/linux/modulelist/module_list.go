package modulelist

import (
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const Name = "linux.module.list"

const OptionDump = "linux.module.list.dump"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "List the modules on the Linux kernel's module list, with taints and parameter values"},
		RunAny,
	)
}

type Row = linuxmodule.Row

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

// Open gives a module tool its model and row options: dump on when the tool's
// dump option is set, which then needs an output directory.
func Open(ctx tools.Context, tool, dumpOption string) (*linuxmodule.Model, linuxmodule.RowOptions, error) {
	o := linuxmodule.RowOptions{Tool: tool, Diag: ctx.AddDiagnostic, Cap: ctx.DumpLimit()}
	if dumpOption != "" {
		dump, err := ctx.BoolOption(dumpOption)
		if err != nil {
			return nil, o, fmt.Errorf("%s: %w", tool, err)
		}
		dir, ok := ctx.OutputDir()
		if dump && !ok {
			return nil, o, fmt.Errorf("%s: %s is set but %s is not", tool, dumpOption, tools.OptionOutputDir)
		}
		o.Dump, o.Dir = dump, dir
	}
	k, err := linuxkern.New(ctx)
	if err != nil {
		return nil, o, fmt.Errorf("%s: %w", tool, err)
	}
	model, err := k.Modules()
	if err != nil {
		return nil, o, fmt.Errorf("%s: %w", tool, err)
	}
	o.Canonical = func(a uint64) uint64 { return linuxkern.CanonicalAddress(a, k.Mask) }
	return model, o, nil
}

// Checked reports a view's losses, and fails in strict mode when it has any.
func Checked(ctx tools.Context, tool string, v linuxmodule.View) error {
	v.Report(ctx.AddDiagnostic, tool)
	if v.Lossy() && ctx.StrictMode() {
		return fmt.Errorf("%s: strict mode: the %s view left modules out", tool, v.Source)
	}
	return nil
}

func Run(ctx tools.Context) ([]Row, error) {
	model, o, err := Open(ctx, Name, OptionDump)
	if err != nil {
		return nil, err
	}
	list, err := model.List()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if err := Checked(ctx, Name, list); err != nil {
		return nil, err
	}
	rows, err := model.Rows(list.Modules, linuxmodule.FromList, o)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	return rows, nil
}
