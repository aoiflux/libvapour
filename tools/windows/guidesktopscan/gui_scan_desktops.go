package guidesktopscan

import (
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/gui"
	"github.com/aoiflux/libvapour/tools/windows/guidesktops"
)

const Name = "windows.gui.scan_desktops"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Scan pool memory for desktop objects whose window station reads: one row per desktop thread, one for a desktop with none",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]guidesktops.Desktop, error) {
	env, err := gui.OpenTool(ctx, Name)
	if err != nil {
		return nil, err
	}
	return rows(env)
}

func rows(env *gui.Env) ([]guidesktops.Desktop, error) {
	found, err := env.ScanDesktops()
	if err != nil {
		return nil, err
	}
	var out []guidesktops.Desktop
	for _, d := range found {
		threads, err := env.Threads(d)
		if err != nil {
			return nil, err
		}
		out = append(out, guidesktops.Rows(d, threads)...)
	}
	return out, nil
}
