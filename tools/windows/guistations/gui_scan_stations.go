package guistations

import (
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/gui"
)

const Name = "windows.gui.scan_stations"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Scan pool memory for window station objects: name, session and address",
		},
		RunAny,
	)
}

type Station struct {
	Address   uint64
	Physical  uint64
	Name      string
	SessionID uint32
	OtherCopy uint64
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Station, error) {
	env, err := gui.OpenTool(ctx, Name)
	if err != nil {
		return nil, err
	}
	return rows(env)
}

func rows(env *gui.Env) ([]Station, error) {
	found, err := env.ScanStations()
	if err != nil {
		return nil, err
	}
	out := make([]Station, len(found))
	for i, s := range found {
		out[i] = Station{Address: s.Address, Physical: s.Physical, Name: s.Name, SessionID: s.SessionID,
			OtherCopy: s.OtherCopy}
	}
	return out, nil
}
