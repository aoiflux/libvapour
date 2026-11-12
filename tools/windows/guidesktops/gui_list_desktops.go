package guidesktops

import (
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/gui"
)

const Name = "windows.gui.list_desktops"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Walk each scanned window station's desktop list: one row per desktop thread, one for a desktop with none",
		},
		RunAny,
	)
}

type Desktop struct {
	Address        uint64
	SessionID      uint32
	Station        string
	Name           string
	NameUnreadable bool

	Threadless        bool
	TID               uint64
	PID               uint64
	Process           string
	ProcessUnreadable bool

	OtherCopy uint64
}

type StationRows struct {
	Station  uint64
	Desktops []uint64
	Rows     []Desktop
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Desktop, error) {
	groups, err := ByStation(ctx)
	if err != nil {
		return nil, err
	}
	var out []Desktop
	for _, g := range groups {
		out = append(out, g.Rows...)
	}
	return out, nil
}

func ByStation(ctx tools.Context) ([]StationRows, error) {
	env, err := gui.OpenTool(ctx, Name)
	if err != nil {
		return nil, err
	}
	return byStation(env)
}

func byStation(env *gui.Env) ([]StationRows, error) {
	stations, err := env.ScanStations()
	if err != nil {
		return nil, err
	}
	out := make([]StationRows, 0, len(stations))
	for i := range stations {
		desktops, err := env.Desktops(&stations[i])
		if err != nil {
			return nil, err
		}
		g := StationRows{Station: stations[i].Address}
		for _, d := range desktops {
			g.Desktops = append(g.Desktops, d.Address)
			threads, err := env.Threads(d)
			if err != nil {
				return nil, err
			}
			g.Rows = append(g.Rows, Rows(d, threads)...)
		}
		out = append(out, g)
	}
	return out, nil
}

func Rows(d gui.Desktop, threads []gui.Thread) []Desktop {
	base := Desktop{
		Address:        d.Address,
		SessionID:      d.SessionID,
		Station:        d.StationName,
		Name:           d.Name,
		NameUnreadable: !d.NameReadable,
		OtherCopy:      d.OtherCopy,
	}
	if len(threads) == 0 {
		base.Threadless = true
		return []Desktop{base}
	}
	out := make([]Desktop, len(threads))
	for i, t := range threads {
		row := base
		row.TID = t.TID
		row.PID = t.Owner.PID
		row.Process = t.Owner.Process
		row.ProcessUnreadable = !t.Owner.ProcessReadable
		out[i] = row
	}
	return out
}
