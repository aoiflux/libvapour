package guiwindows

import (
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/gui"
)

const Name = "windows.gui.list_windows"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Walk the window tree of each scanned window station's desktops: text, procedure and owning process",
		},
		RunAny,
	)
}

type Window struct {
	Address           uint64
	SessionID         uint32
	Station           string
	Desktop           string
	DesktopAddress    uint64
	DesktopUnreadable bool

	Parent uint64
	Depth  int

	Text           string
	TextUnreadable bool

	Procedure           uint64
	ProcedureUnreadable bool

	TID               uint64
	PID               uint64
	Process           string
	ProcessUnreadable bool
}

type StationRows struct {
	Station  uint64
	Desktops []uint64
	Rows     []Window
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Window, error) {
	groups, err := ByStation(ctx)
	if err != nil {
		return nil, err
	}
	var out []Window
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
	return byStation(ctx, env)
}

func byStation(ctx tools.Context, env *gui.Env) ([]StationRows, error) {
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
			walk, err := env.Windows(d)
			if err != nil {
				return nil, err
			}
			report(ctx, d, walk)
			for _, w := range walk.Windows {
				g.Rows = append(g.Rows, row(d, w))
			}
		}
		out = append(out, g)
	}
	return out, nil
}

func report(ctx tools.Context, d gui.Desktop, walk gui.WindowWalk) {
	if len(walk.Rejected) == 0 {
		return
	}
	reasons := make([]string, 0, len(walk.Rejected))
	for reason, n := range walk.Rejected {
		reasons = append(reasons, fmt.Sprintf("%s %d", reason, n))
	}
	slices.Sort(reasons)
	ctx.AddDiagnostic("%s: desktop at 0x%x: windows left out with their subtrees: %s", Name, d.Address,
		strings.Join(reasons, ", "))
}

func row(d gui.Desktop, w gui.Window) Window {
	return Window{
		Address:             w.Address,
		SessionID:           d.SessionID,
		Station:             d.StationName,
		Desktop:             d.Name,
		DesktopAddress:      d.Address,
		DesktopUnreadable:   !d.NameReadable,
		Parent:              w.Parent,
		Depth:               w.Depth,
		Text:                w.Text,
		TextUnreadable:      !w.TextReadable,
		Procedure:           w.Procedure,
		ProcedureUnreadable: !w.ProcedureReadable,
		TID:                 w.Thread.TID,
		PID:                 w.Thread.Owner.PID,
		Process:             w.Thread.Owner.Process,
		ProcessUnreadable:   !w.Thread.Owner.ProcessReadable,
	}
}
