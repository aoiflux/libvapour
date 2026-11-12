package memorytree

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.memory.tree"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Show each process's VAD tree: every kept node with its parent, left and right links and its range",
		},
		RunAny,
	)
}

type Row struct {
	PID     uint64
	Process string
	Address uint64
	Parent  uint64
	Left    uint64
	Right   uint64
	Start   uint64
	End     uint64
	Tag     string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	walker, err := memoryranges.NewTreeWalker(ctx.Symbols)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	pids := ctx.PIDs()
	var out []Row
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		rows, err := treeRows(ctx, walker, p)
		if err != nil {
			if ctx.StrictMode() {
				return nil, err
			}
			ctx.AddDiagnostic("%v", err)
			continue
		}
		out = append(out, rows...)
	}
	return out, nil
}

func treeRows(ctx tools.Context, walker memoryranges.TreeWalker, p processlist.Process) ([]Row, error) {
	nodes, err := walker.Walk(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("%s: pid %d _EPROCESS at 0x%x: VAD tree not read: %w", Name, p.PID, p.EPROCESS, err)
	}
	name := util.ReplaceInvalidUTF8(p.Name)
	rows := make([]Row, 0, len(nodes))
	for _, n := range nodes {
		rows = append(rows, Row{PID: p.PID, Process: name, Address: n.Base, Parent: n.Parent,
			Left: n.Left, Right: n.Right, Start: n.Start, End: n.End, Tag: n.Tag})
	}
	return rows, nil
}
