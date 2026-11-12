package processtree

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "any.process.tree"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Arrange the listed processes by the parent each one recorded, refusing self-parented and reused parent IDs",
		},
		RunAny,
	)
}

type Entry struct {
	PID      uint64
	Name     string
	EPROCESS uint64
	processlist.Columns

	Depth           int
	Children        []*Entry
	ParentPIDReused bool

	AuditImageName           string
	AuditImageNameUnreadable bool
	ImagePathName            string
	ImagePathNameUnreadable  bool
	CommandLine              string
	CommandLineUnreadable    bool
	ParametersUnreadable     bool
}

func RunAny(ctx tools.Context) (any, error) {
	roots, err := Run(ctx)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(ctx.Profile.OS(), "windows") {
		columns := processlist.NewColumnReader(ctx)
		columns.ReportAbsent(ctx, Name)
		for _, e := range Flatten(roots) {
			if err := columns.ReportUnread(ctx, Name, e.PID, e.Name, e.EPROCESS, e.Columns); err != nil {
				return nil, err
			}
		}
	}
	return roots, nil
}

func Run(ctx tools.Context) ([]*Entry, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	windows := strings.EqualFold(ctx.Profile.OS(), "windows")
	if !windows && !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	// A narrowed list would cut the ancestors the PID set keeps.
	procs, err := processlist.Run(ctx.WithoutPIDFilter())
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	entries := make([]*Entry, len(procs))
	nodes := make([]node, len(procs))
	if windows {
		d := newDetailReader(ctx)
		system := initialSystemProcess(ctx)
		for i, p := range procs {
			entries[i] = &Entry{PID: p.PID, Name: p.Name, EPROCESS: p.EPROCESS, Columns: p.Columns}
			d.read(p, entries[i])
			nodes[i] = node{pid: p.PID, ppid: p.PPID, ppidKnown: !p.PPIDUnreadable, systemProcess: system != 0 && p.EPROCESS == system}
			if !p.CreateTimeUnreadable {
				nodes[i].created = p.CreateTime
			}
			if !p.ExitTimeUnreadable {
				nodes[i].ended = p.ExitTime
			}
		}
	} else {
		k := linuxobj.New(ctx)
		for i, p := range procs {
			entries[i] = &Entry{PID: p.PID, Name: p.Name, EPROCESS: p.EPROCESS}
			ppid, err := k.ParentPID(linuxobj.Task{Addr: p.EPROCESS})
			entries[i].PPIDUnreadable = err != nil || ppid < 0
			if !entries[i].PPIDUnreadable {
				entries[i].PPID = uint64(ppid)
			}
			nodes[i] = node{pid: p.PID, ppid: entries[i].PPID, ppidKnown: !entries[i].PPIDUnreadable}
		}
	}
	return assemble(entries, nodes, ctx.PIDs()), nil
}

func initialSystemProcess(ctx tools.Context) uint64 {
	sym, err := ctx.Symbols.LookupSymbol("PsInitialSystemProcess")
	if err != nil {
		return 0
	}
	v, err := ctx.Symbols.ReadPointer(ctx.Memory, sym.Address)
	if err != nil {
		return 0
	}
	return v
}

func assemble(entries []*Entry, nodes []node, pids tools.PIDSet) []*Entry {
	placed := place(nodes)
	var roots []int
	for i, p := range placed {
		entries[i].Depth, entries[i].ParentPIDReused = p.depth, p.reused
		for _, c := range p.children {
			entries[i].Children = append(entries[i].Children, entries[c])
		}
		if p.parent < 0 {
			roots = append(roots, i)
		}
	}
	sortByPID(roots, nodes)
	out := make([]*Entry, len(roots))
	for i, r := range roots {
		out[i] = entries[r]
	}
	if pids.All() {
		return out
	}
	return keepSelected(out, pids)
}

func sortByPID(idx []int, nodes []node) {
	slices.SortStableFunc(idx, func(a, b int) int { return cmp.Compare(nodes[a].pid, nodes[b].pid) })
}

// A row stays when the PID set names it or one of its descendants, so a
// selected process keeps the chain of parents above it.
func keepSelected(level []*Entry, pids tools.PIDSet) []*Entry {
	var kept []*Entry
	for _, e := range level {
		e.Children = keepSelected(e.Children, pids)
		if pids.Keep(e.PID) || len(e.Children) > 0 {
			kept = append(kept, e)
		}
	}
	return kept
}

func Flatten(roots []*Entry) []*Entry {
	var out []*Entry
	stack := make([]*Entry, 0, len(roots))
	for i := len(roots) - 1; i >= 0; i-- {
		stack = append(stack, roots[i])
	}
	for len(stack) > 0 {
		e := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		out = append(out, e)
		for i := len(e.Children) - 1; i >= 0; i-- {
			stack = append(stack, e.Children[i])
		}
	}
	return out
}
