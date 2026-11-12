// Command history buffers found by searching conhost.exe's memory for their
// shape, whether or not a console still lists them (S33 4.3).
package consolehistory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/consolelist"
)

const Name = "windows.console.scan_history"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Search conhost.exe memory for command history buffers and the commands they hold",
		},
		RunAny,
	)
}

const (
	OptionNoRegistry = "windows.console.scan_history.no_registry"
	OptionMaxHistory = "windows.console.scan_history.max_history"
)

type FoundHistory struct {
	PID     uint64
	Process string
	consolelist.History
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]FoundHistory, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	o, err := consolelist.ReadOptions(ctx, OptionNoRegistry, OptionMaxHistory, "")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	l, err := consolelist.LoadLayout(ctx)
	if err != nil {
		return nil, err
	}
	sizes, _ := consolelist.SearchSizes(ctx, o)
	hosts, _, err := consolelist.FindHosts(ctx, Name)
	if err != nil {
		return nil, err
	}
	b := ctx.Bounds()
	var out []FoundHistory
	var firstGap error
	for _, h := range hosts {
		found, err := l.FindHistories(h.Space, sizes, b)
		if err != nil {
			ctx.AddDiagnostic("%s: process %d at 0x%x: search cut short: %v", Name, h.Process.PID, h.Process.EPROCESS, err)
		}
		if n := found.RejectedCount(); n > 0 {
			ctx.AddDiagnostic("%s: process %d at 0x%x: %d candidates rejected: %s", Name, h.Process.PID,
				h.Process.EPROCESS, n, found.Summary())
		}
		for _, node := range found.Accepted {
			hist := l.ReadHistory(h.Space, node, b)
			if hist.CommandsIncomplete || hist.ApplicationUnreadable || unreadCommands(hist) {
				ctx.AddDiagnostic("%s: history at 0x%x: not every command read", Name, node)
				if firstGap == nil {
					firstGap = fmt.Errorf("%s: history at 0x%x: %w", Name, node, consolelist.ErrIncomplete)
				}
			}
			out = append(out, FoundHistory{PID: h.Process.PID, Process: h.Process.Name, History: hist})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].Address < out[j].Address
	})
	if firstGap != nil && ctx.StrictMode() {
		return out, firstGap
	}
	return out, nil
}

func unreadCommands(h consolelist.History) bool {
	for _, c := range h.Commands {
		if c.Unreadable {
			return true
		}
	}
	return false
}
