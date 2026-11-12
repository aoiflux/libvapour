// Console state kept by conhost.exe: titles, screen buffers, attached
// processes, aliases and command history buffers (S33).
package consolelist

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools"
)

const Name = "windows.console.list"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Read each console conhost.exe hosts: titles, screen buffer text, attached processes, aliases and command history buffers",
		},
		RunAny,
	)
}

const (
	OptionNoRegistry = "windows.console.list.no_registry"
	OptionMaxHistory = "windows.console.list.max_history"
	OptionMaxBuffers = "windows.console.list.max_buffers"
)

var ErrIncomplete = errors.New("consolelist: part of a console or history did not read")

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type Options struct {
	NoRegistry             bool
	HistoryBufferSizes     []uint64
	NumberOfHistoryBuffers []uint64
}

// buffersKey may be empty for a tool that searches histories only.
func ReadOptions(ctx tools.Context, noRegistryKey, historyKey, buffersKey string) (Options, error) {
	var o Options
	var err error
	if o.NoRegistry, err = ctx.BoolOption(noRegistryKey); err != nil {
		return o, err
	}
	if o.HistoryBufferSizes, err = ctx.UintListOption(historyKey); err != nil {
		return o, err
	}
	if buffersKey != "" {
		if o.NumberOfHistoryBuffers, err = ctx.UintListOption(buffersKey); err != nil {
			return o, err
		}
	}
	// Both are UINT members of CONSOLE_HISTORY_INFO (S33 F10).
	for key, values := range map[string][]uint64{historyKey: o.HistoryBufferSizes, buffersKey: o.NumberOfHistoryBuffers} {
		for _, v := range values {
			if v == 0 || v > 1<<32-1 {
				return o, fmt.Errorf("option %q: %w: %d is not a 32-bit count above zero", key, tools.ErrOptionType, v)
			}
		}
	}
	return o, nil
}

func checkContext(ctx tools.Context, tool string) error {
	if err := ctx.Validate(); err != nil {
		return err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return fmt.Errorf("%s: unsupported profile os %q", tool, ctx.Profile.OS())
	}
	return nil
}

func SearchSizes(ctx tools.Context, o Options) (historyBufferSizes, numberOfHistoryBuffers []uint64) {
	var settings []Setting
	if !o.NoRegistry {
		settings = ReadSettings(ctx)
	}
	z := gatherSizes(settings, o.HistoryBufferSizes, o.NumberOfHistoryBuffers)
	return z.historyBufferSizes, z.numberOfHistoryBuffers
}

func Run(ctx tools.Context) ([]Console, error) {
	if err := checkContext(ctx, Name); err != nil {
		return nil, err
	}
	o, err := ReadOptions(ctx, OptionNoRegistry, OptionMaxHistory, OptionMaxBuffers)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	l, err := LoadLayout(ctx)
	if err != nil {
		return nil, err
	}
	if !l.HasConsole() {
		return nil, fmt.Errorf("%s: %s: %w", Name, l.ConsoleGap(), ErrUnsupportedVersion)
	}
	sizes, buffers := SearchSizes(ctx, o)
	hosts, procs, err := FindHosts(ctx, Name)
	if err != nil {
		return nil, err
	}
	listed := map[uint64]bool{}
	for _, p := range procs {
		listed[p.PID] = true
	}
	b := ctx.Bounds()
	var out []Console
	var firstGap error
	for _, h := range hosts {
		found, err := l.FindConsoles(h.Space, sizes, buffers, b)
		if err != nil {
			ctx.AddDiagnostic("%s: process %d at 0x%x: search cut short: %v", Name, h.Process.PID, h.Process.EPROCESS, err)
		}
		if n := found.RejectedCount(); n > 0 {
			ctx.AddDiagnostic("%s: process %d at 0x%x: %d candidates rejected: %s", Name, h.Process.PID,
				h.Process.EPROCESS, n, found.Summary())
		}
		if len(found.Accepted) == 0 {
			ctx.AddDiagnostic("%s: process %d at 0x%x: no console state found", Name, h.Process.PID, h.Process.EPROCESS)
		}
		for _, at := range found.Accepted {
			c := l.ReadConsole(h.Space, at, listed, b)
			c.PID, c.Process = h.Process.PID, h.Process.Name
			for _, g := range c.Incomplete {
				ctx.AddDiagnostic("%s: console at 0x%x: %s", Name, at, g)
				if firstGap == nil {
					firstGap = fmt.Errorf("%s: console at 0x%x: %s: %w", Name, at, g, ErrIncomplete)
				}
			}
			out = append(out, c)
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

type Candidates struct {
	Accepted   []uint64
	RejectedBy map[string]int
	Rejections []Verdict
}

func (c Candidates) RejectedCount() int {
	n := 0
	for _, v := range c.RejectedBy {
		n += v
	}
	return n
}

func (c Candidates) Summary() string {
	rules := make([]string, 0, len(c.RejectedBy))
	for r := range c.RejectedBy {
		rules = append(rules, r)
	}
	slices.Sort(rules)
	parts := make([]string, len(rules))
	for i, r := range rules {
		parts[i] = fmt.Sprintf("%s %d", r, c.RejectedBy[r])
	}
	return strings.Join(parts, ", ")
}
