package servicecandidates

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processarguments"
)

const Name = "windows.service.find_candidates"

const serviceHostImage = "svchost.exe"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name: Name,
			Description: "List service host processes (svchost.exe) with the group and service their command lines name; " +
				"a placeholder that reads no service records",
		},
		RunAny,
	)
}

type Service struct {
	PID         uint64
	Process     string
	EPROCESS    uint64
	Group       string
	Service     string
	CommandLine string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Service, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	cmds, err := processarguments.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	pids := ctx.PIDs()
	var out []Service
	for _, c := range cmds {
		if !pids.Keep(c.PID) || !strings.EqualFold(c.Name, serviceHostImage) {
			continue
		}
		if c.CmdlineUnreadable {
			ctx.AddDiagnostic("%s: _EPROCESS at 0x%x: pid %d: command line does not read, left out", Name, c.Address, c.PID)
			continue
		}
		args := splitCommandLine(c.Cmdline)
		out = append(out, Service{PID: c.PID, Process: c.Name, EPROCESS: c.Address,
			Group: argumentAfter(args, "-k"), Service: argumentAfter(args, "-s"), CommandLine: c.Cmdline})
	}
	slices.SortStableFunc(out, func(a, b Service) int {
		return cmp.Or(cmp.Compare(a.PID, b.PID), cmp.Compare(a.EPROCESS, b.EPROCESS))
	})
	return out, nil
}

func argumentAfter(args []string, flag string) string {
	for i := 1; i+1 < len(args); i++ {
		if strings.EqualFold(args[i], flag) {
			return args[i+1]
		}
	}
	return ""
}

// The program name only takes quotes as space guards; later arguments also
// read a doubled quote inside quotes as one quote (Microsoft C startup rules).
func splitCommandLine(line string) []string {
	var out []string
	var arg strings.Builder
	quoted, started := false, false
	flush := func() {
		if started {
			out = append(out, arg.String())
		}
		arg.Reset()
		started = false
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			started = true
			if quoted && len(out) > 0 && i+1 < len(line) && line[i+1] == '"' {
				arg.WriteByte('"')
				i++
				continue
			}
			quoted = !quoted
		case (c == ' ' || c == '\t') && !quoted:
			flush()
		default:
			started = true
			arg.WriteByte(c)
		}
	}
	flush()
	return out
}
