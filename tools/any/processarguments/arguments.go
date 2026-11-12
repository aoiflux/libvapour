package processarguments

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
)

const Name = "any.process.read_arguments"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Read each process's command line",
		},
		RunAny,
	)
}

type ProcessCmdline struct {
	PID               uint64
	Name              string
	Address           uint64
	Cmdline           string
	Arguments         []string
	CmdlineUnreadable bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]ProcessCmdline, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	switch {
	case strings.EqualFold(ctx.Profile.OS(), "windows"):
		return runWindows(ctx)
	case strings.EqualFold(ctx.Profile.OS(), "linux"):
		return runLinux(ctx)
	}
	return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
}

type unread struct {
	count int
	first string
}

func (u *unread) add(object string, addr uint64, why error) {
	if u.count == 0 {
		u.first = fmt.Sprintf("%s at %#x: %v", object, addr, why)
	}
	u.count++
}

func (u unread) report(ctx tools.Context) error {
	if u.count == 0 {
		return nil
	}
	if ctx.StrictMode() {
		return fmt.Errorf("%s: strict mode: %d command lines not read, first: %s", Name, u.count, u.first)
	}
	ctx.AddDiagnostic("%s: %d command lines not read, first: %s", Name, u.count, u.first)
	return nil
}
