package sessionlist

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processenvironment"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.session.list"

const (
	SessionIDNotApplicable = processlist.SessionIDNotApplicable
	SessionIDUnreadable    = processlist.SessionIDUnreadable
)

var ErrNotWindows = errors.New("sessionlist: profile is not windows")

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List processes by logon session with the session's name and the process's user",
		},
		RunAny,
	)
}

type Row struct {
	SessionID   int64
	SessionType string
	PID         uint64
	Process     string
	EPROCESS    uint64
	UserName    string
	CreateTime  time.Time
}

func RunAny(ctx tools.Context) (any, error) {
	return Run(ctx)
}

// The session id is the kernel's: _EPROCESS.Session leads to the session
// space and its id (S25). User and session name are what the process's own
// environment block says.
func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: %q: %w", Name, ctx.Profile.OS(), ErrNotWindows)
	}
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: process list: %w", Name, err)
	}
	env := sessionEnvironment(ctx)
	pids := ctx.PIDs()
	out := make([]Row, 0, len(procs))
	for _, p := range procs {
		if !pids.Keep(p.PID) {
			continue
		}
		v := env[p.PID]
		out = append(out, Row{
			SessionID:   p.SessionID,
			SessionType: v.session,
			PID:         p.PID,
			Process:     util.ReplaceInvalidUTF8(p.Name),
			EPROCESS:    p.EPROCESS,
			UserName:    accountName(v.domain, v.user),
			CreateTime:  p.CreateTime,
		})
	}
	slices.SortStableFunc(out, func(a, b Row) int { return cmp.Compare(orderKey(a.SessionID), orderKey(b.SessionID)) })
	return out, nil
}

// Both absent markers sort first, together, so a process without a session
// space and one whose session does not read stay in list order.
func orderKey(id int64) int64 { return max(id, -1) }

type variables struct{ user, domain, session string }

// Names are compared without regard to case and the first in block order
// wins (S69 O7).
func sessionEnvironment(ctx tools.Context) map[uint64]variables {
	vars, err := processenvironment.Run(ctx)
	if err != nil {
		ctx.AddDiagnostic("%s: environment blocks: %v; user and session name left empty", Name, err)
		return nil
	}
	return variablesOf(vars)
}

func variablesOf(vars []processenvironment.EnvVar) map[uint64]variables {
	out := map[uint64]variables{}
	seen := map[uint64]map[string]bool{}
	for _, v := range vars {
		name := strings.ToUpper(v.Variable)
		if name != "USERNAME" && name != "USERDOMAIN" && name != "SESSIONNAME" {
			continue
		}
		if seen[v.PID] == nil {
			seen[v.PID] = map[string]bool{}
		}
		if seen[v.PID][name] {
			continue
		}
		seen[v.PID][name] = true
		e := out[v.PID]
		switch name {
		case "USERNAME":
			e.user = v.Value
		case "USERDOMAIN":
			e.domain = v.Value
		default:
			e.session = v.Value
		}
		out[v.PID] = e
	}
	return out
}

// DOMAIN\user is the down-level logon name form (Learn, User Name Formats).
func accountName(domain, user string) string {
	switch {
	case user == "":
		return ""
	case domain == "":
		return user
	}
	return domain + `\` + user
}
