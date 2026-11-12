package processcredentials

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.process.check_credentials"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the credential structures that more than one Linux process acts with",
		},
		RunAny,
	)
}

type SharedCred struct {
	CredAddress uint64
	PIDs        []int64
	InitCred    bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]SharedCred, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	k := linuxobj.New(ctx)
	if !k.Has("task_struct", "cred") {
		return nil, fmt.Errorf("%s: symbol table has no task_struct.cred: %w", Name, linuxobj.ErrUnsupported)
	}
	var initCred uint64
	if s, err := k.Symbol("init_cred"); err == nil {
		initCred = k.Canonical(s.Address)
	}
	walk, err := k.Walker().Tasks(false, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)

	holders := map[uint64][]int64{}
	unread, first := 0, ""
	for _, addr := range walk.Tasks {
		t := linuxobj.Task{Addr: addr}
		cred, ok, err := k.TaskCred(t)
		var pid int64
		if err == nil && ok {
			pid, err = k.TGID(t)
		}
		if err != nil || !ok {
			if unread == 0 {
				first = fmt.Sprintf("task_struct at %#x: cred is null or does not read", addr)
				if err != nil {
					first = fmt.Sprintf("task_struct at %#x: %v", addr, err)
				}
			}
			unread++
			continue
		}
		cred = k.Canonical(cred)
		holders[cred] = append(holders[cred], pid)
	}
	if unread > 0 {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: strict mode: %d processes without a readable cred, first: %s", Name, unread, first)
		}
		ctx.AddDiagnostic("%s: %d processes without a readable cred, first: %s", Name, unread, first)
	}
	// S61 C2: copy_creds gives every new thread group its own cred, so one
	// cred held by two groups did not come from fork.
	var out []SharedCred
	for cred, pids := range holders {
		if len(pids) < 2 {
			continue
		}
		sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
		out = append(out, SharedCred{CredAddress: cred, PIDs: pids, InitCred: initCred != 0 && cred == initCred})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PIDs[0] < out[j].PIDs[0] })
	return out, nil
}
