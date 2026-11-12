package processcapabilities

import (
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.process.list_capabilities"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the capability sets of every Linux task",
		},
		RunAny,
	)
}

type Process struct {
	Process     string
	PID, TID    int64
	PPID        int64
	EUID        int64
	Inheritable string
	Permitted   string
	Effective   string
	Bounding    string
	Ambient     string
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type tally struct {
	count int
	first string
}

func (t *tally) add(format string, args ...any) {
	if t.count == 0 {
		t.first = fmt.Sprintf(format, args...)
	}
	t.count++
}

var setMembers = [...]string{"cap_inheritable", "cap_permitted", "cap_effective", "cap_bset", "cap_ambient"}

func Run(ctx tools.Context) ([]Process, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	k := linuxobj.New(ctx)
	for _, m := range setMembers {
		if !k.Has("cred", m) {
			return nil, fmt.Errorf("%s: symbol table has no cred.%s: %w", Name, m, linuxobj.ErrUnsupported)
		}
	}
	if last, ok, err := k.CapLastCap(); err == nil && ok && last > linuxobj.LastCapValue() {
		ctx.AddDiagnostic("%s: cap_last_cap is %d, capabilities above %d have no name and are shown in hex",
			Name, last, linuxobj.LastCapValue())
	}
	full := k.KernelCapFull()
	walk, err := k.Walker().Tasks(true, k.PIDSkip(ctx.PIDs()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)

	var out []Process
	var skipped, ambient tally
	for _, addr := range walk.Tasks {
		p, outside, err := task(k, linuxobj.Task{Addr: addr}, full)
		if err != nil {
			skipped.add("task_struct at %#x: %v", addr, err)
			continue
		}
		if outside != 0 {
			ambient.add("tid %d: ambient bits %#x", p.TID, outside)
		}
		out = append(out, p)
	}
	if skipped.count > 0 {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: strict mode: %d tasks not read, first: %s", Name, skipped.count, skipped.first)
		}
		ctx.AddDiagnostic("%s: %d tasks not read, first: %s", Name, skipped.count, skipped.first)
	}
	if ambient.count > 0 {
		ctx.AddDiagnostic("%s: %d tasks hold ambient capabilities outside permitted and inheritable, first: %s",
			Name, ambient.count, ambient.first)
	}
	return out, nil
}

// S61 P1: /proc/<pid>/status reads the sets from the objective credentials,
// real_cred. outside holds ambient bits that P2's invariant forbids.
func task(k *linuxobj.Kernel, t linuxobj.Task, full linuxobj.CapFull) (p Process, outside uint64, err error) {
	if p.Process, err = k.Comm(t); err != nil {
		return p, 0, err
	}
	if p.TID, err = k.PID(t); err != nil {
		return p, 0, err
	}
	if p.PID, err = k.TGID(t); err != nil {
		return p, 0, err
	}
	if p.PPID, err = k.ParentPID(t); err != nil {
		return p, 0, err
	}
	cred, err := k.Pointer(k.Memory(), t.Addr, "task_struct", "real_cred")
	if err != nil {
		return p, 0, err
	}
	if cred == 0 {
		return p, 0, linuxobj.ErrNoCredentials
	}
	if p.EUID, err = k.CredValue(cred, "euid"); err != nil {
		return p, 0, err
	}
	var sets [len(setMembers)]uint64
	for i, m := range setMembers {
		f, err := k.Member("cred", m)
		if err != nil {
			return p, 0, err
		}
		if sets[i], err = k.Capabilities(cred+f.Offset, f.Type.Name); err != nil {
			return p, 0, fmt.Errorf("cred at %#x: %s: %w", cred, m, err)
		}
	}
	texts := []*string{&p.Inheritable, &p.Permitted, &p.Effective, &p.Bounding, &p.Ambient}
	for i, to := range texts {
		*to = linuxobj.DecodeCapabilities(sets[i], full)
	}
	return p, sets[4] &^ (sets[0] & sets[1]), nil
}
