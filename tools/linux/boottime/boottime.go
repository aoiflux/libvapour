package boottime

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.boot.read_time"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "Show the time the Linux system was booted, per time namespace"},
		RunAny,
	)
}

type Row struct {
	Namespace        uint64
	NamespaceAddress uint64
	BootOffset       time.Duration
	Tasks            int
	BootTime         time.Time
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	k := linuxobj.New(ctx)
	clock, err := k.BootClock()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if err := checkClock(ctx, clock); err != nil {
		return nil, err
	}
	if !k.HasTimeNamespaces() {
		return []Row{{BootTime: clock.Boot}}, nil
	}
	return perNamespace(ctx, k, clock.Boot)
}

func checkClock(ctx tools.Context, c linuxobj.BootClock) error {
	var why string
	switch {
	case c.Updating():
		why = fmt.Sprintf("sequence %d is odd: an update was in progress", c.Sequence)
	case c.WallChecked && !c.WallAgrees:
		why = "offs_real is not the negated wall_to_monotonic"
	case c.SleepChecked && !c.SleepAgrees:
		why = "offs_boot is not monotonic_to_boot"
	default:
		return nil
	}
	if ctx.StrictMode() {
		return fmt.Errorf("%s: timekeeper at %#x: %s", Name, c.Timekeeper, why)
	}
	ctx.AddDiagnostic("%s: timekeeper at %#x: %s", Name, c.Timekeeper, why)
	return nil
}

// S46 4.7 step 3: every task, threads too, since a thread can enter a namespace of
// its own.
func perNamespace(ctx tools.Context, k *linuxobj.Kernel, host time.Time) ([]Row, error) {
	walk, err := k.Walker().Tasks(true, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)
	rows := map[uint64]*Row{}
	var unread []string
	for _, addr := range walk.Tasks {
		ns, held, err := k.TaskTimeNamespace(linuxobj.Task{Addr: addr})
		if err != nil {
			unread = append(unread, fmt.Sprintf("task at %#x: %v", addr, err))
			continue
		}
		if !held {
			continue
		}
		r, ok := rows[ns.Address]
		if !ok {
			boot, err := ns.BootTime(host)
			if err != nil {
				unread = append(unread, fmt.Sprintf("task at %#x: %v", addr, err))
				continue
			}
			r = &Row{Namespace: ns.Inode, NamespaceAddress: ns.Address, BootOffset: ns.BootOffset, BootTime: boot}
			rows[ns.Address] = r
		}
		r.Tasks++
	}
	if len(unread) > 0 {
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s strict mode: %d tasks without a readable time namespace, first: %s",
				Name, len(unread), unread[0])
		}
		ctx.AddDiagnostic("%s: %d tasks without a readable time namespace, first: %s", Name, len(unread), unread[0])
	}
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].NamespaceAddress < out[j].NamespaceAddress
	})
	return out, nil
}
