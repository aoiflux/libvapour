package tracingperf

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxtrace"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const Name = "linux.tracing.list_perf_events"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the performance events each Linux task opened that run an eBPF program, with the program's identity",
		},
		RunAny,
	)
}

var ErrNoPerfEvents = errors.New("tracingperf: task_struct has no perf_event_list; the kernel was built without CONFIG_PERF_EVENTS")

type Event struct {
	PID            int64
	TID            int64
	Process        string
	EventAddress   uint64
	PMU            string
	Type           uint64
	Config         uint64
	ProgramAddress uint64
	ProgramID      uint64
	ProgramName    string
	ProgramSymbol  string
	ProgramCode    uint64
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

// PE5: a PMU's name is the name of its sysfs directory under
// /sys/bus/event_source/devices, so it fits in NAME_MAX (255) bytes.
const pmuNameBytes = 256

func Run(ctx tools.Context) ([]Event, error) {
	if err := ctx.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	k := linuxtrace.New(ctx)
	if !k.Has("task_struct", "perf_event_list") {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPerfEvents)
	}
	for _, m := range [][2]string{{"task_struct", "pid"}, {"task_struct", "tgid"}, {"task_struct", "comm"},
		{"perf_event", "owner_entry"}, {"perf_event", "pmu"}, {"perf_event", "attr"}, {"perf_event_attr", "type"},
		{"perf_event_attr", "config"}, {"pmu", "name"}} {
		if _, err := k.Field(m[0], m[1]); err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
	}
	if !k.Has("perf_event", "prog") {
		ctx.AddDiagnostic("%s: perf_event has no prog member: the kernel was built without CONFIG_BPF_SYSCALL, so no event runs a program", Name)
		return nil, nil
	}
	r := k.Walker()
	walk, err := r.Tasks(true, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)
	lossy := len(walk.Invalid) > 0 || walk.ThreadListsBroken > 0
	for _, l := range walk.Walks {
		lossy = lossy || l.Broken()
	}
	listAt, _ := k.Field("task_struct", "perf_event_list")
	attrAt, _ := k.Field("perf_event", "attr")
	var out []Event
	for _, task := range walk.Tasks {
		head := task + listAt.Offset
		events, err := r.List(head, "perf_event", "owner_entry", linuxwalk.Forward)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		if events.Broken() {
			lossy = true
			ctx.AddDiagnostic("%s: task_struct at %#x: perf_event_list ends %s at %#x after %d events", Name, task,
				events.End, events.At, len(events.Entries))
		}
		var id taskID
		for _, ev := range events.Entries {
			prog, err := k.Pointer(ev, "perf_event", "prog")
			if err != nil {
				lossy = true
				ctx.AddDiagnostic("%s: perf_event at %#x: prog: %v", Name, ev, err)
				continue
			}
			if k.Masked(prog) == 0 {
				continue
			}
			if !id.read {
				id = readTaskID(k, task)
				if id.err != nil {
					ctx.AddDiagnostic("%s: task_struct at %#x: %v", Name, task, id.err)
				}
			}
			row := Event{PID: id.tgid, TID: id.pid, Process: id.comm, EventAddress: ev, ProgramAddress: prog}
			if err := readEvent(k, ev, attrAt.Offset, &row); err != nil {
				lossy = true
				ctx.AddDiagnostic("%s: perf_event at %#x: %v", Name, ev, err)
			}
			p, err := readProgram(k, prog)
			if err != nil {
				lossy = true
				ctx.AddDiagnostic("%s: bpf_prog at %#x: %v", Name, prog, err)
			}
			row.ProgramID, row.ProgramName, row.ProgramSymbol, row.ProgramCode = p.id, p.name, p.symbol, p.code
			out = append(out, row)
		}
	}
	if lossy && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: tasks, event lists, events or programs were read in part", Name)
	}
	return out, nil
}

type taskID struct {
	read      bool
	pid, tgid int64
	comm      string
	err       error
}

func readTaskID(k *linuxtrace.Kernel, task uint64) taskID {
	id := taskID{read: true}
	var err1, err2, err3 error
	id.pid, err1 = k.Int(task, "task_struct", "pid")
	id.tgid, err2 = k.Int(task, "task_struct", "tgid")
	id.comm, err3 = k.CharArray(task, "task_struct", "comm")
	id.err = errors.Join(err1, err2, err3)
	return id
}

// PE3, PE4: the event's PMU names its kind in the kernel's own words, and
// attr holds the type and config user space asked for.
func readEvent(k *linuxtrace.Kernel, ev, attrOffset uint64, row *Event) error {
	var err1, err2, err3 error
	row.Type, err1 = k.Uint(ev+attrOffset, "perf_event_attr", "type")
	row.Config, err2 = k.Uint(ev+attrOffset, "perf_event_attr", "config")
	pmu, err3 := k.Pointer(ev, "perf_event", "pmu")
	if err := errors.Join(err1, err2, err3); err != nil {
		return err
	}
	if k.Masked(pmu) == 0 {
		return nil
	}
	name, err := k.Pointer(pmu, "pmu", "name")
	if err != nil || k.Masked(name) == 0 {
		return err
	}
	row.PMU, err = k.StringAt(name, pmuNameBytes)
	return err
}
