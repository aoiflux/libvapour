package processenvironment

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

type taskCounts struct {
	n     int
	first string
}

type linuxReport struct {
	counts map[string]*taskCounts
	order  []string
}

func (r *linuxReport) add(kind string, task uint64, detail string) {
	if r.counts == nil {
		r.counts = map[string]*taskCounts{}
	}
	c, ok := r.counts[kind]
	if !ok {
		c = &taskCounts{first: fmt.Sprintf("task at 0x%x", task)}
		if detail != "" {
			c.first += ": " + detail
		}
		r.counts[kind] = c
		r.order = append(r.order, kind)
	}
	c.n++
}

func (r *linuxReport) emit(ctx tools.Context) {
	for _, kind := range r.order {
		c := r.counts[kind]
		ctx.AddDiagnostic("%s: %d tasks %s, first: %s", Name, c.n, kind, c.first)
	}
}

const (
	kindUnread    = "with members that do not read"
	kindNotUser   = "with environment bounds outside user space"
	kindCut       = "with an environment area over MaxBufferBytes, cut"
	kindNoSpace   = "whose address space cannot be reached"
	kindAreaUnset = "whose environment area does not read"
	kindPartial   = "whose environment area reads only in part"
	kindUnnamed   = "with environment strings lacking a name, skipped"
)

func RunLinux(ctx tools.Context) ([]LinuxEnvVar, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	k := linuxobj.New(ctx)
	walk, err := k.Walker().Tasks(false, k.PIDSkip(ctx.PIDs()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)
	var out []LinuxEnvVar
	var report linuxReport
	var firstUnread error
	for _, addr := range walk.Tasks {
		rows, err := taskEnvironment(ctx, k, linuxobj.Task{Addr: addr}, &report)
		if errors.Is(err, linuxobj.ErrNoTranslator) {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		if err != nil {
			report.add(kindUnread, addr, err.Error())
			if firstUnread == nil {
				firstUnread = fmt.Errorf("%s: task at 0x%x: %w", Name, addr, err)
			}
			continue
		}
		out = append(out, rows...)
	}
	if firstUnread != nil && ctx.StrictMode() {
		return nil, firstUnread
	}
	report.emit(ctx)
	return out, nil
}

func taskEnvironment(ctx tools.Context, k *linuxobj.Kernel, t linuxobj.Task, report *linuxReport) ([]LinuxEnvVar, error) {
	kthread, err := k.IsKernelThread(t)
	if err != nil || kthread {
		return nil, err
	}
	mm, err := k.Pointer(k.Memory(), t.Addr, "task_struct", "mm")
	if err != nil || mm == 0 {
		return nil, err
	}
	start, err := k.Uint(k.Memory(), mm, "mm_struct", "env_start")
	if err != nil {
		return nil, err
	}
	end, err := k.Uint(k.Memory(), mm, "mm_struct", "env_end")
	if err != nil {
		return nil, err
	}
	if end == 0 || end <= start {
		return nil, nil
	}
	if end>>63 != 0 {
		report.add(kindNotUser, t.Addr, fmt.Sprintf("0x%x to 0x%x", start, end))
		return nil, nil
	}
	size := end - start
	if limit := uint64(ctx.Bounds().MaxBufferBytes); size > limit {
		report.add(kindCut, t.Addr, fmt.Sprintf("%d bytes", size))
		size = limit
	}
	layer, ok, why, err := k.ProcessLayer(t)
	if err != nil {
		return nil, err
	}
	if !ok {
		detail := ""
		if why != nil {
			detail = why.Error()
		}
		report.add(kindNoSpace, t.Addr, detail)
		return nil, nil
	}
	raw := readPages(layer.Reader, start, size)
	switch {
	case len(raw) == 0:
		report.add(kindAreaUnset, t.Addr, fmt.Sprintf("at 0x%x", start))
		return nil, nil
	case uint64(len(raw)) < size:
		report.add(kindPartial, t.Addr, fmt.Sprintf("0x%x of 0x%x bytes at 0x%x", len(raw), size, start))
	}
	area := splitLinuxArea(raw)
	if area.unnamed > 0 {
		report.add(kindUnnamed, t.Addr, fmt.Sprintf("%d strings", area.unnamed))
	}
	if len(area.vars) == 0 {
		return nil, nil
	}
	f, err := k.TaskFields(t, false)
	if err != nil {
		return nil, err
	}
	rows := make([]LinuxEnvVar, 0, len(area.vars))
	for _, v := range area.vars {
		rows = append(rows, LinuxEnvVar{PID: f.PID, PPID: f.PPID, Comm: f.Comm, Key: v.name, Value: v.value})
	}
	return rows, nil
}
