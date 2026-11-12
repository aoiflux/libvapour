package librarylist

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.library.list"

const (
	RouteLinkerList  = "linker list"
	RouteMappedImage = "mapped image"
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the shared objects the dynamic linker records in each Linux process, or the ELF images its file mappings hold",
		},
		RunAny,
	)
}

type Library struct {
	Process     string
	PID         int64
	BaseAddress uint64
	Path        string
	Route       string
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

func Run(ctx tools.Context) ([]Library, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	k := linuxobj.New(ctx)
	lw, err := memoryranges.NewLinuxWalker(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk, err := k.Walker().Tasks(false, k.PIDSkip(ctx.PIDs()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	walk.Report(ctx.AddDiagnostic, Name)

	var out []Library
	var skipped, noSpace, cut, mapped tally
	for _, addr := range walk.Tasks {
		t := linuxobj.Task{Addr: addr}
		comm, err := k.Comm(t)
		if err != nil {
			skipped.add("task_struct at %#x: %v", addr, err)
			continue
		}
		pid, err := k.TGID(t)
		if err != nil {
			skipped.add("task_struct at %#x: %v", addr, err)
			continue
		}
		layer, ok, why, err := k.ProcessLayer(t)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		if !ok {
			if why != nil {
				noSpace.add("task_struct at %#x: %v", addr, why)
			}
			continue
		}
		rows, why, mappedWhy := libraries(ctx, k, lw, t, layer)
		for _, r := range rows {
			r.Process, r.PID = comm, pid
			out = append(out, r)
		}
		if why != nil {
			cut.add("task_struct at %#x: %v", addr, why)
		}
		if mappedWhy != nil {
			mapped.add("task_struct at %#x: %v", addr, mappedWhy)
		}
	}
	if noSpace.count > 0 {
		ctx.AddDiagnostic("%s: %d processes without a usable address space, first: %s", Name, noSpace.count, noSpace.first)
	}
	for _, f := range []struct {
		what string
		t    tally
	}{{"processes not read", skipped}, {"library lists cut short", cut}, {"processes with mapped images not read", mapped}} {
		if f.t.count == 0 {
			continue
		}
		if ctx.StrictMode() {
			return nil, fmt.Errorf("%s: strict mode: %d %s, first: %s", Name, f.t.count, f.what, f.t.first)
		}
		ctx.AddDiagnostic("%s: %d %s, first: %s", Name, f.t.count, f.what, f.t.first)
	}
	return out, nil
}

// S61 L1, L2: every image the process maps may carry DT_DEBUG; the dynamic
// linker fills the executable's, and each distinct value leads to one list.
// A process whose lists give no row, or end early, also reads its mapped
// images (L3 to L5, 4.10 step 5).
func libraries(ctx tools.Context, k *linuxobj.Kernel, lw *memoryranges.LinuxWalker, t linuxobj.Task, layer linuxobj.ProcessLayer) (rows []Library, listErr, mappedErr error) {
	bounds := ctx.Bounds()
	mm, areas, walkErr := lw.TaskVMAs(t.Addr)
	var out []Library
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	debugSeen := map[uint64]bool{}
	entrySeen := map[uint64]bool{}
	early := false
	for _, a := range areas {
		e, ok, err := linuxobj.ParseELF(layer.Reader, a.Start)
		if err != nil || !ok {
			continue
		}
		debug, err := e.DebugAddress(bounds.MaxTableEntries)
		if err != nil || debug == 0 || debugSeen[debug] {
			continue
		}
		debugSeen[debug] = true
		entries, err := e.LinkMap(bounds.MaxTableEntries)
		if err != nil {
			note(err)
			early = true
		}
		if n := len(entries); n > 0 && zeroEntry(entries[n-1]) {
			early = true
		}
		for _, m := range entries {
			if entrySeen[m.Address] || m.Name == 0 {
				continue
			}
			entrySeen[m.Address] = true
			path, ok := e.NameAt(m.Name, bounds.MaxNameBytes)
			if !ok {
				note(fmt.Errorf("library entry at %#x: name at %#x: %w", m.Address, m.Name, linuxobj.ErrELFRead))
				continue
			}
			if path == "" {
				continue
			}
			out = append(out, Library{BaseAddress: m.LoadBias, Path: path, Route: RouteLinkerList})
		}
	}
	if walkErr != nil {
		note(walkErr)
	}
	if len(out) > 0 && !early {
		return out, firstErr, nil
	}
	mapped, mappedErr := mappedImages(k, lw, t, mm, areas, layer, bounds.MaxTableEntries)
	listed := map[uint64]bool{}
	for _, r := range out {
		listed[r.BaseAddress] = true
	}
	for _, r := range mapped {
		if !listed[r.BaseAddress] {
			out = append(out, r)
		}
	}
	return out, firstErr, mappedErr
}

// S61 4.10 step 5, S38 O10: a list whose last entry reads as zero bytes ended
// where the image no longer holds it, not where the linker's list ends.
func zeroEntry(m linuxobj.LinkMapEntry) bool {
	return m.LoadBias == 0 && m.Name == 0 && m.Dynamic == 0
}

// S61 L3 to L5: an area mapped from file offset 0 that begins with an ELF
// header holds that file's image. The executable is left out, as the linker
// list leaves out its own entry.
func mappedImages(k *linuxobj.Kernel, lw *memoryranges.LinuxWalker, t linuxobj.Task, mm uint64, areas []memoryranges.LinuxVMA, layer linuxobj.ProcessLayer, maxEntries int) ([]Library, error) {
	if len(areas) == 0 {
		return nil, nil
	}
	exe, err := k.Pointer(k.Memory(), mm, "mm_struct", "exe_file")
	if err != nil {
		return nil, fmt.Errorf("mm_struct at %#x: exe_file: %w", mm, err)
	}
	var out []Library
	var firstErr error
	for _, a := range areas {
		if a.File == 0 || a.File == exe {
			continue
		}
		pgoff, err := k.Uint(k.Memory(), a.Addr, "vm_area_struct", "vm_pgoff")
		if err != nil {
			firstErr = cmp.Or(firstErr, fmt.Errorf("vm_area_struct at %#x: vm_pgoff: %w", a.Addr, err))
			continue
		}
		if pgoff != 0 {
			continue
		}
		e, ok, err := linuxobj.ParseELF(layer.Reader, a.Start)
		if err != nil || !ok {
			continue
		}
		headers, err := e.ProgramHeaders(maxEntries)
		if err != nil {
			continue
		}
		base, ok := e.LoadBias(headers)
		if !ok {
			continue
		}
		path, named, err := lw.AreaName(t.Addr, mm, a)
		if err != nil {
			firstErr = cmp.Or(firstErr, fmt.Errorf("vm_area_struct at %#x: %w", a.Addr, err))
			continue
		}
		if !named {
			continue
		}
		out = append(out, Library{BaseAddress: base, Path: path, Route: RouteMappedImage})
	}
	return out, firstErr
}
