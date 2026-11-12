package pesymbols

import (
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/windows/librarylist"
	"github.com/aoiflux/libvapour/tools/windows/modulelist"
)

// folded merges the asks of module names that differ only in case or
// surrounding space, so the answers are keyed by the folded name.
func folded[T any](wanted map[string][]T) map[string][]T {
	out := make(map[string][]T, len(wanted))
	for _, m := range moduleKeys(wanted) {
		k := moduleKey(m)
		out[k] = append(out[k], wanted[m]...)
	}
	return out
}

func moduleKeys[T any](wanted map[string][]T) []string {
	keys := make([]string, 0, len(wanted))
	for m := range wanted {
		keys = append(keys, m)
	}
	slices.Sort(keys)
	return keys
}

type instanceSet struct {
	collect func() (map[string][]Module, error)
	found   map[string][]Module
	err     error
	done    bool
}

// Collecting walks every process, so it waits until a module needs more than
// the kernel's own table can answer.
func lazyInstances[T any](ctx tools.Context, source string, wanted map[string][]T) *instanceSet {
	keys := moduleKeys(wanted)
	return &instanceSet{collect: func() (map[string][]Module, error) { return CollectModules(ctx, source, keys) }}
}

func (s *instanceSet) of(module string) []Module {
	if !s.done {
		s.done = true
		s.found, s.err = s.collect()
	}
	return s.found[module]
}

func CollectModules(ctx tools.Context, source string, want []string) (map[string][]Module, error) {
	keys := map[string]bool{}
	for _, n := range want {
		if k := moduleKey(n); k != "" {
			keys[k] = true
		}
	}
	if len(keys) == 0 {
		return map[string][]Module{}, nil
	}
	if source == SourceKernel {
		return kernelInstances(ctx, keys)
	}
	fromLoader, err := ctx.BoolOption(OptionLoaderList)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	// Every process is read whatever the pid option says: a name missing from
	// a narrowed set would read as absent rather than unexamined.
	all := ctx.WithoutPIDFilter()
	if fromLoader {
		return loaderInstances(all, keys)
	}
	return viewInstances(all, keys)
}

func kernelInstances(ctx tools.Context, keys map[string]bool) (map[string][]Module, error) {
	mods, err := modulelist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("kernel modules: %w", err)
	}
	out := map[string][]Module{}
	for _, m := range modulelist.Placed(ctx, Name, mods) {
		if k := moduleKey(m.Name); keys[k] && !m.NameUnreadable {
			out[k] = append(out[k], Module{Name: k, Base: m.Base, Size: m.Size})
		}
	}
	return out, nil
}

func loaderInstances(ctx tools.Context, keys map[string]bool) (map[string][]Module, error) {
	dlls, err := librarylist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("process modules: %w", err)
	}
	out := map[string][]Module{}
	for _, d := range dlls {
		k := moduleKey(d.Name)
		if !keys[k] || d.NameUnreadable || d.Base == 0 {
			continue
		}
		out[k] = append(out[k], Module{PID: d.PID, ProcessName: d.ProcName, DirectoryTableBase: d.DirectoryTableBase,
			Name: k, Base: d.Base, Size: d.Size})
	}
	return out, nil
}

// A view's file name is the last element of the mapped file's path; a view
// with no path, or a path without a separator, names no module.
func viewInstances(ctx tools.Context, keys map[string]bool) (map[string][]Module, error) {
	procs, err := processlist.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("process list: %w", err)
	}
	files, err := memoryranges.ResolveFileNames(ctx)
	if err != nil {
		return nil, fmt.Errorf("mapped file names: %w", err)
	}
	out := map[string][]Module{}
	unopened := 0
	for _, p := range procs {
		if _, err := ctx.ProcessSpace(p.DirectoryTableBase); err != nil {
			unopened++
			continue
		}
		vads, err := memoryranges.ProcessVADs(ctx, p)
		if err != nil {
			ctx.AddDiagnostic("%s: pid %d (%s): views not walked: %v", Name, p.PID, p.Name, err)
			continue
		}
		for _, v := range vads {
			path, ok := files.Name(ctx, v.Base)
			cut := strings.LastIndexAny(path, `\/`)
			if !ok || cut < 0 || v.End < v.Start {
				continue
			}
			k := moduleKey(path[cut+1:])
			if !keys[k] {
				continue
			}
			out[k] = append(out[k], Module{PID: p.PID, ProcessName: p.Name, DirectoryTableBase: p.DirectoryTableBase,
				Name: k, Base: v.Start, Size: v.End - v.Start + 1})
		}
	}
	if unopened > 0 {
		ctx.AddDiagnostic("%s: %d processes passed over: their address space does not open", Name, unopened)
	}
	return out, nil
}
