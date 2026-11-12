package kerneliomemory

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
)

const Name = "linux.kernel.list_io_memory"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "List the Linux kernel's I/O memory resource tree in /proc/iomem order"},
		RunAny,
	)
}

type NameState string

const (
	NameRead   NameState = "read"
	NameNull   NameState = "null"
	NameUnread NameState = "unread"
)

type Row struct {
	Address   uint64
	Depth     int
	Start     uint64
	End       uint64
	Flags     uint64
	Name      string
	NameState NameState
}

var (
	ErrNoRoot      = errors.New("kerneliomemory: iomem_resource not in the symbol table")
	ErrUnsupported = errors.New("kerneliomemory: struct resource is not in the symbol table")
)

var resourceMembers = []string{"start", "end", "name", "flags", "parent", "sibling", "child"}

type resource struct {
	start, end, name, flags uint64
	parent, sibling, child  uint64
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	k, err := linuxkern.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	root, err := k.Symbol("iomem_resource")
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", Name, ErrNoRoot, err)
	}
	for _, m := range resourceMembers {
		if _, err := k.Member("resource", m); err != nil {
			return nil, fmt.Errorf("%s: resource.%s: %w: %w", Name, m, ErrUnsupported, err)
		}
	}
	w := walker{k: k, lim: ctx.Bounds().MaxListEntries, depthLimit: ctx.Bounds().MaxRecursionDepth,
		nameBytes: uint64(ctx.Bounds().MaxNameBytes), seen: map[uint64]bool{root: true}}
	top, err := w.read(root)
	if err != nil {
		return nil, fmt.Errorf("%s: iomem_resource at 0x%x: %w", Name, k.Canonical(root), err)
	}
	w.walk(root, top)
	w.report(ctx)
	if w.lossy && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: the resource tree was read in part", Name)
	}
	return w.rows, nil
}

type frame struct {
	at      uint64
	res     resource
	lastEnd uint64
	listed  bool
}

type walker struct {
	k          *linuxkern.Kernel
	lim        int
	depthLimit int
	nameBytes  uint64
	seen       map[uint64]bool
	rows       []Row
	lossy      bool
	notes      []string
	unread     int
	firstBad   uint64
	parentOff  int
	outside    int
	disordered int
}

func (w *walker) read(at uint64) (resource, error) {
	var r resource
	for _, m := range []struct {
		name string
		to   *uint64
		ptr  bool
	}{{"start", &r.start, false}, {"end", &r.end, false}, {"name", &r.name, true}, {"flags", &r.flags, false},
		{"parent", &r.parent, true}, {"sibling", &r.sibling, true}, {"child", &r.child, true}} {
		var err error
		if m.ptr {
			*m.to, err = w.k.Ptr(at, "resource", m.name)
		} else {
			*m.to, err = w.k.Uint(at, "resource", m.name)
		}
		if err != nil {
			return resource{}, fmt.Errorf("resource.%s: %w", m.name, err)
		}
	}
	return r, nil
}

// The kernel's own traversal (next_resource) climbs back through parent
// pointers; this walk keeps its own path, so a corrupt parent pointer cannot
// send it elsewhere, and the stored parent is only checked.
func (w *walker) walk(root uint64, top resource) {
	path := []*frame{{at: root, res: top}}
	next := top.child
	for {
		for next == 0 {
			done := path[len(path)-1]
			path = path[:len(path)-1]
			if len(path) == 0 {
				return
			}
			next = done.res.sibling
		}
		at := next
		next = 0
		if w.seen[at] {
			w.stop("resource at 0x%x reached twice; the rest of its branch is not listed", w.k.Canonical(at))
			continue
		}
		if len(w.rows) >= w.lim {
			w.stop("listing stops at Limits.MaxListEntries (%d)", w.lim)
			return
		}
		w.seen[at] = true
		r, err := w.read(at)
		if err != nil {
			w.lossy = true
			if w.unread == 0 {
				w.firstBad = w.k.Canonical(at)
				w.notes = append(w.notes, fmt.Sprintf("resource at 0x%x: %v; its children and later siblings are not listed", w.k.Canonical(at), err))
			}
			w.unread++
			continue
		}
		parent := path[len(path)-1]
		w.check(parent, r)
		w.rows = append(w.rows, w.row(at, len(path)-1, r))
		switch {
		case r.child == 0:
			next = r.sibling
		case len(path) >= w.depthLimit:
			w.stop("resource at 0x%x: children below depth %d are not listed (Limits.MaxRecursionDepth)", w.k.Canonical(at), w.depthLimit)
			next = r.sibling
		default:
			path = append(path, &frame{at: at, res: r})
			next = r.child
		}
	}
}

func (w *walker) stop(format string, args ...any) {
	w.lossy = true
	w.notes = append(w.notes, fmt.Sprintf(format, args...))
}

func (w *walker) check(parent *frame, r resource) {
	if r.parent != parent.at {
		w.parentOff++
	}
	if r.start > r.end || r.start < parent.res.start || r.end > parent.res.end {
		w.outside++
	}
	if parent.listed && r.start <= parent.lastEnd {
		w.disordered++
	}
	parent.lastEnd, parent.listed = r.end, true
}

func (w *walker) row(at uint64, depth int, r resource) Row {
	out := Row{Address: w.k.Canonical(at), Depth: depth, Start: r.start, End: r.end, Flags: r.flags}
	switch {
	case r.name == 0:
		out.NameState = NameNull
	default:
		s, err := w.k.StringAt(r.name, w.nameBytes)
		if err != nil {
			out.NameState = NameUnread
			w.lossy = true
			w.notes = append(w.notes, fmt.Sprintf("resource at 0x%x: name at 0x%x: %v", w.k.Canonical(at), w.k.Canonical(r.name), err))
			break
		}
		out.Name, out.NameState = s, NameRead
	}
	return out
}

func (w *walker) report(ctx tools.Context) {
	for _, n := range w.notes {
		ctx.AddDiagnostic("%s: %s", Name, n)
	}
	if w.unread > 1 {
		ctx.AddDiagnostic("%s: %d resources do not read, first at 0x%x", Name, w.unread, w.firstBad)
	}
	if w.parentOff > 0 {
		ctx.AddDiagnostic("%s: %d resources name a parent other than the resource they are listed under", Name, w.parentOff)
	}
	if w.outside > 0 {
		ctx.AddDiagnostic("%s: %d resources are not inside their parent's range", Name, w.outside)
	}
	if w.disordered > 0 {
		ctx.AddDiagnostic("%s: %d resources start at or before the end of the sibling before them", Name, w.disordered)
	}
}
