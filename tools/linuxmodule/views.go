package linuxmodule

import (
	"errors"
	"fmt"
	"sort"

	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

var (
	ErrNoModuleList = errors.New("linuxmodule: modules list head not in the symbol table")
	ErrNoKset       = errors.New("linuxmodule: module_kset missing, null or unreadable")
	ErrNoModuleArea = errors.New("linuxmodule: mod_tree not in the symbol table")
	ErrModuleArea   = errors.New("linuxmodule: module area outside the x86 module range or over the scan cap")
)

type Source uint8

const (
	FromList Source = iota
	FromSysfs
	FromScan
)

func (s Source) String() string {
	switch s {
	case FromList:
		return "list"
	case FromSysfs:
		return "sysfs"
	case FromScan:
		return "scan"
	}
	return fmt.Sprintf("source %d", uint8(s))
}

// View is one source's module set, with what was left out and why.
type View struct {
	Source  Source
	Modules []Module
	Failed  map[error]int
	Walk    *linuxwalk.List
	BuiltIn int
	Capped  bool
	Ranges  [][2]uint64
}

func (v *View) fail(err error) {
	if v.Failed == nil {
		v.Failed = map[error]int{}
	}
	v.Failed[err]++
}

func (v View) Has(addr uint64) bool {
	for _, m := range v.Modules {
		if m.Address == addr {
			return true
		}
	}
	return false
}

func (v View) set() map[uint64]bool {
	out := make(map[uint64]bool, len(v.Modules))
	for _, m := range v.Modules {
		out[m.Address] = true
	}
	return out
}

// Report puts the view's losses into diagnostics.
func (v View) Report(diag func(format string, args ...any), tool string) {
	if v.Walk != nil && v.Walk.Broken() {
		diag("%s: the %s walk ends after %d entries at %#x: %s", tool, v.Source, len(v.Walk.Entries), v.Walk.At, v.Walk.End)
	}
	errs := make([]error, 0, len(v.Failed))
	for err := range v.Failed {
		errs = append(errs, err)
	}
	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	for _, err := range errs {
		diag("%s: %d %s entries are left out: %v", tool, v.Failed[err], v.Source, err)
	}
	if v.Capped {
		diag("%s: the %s view stops at Limits.MaxListEntries", tool, v.Source)
	}
}

// Lossy is true when the view left anything out, for strict mode.
func (v View) Lossy() bool {
	return len(v.Failed) > 0 || v.Capped || (v.Walk != nil && v.Walk.Broken())
}

// List is the modules list view (S07 4.1).
func (m *Model) List() (View, error) {
	head, ok := m.symbol("modules")
	if !ok {
		return View{}, ErrNoModuleList
	}
	walk, err := m.r.List(head, "module", "list", linuxwalk.Forward)
	if err != nil {
		return View{}, err
	}
	v := View{Source: FromList, Walk: &walk}
	for _, at := range walk.Entries {
		mod, err := m.Read(at)
		if err != nil {
			v.fail(err)
			continue
		}
		v.Modules = append(v.Modules, mod)
	}
	return v, nil
}

// Sysfs is the module_kset view (S07 4.2).
func (m *Model) Sysfs() (View, error) {
	at, ok := m.symbol("module_kset")
	if !ok {
		return View{}, ErrNoKset
	}
	kset, ok := m.pointer(at)
	if !ok || kset == 0 {
		return View{}, ErrNoKset
	}
	list, err := m.offset("kset", "list")
	if err != nil {
		return View{}, err
	}
	kobj, err := m.offset("module_kobject", "kobj")
	if err != nil {
		return View{}, err
	}
	back, err := m.offset("module_kobject", "mod")
	if err != nil {
		return View{}, err
	}
	walk, err := m.r.List(kset+list, "kobject", "entry", linuxwalk.Forward)
	if err != nil {
		return View{}, err
	}
	if walk.End == linuxwalk.HeadUnreadable {
		return View{}, ErrNoKset
	}
	v := View{Source: FromSysfs, Walk: &walk}
	for _, ko := range walk.Entries {
		mod, ok := m.pointer(ko - kobj + back)
		if !ok {
			v.fail(ErrUnreadable)
			continue
		}
		if mod == 0 {
			v.BuiltIn++
			continue
		}
		read, err := m.Read(mod)
		if err != nil {
			v.fail(err)
			continue
		}
		v.Modules = append(v.Modules, read)
	}
	return v, nil
}

// x86-64 module area bounds (S07 D6).
const (
	moduleAreaStart = 0xffffffffa0000000
	moduleAreaEnd   = 0xffffffffff000000
)

func (m *Model) scanRanges() ([][2]uint64, error) {
	tree, ok := m.symbol("mod_tree")
	if !ok {
		return nil, ErrNoModuleArea
	}
	var out [][2]uint64
	var total uint64
	for _, pair := range [][2]string{{"addr_min", "addr_max"}, {"data_addr_min", "data_addr_max"}} {
		if !m.has("mod_tree_root", pair[0]) || !m.has("mod_tree_root", pair[1]) {
			continue
		}
		lo, err := m.offset("mod_tree_root", pair[0])
		if err != nil {
			return nil, err
		}
		hi, err := m.offset("mod_tree_root", pair[1])
		if err != nil {
			return nil, err
		}
		minV, ok1 := m.word(tree + lo)
		maxV, ok2 := m.word(tree + hi)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("linuxmodule: mod_tree.%s does not read: %w", pair[0], ErrNoModuleArea)
		}
		if minV >= maxV {
			continue
		}
		if m.width == 8 && (minV < moduleAreaStart || maxV > moduleAreaEnd) {
			return nil, fmt.Errorf("linuxmodule: %#x-%#x: %w", minV, maxV, ErrModuleArea)
		}
		total += maxV - minV
		out = append(out, [2]uint64{m.form(minV), m.form(minV) + (maxV - minV)})
	}
	if lim := m.r.Limits.Effective().MaxRegionScanBytes; lim > 0 && total > uint64(lim) {
		return nil, fmt.Errorf("linuxmodule: %d bytes to scan, cap %d: %w", total, lim, ErrModuleArea)
	}
	return out, nil
}

// Scan is the module-area scan view (S07 4.3).
func (m *Model) Scan() (View, error) {
	ranges, err := m.scanRanges()
	if err != nil {
		return View{}, err
	}
	v := View{Source: FromScan, Ranges: ranges}
	limit := m.r.Limits.Effective().MaxListEntries
	seen := map[uint64]bool{}
	pages := newPages(m)
scan:
	for _, rg := range ranges {
		for page := rg[0] &^ (pageSize - 1); page < rg[1]; page += pageSize {
			if !pages.readable(page) {
				continue
			}
			for at := max(page, rg[0]); at < page+pageSize && at < rg[1]; at += m.width {
				if !m.candidate(pages, at) || seen[at] {
					continue
				}
				mod, err := m.Read(at)
				if err != nil || !mod.SelfLinked || !mod.Placed {
					continue
				}
				seen[at] = true
				v.Modules = append(v.Modules, mod)
				if limit > 0 && len(v.Modules) >= limit {
					v.Capped = true
					break scan
				}
			}
			if page+pageSize < page {
				break
			}
		}
	}
	sort.Slice(v.Modules, func(i, j int) bool { return v.Modules[i].Address < v.Modules[j].Address })
	return v, nil
}

func (m *Model) candidate(p *pages, at uint64) bool {
	s := &m.s
	state, ok := p.uint(at+s.state.Offset, s.state.Width)
	if !ok || state > uint64(Unformed) {
		return false
	}
	self, ok := p.uint(at+s.selfLink, m.width)
	return ok && m.form(self) == at
}

// pages keeps the last few pages read, so the per-address candidate test
// reads memory once per page.
type pages struct {
	m     *Model
	cache map[uint64][]byte
	order []uint64
}

func newPages(m *Model) *pages { return &pages{m: m, cache: map[uint64][]byte{}} }

func (p *pages) get(page uint64) ([]byte, bool) {
	if b, ok := p.cache[page]; ok {
		return b, b != nil
	}
	b, ok := p.m.bytes(page, pageSize)
	if !ok {
		b = nil
	}
	if len(p.order) >= 4 {
		delete(p.cache, p.order[0])
		p.order = p.order[1:]
	}
	p.cache[page] = b
	p.order = append(p.order, page)
	return b, b != nil
}

func (p *pages) readable(page uint64) bool {
	_, ok := p.get(page)
	return ok
}

func (p *pages) uint(at, width uint64) (uint64, bool) {
	var v uint64
	for i := range width {
		a := at + i
		b, ok := p.get(a &^ (pageSize - 1))
		if !ok {
			return 0, false
		}
		v |= uint64(b[a%pageSize]) << (8 * i)
	}
	return v, true
}

// Union combines views by struct module address in the order given: the
// first view's order, then each later view's new modules in its order.
func Union(views ...View) []Module {
	seen := map[uint64]bool{}
	var out []Module
	for _, v := range views {
		for _, mod := range v.Modules {
			if !seen[mod.Address] {
				seen[mod.Address] = true
				out = append(out, mod)
			}
		}
	}
	return out
}

// Missing gives the modules of v whose address is not in other.
func Missing(v, other View) []Module {
	have := other.set()
	var out []Module
	for _, mod := range v.Modules {
		if !have[mod.Address] {
			out = append(out, mod)
		}
	}
	return out
}

// Views builds every view it can. It fails only when none builds; errs holds
// each view's failure.
type Views struct {
	List, Sysfs, Scan          View
	ListErr, SysfsErr, ScanErr error
}

func (m *Model) Views() (Views, error) {
	var vs Views
	vs.List, vs.ListErr = m.List()
	vs.Sysfs, vs.SysfsErr = m.Sysfs()
	vs.Scan, vs.ScanErr = m.Scan()
	if vs.ListErr != nil && vs.SysfsErr != nil && vs.ScanErr != nil {
		return vs, errors.Join(vs.ListErr, vs.SysfsErr, vs.ScanErr)
	}
	return vs, nil
}

func (vs Views) Known() []Module { return Union(vs.List, vs.Sysfs, vs.Scan) }

// Report puts each failed view and each view's losses into diagnostics.
func (vs Views) Report(diag func(format string, args ...any), tool string) {
	for _, f := range []struct {
		v   View
		err error
		s   Source
	}{{vs.List, vs.ListErr, FromList}, {vs.Sysfs, vs.SysfsErr, FromSysfs}, {vs.Scan, vs.ScanErr, FromScan}} {
		if f.err != nil {
			diag("%s: no %s view: %v", tool, f.s, f.err)
			continue
		}
		f.v.Report(diag, tool)
	}
}

// Lossy reports whether any view failed or left anything out.
func (vs Views) Lossy() bool {
	return vs.ListErr != nil || vs.SysfsErr != nil || vs.ScanErr != nil ||
		vs.List.Lossy() || vs.Sysfs.Lossy() || vs.Scan.Lossy()
}
