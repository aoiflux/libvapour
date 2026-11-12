package tracingtracepoints

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
	"github.com/aoiflux/libvapour/tools/linuxtrace"
)

const Name = "linux.tracing.check_tracepoints"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the probes attached to the kernel's and modules' tracepoints and the module or kernel code that holds them",
		},
		RunAny,
	)
}

var (
	ErrNoTracepoints = errors.New("tracingtracepoints: __start___tracepoints_ptrs or __stop___tracepoints_ptrs not in the symbol table")
	ErrNoEntryForm   = errors.New("tracingtracepoints: no entry of __tracepoints_ptrs names a readable tracepoint under either entry form")
)

type Probe struct {
	Tracepoint        string
	TracepointAddress uint64
	TracepointOwner   string
	KeyEnabled        bool
	Probes            int
	ProbeAddress      uint64
	ProbeSymbol       string
	DataAddress       uint64
	Priority          int64
	Module            string
	ModuleAddress     uint64
	ModuleFound       bool
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

// TP6: a tracepoint name is the text of an identifier that also names the
// symbol __tracepoint_<name>, so it fits in KSYM_NAME_LEN (512 from v6.1,
// 128 at v4.19).
const nameBytes = 512

func Run(ctx tools.Context) ([]Probe, error) {
	if err := ctx.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	k := linuxtrace.New(ctx)
	for _, m := range [][2]string{{"tracepoint", "name"}, {"tracepoint", "funcs"}, {"tracepoint_func", "func"},
		{"tracepoint_func", "data"}, {"tracepoint_func", "prio"}} {
		if _, err := k.Field(m[0], m[1]); err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
	}
	funcSize, err := k.SizeOf("tracepoint_func")
	if err != nil || funcSize == 0 {
		return nil, fmt.Errorf("%s: tracepoint_func: no size: %w", Name, errors.Join(err, linuxtrace.ErrUnsupported))
	}
	c := &check{k: k, diag: ctx.AddDiagnostic, funcSize: funcSize, lim: ctx.Bounds().MaxListEntries,
		maxEntries: uint64(ctx.Bounds().MaxTableEntries)}
	c.keyOffset, c.keyKnown = keyEnabledOffset(k)
	if !c.keyKnown {
		ctx.AddDiagnostic("%s: tracepoint.key: no static_key.enabled member in the table; KeyEnabled is false on every row", Name)
	}
	kernel, err := c.kernelSection()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	c.owners = newOwners(k, ctx.AddDiagnostic)
	var out []Probe
	for _, tp := range kernel {
		out = append(out, c.probes(tp, linuxmodule.KernelOwner)...)
	}
	for _, mod := range c.owners.known {
		for _, tp := range c.moduleSection(mod) {
			out = append(out, c.probes(tp, mod.Name)...)
		}
	}
	if (c.lossy || c.owners.lossy) && ctx.StrictMode() {
		return nil, fmt.Errorf("%s: strict mode: tracepoint sections, probe arrays or module views were read in part", Name)
	}
	return out, nil
}

type check struct {
	k          *linuxtrace.Kernel
	diag       func(string, ...any)
	owners     *owners
	funcSize   uint64
	lim        int
	maxEntries uint64
	form       entryForm
	keyOffset  uint64
	keyKnown   bool
	lossy      bool
}

func (c *check) kernelSection() ([]uint64, error) {
	k := c.k
	start, err1 := k.Symbol("__start___tracepoints_ptrs")
	stop, err2 := k.Symbol("__stop___tracepoints_ptrs")
	if err1 != nil || err2 != nil {
		return nil, ErrNoTracepoints
	}
	if stop.Address < start.Address {
		return nil, fmt.Errorf("__tracepoints_ptrs at %#x: ends at %#x, before it starts: %w", start.Address,
			stop.Address, linuxtrace.ErrUnsupported)
	}
	size := stop.Address - start.Address
	if size == 0 {
		return nil, nil
	}
	ptr := k.PointerSize()
	if most := c.maxEntries * max(ptr, 4); size > most {
		c.lossy = true
		c.diag("%s: __tracepoints_ptrs at %#x: %d bytes, only the first %d are read (Limits.MaxTableEntries)",
			Name, start.Address, size, most)
		size = most
	}
	raw, err := k.Memory().ReadAt(start.Address, size)
	if err == nil && uint64(len(raw)) < size {
		err = fmt.Errorf("tracingtracepoints: %d of %d bytes read", len(raw), size)
	}
	if err != nil {
		return nil, fmt.Errorf("__tracepoints_ptrs at %#x: %w", start.Address, err)
	}
	form, n, ok := chooseForm(size, ptr, c.typedForm(), func(f entryForm) int {
		count := 0
		for _, tp := range decodeEntries(raw, start.Address, f, ptr, k.Canonical) {
			if _, err := c.name(tp); err == nil {
				count++
			}
		}
		return count
	})
	if !ok {
		return nil, ErrNoEntryForm
	}
	c.form = form
	entries := decodeEntries(raw, start.Address, form, ptr, k.Canonical)
	if uint64(len(entries)) > c.maxEntries {
		c.lossy = true
		c.diag("%s: __tracepoints_ptrs at %#x: %d entries, only the first %d are read (Limits.MaxTableEntries)",
			Name, start.Address, len(entries), c.maxEntries)
		entries = entries[:c.maxEntries]
	}
	if n < len(entries) {
		c.diag("%s: __tracepoints_ptrs at %#x: %d of %d entries do not name a readable tracepoint", Name,
			start.Address, len(entries)-n, len(entries))
	}
	return entries, nil
}

// TP4: module.tracepoints_ptrs is a tracepoint_ptr_t pointer, so the table's
// type of its target tells the configured form where the table has it.
func (c *check) typedForm() *entryForm {
	f, err := c.k.Field("module", "tracepoints_ptrs")
	if err != nil || !f.Type.IsPointer || f.Type.Element == nil {
		return nil
	}
	form := formRelative
	if f.Type.Element.IsPointer {
		form = formPointer
	}
	return &form
}

// TP7: a module's own entries are in the same form, num_tracepoints of them.
func (c *check) moduleSection(mod linuxmodule.Module) []uint64 {
	k := c.k
	if !k.Has("module", "tracepoints_ptrs") || !k.Has("module", "num_tracepoints") {
		return nil
	}
	ptrs, err1 := k.Pointer(mod.Address, "module", "tracepoints_ptrs")
	num, err2 := k.Uint(mod.Address, "module", "num_tracepoints")
	if err := errors.Join(err1, err2); err != nil {
		c.lossy = true
		c.diag("%s: module at %#x: tracepoint section: %v", Name, mod.Address, err)
		return nil
	}
	if ptrs == 0 || num == 0 {
		return nil
	}
	if num > c.maxEntries {
		c.lossy = true
		c.diag("%s: module at %#x: %d tracepoints, only the first %d are read (Limits.MaxTableEntries)", Name,
			mod.Address, num, c.maxEntries)
		num = c.maxEntries
	}
	ptr := k.PointerSize()
	size := num * c.form.width(ptr)
	raw, err := k.Memory().ReadAt(ptrs, size)
	if err == nil && uint64(len(raw)) < size {
		err = fmt.Errorf("tracingtracepoints: %d of %d bytes read", len(raw), size)
	}
	if err != nil {
		c.lossy = true
		c.diag("%s: module at %#x: __tracepoints_ptrs at %#x: %v", Name, mod.Address, ptrs, err)
		return nil
	}
	return decodeEntries(raw, ptrs, c.form, ptr, k.Canonical)
}

func (c *check) name(tp uint64) (string, error) {
	if c.k.Masked(tp) == 0 {
		return "", errors.New("tracingtracepoints: entry is null")
	}
	p, err := c.k.Pointer(tp, "tracepoint", "name")
	if err != nil {
		return "", err
	}
	if c.k.Masked(p) == 0 {
		return "", errors.New("tracingtracepoints: name pointer is null")
	}
	s, err := c.k.StringAt(p, nameBytes)
	if err == nil && s == "" {
		err = errors.New("tracingtracepoints: name is empty")
	}
	return s, err
}

// TP10: the key's enabled count is a static_key member, inside a
// static_key_false from v6.14 and directly at v4.19 to v6.4.
func keyEnabledOffset(k *linuxtrace.Kernel) (uint64, bool) {
	f, err := k.Field("tracepoint", "key")
	if err != nil {
		return 0, false
	}
	off, typ := f.Offset, f.Type.Name
	if typ != "static_key" {
		inner, err := k.Field(typ, "key")
		if err != nil {
			return 0, false
		}
		off += inner.Offset
	}
	if _, err := k.Field("static_key", "enabled"); err != nil {
		return 0, false
	}
	return off, true
}

// TP8, TP9: the probe array ends at the first null func and the kernel calls
// the probes in array order. A tracepoint with no probe gives one row with no
// probe, so the listing covers every tracepoint (TP-O1).
func (c *check) probes(tp uint64, tpOwner string) []Probe {
	k := c.k
	name, err := c.name(tp)
	if err != nil {
		c.lossy = true
		c.diag("%s: tracepoint at %#x: name: %v", Name, tp, err)
		return nil
	}
	funcs, err := k.Pointer(tp, "tracepoint", "funcs")
	if err != nil {
		c.lossy = true
		c.diag("%s: tracepoint at %#x: funcs: %v", Name, tp, err)
		return nil
	}
	base := Probe{Tracepoint: name, TracepointAddress: tp, TracepointOwner: tpOwner}
	if c.keyKnown {
		v, err := k.Uint(tp+c.keyOffset, "static_key", "enabled")
		if err != nil {
			c.lossy = true
			c.diag("%s: tracepoint at %#x: key: %v", Name, tp, err)
		}
		base.KeyEnabled = v != 0
	}
	var out []Probe
	for i := 0; k.Masked(funcs) != 0; i++ {
		if i >= c.lim {
			c.lossy = true
			c.diag("%s: tracepoint at %#x: probe array at %#x: more than %d probes (Limits.MaxListEntries)", Name,
				tp, funcs, c.lim)
			break
		}
		at := funcs + uint64(i)*c.funcSize
		fn, err1 := k.Pointer(at, "tracepoint_func", "func")
		if err1 == nil && k.Masked(fn) == 0 {
			break
		}
		data, err2 := k.Pointer(at, "tracepoint_func", "data")
		prio, err3 := k.Int(at, "tracepoint_func", "prio")
		if err := errors.Join(err1, err2, err3); err != nil {
			c.lossy = true
			c.diag("%s: tracepoint at %#x: probe %d at %#x: %v", Name, tp, i, at, err)
			break
		}
		o := c.owners.of(fn)
		row := base
		row.ProbeAddress, row.ProbeSymbol, row.DataAddress, row.Priority = fn, o.symbol, data, prio
		row.Module, row.ModuleAddress, row.ModuleFound = o.module, o.moduleAddress, o.found
		out = append(out, row)
	}
	if c.keyKnown && base.KeyEnabled != (len(out) > 0) {
		c.diag("%s: tracepoint at %#x: static key enabled %v with %d probes", Name, tp, base.KeyEnabled, len(out))
	}
	if len(out) == 0 {
		return []Probe{base}
	}
	for i := range out {
		out[i].Probes = len(out)
	}
	return out
}
