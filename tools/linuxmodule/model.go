// Package linuxmodule reads Linux kernel modules: one struct module and its
// memory and symbols (S06), the list, sysfs and scan views of the module set
// (S07), and the ELF rebuild of a module (S08).
package linuxmodule

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

var (
	ErrUnsupported = errors.New("linuxmodule: kernel layout not recognised")
	ErrUnreadable  = errors.New("linuxmodule: module fields do not read")
	ErrState       = errors.New("linuxmodule: state outside the module_state enum")
	ErrName        = errors.New("linuxmodule: name is empty, unterminated or not printable")
	ErrRegion      = errors.New("linuxmodule: region end wraps")
	ErrNoSymbols   = errors.New("linuxmodule: module has no symbol table")
)

type State uint8

const (
	Live State = iota
	Coming
	Going
	Unformed
)

func (s State) String() string {
	switch s {
	case Live:
		return "live"
	case Coming:
		return "coming"
	case Going:
		return "going"
	case Unformed:
		return "unformed"
	}
	return fmt.Sprintf("state %d", uint8(s))
}

// Kind values are the enum mod_mem_type indices (S06 F8), so the regions
// form maps mem[i] to Kind(i).
type Kind uint8

const (
	Text Kind = iota
	Data
	ROData
	ROAfterInit
	InitText
	InitData
	InitROData
	kinds
)

func (k Kind) String() string {
	switch k {
	case Text:
		return "text"
	case Data:
		return "data"
	case ROData:
		return "rodata"
	case ROAfterInit:
		return "ro_after_init"
	case InitText:
		return "init_text"
	case InitData:
		return "init_data"
	case InitROData:
		return "init_rodata"
	}
	return fmt.Sprintf("kind %d", uint8(k))
}

func (k Kind) Init() bool       { return k >= InitText }
func (k Kind) Executable() bool { return k == Text || k == InitText }
func (k Kind) Writable() bool   { return k == Data || k == InitData }

type Region struct {
	Kind Kind
	Base uint64
	Size uint64
}

func (r Region) End() uint64         { return r.Base + r.Size }
func (r Region) Holds(a uint64) bool { return a >= r.Base && a-r.Base < r.Size }

type Module struct {
	Address          uint64
	Name             string
	State            State
	Regions          []Region
	SelfLinked       bool
	Placed           bool
	LayoutDisordered bool
	Taints           uint64
	HasTaints        bool
	TaintsUnread     bool
}

func (m Module) region(k Kind) (Region, bool) {
	for _, r := range m.Regions {
		if r.Kind == k {
			return r, true
		}
	}
	return Region{}, false
}

func (m Module) Base() uint64 {
	r, _ := m.region(Text)
	return r.Base
}

func (m Module) TextSize() uint64 {
	r, _ := m.region(Text)
	return r.Size
}

func (m Module) CoreSize() uint64 { return m.sum(false) }
func (m Module) InitSize() uint64 { return m.sum(true) }

func (m Module) sum(init bool) uint64 {
	var n uint64
	for _, r := range m.Regions {
		if r.Kind.Init() == init {
			n += r.Size
		}
	}
	return n
}

func (m Module) RegionOf(a uint64) (Region, bool) {
	for _, r := range m.Regions {
		if r.Holds(a) {
			return r, true
		}
	}
	return Region{}, false
}

func (m Module) Holds(a uint64) bool {
	_, ok := m.RegionOf(a)
	return ok
}

type layoutShape struct {
	at                  uint64
	base, size, text    symbols.IntField
	ro, roAfterInit     symbols.IntField
	hasRO, hasROAfter   bool
	elementSize, count  uint64
	regionBase, regSize symbols.IntField
}

type shape struct {
	state      symbols.IntField
	list       uint64
	name       uint64
	nameLen    uint64
	selfLink   uint64
	regions    bool
	mem        layoutShape
	core, init layoutShape

	taints    symbols.IntField
	hasTaints bool

	kallsyms   uint64
	hasSymbols bool
	symtab     uint64
	numSymtab  symbols.IntField
	strtab     uint64
	typetab    uint64
	hasTypetab bool
	symSize    uint64

	kpPointer uint64
	numKP     symbols.IntField
	hasParams bool

	sectAttrs    uint64
	hasSectAttrs bool
}

type Model struct {
	r     linuxwalk.Reader
	width uint64
	s     shape
	syms  map[uint64]symbolSet
	kimg  *kernelImage
}

func New(r linuxwalk.Reader) (*Model, error) {
	if r.Mem == nil || r.Sym == nil {
		return nil, errors.New("linuxmodule: reader has no memory or no symbol table")
	}
	w := uint64(r.Sym.PointerSize())
	if w != 4 && w != 8 {
		return nil, fmt.Errorf("linuxmodule: %d-byte pointers: %w", w, ErrUnsupported)
	}
	m := &Model{r: r, width: w, syms: map[uint64]symbolSet{}}
	if err := m.resolve(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Model) Reader() linuxwalk.Reader { return m.r }

func (m *Model) PointerWidth() uint64 { return m.width }

// S06 F8: from v6.4 the kernel allocates each module_memory region on its
// own, so a module's regions need not touch.
func (m *Model) SeparateRegions() bool { return m.s.regions }

func (m *Model) resolve() error {
	s := &m.s
	var err error
	if s.state, err = m.intField("module", "state"); err != nil {
		return err
	}
	if s.list, err = m.offset("module", "list"); err != nil {
		return err
	}
	name, err := m.field("module", "name")
	if err != nil {
		return err
	}
	if s.nameLen = name.Type.ArrayLength; s.nameLen == 0 {
		return fmt.Errorf("linuxmodule: module.name has no array length: %w", ErrUnsupported)
	}
	s.name = name.Offset
	if s.selfLink, err = m.path("module", "mkobj", "mod"); err != nil {
		return err
	}
	if err := m.resolveMemory(); err != nil {
		return err
	}
	if s.taints, err = m.intField("module", "taints"); err == nil {
		s.hasTaints = true
	}
	m.resolveSymbols()
	m.resolveParams()
	if s.sectAttrs, err = m.offset("module", "sect_attrs"); err == nil {
		s.hasSectAttrs = true
	}
	return nil
}

func (m *Model) resolveMemory() error {
	s := &m.s
	if mem, err := m.field("module", "mem"); err == nil {
		elem := mem.Type.Name
		if mem.Type.Element != nil && mem.Type.Element.Name != "" {
			elem = mem.Type.Element.Name
		}
		size, err := m.size(elem)
		if err != nil {
			return err
		}
		if mem.Type.ArrayLength < uint64(kinds) {
			return fmt.Errorf("linuxmodule: module.mem has %d entries, fewer than %d: %w",
				mem.Type.ArrayLength, kinds, ErrUnsupported)
		}
		l := layoutShape{at: mem.Offset, elementSize: size, count: mem.Type.ArrayLength}
		base, err := m.field(elem, "base")
		if err != nil {
			return err
		}
		l.regionBase = symbols.IntField{Offset: base.Offset, Width: m.width}
		if l.regSize, err = m.intField(elem, "size"); err != nil {
			return err
		}
		s.regions, s.mem = true, l
		return nil
	}
	var err error
	if s.core, err = m.layout("core_layout"); err != nil {
		return fmt.Errorf("linuxmodule: module has neither mem nor core_layout: %w", err)
	}
	if s.init, err = m.layout("init_layout"); err != nil {
		return err
	}
	return nil
}

func (m *Model) layout(member string) (layoutShape, error) {
	at, err := m.offset("module", member)
	if err != nil {
		return layoutShape{}, err
	}
	l := layoutShape{at: at}
	b, err := m.field("module_layout", "base")
	if err != nil {
		return layoutShape{}, err
	}
	l.base = symbols.IntField{Offset: b.Offset, Width: m.width}
	if l.size, err = m.intField("module_layout", "size"); err != nil {
		return layoutShape{}, err
	}
	if l.text, err = m.intField("module_layout", "text_size"); err != nil {
		return layoutShape{}, err
	}
	if l.ro, err = m.intField("module_layout", "ro_size"); err == nil {
		l.hasRO = true
	}
	if l.roAfterInit, err = m.intField("module_layout", "ro_after_init_size"); err == nil {
		l.hasROAfter = true
	}
	return l, nil
}

func (m *Model) resolveSymbols() {
	s := &m.s
	var err error
	if s.kallsyms, err = m.offset("module", "kallsyms"); err != nil {
		return
	}
	if s.symtab, err = m.offset("mod_kallsyms", "symtab"); err != nil {
		return
	}
	if s.numSymtab, err = m.intField("mod_kallsyms", "num_symtab"); err != nil {
		return
	}
	if s.strtab, err = m.offset("mod_kallsyms", "strtab"); err != nil {
		return
	}
	if s.typetab, err = m.offset("mod_kallsyms", "typetab"); err == nil {
		s.hasTypetab = true
	}
	s.symSize = 24
	name := "elf64_sym"
	if m.width == 4 {
		s.symSize, name = 16, "elf32_sym"
	}
	if n, err := m.size(name); err == nil && n == s.symSize {
		s.symSize = n
	}
	s.hasSymbols = true
}

func (m *Model) resolveParams() {
	s := &m.s
	var err error
	if s.kpPointer, err = m.offset("module", "kp"); err != nil {
		return
	}
	if s.numKP, err = m.intField("module", "num_kp"); err != nil {
		return
	}
	s.hasParams = true
}

// Read reads one struct module and records the S06 facts about it.
func (m *Model) Read(addr uint64) (Module, error) {
	addr = m.form(addr)
	s := &m.s
	mod := Module{Address: addr}
	state, ok := m.uintField(addr, s.state)
	if !ok {
		return mod, ErrUnreadable
	}
	if state > uint64(Unformed) {
		return mod, ErrState
	}
	mod.State = State(state)
	raw, ok := m.bytes(addr+s.name, s.nameLen)
	if !ok {
		return mod, ErrUnreadable
	}
	name, ok := moduleName(raw)
	if !ok {
		return mod, ErrName
	}
	mod.Name = name
	if self, ok := m.pointer(addr + s.selfLink); ok {
		mod.SelfLinked = self == addr
	}
	if err := m.readRegions(&mod); err != nil {
		return mod, err
	}
	for _, r := range mod.Regions {
		if (r.Kind == Data) && r.Holds(addr) {
			mod.Placed = true
		}
	}
	if s.hasTaints {
		mod.HasTaints = true
		if t, ok := m.uintField(addr, s.taints); ok {
			mod.Taints = t
		} else {
			mod.TaintsUnread = true
		}
	}
	return mod, nil
}

func moduleName(raw []byte) (string, bool) {
	for i, b := range raw {
		if b == 0 {
			return string(raw[:i]), i > 0
		}
		if b < 0x21 || b > 0x7e {
			return "", false
		}
	}
	return "", false
}

func (m *Model) readRegions(mod *Module) error {
	s := &m.s
	if s.regions {
		for i := range uint64(kinds) {
			at := mod.Address + s.mem.at + i*s.mem.elementSize
			base, ok1 := m.uintField(at, s.mem.regionBase)
			size, ok2 := m.uintField(at, s.mem.regSize)
			if !ok1 || !ok2 {
				return ErrUnreadable
			}
			if err := m.addRegion(mod, Kind(i), base, size); err != nil {
				return err
			}
		}
		return nil
	}
	for _, l := range []struct {
		shape layoutShape
		first Kind
	}{{s.core, Text}, {s.init, InitText}} {
		if err := m.readLayout(mod, l.shape, l.first); err != nil {
			return err
		}
	}
	return nil
}

func (m *Model) readLayout(mod *Module, l layoutShape, first Kind) error {
	at := mod.Address + l.at
	base, ok1 := m.uintField(at, l.base)
	size, ok2 := m.uintField(at, l.size)
	text, ok3 := m.uintField(at, l.text)
	if !ok1 || !ok2 || !ok3 {
		return ErrUnreadable
	}
	ro, roAfter := text, text
	if l.hasRO {
		v, ok := m.uintField(at, l.ro)
		if !ok {
			return ErrUnreadable
		}
		ro, roAfter = v, v
	}
	if l.hasROAfter {
		v, ok := m.uintField(at, l.roAfterInit)
		if !ok {
			return ErrUnreadable
		}
		roAfter = v
	}
	if !(text <= ro && ro <= roAfter && roAfter <= size) {
		mod.LayoutDisordered = true
		return m.addRegion(mod, first, base, size)
	}
	data, rodata, after := Data, ROData, ROAfterInit
	if first == InitText {
		data, rodata, after = InitData, InitROData, InitROData
	}
	parts := []struct {
		kind       Kind
		start, end uint64
	}{{first, 0, text}, {rodata, text, ro}, {after, ro, roAfter}, {data, roAfter, size}}
	for _, p := range parts {
		if err := m.addRegion(mod, p.kind, base+p.start, p.end-p.start); err != nil {
			return err
		}
	}
	return nil
}

func (m *Model) addRegion(mod *Module, k Kind, base, size uint64) error {
	if size == 0 {
		return nil
	}
	limit := ^uint64(0)
	if m.width == 4 {
		limit = 1<<32 - 1
	}
	if base > limit || size-1 > limit-base {
		return ErrRegion
	}
	mod.Regions = append(mod.Regions, Region{Kind: k, Base: m.form(base), Size: size})
	return nil
}
