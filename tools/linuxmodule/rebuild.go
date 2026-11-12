package linuxmodule

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

var (
	ErrNoSections = errors.New("linuxmodule: module has no readable section attributes")
	ErrTooLarge   = errors.New("linuxmodule: rebuilt file is over the artefact cap")
)

type Section struct {
	Name    string
	Address uint64
	Size    uint64
	Region  Region
}

type Sections struct {
	List            []Section
	Dropped         []string
	Skipped         int
	Capped          bool
	AttrsDisordered bool
}

type sectForm uint8

const (
	formA sectForm = iota + 1
	formB
	formC
)

// Sections reads a module's sysfs section entries (S08 4.1).
func (m *Model) Sections(mod Module) (Sections, error) {
	s := &m.s
	if !s.hasSectAttrs {
		return Sections{}, fmt.Errorf("linuxmodule: module.sect_attrs: %w", ErrUnsupported)
	}
	attrs, ok := m.pointer(mod.Address + s.sectAttrs)
	if !ok || attrs == 0 {
		return Sections{}, ErrNoSections
	}
	form, elem, err := m.sectForm()
	if err != nil {
		return Sections{}, err
	}
	first, err := m.offset("module_sect_attrs", "attrs")
	if err != nil {
		return Sections{}, err
	}
	size, err := m.size(elem)
	if err != nil {
		return Sections{}, err
	}
	var out Sections
	count, err := m.sectCount(form, attrs, attrs+first, size, &out)
	if err != nil {
		return Sections{}, err
	}
	nameAt, addrAt, err := m.sectFields(form)
	if err != nil {
		return Sections{}, err
	}
	nameLimit := uint64(m.r.Limits.Effective().MaxNameBytes)
	var kept []Section
	for i := range count {
		at := attrs + first + i*size
		namePtr, ok1 := m.pointer(at + nameAt)
		addr, ok2 := m.pointer(at + addrAt)
		if !ok1 || !ok2 {
			out.Skipped++
			continue
		}
		name, _, ok := m.cstring(namePtr, nameLimit)
		if !ok {
			out.Skipped++
			continue
		}
		r, ok := mod.RegionOf(addr)
		if !ok {
			out.Dropped = append(out.Dropped, name)
			continue
		}
		kept = append(kept, Section{Name: name, Address: addr, Region: r})
	}
	if len(kept) == 0 {
		return out, ErrNoSections
	}
	sizeSections(kept)
	out.List = kept
	return out, nil
}

func (m *Model) sectForm() (sectForm, string, error) {
	if f, err := m.r.Sym.Field("module_sect_attrs", "attrs"); err == nil {
		elem := f.Type.Name
		if f.Type.Element != nil && f.Type.Element.Name != "" {
			elem = f.Type.Element.Name
		}
		switch {
		case elem == "bin_attribute":
			return formC, elem, nil
		case m.has("module_sect_attr", "battr") && m.has("module_sect_attr", "address"):
			return formB, "module_sect_attr", nil
		case m.has("module_sect_attr", "name") && m.has("module_sect_attr", "address"):
			return formA, "module_sect_attr", nil
		}
	}
	return 0, "", fmt.Errorf("linuxmodule: no known module_sect_attrs form: %w", ErrUnsupported)
}

func (m *Model) sectFields(form sectForm) (name, addr uint64, err error) {
	switch form {
	case formA:
		if name, err = m.offset("module_sect_attr", "name"); err != nil {
			return
		}
		addr, err = m.offset("module_sect_attr", "address")
	case formB:
		if name, err = m.path("module_sect_attr", "battr", "attr", "name"); err != nil {
			return
		}
		addr, err = m.offset("module_sect_attr", "address")
	case formC:
		if name, err = m.path("bin_attribute", "attr", "name"); err != nil {
			return
		}
		addr, err = m.offset("bin_attribute", "private")
	}
	return
}

func (m *Model) sectCount(form sectForm, attrs, first, size uint64, out *Sections) (uint64, error) {
	limit := uint64(m.r.Limits.Effective().MaxTableEntries)
	if form != formC {
		f, err := m.intField("module_sect_attrs", "nsections")
		if err != nil {
			return 0, err
		}
		n, ok := m.uintField(attrs, f)
		if !ok {
			return 0, ErrNoSections
		}
		if limit > 0 && n > limit {
			n, out.Capped = limit, true
		}
		return n, nil
	}
	grp, err := m.path("module_sect_attrs", "grp", "bin_attrs")
	if err != nil {
		return 0, err
	}
	list, ok := m.pointer(attrs + grp)
	if !ok || list == 0 {
		return 0, ErrNoSections
	}
	var n uint64
	for {
		if limit > 0 && n >= limit {
			out.Capped = true
			return n, nil
		}
		p, ok := m.pointer(list + n*m.width)
		if !ok || p == 0 {
			return n, nil
		}
		if p != first+n*size {
			out.AttrsDisordered = true
			return n, nil
		}
		n++
	}
}

// sizeSections gives each section the distance to the next section in its
// region, or to the region's end (S08 4.1 step 6).
func sizeSections(secs []Section) {
	idx := make([]int, len(secs))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		sa, sb := secs[idx[a]], secs[idx[b]]
		if sa.Region.Base != sb.Region.Base {
			return sa.Region.Base < sb.Region.Base
		}
		return sa.Address < sb.Address
	})
	for k, i := range idx {
		end := secs[i].Region.End()
		if k+1 < len(idx) {
			if next := secs[idx[k+1]]; next.Region.Base == secs[i].Region.Base {
				end = next.Address
			}
		}
		secs[i].Size = end - secs[i].Address
	}
}

type Rebuild struct {
	File            []byte
	Sections        int
	Dropped         []string
	Skipped         int
	Capped          bool
	Symbols         int
	NoSymbols       bool
	ZeroPages       int
	AttrsDisordered bool
}

// ELF constants (S08 G1 to G6).
const (
	etRel       = 1
	emI386      = 3
	emX8664     = 62
	shtProgbits = 1
	shtSymtab   = 2
	shtStrtab   = 3
	shfWrite    = 1
	shfAlloc    = 2
	shfExec     = 4
	shnAbs      = 0xfff1
	stbLocal    = 0
	stbGlobal   = 1
	stbWeak     = 2
	sttNotype   = 0
	sttObject   = 1
	sttFunc     = 2
)

type outSym struct {
	name   uint32
	info   byte
	shndx  uint16
	value  uint64
	size   uint64
	global bool
}

// RebuildELF writes the S08 relocatable ELF file of mod.
func (m *Model) RebuildELF(mod Module, capBytes uint64) (Rebuild, error) {
	secs, err := m.Sections(mod)
	if err != nil {
		return Rebuild{}, err
	}
	out := Rebuild{Sections: len(secs.List), Dropped: secs.Dropped, Skipped: secs.Skipped, Capped: secs.Capped,
		AttrsDisordered: secs.AttrsDisordered}
	syms, serr := m.Symbols(mod)
	if serr != nil {
		out.NoSymbols = true
	}
	strtab := []byte{0}
	var locals, globals []outSym
	for _, s := range syms.List {
		if s.Name == "" || s.Section == 0 {
			continue
		}
		o := outSym{name: uint32(len(strtab)), size: s.Size}
		strtab = append(append(strtab, s.Name...), 0)
		bind, typ, abs := m.symbolKind(s, syms.HasType)
		o.info = bind<<4 | typ&0xf
		o.global = bind != stbLocal
		o.shndx, o.value = shnAbs, s.Address
		if !abs {
			for i, sec := range secs.List {
				if (s.Address >= sec.Address && s.Address-sec.Address < sec.Size) ||
					(sec.Size == 0 && s.Address == sec.Address) {
					o.shndx, o.value = uint16(i+1), s.Address-sec.Address
					break
				}
			}
		}
		if o.global {
			globals = append(globals, o)
		} else {
			locals = append(locals, o)
		}
	}
	out.Symbols = len(locals) + len(globals)

	is64 := m.width == 8
	ehSize, shSize, symSize := uint64(52), uint64(40), uint64(16)
	if is64 {
		ehSize, shSize, symSize = 64, 64, 24
	}
	shstr := []byte{0}
	addName := func(n string) uint32 {
		at := uint32(len(shstr))
		shstr = append(append(shstr, n...), 0)
		return at
	}
	type hdr struct {
		name                   uint32
		typ                    uint32
		flags, addr, off, size uint64
		link, info             uint32
		align, entsize         uint64
	}
	align := func(v, a uint64) uint64 { return (v + a - 1) &^ (a - 1) }
	pos := ehSize
	hdrs := []hdr{{}}
	for _, sec := range secs.List {
		pos = align(pos, 16)
		flags := uint64(shfAlloc)
		if sec.Region.Kind.Executable() {
			flags |= shfExec
		}
		if sec.Region.Kind.Writable() {
			flags |= shfWrite
		}
		hdrs = append(hdrs, hdr{name: addName(sec.Name), typ: shtProgbits, flags: flags, addr: sec.Address,
			off: pos, size: sec.Size, align: 1})
		pos += sec.Size
	}
	nsym := uint64(1 + len(locals) + len(globals))
	pos = align(pos, 8)
	symIndex := len(hdrs)
	hdrs = append(hdrs, hdr{name: addName(".symtab"), typ: shtSymtab, off: pos, size: nsym * symSize,
		link: uint32(symIndex + 1), info: uint32(1 + len(locals)), align: 8, entsize: symSize})
	pos += nsym * symSize
	hdrs = append(hdrs, hdr{name: addName(".strtab"), typ: shtStrtab, off: pos, size: uint64(len(strtab)), align: 1})
	pos += uint64(len(strtab))
	shstrIndex := len(hdrs)
	shstrName := addName(".shstrtab")
	hdrs = append(hdrs, hdr{name: shstrName, typ: shtStrtab, off: pos, size: uint64(len(shstr)), align: 1})
	pos += uint64(len(shstr))
	shoff := align(pos, 8)
	total := shoff + uint64(len(hdrs))*shSize
	if capBytes > 0 && total > capBytes {
		return out, fmt.Errorf("linuxmodule: %d bytes: %w", total, ErrTooLarge)
	}

	var b bytes.Buffer
	b.Grow(int(total))
	order := binary.LittleEndian
	put16 := func(v uint16) { b.Write(order.AppendUint16(nil, v)) }
	put32 := func(v uint32) { b.Write(order.AppendUint32(nil, v)) }
	putW := func(v uint64) {
		if is64 {
			b.Write(order.AppendUint64(nil, v))
		} else {
			put32(uint32(v))
		}
	}
	class, machine := byte(1), uint16(emI386)
	if is64 {
		class, machine = 2, emX8664
	}
	b.Write([]byte{0x7f, 'E', 'L', 'F', class, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	put16(etRel)
	put16(machine)
	put32(1)
	putW(0)
	putW(0)
	putW(shoff)
	put32(0)
	put16(uint16(ehSize))
	put16(0)
	put16(0)
	put16(uint16(shSize))
	put16(uint16(len(hdrs)))
	put16(uint16(shstrIndex))
	pad := func(to uint64) {
		for uint64(b.Len()) < to {
			b.WriteByte(0)
		}
	}
	for i, sec := range secs.List {
		pad(hdrs[i+1].off)
		out.ZeroPages += m.copyRange(&b, sec.Address, sec.Size)
	}
	pad(hdrs[symIndex].off)
	b.Write(make([]byte, symSize))
	for _, list := range [][]outSym{locals, globals} {
		for _, o := range list {
			put32(o.name)
			if is64 {
				b.WriteByte(o.info)
				b.WriteByte(0)
				put16(o.shndx)
				putW(o.value)
				putW(o.size)
			} else {
				putW(o.value)
				putW(o.size)
				b.WriteByte(o.info)
				b.WriteByte(0)
				put16(o.shndx)
			}
		}
	}
	b.Write(strtab)
	b.Write(shstr)
	pad(shoff)
	for _, h := range hdrs {
		put32(h.name)
		put32(h.typ)
		putW(h.flags)
		putW(h.addr)
		putW(h.off)
		putW(h.size)
		put32(h.link)
		put32(h.info)
		putW(h.align)
		putW(h.entsize)
	}
	out.File = b.Bytes()
	return out, nil
}

// symbolKind gives binding, type and whether the symbol is absolute
// (S08 4.2 step 2).
func (m *Model) symbolKind(s Symbol, hasType bool) (bind, typ byte, abs bool) {
	if hasType {
		return s.Info >> 4, s.Info & 0xf, s.Section == shnAbs || s.Type == 'a'
	}
	switch s.Type {
	case 't':
		return stbGlobal, sttFunc, false
	case 'r', 'd', 'g', 'b', 's':
		return stbGlobal, sttObject, false
	case 'v':
		return stbWeak, sttObject, false
	case 'w':
		return stbWeak, sttNotype, false
	case 'a':
		return stbGlobal, sttNotype, true
	}
	return stbGlobal, sttNotype, false
}

// copyRange writes size bytes from memory at addr, a page at a time, with
// zeros for a page that does not read. It returns the zero-filled pages.
func (m *Model) copyRange(b *bytes.Buffer, addr, size uint64) int {
	zero := 0
	for size > 0 {
		n := min(size, pageSize-addr%pageSize)
		if chunk, ok := m.bytes(addr, n); ok {
			b.Write(chunk)
		} else {
			b.Write(make([]byte, n))
			zero++
		}
		addr += n
		size -= n
	}
	return zero
}
