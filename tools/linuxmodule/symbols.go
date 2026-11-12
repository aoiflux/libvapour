package linuxmodule

import (
	"fmt"
	"strings"
)

// Elf_Sym fields (S06 F14).
type Symbol struct {
	Name    string
	Address uint64
	Type    byte
	Info    byte
	Section uint16
	Size    uint64
}

type Symbols struct {
	List    []Symbol
	Unread  int
	Cut     int
	Capped  bool
	HasType bool
}

type symbolSet struct {
	syms Symbols
	err  error
}

const symbolNameBytes = 512

// Symbols reads a module's kallsyms table (S06 4.4) once and keeps it.
func (m *Model) Symbols(mod Module) (Symbols, error) {
	if c, ok := m.syms[mod.Address]; ok {
		return c.syms, c.err
	}
	syms, err := m.readSymbols(mod.Address)
	m.syms[mod.Address] = symbolSet{syms: syms, err: err}
	return syms, err
}

func (m *Model) readSymbols(addr uint64) (Symbols, error) {
	s := &m.s
	if !s.hasSymbols {
		return Symbols{}, ErrNoSymbols
	}
	ks, ok := m.pointer(addr + s.kallsyms)
	if !ok || ks == 0 {
		return Symbols{}, ErrNoSymbols
	}
	symtab, ok1 := m.pointer(ks + s.symtab)
	count, ok2 := m.uintField(ks, s.numSymtab)
	strtab, ok3 := m.pointer(ks + s.strtab)
	if !ok1 || !ok2 || !ok3 || symtab == 0 {
		return Symbols{}, ErrNoSymbols
	}
	var typetab uint64
	if s.hasTypetab {
		if typetab, ok = m.pointer(ks + s.typetab); !ok {
			typetab = 0
		}
	}
	out := Symbols{HasType: s.hasTypetab}
	if lim := uint64(m.r.Limits.Effective().MaxTableEntries); lim > 0 && count > lim {
		count, out.Capped = lim, true
	}
	for i := uint64(1); i < count; i++ {
		rec, ok := m.bytes(symtab+i*s.symSize, s.symSize)
		if !ok {
			out.Unread++
			continue
		}
		sym := m.decodeSym(rec)
		nameAt := uint64(le(rec[0:4]))
		name, cut, ok := m.cstring(strtab+nameAt, symbolNameBytes)
		if !ok {
			out.Unread++
			continue
		}
		if cut {
			out.Cut++
		}
		sym.Name = name
		sym.Type = sym.Info
		if typetab != 0 {
			if b, ok := m.bytes(typetab+i, 1); ok {
				sym.Type = b[0]
			}
		}
		out.List = append(out.List, sym)
	}
	return out, nil
}

func (m *Model) decodeSym(rec []byte) Symbol {
	if m.width == 4 {
		return Symbol{
			Address: m.form(le(rec[4:8])),
			Size:    le(rec[8:12]),
			Info:    rec[12],
			Section: uint16(le(rec[14:16])),
		}
	}
	return Symbol{
		Info:    rec[4],
		Section: uint16(le(rec[6:8])),
		Address: m.form(le(rec[8:16])),
		Size:    le(rec[16:24]),
	}
}

// mappingSymbol is the v6.17 test (S06 F13), the widest of the tags read.
func mappingSymbol(name string) bool {
	return strings.HasPrefix(name, "$") || strings.HasPrefix(name, ".L") || strings.HasPrefix(name, "L0")
}

// Nearest gives the S06 F13 symbol for addr: the largest value not above it
// among defined, named, non-mapping symbols.
func (s Symbols) Nearest(addr uint64) (Symbol, bool) {
	var best Symbol
	found := false
	for _, sym := range s.List {
		if sym.Section == 0 || sym.Name == "" || mappingSymbol(sym.Name) || sym.Address > addr {
			continue
		}
		if !found || sym.Address > best.Address {
			best, found = sym, true
		}
	}
	return best, found
}

type kernelImage struct {
	start, end uint64
	ok         bool
}

func (m *Model) kernelRange() kernelImage {
	if m.kimg == nil {
		k := kernelImage{}
		start, ok1 := m.symbol("_text")
		end, ok2 := m.symbol("_etext")
		if ok1 && ok2 && start < end {
			k = kernelImage{start: start, end: end, ok: true}
		}
		m.kimg = &k
	}
	return *m.kimg
}

// KernelOwner is the module name shown for an address in the kernel image.
const KernelOwner = "kernel"

type Owner struct {
	Found   bool
	Kernel  bool
	Module  Module
	Owners  int
	Symbol  string
	Offset  uint64
	Unnamed bool
}

// Names gives the owner's module name, KernelOwner for the kernel image, and its symbol as name+0x<offset>.
func (o Owner) Names() (module, symbol string) {
	if !o.Found {
		return "", ""
	}
	module = o.Module.Name
	if o.Kernel {
		module = KernelOwner
	}
	symbol = o.Symbol
	if symbol != "" && o.Offset != 0 {
		symbol = fmt.Sprintf("%s+%#x", symbol, o.Offset)
	}
	return module, symbol
}

// KernelNamer names an address in the kernel image.
type KernelNamer func(addr uint64) []string

// Lookup finds the module, or the kernel image, that holds addr (S06 4.5).
func (m *Model) Lookup(mods []Module, addr uint64, namer KernelNamer) Owner {
	addr = m.form(addr)
	var out Owner
	for _, mod := range mods {
		if mod.Holds(addr) {
			if out.Owners == 0 {
				out.Module, out.Found = mod, true
			}
			out.Owners++
		}
	}
	if !out.Found {
		if k := m.kernelRange(); k.ok && addr >= k.start && addr < k.end {
			out.Found, out.Kernel, out.Owners = true, true, 1
			if namer != nil {
				if names := namer(addr); len(names) > 0 {
					out.Symbol = names[0]
				}
			}
		}
		return out
	}
	syms, err := m.Symbols(out.Module)
	if err != nil {
		out.Unnamed = true
		return out
	}
	if sym, ok := syms.Nearest(addr); ok {
		out.Symbol, out.Offset = sym.Name, addr-sym.Address
	}
	return out
}
