package linuxkern

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/linuxkernel"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

const PageSize = 0x1000

var (
	ErrNoSymbol     = errors.New("linuxkern: symbol not in the symbol table")
	ErrNoSymbolList = errors.New("linuxkern: symbol table cannot list its symbols")
	ErrShortRead    = errors.New("linuxkern: fewer bytes read than asked for")
)

// Pointers and symbol addresses leave Kernel in the masked form (bits above
// the paging mode's width cleared); Mem puts them back in canonical form
// before every read.
type Kernel struct {
	ctx     tools.Context
	Mem     memory.MemoryReader
	Sym     symbols.SymbolTable
	PtrSize uint64
	Mask    uint64

	shift      uint64
	shiftErr   error
	shiftKnown bool

	modules    *linuxmodule.Model
	modulesErr error
}

func New(ctx tools.Context) (*Kernel, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if name := ctx.Profile.OS(); !strings.EqualFold(name, "linux") {
		return nil, fmt.Errorf("linuxkern: profile os %q is not linux", name)
	}
	ptr := uint64(ctx.Symbols.PointerSize())
	if ptr != 4 && ptr != 8 {
		return nil, fmt.Errorf("linuxkern: %d-byte pointers: only 4 and 8 are read", ptr)
	}
	mask := AddressMask(ptr, ctx.PagingMode())
	return &Kernel{ctx: ctx, Sym: ctx.Symbols, PtrSize: ptr, Mask: mask,
		Mem: canonicalReader{inner: ctx.Memory, mask: mask}}, nil
}

// S54 A1, A2: 32-bit and PAE paging translate 32-bit addresses, 4-level
// paging 48-bit ones and 5-level paging 57-bit ones.
func AddressMask(pointerSize uint64, pagingMode string) uint64 {
	switch {
	case pointerSize == 4:
		return 1<<32 - 1
	case strings.HasSuffix(pagingMode, "la57"):
		return 1<<57 - 1
	}
	return 1<<48 - 1
}

func CanonicalAddress(addr, mask uint64) uint64 {
	addr &= mask
	if mask <= 1<<32-1 {
		return addr
	}
	if top := (mask >> 1) + 1; addr&top != 0 {
		addr |= ^mask
	}
	return addr
}

type canonicalReader struct {
	inner memory.MemoryReader
	mask  uint64
}

func (r canonicalReader) ReadAt(offset, size uint64) ([]byte, error) {
	return r.inner.ReadAt(CanonicalAddress(offset, r.mask), size)
}

func (r canonicalReader) Size() uint64 { return r.inner.Size() }

func (k *Kernel) Context() tools.Context { return k.ctx }

func (k *Kernel) Diag(format string, args ...any) { k.ctx.AddDiagnostic(format, args...) }

func (k *Kernel) Canonical(addr uint64) uint64 { return CanonicalAddress(addr, k.Mask) }

func (k *Kernel) Walker() linuxwalk.Reader {
	return linuxwalk.Reader{Mem: k.Mem, Sym: k.Sym, Address: func(a uint64) uint64 { return a & k.Mask },
		Limits: k.ctx.Bounds()}
}

func (k *Kernel) Modules() (*linuxmodule.Model, error) {
	if k.modules == nil && k.modulesErr == nil {
		k.modules, k.modulesErr = linuxmodule.New(k.Walker())
	}
	return k.modules, k.modulesErr
}

func (k *Kernel) Read(addr, n uint64) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}
	if addr+n < addr {
		return nil, fmt.Errorf("linuxkern: %d bytes at %#x run past the top of the address space", n, addr)
	}
	b, err := k.Mem.ReadAt(addr, n)
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) < n {
		return nil, fmt.Errorf("%w: %d of %d at %#x", ErrShortRead, len(b), n, addr)
	}
	return b[:n], nil
}

// A layer can answer a multi-page read from its first page alone, so every
// page of the range is read.
func Readable(mem memory.MemoryReader, addr, size uint64) bool {
	size = max(size, 1)
	if addr+size < addr {
		return false
	}
	for size > 0 {
		chunk := min(PageSize-addr%PageSize, size)
		b, err := mem.ReadAt(addr, chunk)
		if err != nil || uint64(len(b)) < chunk {
			return false
		}
		addr, size = addr+chunk, size-chunk
	}
	return true
}

func (k *Kernel) Valid(addr, n uint64) bool { return Readable(k.Mem, addr, n) }

func (k *Kernel) ReadPadded(addr, n uint64) []byte {
	b, _ := extract.ReadPadded(k.Mem, addr, n)
	return b
}

func word(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func (k *Kernel) ReadPointer(addr uint64) (uint64, error) {
	b, err := k.Read(addr, k.PtrSize)
	if err != nil {
		return 0, err
	}
	if k.PtrSize == 4 {
		return uint64(binary.LittleEndian.Uint32(b)) & k.Mask, nil
	}
	return binary.LittleEndian.Uint64(b) & k.Mask, nil
}

func (k *Kernel) ReadUint(addr, width uint64) (uint64, error) {
	if width == 0 || width > 8 {
		return 0, fmt.Errorf("linuxkern: %d-byte integer: widths are 1 to 8 bytes", width)
	}
	b, err := k.Read(addr, width)
	if err != nil {
		return 0, err
	}
	return word(b), nil
}

func (k *Kernel) HasSymbol(name string) bool {
	_, err := k.Sym.LookupSymbol(name)
	return err == nil
}

func (k *Kernel) Symbol(name string) (uint64, error) {
	s, err := k.Sym.LookupSymbol(name)
	if err != nil {
		return 0, fmt.Errorf("%w: %s", ErrNoSymbol, name)
	}
	return s.Address & k.Mask, nil
}

func (k *Kernel) SymbolType(name string) (string, error) {
	s, err := k.Sym.LookupSymbol(name)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNoSymbol, name)
	}
	return s.Type, nil
}

type SymbolLister interface {
	TableSymbols() []symbols.Symbol
}

type SymbolTyper interface {
	SymbolTypeRef(name string) (symbols.TypeRef, error)
}

type symbolNamer interface {
	SymbolNames() []string
}

// Addresses are in the table's own space (link time), as a listing table
// gives them; callers add Shift to reach the running kernel.
func (k *Kernel) TableSymbols() ([]symbols.Symbol, error) {
	if l, ok := k.Sym.(SymbolLister); ok {
		if syms := l.TableSymbols(); syms != nil {
			return syms, nil
		}
	}
	n, ok := k.Sym.(symbolNamer)
	var names []string
	if ok {
		names = n.SymbolNames()
	}
	if names == nil {
		return nil, ErrNoSymbolList
	}
	shift, err := k.Shift()
	if err != nil {
		return nil, fmt.Errorf("%w: no shift to take running addresses back to link time: %w", ErrNoSymbolList, err)
	}
	out := make([]symbols.Symbol, 0, len(names))
	for _, name := range names {
		s, err := k.Sym.LookupSymbol(name)
		if err != nil {
			continue
		}
		// S54 T8, T9: only the image mapping moves with the shift.
		if s.Address >= shift && linuxkernel.InKernelImage(s.Address-shift) {
			s.Address -= shift
		}
		out = append(out, s)
	}
	return out, nil
}

func (k *Kernel) SymbolTypeRef(name string) (symbols.TypeRef, error) {
	t, ok := k.Sym.(SymbolTyper)
	if !ok {
		return symbols.TypeRef{}, errors.New("linuxkern: symbol table gives no symbol types")
	}
	return t.SymbolTypeRef(name)
}

// S54 T7: both name the first byte of the image's text.
var imageStart = []string{"_text", "_stext"}

func (k *Kernel) Shift() (uint64, error) {
	if !k.shiftKnown {
		k.shiftKnown = true
		k.shift, k.shiftErr = k.kaslrShift()
	}
	return k.shift, k.shiftErr
}

// S54 T8: one delta moves the whole image, so one symbol's running address
// less its link address is the shift of every symbol in the image.
func (k *Kernel) kaslrShift() (uint64, error) {
	if l, ok := k.Sym.(SymbolLister); ok {
		linked := map[string]uint64{}
		for _, s := range l.TableSymbols() {
			linked[s.Name] = s.Address
		}
		for _, name := range imageStart {
			at, ok := linked[name]
			if !ok {
				continue
			}
			if s, err := k.Sym.LookupSymbol(name); err == nil {
				return s.Address - at, nil
			}
		}
	}
	physical := k.ctx.PhysicalMemory()
	if physical == nil {
		return 0, errors.New("linuxkern: kaslr shift: no image-start symbol in the list and no physical memory to search for VMCOREINFO")
	}
	found, err := linuxkernel.FindKernel(physical, k.ctx.Bounds())
	if err != nil {
		return 0, fmt.Errorf("linuxkern: kaslr shift: %w", err)
	}
	if err := found.DamageError(); err != nil && k.ctx.StrictMode() {
		return 0, fmt.Errorf("linuxkern: kaslr shift: strict mode: %w", err)
	}
	tool := k.ctx.Running()
	if tool == "" {
		tool = "linuxkern"
	}
	for _, d := range found.Damaged {
		k.Diag("%s: VMCOREINFO note at %#x: skipped: %v", tool, d.Offset, d.Err)
	}
	return found.Layout.VirtualShift, nil
}

func (k *Kernel) SymbolsAt(addr uint64) ([]string, bool) {
	return SymbolsAt(k.Sym, k.Canonical(addr))
}

func SymbolsAt(sym symbols.SymbolTable, addr uint64) ([]string, bool) {
	l, ok := sym.(symbols.SymbolLocator)
	if !ok {
		return nil, false
	}
	names := symbols.NamesAt(l, addr)
	sort.Strings(names)
	return names, true
}
