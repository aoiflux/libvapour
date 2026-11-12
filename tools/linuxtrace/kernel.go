package linuxtrace

import (
	"fmt"

	"github.com/aoiflux/libvapour/extract"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

var ErrUnsupported = linuxwalk.ErrUnsupported

// Unlike linuxkern.Kernel, every address leaves this Kernel in canonical
// form, and reads go to the session's memory as given.
type Kernel struct {
	ctx  tools.Context
	mem  memory.MemoryReader
	sym  symbols.SymbolTable
	mask uint64

	modules    *linuxmodule.Model
	modulesErr error
}

func New(ctx tools.Context) *Kernel {
	var mask uint64
	if ctx.Symbols != nil {
		mask = linuxkern.AddressMask(uint64(ctx.Symbols.PointerSize()), ctx.PagingMode())
	}
	return &Kernel{ctx: ctx, mem: ctx.Memory, sym: ctx.Symbols, mask: mask}
}

func (k *Kernel) Context() tools.Context { return k.ctx }

func (k *Kernel) Memory() memory.MemoryReader { return k.mem }

func (k *Kernel) Symbols() symbols.SymbolTable { return k.sym }

func (k *Kernel) Masked(addr uint64) uint64 { return addr & k.mask }

func (k *Kernel) Canonical(addr uint64) uint64 { return linuxkern.CanonicalAddress(addr, k.mask) }

func (k *Kernel) PointerSize() uint64 { return uint64(k.sym.PointerSize()) }

func (k *Kernel) Walker() linuxwalk.Reader {
	return linuxwalk.Reader{Mem: k.mem, Sym: k.sym, Address: k.Canonical, Limits: k.ctx.Bounds()}
}

func (k *Kernel) Modules() (*linuxmodule.Model, error) {
	if k.modules == nil && k.modulesErr == nil {
		k.modules, k.modulesErr = linuxmodule.New(k.Walker())
	}
	return k.modules, k.modulesErr
}

func (k *Kernel) Field(typeName, name string) (symbols.Field, error) {
	f, err := k.sym.Field(typeName, name)
	if err != nil {
		return symbols.Field{}, fmt.Errorf("linuxtrace: %s.%s: %w", typeName, name, err)
	}
	return f, nil
}

func (k *Kernel) Has(typeName, name string) bool {
	_, err := k.sym.Field(typeName, name)
	return err == nil
}

func (k *Kernel) HasType(name string) bool { return linuxkern.HasType(k.sym, name) }

func (k *Kernel) HasSymbol(name string) bool {
	_, err := k.sym.LookupSymbol(name)
	return err == nil
}

func (k *Kernel) Symbol(name string) (symbols.Symbol, error) {
	s, err := k.sym.LookupSymbol(name)
	if err != nil {
		return symbols.Symbol{}, fmt.Errorf("linuxtrace: symbol %s: %w", name, err)
	}
	s.Address = k.Canonical(s.Address)
	return s, nil
}

func (k *Kernel) SizeOf(name string) (uint64, error) { return linuxkern.SizeOf(k.sym, name) }

func (k *Kernel) PointeeSize(f symbols.Field) uint64 { return linuxkern.PointeeSize(k.sym, f) }

func (k *Kernel) Readable(addr, size uint64) bool { return Readable(k.mem, addr, size) }

func Readable(mem memory.MemoryReader, addr, size uint64) bool {
	return linuxkern.Readable(mem, addr, size)
}

func (k *Kernel) integer(typeName, member string) (linuxkern.Integer, error) {
	f, err := k.Field(typeName, member)
	if err != nil {
		return linuxkern.Integer{}, err
	}
	in, err := linuxkern.IntegerMember(k.sym, typeName, f, f.Offset)
	if err != nil {
		return linuxkern.Integer{}, fmt.Errorf("linuxtrace: %w", err)
	}
	return in, nil
}

func (k *Kernel) Uint(base uint64, typeName, member string) (uint64, error) {
	in, err := k.integer(typeName, member)
	if err != nil {
		return 0, err
	}
	v, err := in.Read(k.mem, base)
	if err != nil {
		return 0, fmt.Errorf("linuxtrace: %s.%s at %#x: %w", typeName, member, base+in.Offset, err)
	}
	return v, nil
}

func (k *Kernel) Int(base uint64, typeName, member string) (int64, error) {
	in, err := k.integer(typeName, member)
	if err != nil {
		return 0, err
	}
	v, err := in.ReadSigned(k.mem, base)
	if err != nil {
		return 0, fmt.Errorf("linuxtrace: %s.%s at %#x: %w", typeName, member, base+in.Offset, err)
	}
	return v, nil
}

func SignExtend(v, width uint64) int64 {
	if width == 0 || width >= 8 {
		return int64(v)
	}
	n := 64 - 8*width
	return int64(v<<n) >> n
}

func (k *Kernel) Pointer(base uint64, typeName, member string) (uint64, error) {
	f, err := k.Field(typeName, member)
	if err != nil {
		return 0, err
	}
	if err := linuxkern.PointerMember(k.sym, typeName, f); err != nil {
		return 0, fmt.Errorf("linuxtrace: %w", err)
	}
	return k.PointerAt(base + f.Offset)
}

func (k *Kernel) PointerAt(addr uint64) (uint64, error) {
	n := k.PointerSize()
	b, err := k.mem.ReadAt(addr, n)
	if err == nil && uint64(len(b)) < n {
		err = fmt.Errorf("%w: %d of %d", linuxkern.ErrShortRead, len(b), n)
	}
	if err != nil {
		return 0, fmt.Errorf("linuxtrace: pointer at %#x: %w", addr, err)
	}
	var v uint64
	for i := int(n) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return k.Canonical(v), nil
}

func (k *Kernel) Deref(base uint64, typeName, member string) (uint64, bool, error) {
	f, err := k.Field(typeName, member)
	if err != nil {
		return 0, false, err
	}
	p, err := k.Pointer(base, typeName, member)
	if err != nil {
		return 0, false, err
	}
	return p, k.Masked(p) != 0 && k.Readable(p, k.PointeeSize(f)), nil
}

func (k *Kernel) StringAt(addr, count uint64) (string, error) {
	s, err := linuxkern.ReadString(k.mem, addr, count)
	if err != nil {
		return "", fmt.Errorf("linuxtrace: %w", err)
	}
	return s, nil
}

func (k *Kernel) CharArray(base uint64, typeName, member string) (string, error) {
	f, err := k.Field(typeName, member)
	if err != nil {
		return "", err
	}
	n, err := linuxkern.ByteArrayLength(k.sym, typeName, f)
	if err != nil {
		return "", fmt.Errorf("linuxtrace: %w", err)
	}
	return k.StringAt(base+f.Offset, n)
}

func (k *Kernel) ReadPadded(addr, size uint64) []byte {
	b, _ := extract.ReadPadded(k.mem, addr, size)
	return b
}

func (k *Kernel) SymbolLocator() (symbols.SymbolLocator, bool) {
	loc, ok := k.sym.(symbols.SymbolLocator)
	return loc, ok
}

func (k *Kernel) SymbolsAt(addr uint64) []string {
	names, _ := linuxkern.SymbolsAt(k.sym, k.Canonical(addr))
	return names
}

func (k *Kernel) EnumName(typeName string, v int64) (string, bool, error) {
	det, ok := k.sym.(symbols.DeterministicLookup)
	if !ok {
		return "", false, fmt.Errorf("linuxtrace: enum %s: the symbol table gives no enumerations", typeName)
	}
	t, err := det.LookupType(typeName)
	if err != nil {
		return "", false, fmt.Errorf("linuxtrace: enum %s: %w", typeName, err)
	}
	if t.Kind != symbols.TypeKindEnum {
		return "", false, fmt.Errorf("linuxtrace: %s is not an enumeration", typeName)
	}
	for _, e := range t.Enum {
		if e.Value == v {
			return e.Name, true, nil
		}
	}
	return "", false, nil
}

func (k *Kernel) EnumField(base uint64, typeName, member string) (int64, string, error) {
	f, err := k.Field(typeName, member)
	if err != nil {
		return 0, "", err
	}
	v, err := k.Int(base, typeName, member)
	if err != nil {
		return 0, "", err
	}
	return v, f.Type.Name, nil
}
