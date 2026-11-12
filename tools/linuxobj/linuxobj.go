package linuxobj

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

var ErrUnsupported = linuxwalk.ErrUnsupported

var (
	ErrNotInteger = errors.New("linuxobj: member is not an integer")
	ErrNotArray   = errors.New("linuxobj: member is not an array")
	ErrShortRead  = errors.New("linuxobj: short read")
	ErrNoSize     = errors.New("linuxobj: type has no known size")
)

// S46 K2: the linear-address widths of 32-bit, 4-level and 5-level paging.
const (
	addressBits32     = 32
	addressBits4Level = 48
	addressBits5Level = 57
)

const readChunk = 0x1000

type Kernel struct {
	ctx  tools.Context
	mem  memory.MemoryReader
	sym  symbols.SymbolTable
	bits uint

	ints map[string]intMember

	clock    *BootClock
	clockErr error

	modules    *linuxmodule.Model
	modulesErr error
	modulesSet bool

	phys    uint64
	physSet bool
}

type intMember struct {
	field  symbols.IntField
	signed bool
	err    error
}

func New(ctx tools.Context) *Kernel {
	return &Kernel{ctx: ctx, mem: ctx.Memory, sym: ctx.Symbols, bits: addressBits(ctx), ints: map[string]intMember{}}
}

func addressBits(ctx tools.Context) uint {
	switch {
	case ctx.Symbols != nil && ctx.Symbols.PointerSize() == 4:
		return addressBits32
	case strings.HasSuffix(ctx.PagingMode(), "la57"):
		return addressBits5Level
	}
	return addressBits4Level
}

func (k *Kernel) Context() tools.Context { return k.ctx }

func (k *Kernel) Memory() memory.MemoryReader { return k.mem }

func (k *Kernel) Symbols() symbols.SymbolTable { return k.sym }

func (k *Kernel) AddressMask() uint64 { return 1<<k.bits - 1 }

func (k *Kernel) Masked(addr uint64) uint64 { return addr & k.AddressMask() }

// S46 K3: a canonical address repeats its top translated bit in every bit
// above it.
func (k *Kernel) Canonical(addr uint64) uint64 {
	v := k.Masked(addr)
	if k.bits >= 64 || k.bits == addressBits32 {
		return v
	}
	if v&(1<<(k.bits-1)) != 0 {
		v |= ^k.AddressMask()
	}
	return v
}

func (k *Kernel) PointerSize() uint64 {
	if k.sym == nil {
		return 8
	}
	return uint64(k.sym.PointerSize())
}

func (k *Kernel) Walker() linuxwalk.Reader {
	return linuxwalk.Reader{Mem: k.mem, Sym: k.sym, Address: k.Canonical, Limits: k.ctx.Limits}
}

func (k *Kernel) Modules() (*linuxmodule.Model, error) {
	if !k.modulesSet {
		k.modules, k.modulesErr = linuxmodule.New(k.Walker())
		k.modulesSet = true
	}
	return k.modules, k.modulesErr
}

func (k *Kernel) moduleName(addr uint64) (string, error) {
	model, err := k.Modules()
	if err != nil {
		return "", err
	}
	mod, err := model.Read(addr)
	if err != nil {
		return "", err
	}
	return mod.Name, nil
}

func (k *Kernel) SymbolsAt(addr uint64) []string {
	locator, ok := k.sym.(symbols.SymbolLocator)
	if !ok {
		return nil
	}
	return symbols.NamesAt(locator, addr)
}

func (k *Kernel) Member(typeName, name string) (symbols.Field, error) {
	return k.sym.Field(typeName, name)
}

func (k *Kernel) Has(typeName, name string) bool {
	_, err := k.sym.Field(typeName, name)
	return err == nil
}

func (k *Kernel) HasType(name string) bool {
	_, err := k.sym.Struct(name)
	return err == nil
}

func (k *Kernel) HasSymbol(name string) bool {
	_, err := k.sym.LookupSymbol(name)
	return err == nil
}

func (k *Kernel) Symbol(name string) (symbols.Symbol, error) {
	s, err := k.sym.LookupSymbol(name)
	if err != nil {
		return symbols.Symbol{}, fmt.Errorf("linuxobj: symbol %s: %w", name, err)
	}
	return s, nil
}

func (k *Kernel) SizeOf(name string) (uint64, error) {
	st, serr := k.sym.Struct(name)
	if serr == nil && st.Size > 0 {
		return st.Size, nil
	}
	if n := baseTypeWidth(name, k.PointerSize()); n > 0 {
		return n, nil
	}
	if det, ok := k.sym.(symbols.DeterministicLookup); ok {
		if n, err := det.SizeOf(name); err == nil && n > 0 {
			return n, nil
		}
	}
	if serr != nil {
		return 0, fmt.Errorf("linuxobj: size of %s: %w", name, serr)
	}
	return 0, fmt.Errorf("%w: %s", ErrNoSize, name)
}

// S46 K5: widths of the C base types under the kernel's data model, where a
// long is as wide as a pointer.
func baseTypeWidth(name string, pointer uint64) uint64 {
	words := strings.Fields(name)
	has := func(w string) int {
		n := 0
		for _, x := range words {
			if x == w {
				n++
			}
		}
		return n
	}
	for _, w := range words {
		switch w {
		case "char", "short", "int", "long", "signed", "unsigned":
		default:
			return 0
		}
	}
	switch {
	case len(words) == 0:
		return 0
	case has("char") > 0:
		return 1
	case has("short") > 0:
		return 2
	case has("long") >= 2:
		return 8
	case has("long") == 1:
		return pointer
	}
	return 4
}

// S46 K6: Int is asked for by a caller that knows the member is signed, so
// only a type known to be unsigned is read without sign extension.
func unsignedTypeName(name string) bool {
	for _, w := range strings.Fields(name) {
		if w == "unsigned" {
			return true
		}
	}
	switch name {
	case "_Bool", "bool", "u8", "u16", "u32", "u64", "__u8", "__u16", "__u32", "__u64", "size_t",
		"__le16", "__le32", "__le64", "__be16", "__be32", "__be64", "uintptr_t", "phys_addr_t":
		return true
	}
	return false
}

func (k *Kernel) PointeeSize(f symbols.Field) uint64 {
	name := f.Type.Name
	if f.Type.Element != nil && f.Type.Element.Name != "" {
		name = f.Type.Element.Name
	}
	if name == "" || name == "void" {
		return 0
	}
	n, err := k.SizeOf(name)
	if err != nil {
		return 0
	}
	return n
}

func (k *Kernel) Readable(addr, size uint64) bool { return readable(k.mem, addr, size) }

func readable(mem memory.MemoryReader, addr, size uint64) bool {
	if mem == nil {
		return false
	}
	size = max(size, 1)
	if addr+size-1 < addr {
		return false
	}
	for size > 0 {
		n := min(size, readChunk-addr%readChunk)
		b, err := mem.ReadAt(addr, n)
		if err != nil || uint64(len(b)) < n {
			return false
		}
		addr, size = addr+n, size-n
	}
	return true
}

func (k *Kernel) intMember(typeName, member string) (intMember, error) {
	key := typeName + "." + member
	if m, ok := k.ints[key]; ok {
		return m, m.err
	}
	m := k.resolveInt(typeName, member)
	k.ints[key] = m
	return m, m.err
}

func (k *Kernel) resolveInt(typeName, member string) intMember {
	f, err := k.sym.Field(typeName, member)
	if err != nil {
		return intMember{err: fmt.Errorf("linuxobj: %s.%s: %w", typeName, member, err)}
	}
	width := baseTypeWidth(f.Type.Name, k.PointerSize())
	if sizer, ok := k.sym.(symbols.FieldSizer); ok && width == 0 {
		if w, err := sizer.FieldSize(typeName, member); err == nil {
			width = w
		}
	}
	switch {
	case f.Type.IsPointer:
		width = k.PointerSize()
	case width == 0:
		width, _ = k.SizeOf(f.Type.Name)
	}
	if width == 0 || width > 8 || f.Type.IsArray || f.Type.ArrayLength > 0 {
		return intMember{err: fmt.Errorf("%w: %s.%s is %d bytes of %q", ErrNotInteger, typeName, member, width, f.Type.Name)}
	}
	return intMember{
		field:  symbols.IntField{Offset: f.Offset, Width: width, BitOffset: f.Type.BitOffset, BitLength: f.Type.BitLength},
		signed: !f.Type.IsPointer && !unsignedTypeName(f.Type.Name),
	}
}

func (k *Kernel) Uint(mem memory.MemoryReader, base uint64, typeName, member string) (uint64, error) {
	m, err := k.intMember(typeName, member)
	if err != nil {
		return 0, err
	}
	v, err := m.field.Read(mem, base)
	if err != nil {
		return 0, fmt.Errorf("linuxobj: %s.%s at %#x: %w", typeName, member, base+m.field.Offset, err)
	}
	return v, nil
}

func (k *Kernel) Int(mem memory.MemoryReader, base uint64, typeName, member string) (int64, error) {
	m, err := k.intMember(typeName, member)
	if err != nil {
		return 0, err
	}
	v, err := m.field.Read(mem, base)
	if err != nil {
		return 0, fmt.Errorf("linuxobj: %s.%s at %#x: %w", typeName, member, base+m.field.Offset, err)
	}
	if !m.signed {
		return int64(v), nil
	}
	bits := m.field.Width * 8
	if m.field.BitLength > 0 {
		bits = uint64(m.field.BitLength)
	}
	return signExtend(v, bits), nil
}

func signExtend(v, bits uint64) int64 {
	if bits == 0 || bits >= 64 {
		return int64(v)
	}
	shift := 64 - bits
	return int64(v<<shift) >> shift
}

func (k *Kernel) Pointer(mem memory.MemoryReader, base uint64, typeName, member string) (uint64, error) {
	f, err := k.sym.Field(typeName, member)
	if err != nil {
		return 0, fmt.Errorf("linuxobj: %s.%s: %w", typeName, member, err)
	}
	v, err := k.word(mem, base+f.Offset)
	if err != nil {
		return 0, fmt.Errorf("linuxobj: %s.%s at %#x: %w", typeName, member, base+f.Offset, err)
	}
	return v, nil
}

func (k *Kernel) PointerAt(mem memory.MemoryReader, addr uint64) (uint64, error) {
	v, err := k.word(mem, addr)
	if err != nil {
		return 0, fmt.Errorf("linuxobj: pointer at %#x: %w", addr, err)
	}
	return v, nil
}

func (k *Kernel) word(mem memory.MemoryReader, addr uint64) (uint64, error) {
	n := k.PointerSize()
	b, err := mem.ReadAt(addr, n)
	if err != nil {
		return 0, err
	}
	if uint64(len(b)) < n {
		return 0, ErrShortRead
	}
	var v uint64
	for i := int(n) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v, nil
}

// S46 4.1 step 3: ok means the pointer is set and the whole object it points at
// reads; an untyped pointee needs its first byte only.
func (k *Kernel) Deref(mem memory.MemoryReader, base uint64, typeName, member string) (uint64, bool, error) {
	v, err := k.Pointer(mem, base, typeName, member)
	if err != nil {
		return 0, false, err
	}
	if v == 0 {
		return 0, false, nil
	}
	f, _ := k.sym.Field(typeName, member)
	return v, readable(mem, v, k.PointeeSize(f)), nil
}

func (k *Kernel) CharArray(mem memory.MemoryReader, base uint64, typeName, member string) (string, error) {
	f, err := k.sym.Field(typeName, member)
	if err != nil {
		return "", fmt.Errorf("linuxobj: %s.%s: %w", typeName, member, err)
	}
	if !f.Type.IsArray && f.Type.ArrayLength == 0 {
		return "", fmt.Errorf("%w: %s.%s", ErrNotArray, typeName, member)
	}
	n := uint64(0)
	if sizer, ok := k.sym.(symbols.FieldSizer); ok {
		if w, err := sizer.FieldSize(typeName, member); err == nil {
			n = w
		}
	}
	if n == 0 {
		n = f.Type.ArrayLength
	}
	if n == 0 {
		return "", fmt.Errorf("%w: %s.%s has no length", ErrNotArray, typeName, member)
	}
	b, err := mem.ReadAt(base+f.Offset, n)
	if err != nil {
		return "", fmt.Errorf("linuxobj: %s.%s at %#x: %w", typeName, member, base+f.Offset, err)
	}
	return cString(b), nil
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// S46 4.1 step 5: a string is read a page at a time, so one that ends before an
// unreadable page still reads.
func (k *Kernel) StringAt(addr, count uint64) (string, error) {
	var out []byte
	at := addr
	for uint64(len(out)) < count {
		n := min(count-uint64(len(out)), readChunk-at%readChunk)
		b, err := k.mem.ReadAt(at, n)
		if err != nil {
			return "", fmt.Errorf("linuxobj: string at %#x: byte %d at %#x: %w", addr, len(out), at, err)
		}
		if uint64(len(b)) < n {
			return "", fmt.Errorf("linuxobj: string at %#x: %w", addr, ErrShortRead)
		}
		for i, c := range b {
			if c == 0 {
				return string(append(out, b[:i]...)), nil
			}
		}
		out = append(out, b...)
		at += n
	}
	return string(out), nil
}
