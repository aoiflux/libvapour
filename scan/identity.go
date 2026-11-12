package scan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/util"
)

var (
	ErrNoTypeTable    = errors.New("scan: kernel object type table not readable")
	ErrTypeNotListed  = errors.New("scan: object type not in the kernel type table")
	ErrNoObjectHeader = errors.New("scan: symbol table has no _OBJECT_HEADER")
)

type Member struct{ Struct, Field string }

// An unresolved tag accepts every body: refusing them all would turn a
// missing member into an empty result that looks clean.
type TypeTag struct {
	Offset   uint64
	Width    uint64
	Want     uint64
	Resolved bool
}

func ResolveTypeTag(sym symbols.SymbolTable, want uint64, chain ...Member) TypeTag {
	if sym == nil || len(chain) == 0 {
		return TypeTag{}
	}
	var offset uint64
	for i, m := range chain {
		if i == len(chain)-1 {
			f, err := symbols.ResolveIntField(sym, m.Struct, m.Field)
			if err != nil || f.BitLength != 0 {
				return TypeTag{}
			}
			offset += f.Offset
			return TypeTag{Offset: offset, Width: f.Width, Want: want, Resolved: true}
		}
		f, err := sym.Field(m.Struct, m.Field)
		if err != nil {
			return TypeTag{}
		}
		offset += f.Offset
	}
	return TypeTag{}
}

func (t TypeTag) Accepts(reader memory.MemoryReader, body uint64) bool {
	if !t.Resolved {
		return true
	}
	if t.Width == 0 || t.Width > 8 {
		return false
	}
	b, err := reader.ReadAt(body+t.Offset, t.Width)
	if err != nil || uint64(len(b)) != t.Width {
		return false
	}
	var v [8]byte
	copy(v[:], b)
	return binary.LittleEndian.Uint64(v[:]) == t.Want
}

// The stored TypeIndex is the type's slot in ObTypeIndexTable XORed with
// the low byte of nt!ObHeaderCookie and with bits 15:8 of the header's own
// virtual address, so a header found by physical address can be tested only
// through the addresses that map its frame.
type TypeIndexTest struct {
	want      byte
	cookie    byte
	hasCookie bool
	offset    uint64
	resolved  bool
}

func (t TypeIndexTest) Resolved() bool { return t.resolved }

const typeSlots = 256

func ResolveTypeIndexTest(sym symbols.SymbolTable, kernel memory.MemoryReader, objectType string) (TypeIndexTest, error) {
	if sym == nil || kernel == nil {
		return TypeIndexTest{}, ErrNoTypeTable
	}
	ti, err := sym.Field("_OBJECT_HEADER", "TypeIndex")
	if err != nil {
		return TypeIndexTest{}, fmt.Errorf("%w: TypeIndex: %v", ErrNoObjectHeader, err)
	}
	slot, err := typeSlot(sym, kernel, objectType)
	if err != nil {
		return TypeIndexTest{}, err
	}
	t := TypeIndexTest{want: byte(slot), offset: ti.Offset, resolved: true}
	if s, err := sym.LookupSymbol("ObHeaderCookie"); err == nil {
		b, rerr := kernel.ReadAt(s.Address, 1)
		if rerr != nil || len(b) != 1 {
			return TypeIndexTest{}, fmt.Errorf("%w: ObHeaderCookie at 0x%x: %v", ErrNoTypeTable, s.Address, rerr)
		}
		t.cookie, t.hasCookie = b[0], true
	}
	return t, nil
}

func typeSlot(sym symbols.SymbolTable, kernel memory.MemoryReader, objectType string) (int, error) {
	table, err := sym.LookupSymbol("ObTypeIndexTable")
	if err != nil {
		return 0, fmt.Errorf("%w: ObTypeIndexTable: %v", ErrNoTypeTable, err)
	}
	nameField, err := sym.Field("_OBJECT_TYPE", "Name")
	if err != nil {
		return 0, fmt.Errorf("%w: _OBJECT_TYPE.Name: %v", ErrNoTypeTable, err)
	}
	index, indexErr := symbols.ResolveIntField(sym, "_OBJECT_TYPE", "Index")
	layout := util.ResolveUnicodeStringLayout(sym)
	width := uint64(sym.PointerSize())
	read := 0
	for slot := range typeSlots {
		p, err := sym.ReadPointer(kernel, table.Address+uint64(slot)*width)
		if err != nil {
			continue
		}
		read++
		if p == 0 {
			continue
		}
		name, err := util.ReadUnicodeString(kernel, p+nameField.Offset, layout, util.MaxUnicodeStringBytes)
		if err != nil || name.Value != objectType {
			continue
		}
		if indexErr == nil {
			if v, err := index.Read(kernel, p); err != nil || v != uint64(slot) {
				continue
			}
		}
		return slot, nil
	}
	if read == 0 {
		return 0, fmt.Errorf("%w: ObTypeIndexTable at 0x%x", ErrNoTypeTable, table.Address)
	}
	return 0, fmt.Errorf("%w: %q", ErrTypeNotListed, objectType)
}

func (t TypeIndexTest) decodes(raw, addressByte byte) bool {
	if !t.hasCookie {
		return raw == t.want
	}
	return raw^t.cookie^addressByte == t.want
}

// The page keys (virtual address bits 15:12) under which the header decodes
// to the wanted type, out of those the kernel maps its frame under.
func (t TypeIndexTest) passingKeys(reader memory.MemoryReader, residency Residency, headerPA uint64) (passing uint16, values int, ok bool) {
	b, err := reader.ReadAt(headerPA+t.offset, 1)
	if err != nil || len(b) != 1 {
		return 0, 0, false
	}
	if !t.hasCookie {
		if t.decodes(b[0], 0) {
			return 0xffff, 1, true
		}
		return 0, 1, true
	}
	if residency == nil {
		return 0, 0, false
	}
	seconds := residency.SecondAddressBytes(headerPA)
	if len(seconds) == 0 {
		return 0, 0, false
	}
	for _, s := range seconds {
		if t.decodes(b[0], s) {
			passing |= 1 << (s >> 4)
		}
	}
	return passing, len(seconds), true
}

type ObjectIdentity struct {
	Index TypeIndexTest
	Tag   TypeTag
	// A freed object's header can lose its TypeIndex while the body still
	// matches, and freed objects are what the scan is for.
	KeepIndexMismatch bool

	masks    [typeSlots]byte
	hasMasks bool
}

// The identity carries ObpInfoMaskToOffset when kernel memory has it: the
// kernel's own offsets of the optional headers decide where an object header
// sits behind its pool header.
func ResolveObjectIdentity(sym symbols.SymbolTable, kernel memory.MemoryReader, filter PoolFilter, tag TypeTag) (ObjectIdentity, error) {
	id := ObjectIdentity{Tag: tag}
	if sym != nil && kernel != nil {
		if s, err := sym.LookupSymbol("ObpInfoMaskToOffset"); err == nil {
			if b, err := kernel.ReadAt(s.Address, typeSlots); err == nil && len(b) == typeSlots && b[0] == 0 {
				copy(id.masks[:], b)
				id.hasMasks = true
			}
		}
	}
	if filter.SkipTypeTest || filter.ObjectType == "" {
		return id, nil
	}
	index, err := ResolveTypeIndexTest(sym, kernel, filter.ObjectType)
	if err != nil {
		return id, fmt.Errorf("type %q: %w", filter.ObjectType, err)
	}
	id.Index = index
	return id, nil
}

func (id ObjectIdentity) AddressesPassing(reader memory.MemoryReader, residency Residency, headerPA uint64) (passing, values int, ok bool) {
	if !id.Index.resolved {
		return 0, 0, false
	}
	keys, values, ok := id.Index.passingKeys(reader, residency, headerPA)
	if !ok {
		return 0, 0, false
	}
	if !id.Index.hasCookie {
		if keys != 0 {
			return 1, 1, true
		}
		return 0, 1, true
	}
	return bits.OnesCount16(keys), values, true
}
