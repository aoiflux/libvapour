package handlelist

import (
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/util"
)

const typeSlots = 256

type typeSlot struct {
	name string
	ok   bool
	read bool
}

// typeResolver turns the TypeIndex byte of an object header into the name of
// the object type in ObTypeIndexTable (S31 4.5 steps 1 and 2).
type typeResolver struct {
	ctx       tools.Context
	err       error
	typeIndex uint64
	table     uint64
	cookie    byte
	hasCookie bool
	typeName  uint64
	index     symbols.IntField
	slots     [typeSlots]typeSlot
}

func newTypeResolver(ctx tools.Context) *typeResolver {
	r := &typeResolver{ctx: ctx}
	sym := ctx.Symbols
	f, err := sym.Field("_OBJECT_HEADER", "TypeIndex")
	if err != nil {
		r.err = fmt.Errorf("_OBJECT_HEADER.TypeIndex: %w", err)
		return r
	}
	r.typeIndex = f.Offset
	table, err := sym.LookupSymbol("ObTypeIndexTable")
	if err != nil {
		r.err = fmt.Errorf("ObTypeIndexTable: %w", err)
		return r
	}
	r.table = table.Address
	if f, err = sym.Field("_OBJECT_TYPE", "Name"); err != nil {
		r.err = fmt.Errorf("_OBJECT_TYPE.Name: %w", err)
		return r
	}
	r.typeName = f.Offset
	if r.index, err = symbols.ResolveIntField(sym, "_OBJECT_TYPE", "Index"); err != nil {
		r.err = err
		return r
	}
	if s, err := sym.LookupSymbol("ObHeaderCookie"); err == nil {
		raw, rerr := ctx.Memory.ReadAt(s.Address, 1)
		if rerr != nil || len(raw) != 1 {
			r.err = fmt.Errorf("ObHeaderCookie at 0x%x does not read: %v", s.Address, rerr)
			return r
		}
		r.cookie, r.hasCookie = raw[0], true
	}
	return r
}

// The bool is false when the header does not read or its slot holds no type
// whose Index is the slot.
func (r *typeResolver) resolve(header uint64) (uint64, string, bool) {
	if r.err != nil {
		return 0, "", false
	}
	raw, err := r.ctx.Memory.ReadAt(header+r.typeIndex, 1)
	if err != nil || len(raw) != 1 {
		return 0, "", false
	}
	slot := raw[0]
	if r.hasCookie {
		slot ^= r.cookie ^ byte(header>>8)
	}
	s := r.slot(slot)
	return uint64(slot), s.name, s.ok
}

func (r *typeResolver) slot(i byte) typeSlot {
	s := &r.slots[i]
	if s.read {
		return *s
	}
	s.read = true
	sym, mem := r.ctx.Symbols, r.ctx.Memory
	objectType, err := sym.ReadPointer(mem, r.table+uint64(i)*uint64(sym.PointerSize()))
	if err != nil || objectType == 0 {
		return *s
	}
	index, err := r.index.Read(mem, objectType)
	if err != nil || index != uint64(i) {
		return *s
	}
	name, err := util.ReadUnicodeString(mem, objectType+r.typeName, util.ResolveUnicodeStringLayout(sym), util.MaxUnicodeStringBytes)
	if err != nil || name.Value == "" {
		return *s
	}
	s.name, s.ok = util.CountedText(name.Value), true
	return *s
}
