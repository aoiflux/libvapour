package generator

import (
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/symbols/btf"
)

type draftMember struct {
	name      string
	offset    uint64
	embeds    bool
	typ       shape
	bitOffset uint8
	bitLength uint8
}

// A draft is one STRUCT, UNION, ENUM or ENUM64 as the table will write it,
// before names are given to the types it refers to.
type draft struct {
	id      uint32
	union   bool
	enum    bool
	size    uint64
	members []draftMember
	values  []symbols.EnumValue
}

func (c *converter) draftEnum(id uint32) (*draft, error) {
	t := c.spec.Types[id]
	switch t.Size {
	case 1, 2, 4, 8:
	default:
		return nil, refuseEnumWidth
	}
	d := &draft{id: id, enum: true, size: uint64(t.Size), values: make([]symbols.EnumValue, 0, len(t.Values))}
	seen := make(map[string]bool, len(t.Values))
	for _, v := range t.Values {
		if !identifier(v.Name, c.maxName) {
			return nil, refuseConstantName
		}
		if seen[v.Name] {
			return nil, refuseConstantRepeat
		}
		seen[v.Name] = true
		d.values = append(d.values, symbols.EnumValue{Name: v.Name, Value: enumValue(t, v.Value)})
	}
	return d, nil
}

// kind_flag marks a signed enumeration. A 32-bit ENUM value is sign-extended
// only then. An ENUM64 value of 2^63 or more keeps its bit pattern in the
// table's signed 64-bit constant.
func enumValue(t btf.Type, v uint64) int64 {
	if t.Kind == btf.KindEnum {
		if t.KindFlag {
			return int64(int32(uint32(v)))
		}
		return int64(uint32(v))
	}
	return int64(v)
}

func (c *converter) draftRecord(id uint32) *draft {
	t := c.spec.Types[id]
	d := &draft{id: id, union: t.Kind == btf.KindUnion, size: uint64(t.Size)}
	seen := make(map[string]bool, len(t.Members))
	var last uint64
	for _, m := range t.Members {
		dm, bit, err := c.draftMember(t, m)
		switch {
		case err != nil:
		case d.union && bit != 0:
			err = refuseUnionOffset
		case !d.union && bit < last:
			err = refuseOffsetOrder
		case (bit+7)/8 > d.size:
			err = refuseOffsetPast
		case dm.name != "" && seen[dm.name]:
			err = refuseDuplicateMember
		}
		if err != nil {
			c.refuse(err)
			continue
		}
		last = bit
		if dm.name == "" && !dm.embeds {
			c.report.Padding++
			continue
		}
		if dm.name != "" {
			seen[dm.name] = true
		}
		d.members = append(d.members, dm)
	}
	return d
}

// The returned bit offset is the member's BTF position, the one the
// kernel's ordering and size checks (btf_struct_check_meta) apply to.
func (c *converter) draftMember(parent btf.Type, m btf.Member) (draftMember, uint64, error) {
	bit := uint64(m.BitOffset)
	dm := draftMember{name: m.Name}
	if m.Name != "" && !identifier(m.Name, c.maxName) {
		return dm, bit, refuseMemberName
	}
	s, err := c.shapeOf(m.Type)
	if err != nil {
		return dm, bit, err
	}
	dm.typ = s
	length := uint64(m.BitSize)
	start := bit
	unit := uint64(0)
	if s.bare() && s.leaf == leafScalar && c.spec.Types[s.id].Kind == btf.KindInt {
		it := c.spec.Types[s.id]
		unit = uint64(it.Size)
		regular := it.IntOffset == 0 && uint64(it.IntBits) == 8*unit && unit&(unit-1) == 0
		switch {
		case parent.KindFlag && !regular:
			return dm, bit, refuseBitfieldRegular
		case !parent.KindFlag && !regular:
			length, start = uint64(it.IntBits), bit+uint64(it.IntOffset)
		}
	} else if s.bare() && s.leaf == leafComposite && c.spec.Types[s.id].Kind != btf.KindStruct &&
		c.spec.Types[s.id].Kind != btf.KindUnion {
		unit = uint64(c.spec.Types[s.id].Size)
	}
	if length == 0 {
		if start%8 != 0 {
			return dm, bit, refuseByteOffset
		}
		dm.offset = start / 8
		if m.Name == "" {
			switch {
			case s.bare() && s.leaf == leafComposite && !c.isEnum(s.id):
				dm.embeds = true
			case s.bare() && (s.leaf == leafScalar || s.leaf == leafComposite):
			default:
				return dm, bit, refuseUnnamedEmbed
			}
		}
		return dm, bit, nil
	}
	if unit == 0 {
		return dm, bit, refuseBitfieldBase
	}
	at, within, ok := storageUnit(start, length, unit, uint64(parent.Size))
	if !ok {
		return dm, bit, refuseBitfieldFit
	}
	dm.offset, dm.bitOffset, dm.bitLength = at, uint8(within), uint8(length)
	return dm, bit, nil
}

func (c *converter) isEnum(id uint32) bool {
	k := c.spec.Types[id].Kind
	return k == btf.KindEnum || k == btf.KindEnum64
}

// The x86-64 psABI puts a bitfield inside a storage unit of its declared
// type's size and alignment, filled from the least significant bit. A packed
// record can break the alignment, so a unit starting at the field's first
// byte is the fallback; a field that fits neither is refused.
func storageUnit(start, length, unit, recordSize uint64) (at, within uint64, ok bool) {
	bits := 8 * unit
	if length > bits {
		return 0, 0, false
	}
	at = start / bits * unit
	if within = start - 8*at; within+length <= bits && at < recordSize {
		return at, within, true
	}
	at = start / 8
	if within = start % 8; within+length <= bits && at < recordSize {
		return at, within, true
	}
	return 0, 0, false
}
