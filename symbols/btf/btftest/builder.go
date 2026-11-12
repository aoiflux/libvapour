// Package btftest writes BTF blobs for tests, one record per call, in the
// layout include/uapi/linux/btf.h gives.
package btftest

import (
	"encoding/binary"
)

type Builder struct {
	Order   binary.ByteOrder
	records []uint32
	strings []byte
	offsets map[string]uint32
	count   uint32
}

func New() *Builder {
	return &Builder{Order: binary.LittleEndian, strings: []byte{0}, offsets: map[string]uint32{"": 0}}
}

func (b *Builder) Name(s string) uint32 {
	if off, ok := b.offsets[s]; ok {
		return off
	}
	off := uint32(len(b.strings))
	b.strings = append(append(b.strings, s...), 0)
	b.offsets[s] = off
	return off
}

func (b *Builder) Raw(name string, info, sizeOrType uint32, data ...uint32) uint32 {
	b.records = append(b.records, b.Name(name), info, sizeOrType)
	b.records = append(b.records, data...)
	b.count++
	return b.count
}

func Info(kind uint8, vlen int, kindFlag bool) uint32 {
	info := uint32(kind)<<24 | uint32(vlen)&0xffff
	if kindFlag {
		info |= 1 << 31
	}
	return info
}

const (
	kindInt = iota + 1
	kindPtr
	kindArray
	kindStruct
	kindUnion
	kindEnum
	kindFwd
	kindTypedef
	kindVolatile
	kindConst
	kindRestrict
	kindFunc
	kindFuncProto
	kindVar
	kindDatasec
	kindFloat
	kindDeclTag
	kindTypeTag
	kindEnum64
)

func (b *Builder) Int(name string, size uint32, encoding uint8) uint32 {
	return b.Raw(name, Info(kindInt, 0, false), size, uint32(encoding)<<24|size*8)
}

func (b *Builder) Ptr(target uint32) uint32 { return b.Raw("", Info(kindPtr, 0, false), target) }

func (b *Builder) Array(elem, index, count uint32) uint32 {
	return b.Raw("", Info(kindArray, 0, false), 0, elem, index, count)
}

type Member struct {
	Name      string
	Type      uint32
	BitOffset uint32
	BitSize   uint32
}

func (b *Builder) Struct(name string, size uint32, ms ...Member) uint32 {
	return b.composite(kindStruct, name, size, ms)
}

func (b *Builder) Union(name string, size uint32, ms ...Member) uint32 {
	return b.composite(kindUnion, name, size, ms)
}

// kind_flag is needed as soon as one member is a bitfield, and then every
// member's offset word carries its size.
func (b *Builder) composite(kind uint8, name string, size uint32, ms []Member) uint32 {
	bitfields := false
	for _, m := range ms {
		bitfields = bitfields || m.BitSize != 0
	}
	words := make([]uint32, 0, 3*len(ms))
	for _, m := range ms {
		offset := m.BitOffset
		if bitfields {
			offset |= m.BitSize << 24
		}
		words = append(words, b.Name(m.Name), m.Type, offset)
	}
	return b.Raw(name, Info(kind, len(ms), bitfields), size, words...)
}

type Value struct {
	Name  string
	Value uint64
}

func (b *Builder) Enum(name string, size uint32, signed bool, vs ...Value) uint32 {
	words := make([]uint32, 0, 2*len(vs))
	for _, v := range vs {
		words = append(words, b.Name(v.Name), uint32(v.Value))
	}
	return b.Raw(name, Info(kindEnum, len(vs), signed), size, words...)
}

func (b *Builder) Enum64(name string, size uint32, signed bool, vs ...Value) uint32 {
	words := make([]uint32, 0, 3*len(vs))
	for _, v := range vs {
		words = append(words, b.Name(v.Name), uint32(v.Value), uint32(v.Value>>32))
	}
	return b.Raw(name, Info(kindEnum64, len(vs), signed), size, words...)
}

func (b *Builder) Fwd(name string, union bool) uint32 {
	return b.Raw(name, Info(kindFwd, 0, union), 0)
}

func (b *Builder) Typedef(name string, target uint32) uint32 {
	return b.Raw(name, Info(kindTypedef, 0, false), target)
}

func (b *Builder) Volatile(target uint32) uint32 {
	return b.Raw("", Info(kindVolatile, 0, false), target)
}

func (b *Builder) Const(target uint32) uint32 { return b.Raw("", Info(kindConst, 0, false), target) }

func (b *Builder) Restrict(target uint32) uint32 {
	return b.Raw("", Info(kindRestrict, 0, false), target)
}

// The linkage of a FUNC is its vlen; 1 is BTF_FUNC_GLOBAL.
func (b *Builder) Func(name string, proto uint32) uint32 {
	return b.Raw(name, Info(kindFunc, 1, false), proto)
}

type Param struct {
	Name string
	Type uint32
}

func (b *Builder) FuncProto(ret uint32, ps ...Param) uint32 {
	words := make([]uint32, 0, 2*len(ps))
	for _, p := range ps {
		words = append(words, b.Name(p.Name), p.Type)
	}
	return b.Raw("", Info(kindFuncProto, len(ps), false), ret, words...)
}

func (b *Builder) Var(name string, typ, linkage uint32) uint32 {
	return b.Raw(name, Info(kindVar, 0, false), typ, linkage)
}

// Each variable is {type, offset, size}.
func (b *Builder) Datasec(name string, size uint32, vars ...[3]uint32) uint32 {
	words := make([]uint32, 0, 3*len(vars))
	for _, v := range vars {
		words = append(words, v[:]...)
	}
	return b.Raw(name, Info(kindDatasec, len(vars), false), size, words...)
}

func (b *Builder) Float(name string, size uint32) uint32 {
	return b.Raw(name, Info(kindFloat, 0, false), size)
}

func (b *Builder) DeclTag(name string, target uint32, component int32) uint32 {
	return b.Raw(name, Info(kindDeclTag, 0, false), target, uint32(component))
}

func (b *Builder) TypeTag(name string, target uint32) uint32 {
	return b.Raw(name, Info(kindTypeTag, 0, false), target)
}

func (b *Builder) Bytes() []byte {
	typeBytes := uint32(4 * len(b.records))
	out := make([]byte, 24+typeBytes, 24+int(typeBytes)+len(b.strings))
	b.Order.PutUint16(out, 0xeb9f)
	out[2] = 1
	for i, w := range []uint32{24, 0, typeBytes, typeBytes, uint32(len(b.strings))} {
		b.Order.PutUint32(out[4+4*i:], w)
	}
	for i, w := range b.records {
		b.Order.PutUint32(out[24+4*i:], w)
	}
	return append(out, b.strings...)
}
