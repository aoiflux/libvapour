// Package btf reads the BPF Type Format a kernel carries for its own types.
// The bytes come from a memory image, so every bound and reference is checked
// before it is used, and a blob that breaks any rule is refused whole.
package btf

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
)

type Kind uint8

const (
	KindUnknown Kind = iota
	KindInt
	KindPtr
	KindArray
	KindStruct
	KindUnion
	KindEnum
	KindFwd
	KindTypedef
	KindVolatile
	KindConst
	KindRestrict
	KindFunc
	KindFuncProto
	KindVar
	KindDatasec
	KindFloat
	KindDeclTag
	KindTypeTag
	KindEnum64
	kindCount
)

var kindLabels = [kindCount]string{
	"UNKN", "INT", "PTR", "ARRAY", "STRUCT", "UNION", "ENUM", "FWD", "TYPEDEF", "VOLATILE",
	"CONST", "RESTRICT", "FUNC", "FUNC_PROTO", "VAR", "DATASEC", "FLOAT", "DECL_TAG", "TYPE_TAG", "ENUM64",
}

func (k Kind) String() string {
	if k < kindCount {
		return kindLabels[k]
	}
	return fmt.Sprintf("kind %d", uint8(k))
}

const (
	IntSigned = 1 << 0
	IntChar   = 1 << 1
	IntBool   = 1 << 2
)

type Member struct {
	Name      string
	Type      uint32
	BitOffset uint32
	BitSize   uint32
}

type EnumValue struct {
	Name  string
	Value uint64
}

type Param struct {
	Name string
	Type uint32
}

type VarSecInfo struct {
	Type   uint32
	Offset uint32
	Size   uint32
}

type Type struct {
	Kind     Kind
	Name     string
	KindFlag bool
	Size     uint32
	Ref      uint32

	IntEncoding, IntOffset, IntBits uint8

	ArrayElem, ArrayIndex, ArrayCount uint32

	Members []Member
	Values  []EnumValue
	Params  []Param
	Vars    []VarSecInfo

	Linkage   uint32
	Component int32
}

type Spec struct {
	ByteOrder binary.ByteOrder
	Types     []Type
}

var (
	ErrHeader     = errors.New("btf: header is not a btf header")
	ErrSections   = errors.New("btf: sections do not fill the blob")
	ErrStrings    = errors.New("btf: string section is malformed")
	ErrRecord     = errors.New("btf: type record is malformed")
	ErrReference  = errors.New("btf: type refers to a type that does not exist")
	ErrKernelSpan = errors.New("btf: kernel span is not readable btf")
)

const (
	btfMagic       = 0xeb9f
	btfVersion     = 1
	headerBytes    = 24
	recordBytes    = 12
	infoKnownBits  = 0x9f00ffff
	intKnownBits   = 0x0fffffff
	maxNameOffset  = 0x00ffffff
	maxTypeID      = 0x000fffff
	maxIntBits     = 128
	memberSizeAt   = 24
	memberOffsMask = 0x00ffffff
)

// Bytes after the kind's 12-byte record: fixed per kind, or per vlen entry.
var trailing = [kindCount]struct{ fixed, each int }{
	KindInt:       {fixed: 4},
	KindArray:     {fixed: 12},
	KindStruct:    {each: 12},
	KindUnion:     {each: 12},
	KindEnum:      {each: 8},
	KindFuncProto: {each: 8},
	KindVar:       {fixed: 4},
	KindDatasec:   {each: 12},
	KindDeclTag:   {fixed: 4},
	KindEnum64:    {each: 12},
}

type header struct {
	order            binary.ByteOrder
	length           uint32
	typeOff, typeLen uint32
	strOff, strLen   uint32
}

func readHeader(data []byte) (header, error) {
	if len(data) < headerBytes {
		return header{}, fmt.Errorf("%w: %d bytes, fewer than the %d a header holds", ErrHeader, len(data), headerBytes)
	}
	var h header
	switch uint16(btfMagic) {
	case binary.LittleEndian.Uint16(data):
		h.order = binary.LittleEndian
	case binary.BigEndian.Uint16(data):
		h.order = binary.BigEndian
	default:
		return header{}, fmt.Errorf("%w: magic 0x%04x", ErrHeader, binary.LittleEndian.Uint16(data))
	}
	if data[2] != btfVersion || data[3] != 0 {
		return header{}, fmt.Errorf("%w: version %d, flags 0x%x", ErrHeader, data[2], data[3])
	}
	h.length = h.order.Uint32(data[4:])
	if h.length < headerBytes || uint64(h.length) > uint64(len(data)) {
		return header{}, fmt.Errorf("%w: hdr_len %d with %d bytes", ErrHeader, h.length, len(data))
	}
	for i := headerBytes; i < int(h.length); i++ {
		if data[i] != 0 {
			return header{}, fmt.Errorf("%w: header byte %d is not zero", ErrHeader, i)
		}
	}
	h.typeOff, h.typeLen = h.order.Uint32(data[8:]), h.order.Uint32(data[12:])
	h.strOff, h.strLen = h.order.Uint32(data[16:]), h.order.Uint32(data[20:])
	return h, nil
}

// The kernel accepts only a type section at offset 0 followed directly by a
// string section that ends the blob.
func (h header) sections(data []byte) (types, strs []byte, err error) {
	body := uint64(len(data)) - uint64(h.length)
	switch {
	case h.typeOff != 0 || h.typeLen == 0:
		return nil, nil, fmt.Errorf("%w: type section at 0x%x, 0x%x bytes", ErrSections, h.typeOff, h.typeLen)
	case uint64(h.strOff) != uint64(h.typeLen) || uint64(h.strOff)+uint64(h.strLen) != body:
		return nil, nil, fmt.Errorf("%w: string section at 0x%x, 0x%x bytes, after 0x%x type bytes in a 0x%x-byte body",
			ErrSections, h.strOff, h.strLen, h.typeLen, body)
	}
	types = data[h.length : h.length+h.typeLen]
	strs = data[h.length+h.strOff:]
	if len(strs) == 0 || len(strs)-1 > maxNameOffset || strs[0] != 0 || strs[len(strs)-1] != 0 {
		return nil, nil, fmt.Errorf("%w: 0x%x bytes", ErrStrings, len(strs))
	}
	return types, strs, nil
}

func Parse(data []byte) (*Spec, error) {
	h, err := readHeader(data)
	if err != nil {
		return nil, err
	}
	types, strs, err := h.sections(data)
	if err != nil {
		return nil, err
	}
	d := decoder{order: h.order, strs: strs}
	spec := &Spec{ByteOrder: h.order, Types: []Type{{}}}
	for at := 0; at < len(types); {
		if len(spec.Types) > maxTypeID {
			return nil, fmt.Errorf("%w: more than %d types", ErrRecord, maxTypeID)
		}
		t, n, err := d.record(types[at:])
		if err != nil {
			return nil, fmt.Errorf("type %d at 0x%x: %w", len(spec.Types), at, err)
		}
		spec.Types = append(spec.Types, t)
		at += n
	}
	if err := spec.resolves(); err != nil {
		return nil, err
	}
	return spec, nil
}

type decoder struct {
	order binary.ByteOrder
	strs  []byte
}

func (d decoder) word(b []byte, i int) uint32 { return d.order.Uint32(b[4*i:]) }

func (d decoder) name(off uint32) (string, error) {
	if uint64(off) >= uint64(len(d.strs)) {
		return "", fmt.Errorf("%w: name offset 0x%x past 0x%x string bytes", ErrRecord, off, len(d.strs))
	}
	end := int(off)
	for d.strs[end] != 0 {
		end++
	}
	return string(d.strs[off:end]), nil
}

func (d decoder) record(b []byte) (Type, int, error) {
	if len(b) < recordBytes {
		return Type{}, 0, fmt.Errorf("%w: %d bytes left for a %d-byte record", ErrRecord, len(b), recordBytes)
	}
	info := d.word(b, 1)
	if info&^infoKnownBits != 0 {
		return Type{}, 0, fmt.Errorf("%w: info 0x%08x sets unused bits", ErrRecord, info)
	}
	t := Type{Kind: Kind(info >> 24 & 0x1f), KindFlag: info>>31 == 1}
	if t.Kind == KindUnknown || t.Kind >= kindCount {
		return Type{}, 0, fmt.Errorf("%w: kind %d", ErrRecord, t.Kind)
	}
	vlen := int(info & 0xffff)
	var err error
	if t.Name, err = d.name(d.word(b, 0)); err != nil {
		return Type{}, 0, err
	}
	shape := trailing[t.Kind]
	extra := shape.fixed + shape.each*vlen
	if len(b)-recordBytes < extra {
		return Type{}, 0, fmt.Errorf("%w: %s with vlen %d needs %d more bytes, %d remain", ErrRecord, t.Kind, vlen, extra, len(b)-recordBytes)
	}
	if err := d.body(&t, d.word(b, 2), vlen, b[recordBytes:recordBytes+extra]); err != nil {
		return Type{}, 0, fmt.Errorf("%s %q: %w", t.Kind, t.Name, err)
	}
	return t, recordBytes + extra, nil
}

func (d decoder) body(t *Type, sizeOrType uint32, vlen int, data []byte) error {
	switch t.Kind {
	case KindInt, KindStruct, KindUnion, KindEnum, KindEnum64, KindDatasec, KindFloat:
		t.Size = sizeOrType
	case KindArray, KindFwd:
		if sizeOrType != 0 {
			return fmt.Errorf("%w: size or type 0x%x where the kind has none", ErrRecord, sizeOrType)
		}
	default:
		t.Ref = sizeOrType
	}
	var err error
	switch t.Kind {
	case KindInt:
		return d.integer(t, d.word(data, 0))
	case KindArray:
		t.ArrayElem, t.ArrayIndex, t.ArrayCount = d.word(data, 0), d.word(data, 1), d.word(data, 2)
	case KindStruct, KindUnion:
		t.Members = make([]Member, vlen)
		for i := range t.Members {
			m := &t.Members[i]
			if m.Name, err = d.name(d.word(data, 3*i)); err != nil {
				return fmt.Errorf("member %d: %w", i, err)
			}
			m.Type = d.word(data, 3*i+1)
			m.BitOffset = d.word(data, 3*i+2)
			if t.KindFlag {
				m.BitSize, m.BitOffset = m.BitOffset>>memberSizeAt, m.BitOffset&memberOffsMask
			}
		}
	case KindEnum, KindEnum64:
		per := 2
		if t.Kind == KindEnum64 {
			per = 3
		}
		t.Values = make([]EnumValue, vlen)
		for i := range t.Values {
			v := &t.Values[i]
			if v.Name, err = d.name(d.word(data, per*i)); err != nil {
				return fmt.Errorf("constant %d: %w", i, err)
			}
			v.Value = uint64(d.word(data, per*i+1))
			if per == 3 {
				v.Value |= uint64(d.word(data, per*i+2)) << 32
			}
		}
	case KindFuncProto:
		t.Params = make([]Param, vlen)
		for i := range t.Params {
			if t.Params[i].Name, err = d.name(d.word(data, 2*i)); err != nil {
				return fmt.Errorf("parameter %d: %w", i, err)
			}
			t.Params[i].Type = d.word(data, 2*i+1)
		}
	case KindDatasec:
		t.Vars = make([]VarSecInfo, vlen)
		for i := range t.Vars {
			t.Vars[i] = VarSecInfo{Type: d.word(data, 3*i), Offset: d.word(data, 3*i+1), Size: d.word(data, 3*i+2)}
		}
	case KindVar:
		t.Linkage = d.word(data, 0)
	case KindFunc:
		t.Linkage = uint32(vlen)
	case KindDeclTag:
		t.Component = int32(d.word(data, 0))
	}
	return nil
}

func (d decoder) integer(t *Type, v uint32) error {
	if v&^intKnownBits != 0 {
		return fmt.Errorf("%w: int data 0x%08x sets unused bits", ErrRecord, v)
	}
	t.IntEncoding, t.IntOffset, t.IntBits = uint8(v>>24&0x0f), uint8(v>>16), uint8(v)
	switch e := t.IntEncoding; e {
	case 0, IntSigned, IntChar, IntBool:
	default:
		return fmt.Errorf("%w: int encoding 0x%x is not one flag", ErrRecord, e)
	}
	bits := uint64(t.IntOffset) + uint64(t.IntBits)
	if bits > maxIntBits || (bits+7)/8 > uint64(t.Size) {
		return fmt.Errorf("%w: %d bits from offset %d in %d bytes", ErrRecord, t.IntBits, t.IntOffset, t.Size)
	}
	return nil
}

func (s *Spec) resolves() error {
	last := uint32(len(s.Types) - 1)
	for id := 1; id < len(s.Types); id++ {
		t := &s.Types[id]
		refs := []uint32{t.Ref}
		if t.Kind == KindArray {
			refs = append(refs, t.ArrayElem, t.ArrayIndex)
		}
		for _, m := range t.Members {
			refs = append(refs, m.Type)
		}
		for _, p := range t.Params {
			refs = append(refs, p.Type)
		}
		for _, v := range t.Vars {
			refs = append(refs, v.Type)
		}
		for _, r := range refs {
			if r > last {
				return fmt.Errorf("%w: type %d (%s %q) names type %d, the last is %d", ErrReference, id, t.Kind, t.Name, r, last)
			}
		}
	}
	return nil
}

func ReadKernel(kernel memory.MemoryReader, start, stop uint64, l limits.Limits) ([]byte, *Spec, error) {
	ceiling := uint64(l.Effective().MaxKernelImageBytes)
	if stop <= start || stop-start > ceiling {
		return nil, nil, fmt.Errorf("%w: [0x%x, 0x%x) does not hold 1 to MaxKernelImageBytes (%d) bytes", ErrKernelSpan, start, stop, ceiling)
	}
	data, err := kernel.ReadAt(start, stop-start)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read [0x%x, 0x%x): %w", ErrKernelSpan, start, stop, err)
	}
	if uint64(len(data)) != stop-start {
		return nil, nil, fmt.Errorf("%w: read %d of %d bytes at 0x%x", ErrKernelSpan, len(data), stop-start, start)
	}
	spec, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}
	return data, spec, nil
}
