package testsupport

import (
	"encoding/binary"

	"github.com/aoiflux/libvapour/symbols"
)

// The 26100 token layout of S45 T1 to T4.
const (
	S45EprocessTokenOffset    = uint64(0x4b8)
	S45PrivilegesOffset       = uint64(0x40)
	S45GroupCountOffset       = uint64(0x7c)
	S45RestrictedCountOffset  = uint64(0x80)
	S45GroupsOffset           = uint64(0x98)
	S45RestrictedOffset       = uint64(0xa0)
	S45CapabilitiesOffset     = uint64(0x318)
	S45CapabilityCountOffset  = uint64(0x320)
	S45VariablePartOffset     = uint64(0x490)
	S45TokenSize              = uint64(0x498)
	S45SIDAndAttributesSize   = uint64(16)
	S45UnmappedKernelAddress  = uint64(0xfffff8000f000000)
	s45TokenBaseVA            = uint64(0xfffff80002000000)
	s45TokenStrideVA          = uint64(0x10000)
	s45TokenPages             = 4
	s45CapabilityPageDistance = uint64(0x3000)
)

func S45AddTokenTypes(t *symbols.Table) {
	eprocess, err := t.Struct("_EPROCESS")
	if err != nil {
		panic("testsupport: fixture table lacks _EPROCESS: " + err.Error())
	}
	eprocess.Fields = append(eprocess.Fields, symbols.Field{Name: "Token", Offset: S45EprocessTokenOffset,
		Type: symbols.TypeRef{Name: "_EX_FAST_REF"}})
	t.AddStruct(eprocess)
	t.AddStruct(symbols.StructType{Name: "_EX_FAST_REF", Size: 8, Fields: []symbols.Field{
		{Name: "Object", Offset: 0, Type: symbols.TypeRef{Name: "void", IsPointer: true}},
		{Name: "RefCnt", Offset: 0, Type: symbols.TypeRef{Name: "unsigned long long", BitOffset: 0, BitLength: 4}},
		{Name: "Value", Offset: 0, Type: symbols.TypeRef{Name: "unsigned long long"}},
	}})
	t.AddStruct(symbols.StructType{Name: "_TOKEN", Size: S45TokenSize, Fields: []symbols.Field{
		{Name: "Privileges", Offset: S45PrivilegesOffset, Type: symbols.TypeRef{Name: "_SEP_TOKEN_PRIVILEGES"}},
		{Name: "UserAndGroupCount", Offset: S45GroupCountOffset, Type: symbols.TypeRef{Name: "unsigned int"}},
		{Name: "RestrictedSidCount", Offset: S45RestrictedCountOffset, Type: symbols.TypeRef{Name: "unsigned int"}},
		{Name: "UserAndGroups", Offset: S45GroupsOffset, Type: symbols.TypeRef{Name: "_SID_AND_ATTRIBUTES", IsPointer: true}},
		{Name: "RestrictedSids", Offset: S45RestrictedOffset, Type: symbols.TypeRef{Name: "_SID_AND_ATTRIBUTES", IsPointer: true}},
		{Name: "Capabilities", Offset: S45CapabilitiesOffset, Type: symbols.TypeRef{Name: "_SID_AND_ATTRIBUTES", IsPointer: true}},
		{Name: "CapabilityCount", Offset: S45CapabilityCountOffset, Type: symbols.TypeRef{Name: "unsigned int"}},
		{Name: "VariablePart", Offset: S45VariablePartOffset, Type: symbols.TypeRef{Name: "unsigned long long"}},
	}})
	t.AddStruct(symbols.StructType{Name: "_SID_AND_ATTRIBUTES", Size: S45SIDAndAttributesSize, Fields: []symbols.Field{
		{Name: "Sid", Offset: 0, Type: symbols.TypeRef{Name: "void", IsPointer: true}},
		{Name: "Attributes", Offset: 8, Type: symbols.TypeRef{Name: "unsigned int"}},
	}})
	t.AddStruct(symbols.StructType{Name: "_SEP_TOKEN_PRIVILEGES", Size: 24, Fields: []symbols.Field{
		{Name: "Present", Offset: 0, Type: symbols.TypeRef{Name: "unsigned long long"}},
		{Name: "Enabled", Offset: 8, Type: symbols.TypeRef{Name: "unsigned long long"}},
		{Name: "EnabledByDefault", Offset: 0x10, Type: symbols.TypeRef{Name: "unsigned long long"}},
	}})
}

type S45SID struct {
	Bytes      []byte
	Attributes uint32
	// Pointer, when nonzero, is written in place of the address of Bytes.
	Pointer uint64
}

type S45Token struct {
	Groups, Restricted, Capabilities   []S45SID
	Present, Enabled, EnabledByDefault uint64
	RefCount                           uint64
	GroupsPointer                      uint64
	RestrictedPointer                  uint64
	CapabilityPointer                  uint64
}

func S45SIDBytes(authority uint64, sub ...uint32) []byte {
	b := make([]byte, 8+4*len(sub))
	b[0], b[1] = 1, byte(len(sub))
	for i := 0; i < 6; i++ {
		b[7-i] = byte(authority >> (8 * i))
	}
	for i, v := range sub {
		binary.LittleEndian.PutUint32(b[8+4*i:], v)
	}
	return b
}

type s45Pages struct {
	f    *ProcessFixture
	base uint64
	pa   []uint64
}

func (p s45Pages) write(va uint64, data []byte) {
	for len(data) > 0 {
		off := va - p.base
		page := off / pageSize
		n := min(uint64(len(data)), pageSize-off%pageSize)
		p.f.Memory.WriteAt(p.pa[page]+off%pageSize, data[:n])
		data, va = data[n:], va+n
	}
}

func (p s45Pages) u64(va, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	p.write(va, b[:])
}

func (p s45Pages) u32(va uint64, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	p.write(va, b[:])
}

func (f *ProcessFixture) S45SetTokenPointer(pid, value uint64) {
	_, pa := f.EPROCESS(pid)
	f.Memory.WriteU64(pa+S45EprocessTokenOffset, value)
}

func (f *ProcessFixture) WriteS45Token(pid uint64, tok S45Token) uint64 {
	va := s45TokenBaseVA + pid*s45TokenStrideVA
	p := s45Pages{f: f, base: va}
	for i := 0; i < s45TokenPages; i++ {
		p.pa = append(p.pa, f.Kernel.MapPage(va+uint64(i)*pageSize))
	}
	f.S45SetTokenPointer(pid, va|tok.RefCount)

	p.u64(va+S45PrivilegesOffset, tok.Present)
	p.u64(va+S45PrivilegesOffset+8, tok.Enabled)
	p.u64(va+S45PrivilegesOffset+0x10, tok.EnabledByDefault)

	groups := va + S45VariablePartOffset
	restricted := groups + uint64(len(tok.Groups))*S45SIDAndAttributesSize
	next := restricted + uint64(len(tok.Restricted))*S45SIDAndAttributesSize
	place := func(array uint64, sids []S45SID, at uint64) uint64 {
		for i, s := range sids {
			entry := array + uint64(i)*S45SIDAndAttributesSize
			ptr := s.Pointer
			if ptr == 0 && s.Bytes != nil {
				ptr = at
				p.write(at, s.Bytes)
				at += (uint64(len(s.Bytes)) + 7) &^ 7
			}
			p.u64(entry, ptr)
			p.u32(entry+8, s.Attributes)
		}
		return at
	}
	next = place(groups, tok.Groups, next)
	place(restricted, tok.Restricted, next)
	caps := va + s45CapabilityPageDistance
	place(caps, tok.Capabilities, caps+uint64(len(tok.Capabilities))*S45SIDAndAttributesSize)

	pointer := func(override, placed uint64) uint64 {
		if override != 0 {
			return override
		}
		return placed
	}
	p.u32(va+S45GroupCountOffset, uint32(len(tok.Groups)))
	p.u64(va+S45GroupsOffset, pointer(tok.GroupsPointer, groups))
	p.u32(va+S45RestrictedCountOffset, uint32(len(tok.Restricted)))
	if len(tok.Restricted) > 0 || tok.RestrictedPointer != 0 {
		p.u64(va+S45RestrictedOffset, pointer(tok.RestrictedPointer, restricted))
	}
	p.u32(va+S45CapabilityCountOffset, uint32(len(tok.Capabilities)))
	if len(tok.Capabilities) > 0 || tok.CapabilityPointer != 0 {
		p.u64(va+S45CapabilitiesOffset, pointer(tok.CapabilityPointer, caps))
	}
	return va
}
