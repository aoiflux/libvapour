package memoryranges

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/processlist"
)

// The 26100 layout of S24 T1 to T5 and T8 to T10.
const (
	tVadRoot       = 0x558
	tFlagsWord     = 0x30
	tCommit        = 0x34
	tCommitHigh    = 0x22
	tStartLow      = 0x18
	tEndLow        = 0x1c
	tStartHigh     = 0x20
	tEndHigh       = 0x21
	tParent        = 0x10
	tSubsection    = 0x48
	tProtectionBit = 7
	tKindBit       = 4
	tPrivateBit    = 21
	tCAFlags       = 0x38
	tCAFile        = 0x40
	tFileBit       = 7
	tFileName      = 0x58

	tEprocess   = uint64(0xffff800000001000)
	tProtectVA  = uint64(0xffff800000002000)
	tHighestVA  = uint64(0xffff800000003000)
	tNodeBase   = uint64(0xffff800000100000)
	tNodeStride = uint64(0x1000)
	tVADOffset  = uint64(0x100)
)

type sparse struct{ bytes map[uint64]byte }

func newSparse() *sparse { return &sparse{bytes: map[uint64]byte{}} }

func (s *sparse) ReadAt(off, n uint64) ([]byte, error) {
	out := make([]byte, n)
	for i := range n {
		b, ok := s.bytes[off+i]
		if !ok {
			return nil, fmt.Errorf("sparse: 0x%x not mapped", off+i)
		}
		out[i] = b
	}
	return out, nil
}

func (s *sparse) Size() uint64 { return 1 << 63 }

func (s *sparse) put(at uint64, b []byte) {
	for i, v := range b {
		s.bytes[at+uint64(i)] = v
	}
}

func (s *sparse) zero(at, n uint64) { s.put(at, make([]byte, n)) }

func (s *sparse) u64(at, v uint64) { s.put(at, binary.LittleEndian.AppendUint64(nil, v)) }

func (s *sparse) u32(at uint64, v uint32) { s.put(at, binary.LittleEndian.AppendUint32(nil, v)) }

func (s *sparse) drop(at, n uint64) {
	for i := range n {
		delete(s.bytes, at+i)
	}
}

func uint32Field(name string, off uint64) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: "unsigned int"}}
}

func bitField(name string, bit, length uint8) symbols.Field {
	return symbols.Field{Name: name, Type: symbols.TypeRef{Name: "unsigned int", BitOffset: bit, BitLength: length}}
}

func pointerField(name string, off uint64) symbols.Field {
	return symbols.Field{Name: name, Offset: off, Type: symbols.TypeRef{Name: "void", IsPointer: true}}
}

func s24Table() *symbols.Table {
	t := symbols.NewTable("s24", 8)
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x840, Fields: []symbols.Field{
		{Name: "VadRoot", Offset: tVadRoot, Type: symbols.TypeRef{Name: "_RTL_AVL_TREE"}},
	}})
	t.AddStruct(symbols.StructType{Name: "_RTL_AVL_TREE", Size: 8, Fields: []symbols.Field{pointerField("Root", 0)}})
	t.AddStruct(symbols.StructType{Name: "_RTL_BALANCED_NODE", Size: 24, Fields: []symbols.Field{
		pointerField("Left", 0), pointerField("Right", 8),
		{Name: "ParentValue", Offset: tParent, Type: symbols.TypeRef{Name: "unsigned long long"}},
		{Name: "Balance", Offset: tParent, Type: symbols.TypeRef{Name: "unsigned char", BitLength: 2}},
		{Name: "Red", Offset: tParent, Type: symbols.TypeRef{Name: "unsigned char", BitLength: 1}},
	}})
	t.AddStruct(symbols.StructType{Name: "_MMVAD_SHORT", Size: 64, Fields: []symbols.Field{
		{Name: "VadNode", Offset: 0, Type: symbols.TypeRef{Name: "_RTL_BALANCED_NODE"}},
		uint32Field("StartingVpn", tStartLow), uint32Field("EndingVpn", tEndLow),
		{Name: "StartingVpnHigh", Offset: tStartHigh, Type: symbols.TypeRef{Name: "unsigned char"}},
		{Name: "EndingVpnHigh", Offset: tEndHigh, Type: symbols.TypeRef{Name: "unsigned char"}},
		{Name: "CommitChargeHigh", Offset: tCommitHigh, Type: symbols.TypeRef{Name: "unsigned char"}},
		{Name: "u", Offset: tFlagsWord, Type: symbols.TypeRef{Name: "<unnamed-tag>"}},
		uint32Field("CommitCharge", tCommit),
	}})
	t.AddStruct(symbols.StructType{Name: "_MMVAD", Size: 136, Fields: []symbols.Field{pointerField("Subsection", tSubsection)}})
	t.AddStruct(symbols.StructType{Name: "_MMVAD_FLAGS", Size: 4, Fields: []symbols.Field{
		bitField("VadType", tKindBit, 3), bitField("Protection", tProtectionBit, 5), bitField("PrivateMemory", tPrivateBit, 1),
	}})
	t.AddStruct(symbols.StructType{Name: "_POOL_HEADER", Size: 16, Fields: []symbols.Field{uint32Field("PoolTag", 4)}})
	t.AddStruct(symbols.StructType{Name: "_SUBSECTION", Size: 56, Fields: []symbols.Field{pointerField("ControlArea", 0)}})
	t.AddStruct(symbols.StructType{Name: "_CONTROL_AREA", Size: 128, Fields: []symbols.Field{
		{Name: "u", Offset: tCAFlags, Type: symbols.TypeRef{Name: "<unnamed-tag>"}},
		{Name: "FilePointer", Offset: tCAFile, Type: symbols.TypeRef{Name: "_EX_FAST_REF"}},
	}})
	t.AddStruct(symbols.StructType{Name: "_MMSECTION_FLAGS", Size: 4, Fields: []symbols.Field{bitField("File", tFileBit, 1)}})
	t.AddStruct(symbols.StructType{Name: "_EX_FAST_REF", Size: 8, Fields: []symbols.Field{
		{Name: "RefCnt", Type: symbols.TypeRef{Name: "unsigned long long", BitLength: 4}},
	}})
	t.AddStruct(symbols.StructType{Name: "_FILE_OBJECT", Size: 216, Fields: []symbols.Field{
		{Name: "FileName", Offset: tFileName, Type: symbols.TypeRef{Name: "_UNICODE_STRING"}},
	}})
	t.AddSymbol(symbols.Symbol{Name: "MmProtectToValue", Address: tProtectVA})
	t.AddSymbol(symbols.Symbol{Name: "MmHighestUserAddress", Address: tHighestVA})
	return t
}

// The measured MmProtectToValue of S24 M2.
func measuredProtectTable() []uint32 {
	base := []uint32{0x01, 0x02, 0x10, 0x20, 0x04, 0x08, 0x40, 0x80}
	mods := []uint32{0, 0x200, 0x100, 0x400}
	out := make([]uint32, 32)
	for i := range out {
		out[i] = base[i&7] | mods[i>>3]
		if i&7 == 0 {
			out[i] = 0x01
		}
	}
	return out
}

type tVAD struct {
	start, end uint64
	protection uint32
	private    bool
	kind       uint32
	tag        string
	commit     uint64
	file       string
}

type tImage struct {
	t     *symbols.Table
	mem   *sparse
	nodes []uint64
	diags []string
}

func nodeAt(i int) uint64 { return tNodeBase + uint64(i)*tNodeStride + tVADOffset }

// newImage lays the VADs out at nodes 0..n-1; link() then sets the tree.
func newImage(vads []tVAD) *tImage {
	img := &tImage{t: s24Table(), mem: newSparse()}
	img.mem.zero(tEprocess, 0x840)
	img.mem.u64(tHighestVA, 0x7FFF_FFFE_FFFF)
	for i, v := range measuredProtectTable() {
		img.mem.u32(tProtectVA+uint64(4*i), v)
	}
	for i, v := range vads {
		img.putVAD(i, v)
	}
	return img
}

func (img *tImage) putVAD(i int, v tVAD) {
	at := nodeAt(i)
	img.mem.zero(at-16, 16+136)
	tag := v.tag
	if tag == "" {
		tag = "VadS"
		if !v.private {
			tag = "Vad "
		}
	}
	img.mem.put(at-12, []byte(tag))
	sv, ev := v.start>>12, v.end>>12
	img.mem.u32(at+tStartLow, uint32(sv))
	img.mem.u32(at+tEndLow, uint32(ev))
	img.mem.put(at+tStartHigh, []byte{byte(sv >> 32)})
	img.mem.put(at+tEndHigh, []byte{byte(ev >> 32)})
	flags := v.protection<<tProtectionBit | v.kind<<tKindBit
	if v.private {
		flags |= 1 << tPrivateBit
	}
	img.mem.u32(at+tFlagsWord, flags)
	img.mem.u32(at+tCommit, uint32(v.commit))
	img.mem.put(at+tCommitHigh, []byte{byte(v.commit >> 32)})
	if v.file != "" {
		img.putFile(i, v.file, true)
	}
	for len(img.nodes) <= i {
		img.nodes = append(img.nodes, 0)
	}
	img.nodes[i] = at
}

func (img *tImage) putFile(i int, name string, fileFlag bool) {
	page := tNodeBase + uint64(i)*tNodeStride
	sub, ca, fo, buf := page+0x400, page+0x500, page+0x600, page+0x800
	img.mem.zero(sub, 56)
	img.mem.zero(ca, 128)
	img.mem.zero(fo, 216)
	img.mem.u64(nodeAt(i)+tSubsection, sub)
	img.mem.u64(sub, ca)
	if fileFlag {
		img.mem.u32(ca+tCAFlags, 1<<tFileBit)
	}
	img.mem.u64(ca+tCAFile, fo|0xf)
	raw := make([]byte, 0, 2*len(name))
	for _, r := range name {
		raw = binary.LittleEndian.AppendUint16(raw, uint16(r))
	}
	img.mem.put(buf, raw)
	img.mem.put(fo+tFileName, binary.LittleEndian.AppendUint16(nil, uint16(len(raw))))
	img.mem.put(fo+tFileName+2, binary.LittleEndian.AppendUint16(nil, uint16(len(raw))))
	img.mem.u64(fo+tFileName+8, buf)
}

func (img *tImage) root(i int) {
	v := uint64(0)
	if i >= 0 {
		v = nodeAt(i)
	}
	img.mem.u64(tEprocess+tVadRoot, v)
}

func (img *tImage) left(parent, child int) {
	img.mem.u64(nodeAt(parent), nodeAt(child))
	img.mem.u64(nodeAt(child)+tParent, nodeAt(parent)|1)
}

func (img *tImage) right(parent, child int) {
	img.mem.u64(nodeAt(parent)+8, nodeAt(child))
	img.mem.u64(nodeAt(child)+tParent, nodeAt(parent)|3)
}

func (img *tImage) ctx(options map[string]any) tools.Context {
	if options == nil {
		options = map[string]any{}
	}
	options["diagnostics"] = &img.diags
	return tools.Context{Memory: img.mem, Symbols: img.t, Profile: profiles.WindowsX64Profile{}, Options: options}
}

var tProcess = processlist.Process{PID: 404, Name: "smss.exe", EPROCESS: tEprocess, DirectoryTableBase: 0x1aa000}

func starts[T any](rows []T, start func(T) uint64) []uint64 {
	out := make([]uint64, len(rows))
	for i, r := range rows {
		out[i] = start(r)
	}
	return out
}

func mappings(t *testing.T, img *tImage, options map[string]any) []Mapping {
	t.Helper()
	ctx := img.ctx(options)
	d, err := NewDecoder(ctx)
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	rows, err := d.Mappings(ctx, tProcess)
	if err != nil {
		t.Fatalf("Mappings: %v", err)
	}
	return rows
}
