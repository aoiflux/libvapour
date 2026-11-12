package credentialkerberoshook

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/subsection"
	"github.com/aoiflux/libvapour/symbols"
)

type flat struct {
	base uint64
	b    []byte
}

func (f flat) Size() uint64 { return f.base + uint64(len(f.b)) }

func (f flat) ReadAt(at, n uint64) ([]byte, error) {
	if at < f.base || at-f.base+n > uint64(len(f.b)) {
		return nil, memory.ErrOutOfBounds
	}
	return f.b[at-f.base : at-f.base+n], nil
}

type pageKinds struct {
	start uint64
	kinds map[uint64]layers.PageErrorKind
	fill  byte
}

func (p pageKinds) Size() uint64 { return 1 << 47 }

func (p pageKinds) ReadAt(at, n uint64) ([]byte, error) {
	if k, ok := p.kinds[(at-p.start)/0x1000]; ok {
		return nil, layers.UnmappedPageError{VirtualAddress: at, Kind: k}
	}
	return bytes.Repeat([]byte{p.fill}, int(n)), nil
}

const (
	irKernel   = uint64(0xffff_8000_0000_0000)
	irVAD      = irKernel + 0x100
	irPTEs     = irKernel + 0x800
	irView     = uint64(0x7ff9_0710_0000)
	irFrame    = uint64(0x5000)
	irStartOff = 0x18
	irProtoOff = 0x50
)

func protoResolver(t *testing.T) (*subsection.Resolver, flat) {
	t.Helper()
	table := symbols.NewTable("proto", 8)
	table.AddStruct(symbols.StructType{Name: "_CONTROL_AREA", Size: 0x80})
	table.AddStruct(symbols.StructType{Name: "_SUBSECTION", Size: 0x38, Fields: []symbols.Field{
		{Name: "ControlArea", Offset: 0}, {Name: "SubsectionBase", Offset: 8}, {Name: "NextSubsection", Offset: 0x10},
		{Name: "PtesInSubsection", Offset: 0x2c}, {Name: "StartingSector", Offset: 0x24},
	}})
	table.AddStruct(symbols.StructType{Name: "_MMVAD_SHORT", Size: 0x40, Fields: []symbols.Field{
		{Name: "StartingVpn", Offset: irStartOff}, {Name: "StartingVpnHigh", Offset: irStartOff + 0xc},
	}})
	table.AddStruct(symbols.StructType{Name: "_MMVAD", Size: 0x88, Fields: []symbols.Field{
		{Name: "FirstPrototypePte", Offset: irProtoOff},
	}})
	kmem := make([]byte, 0x1000)
	binary.LittleEndian.PutUint32(kmem[irVAD-irKernel+irStartOff:], uint32(irView>>12&0xffffffff))
	kmem[irVAD-irKernel+irStartOff+0xc] = byte(irView >> 44)
	binary.LittleEndian.PutUint64(kmem[irVAD-irKernel+irProtoOff:], irPTEs)
	for i := range uint64(3) {
		binary.LittleEndian.PutUint64(kmem[irPTEs-irKernel+i*8:], (irFrame+i*0x1000)|1)
	}
	kernel := flat{base: irKernel, b: kmem}
	r, err := subsection.NewResolver(kernel, table)
	if err != nil {
		t.Fatal(err)
	}
	phys := make([]byte, 0x8000)
	for i := range 3 {
		copy(phys[irFrame+uint64(i)*0x1000:], bytes.Repeat([]byte{0xa0 + byte(i)}, 0x1000))
	}
	return r, flat{b: phys}
}

func TestImageReaderFollowsPrototypesOnlyForSharedPages(t *testing.T) {
	res, phys := protoResolver(t)
	space := pageKinds{start: irView, fill: 0x11, kinds: map[uint64]layers.PageErrorKind{
		0: layers.PageInvalid, 1: layers.PagePrototype, 2: layers.PageInPagefile,
	}}
	r := imageReader{space: space, physical: phys, resolver: res, vad: irVAD, start: irView, end: irView + 0x3fff}

	for page, want := range map[uint64]byte{0: 0xa0, 1: 0xa1, 3: 0x11} {
		b, err := r.ReadAt(irView+page*0x1000+0x10, 4)
		if err != nil || !bytes.Equal(b, bytes.Repeat([]byte{want}, 4)) {
			t.Errorf("page %d: % x, %v", page, b, err)
		}
	}
	if _, err := r.ReadAt(irView+0x2000, 4); !errors.Is(err, layers.ErrPageInPagefile) {
		t.Errorf("a paging-file page was answered from the prototype: %v", err)
	}
	if b, err := r.ReadAt(irView+0xffe, 4); err != nil || !bytes.Equal(b, []byte{0xa0, 0xa0, 0xa1, 0xa1}) {
		t.Errorf("read across a page boundary: % x, %v", b, err)
	}
	if _, err := r.ReadAt(irView+0x3ffe, 4); err == nil {
		t.Error("a read past the view's end succeeded")
	}
	if _, err := r.ReadAt(irView-1, 1); err == nil {
		t.Error("a read before the view succeeded")
	}

	r.resolver = nil
	if _, err := r.ReadAt(irView, 4); err == nil {
		t.Error("without a resolver an invalid page still read")
	}
}
