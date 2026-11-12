package memorycode

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
)

// Protection indexes of S24 M2: base b plus 8 times the modifier.
const (
	indexReadWrite        = 4
	indexExecuteRead      = 3
	indexExecuteReadWrite = 6
)

const (
	testPID   = uint64(1000)
	regionVA  = uint64(0x10000000)
	noExecute = uint64(1) << 63
	vadTypeAt = 4
)

// The 32 values of MmProtectToValue measured in S24 M2.
func protectToValue() []uint32 {
	base := []uint32{0x01, 0x02, 0x10, 0x20, 0x04, 0x08, 0x40, 0x80}
	modifier := []uint32{0, 0x200, 0x100, 0x400}
	out := make([]uint32, 32)
	for i := range out {
		b, m := i%8, i/8
		out[i] = base[b] | modifier[m]
		if b == 0 {
			out[i] = 0x01
		}
	}
	return out
}

type codeFixture struct {
	t     *testing.T
	f     *testsupport.ProcessFixture
	diags []string
}

func newCodeFixture(t *testing.T, vads ...testsupport.FixtureVAD) *codeFixture {
	t.Helper()
	f := testsupport.BuildProcessFixture([]testsupport.FixtureProcess{{PID: testPID, Name: "code.exe", VADs: vads}})
	f.Table.AddStruct(symbols.StructType{Name: "_MMPTE_SOFTWARE", Size: 8, Fields: []symbols.Field{
		{Name: "Protection", Type: symbols.TypeRef{Name: "unsigned long long", BitOffset: 5, BitLength: 5}},
	}})
	f.Table.AddStruct(symbols.StructType{Name: "_MMPTE_TRANSITION", Size: 8, Fields: []symbols.Field{
		{Name: "Protection", Type: symbols.TypeRef{Name: "unsigned long long", BitOffset: 5, BitLength: 5}},
	}})
	c := &codeFixture{t: t, f: f}
	sym, err := f.Table.LookupSymbol("MmProtectToValue")
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32*4)
	for i, v := range protectToValue() {
		binary.LittleEndian.PutUint32(raw[4*i:], v)
	}
	c.writeKernel(sym.Address, raw)
	return c
}

func (c *codeFixture) writeKernel(va uint64, data []byte) {
	c.t.Helper()
	pa, err := layers.NewProcessLayer(c.f.Memory, c.f.Kernel.DTB, 0).Translate(va)
	if err != nil {
		c.t.Fatalf("kernel address 0x%x: %v", va, err)
	}
	c.f.Memory.WriteAt(pa, data)
}

func (c *codeFixture) space() *testsupport.AddressSpace { return c.f.Space(testPID) }

// A present page; a nonexecutable one carries XD.
func (c *codeFixture) page(va uint64, exec bool, data []byte) uint64 {
	flags := uint64(0)
	if !exec {
		flags = noExecute
	}
	pa := c.space().MapPageFlags(va, flags)
	c.f.Memory.WriteAt(pa, data)
	return pa
}

func (c *codeFixture) leafAddress(va uint64) uint64 {
	table := c.space().DTB &^ 0xfff
	for _, shift := range []uint{39, 30, 21} {
		raw, err := c.f.Memory.ReadAt(table+(va>>shift&0x1ff)*8, 8)
		if err != nil {
			c.t.Fatal(err)
		}
		e := binary.LittleEndian.Uint64(raw)
		if e&1 == 0 {
			c.t.Fatalf("no table maps 0x%x at shift %d", va, shift)
		}
		table = e & 0x000ffffffffff000
	}
	return table + (va>>12&0x1ff)*8
}

// The page's tables are built by mapping it first; the entry then replaces
// the present one.
func (c *codeFixture) entry(va, value uint64) {
	c.space().MapPage(va)
	c.f.Memory.WriteU64(c.leafAddress(va), value)
}

func softwareEntry(index uint64) uint64 { return index<<5 | 0x2<<12 }

func transitionEntry(frame, index uint64) uint64 { return frame&^0xfff | 1<<11 | index<<5 }

func (c *codeFixture) context() tools.Context {
	ctx := c.f.Context()
	c.diags = nil
	ctx.Options["diagnostics"] = &c.diags
	return ctx
}

func (c *codeFixture) run(ctx tools.Context) []Finding {
	c.t.Helper()
	rows, err := Run(ctx)
	if err != nil {
		c.t.Fatalf("Run: %v", err)
	}
	return rows
}

func (c *codeFixture) vadBase(start uint64) uint64 {
	c.t.Helper()
	rows, err := memoryranges.Run(c.f.Context())
	if err != nil {
		c.t.Fatal(err)
	}
	for _, m := range rows {
		if m.Start == start {
			return m.VadAddress
		}
	}
	c.t.Fatalf("no VAD at 0x%x", start)
	return 0
}

func (c *codeFixture) markImage(start uint64) {
	c.t.Helper()
	c.f.Table.AddStruct(symbols.StructType{Name: "_MMVAD_FLAGS", Size: 4, Fields: []symbols.Field{
		{Name: "Protection", Type: symbols.TypeRef{BitOffset: testsupport.FixtureVadProtectionBit, BitLength: testsupport.FixtureVadProtectionBits}},
		{Name: "PrivateMemory", Type: symbols.TypeRef{BitOffset: testsupport.FixtureVadPrivateMemoryBit, BitLength: 1}},
		{Name: "VadType", Type: symbols.TypeRef{BitOffset: vadTypeAt, BitLength: 3}},
	}})
	flagsAt := c.vadBase(start) + testsupport.FixtureVadFlagsOffset
	raw, err := c.f.Context().Memory.ReadAt(flagsAt, 4)
	if err != nil {
		c.t.Fatal(err)
	}
	v := binary.LittleEndian.Uint32(raw) | 2<<vadTypeAt
	binary.LittleEndian.PutUint32(raw, v)
	c.writeKernel(flagsAt, raw)
}
