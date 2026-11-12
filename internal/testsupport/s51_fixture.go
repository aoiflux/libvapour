package testsupport

import (
	"encoding/binary"
	"errors"

	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

// Member offsets of the S51 table: the 26100 layout of S51 T1 to T4.
const (
	S51MiscFlags     = uint64(0x74)
	S51ThreadFlags   = uint64(0x78)
	S51CrossFlags    = uint64(0x5a0)
	S51DebugActive   = uint64(0x3)
	S51SystemBit     = 10
	S51FreezeBit     = 14
	S51Dr0           = uint64(0xd8)
	S51Dr7           = uint64(0x100)
	S51SegCs         = uint64(0x170)
	S51Rip           = uint64(0x168)
	S51Rsp           = uint64(0x180)
	S51VadCount      = uint64(0x3e0)
	S51SecureState   = uint64(0x1a0)
	S51UserCodeSeg   = uint64(0x33)
	S51KernelCodeSeg = uint64(0x10)
)

var errS51Hole = errors.New("testsupport: page not in the s51 image")

// S51Memory is sparse: a read of a page never written fails, as a hole in a
// capture does.
type S51Memory map[uint64]*[4096]byte

func (m S51Memory) page(addr uint64) *[4096]byte {
	p, ok := m[addr&^0xfff]
	if !ok {
		p = new([4096]byte)
		m[addr&^0xfff] = p
	}
	return p
}

func (m S51Memory) Put(addr uint64, b []byte) {
	for i, v := range b {
		m.page(addr + uint64(i))[(addr+uint64(i))&0xfff] = v
	}
}

func (m S51Memory) Put64(addr, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	m.Put(addr, b[:])
}

func (m S51Memory) Put32(addr uint64, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	m.Put(addr, b[:])
}

func (m S51Memory) ReadAt(addr, size uint64) ([]byte, error) {
	out := make([]byte, size)
	for i := uint64(0); i < size; i++ {
		p, ok := m[(addr+i)&^0xfff]
		if !ok {
			return nil, errS51Hole
		}
		out[i] = p[(addr+i)&0xfff]
	}
	return out, nil
}

func (m S51Memory) Size() uint64 { return 1<<64 - 1 }

// S51Table holds the members the S51 tools read. omit drops "Type.Member"
// entries, to test a table that lacks them.
func S51Table(omit ...string) *symbols.Table {
	skip := map[string]bool{}
	for _, o := range omit {
		skip[o] = true
	}
	keep := func(typ string, fs ...symbols.Field) []symbols.Field {
		var out []symbols.Field
		for _, f := range fs {
			if !skip[typ+"."+f.Name] {
				out = append(out, f)
			}
		}
		return out
	}
	u32 := symbols.TypeRef{Name: "unsigned int"}
	u64 := symbols.TypeRef{Name: "unsigned long long"}
	bit := func(at uint8) symbols.TypeRef {
		return symbols.TypeRef{Name: "unsigned int", BitOffset: at, BitLength: 1}
	}
	t := symbols.NewTable("s51", 8)
	t.AddStruct(symbols.StructType{Name: "_ETHREAD", Size: 0x798, Fields: keep("_ETHREAD",
		symbols.Field{Name: "Tcb", Offset: 0},
		symbols.Field{Name: "CrossThreadFlags", Offset: S51CrossFlags, Type: u32},
		symbols.Field{Name: "Terminated", Offset: S51CrossFlags, Type: bit(0)},
	)})
	t.AddStruct(symbols.StructType{Name: "_KTHREAD", Size: 0x4c0, Fields: keep("_KTHREAD",
		symbols.Field{Name: "Header", Offset: 0},
		symbols.Field{Name: "SystemThread", Offset: S51MiscFlags, Type: bit(S51SystemBit)},
		symbols.Field{Name: "FreezeCount", Offset: S51ThreadFlags, Type: bit(S51FreezeBit)},
	)})
	t.AddStruct(symbols.StructType{Name: "_DISPATCHER_HEADER", Size: 0x18, Fields: keep("_DISPATCHER_HEADER",
		symbols.Field{Name: "DebugActive", Offset: S51DebugActive, Type: symbols.TypeRef{Name: "unsigned char"}},
	)})
	frame := []symbols.Field{
		{Name: "Rip", Offset: S51Rip, Type: u64},
		{Name: "SegCs", Offset: S51SegCs, Type: symbols.TypeRef{Name: "unsigned short"}},
		{Name: "Rsp", Offset: S51Rsp, Type: u64},
		{Name: "Dr7", Offset: S51Dr7, Type: u64},
	}
	for i := range 4 {
		frame = append(frame, symbols.Field{Name: "Dr" + string(rune('0'+i)), Offset: S51Dr0 + 8*uint64(i), Type: u64})
	}
	t.AddStruct(symbols.StructType{Name: "_KTRAP_FRAME", Size: 0x190, Fields: keep("_KTRAP_FRAME", frame...)})
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x840, Fields: keep("_EPROCESS",
		symbols.Field{Name: "Pcb", Offset: 0},
		symbols.Field{Name: "VadCount", Offset: S51VadCount, Type: u64},
	)})
	t.AddStruct(symbols.StructType{Name: "_KPROCESS", Size: 0x1c8, Fields: keep("_KPROCESS",
		symbols.Field{Name: "SecureState", Offset: S51SecureState, Type: u64},
	)})
	return t
}

func S51Context(mem S51Memory, table *symbols.Table, strict bool) (tools.Context, *[]string) {
	diags := &[]string{}
	opts := map[string]any{"diagnostics": diags}
	if strict {
		opts["strict"] = true
	}
	return tools.Context{Memory: mem, Symbols: table, Profile: profiles.WindowsX64Profile{}, Options: opts}, diags
}

func S51SetBit(mem S51Memory, addr uint64, bit uint) {
	b, err := mem.ReadAt(addr, 4)
	v := uint32(0)
	if err == nil {
		v = binary.LittleEndian.Uint32(b)
	}
	mem.Put32(addr, v|1<<bit)
}
