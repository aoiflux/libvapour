package syscallstub

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

type sparse map[uint64][]byte

func (m sparse) write(at uint64, b []byte) {
	for i, v := range b {
		a := at + uint64(i)
		p := m[a&^0xFFF]
		if p == nil {
			p = make([]byte, 0x1000)
			m[a&^0xFFF] = p
		}
		p[a&0xFFF] = v
	}
}

func (m sparse) ReadAt(at, size uint64) ([]byte, error) {
	out := make([]byte, 0, size)
	for uint64(len(out)) < size {
		cur := at + uint64(len(out))
		p, ok := m[cur&^0xFFF]
		if !ok {
			if len(out) == 0 {
				return nil, fmt.Errorf("unmapped 0x%x", cur)
			}
			return out, nil
		}
		n := min(0x1000-cur&0xFFF, size-uint64(len(out)))
		out = append(out, p[cur&0xFFF:cur&0xFFF+n]...)
	}
	return out, nil
}

func (m sparse) Size() uint64 { return 0 }

const systemCallOffset = 0x308

// The x64 stub as the captures carry it (S29 M3), with the SystemCall test.
func stub(number uint32) []byte {
	b := []byte{0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0xF6, 0x04, 0x25, 0, 0, 0, 0, 0x01, 0x75, 0x03, 0x0F, 0x05, 0xC3,
		0xCD, 0x2E, 0xC3, 0x0F, 0x1F, 0x84, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(b[4:], number)
	binary.LittleEndian.PutUint32(b[11:], uint32(userSharedData+systemCallOffset))
	return b
}

func contextFor(spaces map[uint64]sparse, diags *[]string) tools.Context {
	t := symbols.NewTable("s29", 8)
	t.AddStruct(symbols.StructType{Name: "_KUSER_SHARED_DATA", Size: 0x800, Fields: []symbols.Field{
		{Name: "SystemCall", Offset: systemCallOffset}}})
	return tools.Context{
		Memory:  sparse{},
		Symbols: t,
		Profile: profiles.WindowsX64Profile{},
		Options: map[string]any{"diagnostics": diags},
		Limits:  limits.Limits{},
		ProcessMemory: func(dtb uint64) (memory.MemoryReader, error) {
			s, ok := spaces[dtb]
			if !ok {
				return nil, fmt.Errorf("no space for 0x%x", dtb)
			}
			return s, nil
		},
	}
}
