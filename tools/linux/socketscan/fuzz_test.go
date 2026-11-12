package socketscan

import (
	"encoding/binary"
	"testing"
)

// The scan must end and only name aligned sock starts, whatever words sit
// around a destructor value.
func FuzzSweep(f *testing.F) {
	f.Add([]byte{}, uint16(0x10))
	f.Add(make([]byte, 0x300), uint16(0x2b0))
	f.Fuzz(func(t *testing.T, around []byte, offset uint16) {
		if len(around) > 0x2000 {
			return
		}
		fx := newFixture()
		at := fx.k.Alloc(uint64(len(around)) + 0x400)
		fx.k.Mem.Write(at, around)
		slot := (at + uint64(offset)%uint64(len(around)+0x3f8)) &^ 7
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], destructorAt["sock_def_destruct"])
		fx.k.Mem.Write(slot, b[:])
		ctx, _ := fx.k.Context(fx.context(nil))
		ctx.Memory = kernelSpace{fx.k.Mem}
		rows, err := Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.SockPhysical%8 != 0 || r.SockPhysical >= physSize {
				t.Fatalf("row at %#x", r.SockPhysical)
			}
		}
	})
}
