package interruptcheck

import (
	"testing"
)

func FuzzDecodeGate(f *testing.F) {
	f.Add(encode(gateSpec{offset: 0xffffffff81000000, selector: 0x10, typ: 0xe, present: true, ist: 3}, 16), true)
	f.Add(encode(gateSpec{selector: 0x28, typ: 0x5, present: true}, 8), false)
	f.Add([]byte{}, true)
	f.Fuzz(func(t *testing.T, b []byte, long bool) {
		size := uint64(8)
		if long {
			size = 16
		}
		g, err := DecodeGate(b, size)
		if uint64(len(b)) < size {
			if err == nil {
				t.Fatalf("%d bytes decoded as a %d-byte gate", len(b), size)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		attr := uint16(b[4]) | uint16(b[5])<<8
		if g.DPL != uint8(attr>>13&3) || g.Present != (attr&0x8000 != 0) || g.Selector != uint16(b[2])|uint16(b[3])<<8 {
			t.Fatalf("%x: %+v", b[:size], g)
		}
		switch g.Type {
		case GateInterrupt, GateTrap, GateInvalid:
		case GateTask, GateInterrupt16, GateTrap16:
			if long {
				t.Fatalf("%x: %s in IA-32e mode", b[:size], g.Type)
			}
		default:
			t.Fatalf("%x: unknown type %q", b[:size], g.Type)
		}
		if !long && (g.IST != 0 || g.Offset > 0xffffffff) {
			t.Fatalf("%x: legacy gate %+v", b[:size], g)
		}
		if g.Type == GateTask && g.Offset != 0 {
			t.Fatalf("%x: task gate with offset %#x", b[:size], g.Offset)
		}
	})
}

func FuzzCheck(f *testing.F) {
	f.Add(encode(gateSpec{offset: handlers, selector: 0x10, typ: 0xe, present: true}, 16), uint16(0xfff))
	f.Add([]byte{0xff, 0xff, 0xff}, uint16(0))
	f.Fuzz(func(t *testing.T, table []byte, limit uint16) {
		fx := newIDT()
		ctx, _ := fx.context(t, nil)
		for len(table) > 0 && len(table) < vectors*16 {
			table = append(table, table...)
		}
		fx.Mem.Write(aliasAt, table[:min(len(table), vectors*16)])
		fx.Mem.U16(descrAt, limit)
		rows, err := Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != vectors {
			t.Fatalf("%d rows", len(rows))
		}
		for _, r := range rows {
			switch r.Placement {
			case InKernel, InKernelInit, InModule, Unowned, NoHandler:
			default:
				t.Fatalf("row %+v", r)
			}
			if r.Source != FromLoaded || r.Address > mask {
				t.Fatalf("row %+v", r)
			}
		}
	})
}
