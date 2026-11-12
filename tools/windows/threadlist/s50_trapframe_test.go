package threadlist

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/symbols"
)

func TestAUserModeTrapFrameGivesItsRegisters(t *testing.T) {
	w := build(t, standardThreads())
	regs, err := ReadTrapFrame(w.ctx(), w.place(0x210).TrapFrame)
	if err != nil {
		t.Fatal(err)
	}
	if regs.Rip != vadStart+0x30 || regs.Rsp != 0x000000a000100000 || regs.SegCs != 0x33 || regs.SegSs != 0x2b ||
		regs.EFlags != 0x246 || regs.Rax != 7 {
		t.Errorf("registers %+v", regs)
	}
	if regs.Rbx != 0 || regs.SegDs != 0 {
		t.Errorf("a register the table does not describe is 0: %+v", regs)
	}
}

func TestAKernelModeTrapFrameIsRefused(t *testing.T) {
	w := build(t, standardThreads())
	if _, err := ReadTrapFrame(w.ctx(), w.place(0x214).TrapFrame); !errors.Is(err, ErrKernelModeTrapFrame) {
		t.Fatalf("err %v, want ErrKernelModeTrapFrame", err)
	}
}

func TestEachUserModeConditionIsNeeded(t *testing.T) {
	for _, c := range []struct {
		name     string
		rip, rsp uint64
		cs       uint16
	}{
		{"privilege level 0", 0x7ff700001000, 0xa000100000, 0x10},
		{"privilege level 2", 0x7ff700001000, 0xa000100000, 0x32},
		{"Rip in system space", 0xfffff80000001000, 0xa000100000, 0x33},
		{"Rsp in system space", 0x7ff700001000, 0xfffff80000001000, 0x33},
	} {
		w := build(t, []testsupport.S50Thread{{TID: 8, Owner: userPID, Created: started,
			TrapFrame: &testsupport.S50TrapFrame{Rip: c.rip, Rsp: c.rsp, SegCs: c.cs}}})
		if _, err := ReadTrapFrame(w.ctx(), w.place(8).TrapFrame); !errors.Is(err, ErrKernelModeTrapFrame) {
			t.Errorf("%s: err %v, want ErrKernelModeTrapFrame", c.name, err)
		}
	}
}

func TestATrapFrameAddressOfZeroIsNoFrame(t *testing.T) {
	w := build(t, standardThreads())
	if _, err := ReadTrapFrame(w.ctx(), 0); !errors.Is(err, ErrNoTrapFrame) {
		t.Fatalf("err %v, want ErrNoTrapFrame", err)
	}
}

func TestATrapFrameThatDoesNotReadIsSaidSo(t *testing.T) {
	w := build(t, []testsupport.S50Thread{{TID: 8, Owner: userPID, Created: started,
		TrapFrame: &testsupport.S50TrapFrame{Unmapped: true}}})
	if _, err := ReadTrapFrame(w.ctx(), w.place(8).TrapFrame); !errors.Is(err, ErrTrapFrameUnread) {
		t.Fatalf("err %v, want ErrTrapFrameUnread", err)
	}
}

func TestATableWithoutRipCannotReadATrapFrame(t *testing.T) {
	w := build(t, standardThreads())
	frame, _ := w.fx.Table.Struct("_KTRAP_FRAME")
	var kept []symbols.Field
	for _, f := range frame.Fields {
		if f.Name != "Rip" {
			kept = append(kept, f)
		}
	}
	frame.Fields = kept
	w.fx.Table.AddStruct(frame)
	if _, err := ReadTrapFrame(w.ctx(), w.place(0x210).TrapFrame); !errors.Is(err, ErrTrapFrameLayout) {
		t.Fatalf("err %v, want ErrTrapFrameLayout", err)
	}
}

func FuzzTrapFrame(f *testing.F) {
	w := build(f, standardThreads())
	layout, err := resolveFrameLayout(w.fx.Table)
	if err != nil {
		f.Fatal(err)
	}
	seed := make([]byte, testsupport.S50FrameSize)
	binary.LittleEndian.PutUint64(seed[testsupport.S50FrameRip:], 0x7ff700001000)
	binary.LittleEndian.PutUint64(seed[testsupport.S50FrameRsp:], 0xa000100000)
	binary.LittleEndian.PutUint16(seed[testsupport.S50FrameSegCs:], 0x33)
	f.Add(seed)
	f.Add(seed[:0x100])
	f.Fuzz(func(t *testing.T, raw []byte) {
		regs, err := layout.decode(raw)
		if err != nil {
			return
		}
		if regs.SegCs&3 != 3 || regs.Rip>>63 != 0 || regs.Rsp>>63 != 0 {
			t.Fatalf("accepted a frame that is not user-mode state: %+v", regs)
		}
	})
}
