package threaddebugregisters

import "testing"

// Any Dr7 and width: a breakpoint is given only for a set enable bit, in
// index order, and never for a value with a reserved bit set.
func FuzzDecodeDebugControl(f *testing.F) {
	f.Add(uint64(0), uint8(8))
	f.Add(uint64(0xffffffff), uint8(8))
	f.Add(uint64(0x2b004a00540049), uint8(8))
	f.Add(uint64(0x55), uint8(4))
	f.Fuzz(func(t *testing.T, dr7 uint64, width uint8) {
		slots, saved := decodeDebugControl(dr7, uint64(width))
		reserved := reservedLow
		if width >= 8 {
			reserved |= reservedHigh
		}
		if saved != (dr7&reserved == 0) {
			t.Fatalf("Dr7 0x%x width %d: saved %v", dr7, width, saved)
		}
		last := -1
		for _, s := range slots {
			if s.index <= last || s.index >= breakpointSlots {
				t.Fatalf("Dr7 0x%x: slot order %+v", dr7, slots)
			}
			last = s.index
			if s.local != (dr7>>(2*s.index)&1 != 0) || s.global != (dr7>>(2*s.index+1)&1 != 0) || !(s.local || s.global) {
				t.Fatalf("Dr7 0x%x: slot %+v", dr7, s)
			}
			if s.length != 1 && s.length != 2 && s.length != 4 && s.length != 8 {
				t.Fatalf("Dr7 0x%x: length %d", dr7, s.length)
			}
		}
		if saved && len(slots) == 0 && dr7&0xff != 0 {
			t.Fatalf("Dr7 0x%x: enable bits set, no slot", dr7)
		}
	})
}
