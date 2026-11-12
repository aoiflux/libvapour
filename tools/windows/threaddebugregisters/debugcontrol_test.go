package threaddebugregisters

import "testing"

func TestEachConditionAndLengthIsDecoded(t *testing.T) {
	// Breakpoint 0: local, execute, LEN 00. 1: global, write, LEN 01.
	// 2: local, I/O, LEN 10. 3: both, read or write, LEN 11.
	dr7 := uint64(1 | 1<<3 | 1<<4 | 3<<6)
	dr7 |= 0b00_00 << 16
	dr7 |= 0b01_01 << 20
	dr7 |= 0b10_10 << 24
	dr7 |= 0b11_11 << 28
	slots, saved := decodeDebugControl(dr7, 8)
	if !saved || len(slots) != 4 {
		t.Fatalf("slots %+v, saved %v", slots, saved)
	}
	want := []slot{
		{0, true, false, ConditionExecute, 1},
		{1, false, true, ConditionWrite, 2},
		{2, true, false, ConditionIO, 8},
		{3, true, true, ConditionReadWrite, 4},
	}
	for i, w := range want {
		if slots[i] != w {
			t.Errorf("slot %d = %+v, want %+v", i, slots[i], w)
		}
	}
}

func TestOnlyEnabledBreakpointsAreGiven(t *testing.T) {
	slots, saved := decodeDebugControl(1<<5|0b11<<24|1<<8|1<<9|1<<10, 8)
	if !saved || len(slots) != 1 || slots[0].index != 2 || !slots[0].global || slots[0].local {
		t.Errorf("slots %+v, saved %v", slots, saved)
	}
	if slots, saved := decodeDebugControl(0x400, 8); !saved || len(slots) != 0 {
		t.Errorf("no enable bit: %+v, %v", slots, saved)
	}
}

func TestAReservedBitMeansTheValueWasNeverSaved(t *testing.T) {
	for _, v := range []uint64{1 << 12, 1 << 14, 1 << 15, 1 << 32, 0x2b004a00540049, 0x6d121, 0x7e229} {
		if _, saved := decodeDebugControl(v|1, 8); saved {
			t.Errorf("Dr7 0x%x taken as saved", v|1)
		}
	}
	if _, saved := decodeDebugControl(1<<13|1<<11|1, 8); !saved {
		t.Error("GD and bit 11 rejected")
	}
	if _, saved := decodeDebugControl(1<<40|1, 4); !saved {
		t.Error("a 4-byte member's high bits are not its own")
	}
}
