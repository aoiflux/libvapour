package disasm

import (
	"testing"
	"unicode/utf8"
)

func FuzzDecode(f *testing.F) {
	f.Add([]byte{0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3}, true)
	f.Add([]byte{0xF0, 0x44, 0x33, 0x33}, true)
	f.Add([]byte{0x62, 0xE6, 0xB1, 0x2E, 0xA7}, true)
	f.Add([]byte{0x0F, 0x26, 0xE5}, false)
	f.Fuzz(func(t *testing.T, code []byte, long bool) {
		mode := Mode32
		if long {
			mode = Mode64
		}
		inst, ok := Decode(code, 0x1000, mode)
		if !ok {
			return
		}
		if inst.Len < 1 || inst.Len > maxInstructionBytes || inst.Len > len(code) {
			t.Fatalf("% x: %d bytes", code, inst.Len)
		}
		if inst.Text == "" || !utf8.ValidString(inst.Text) {
			t.Fatalf("% x: text %q", code, inst.Text)
		}
		alone, ok := Decode(code[:inst.Len], 0x1000, mode)
		if !ok || alone.Len != inst.Len || alone.Text != inst.Text {
			t.Fatalf("% x: %q, its own bytes give %q %v", code, inst.Text, alone.Text, ok)
		}
		if inst.IsSyscall() && mode == Mode32 {
			t.Fatalf("% x: SYSCALL in 32-bit mode", code)
		}
		if target, rel := inst.RIPRelativeTarget(); rel && mode == Mode32 {
			t.Fatalf("% x: RIP-relative %#x in 32-bit mode", code, target)
		}
		_ = inst.WritesAccumulator() || inst.WritesR10() || inst.IsMov() || inst.IsInt3() || inst.HasZeroOpcode()
	})
}
