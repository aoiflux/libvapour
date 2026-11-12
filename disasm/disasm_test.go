package disasm

import (
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

const at = uint64(0x7FFB00001000)

func decodeHex(t *testing.T, s string, mode Mode) (Inst, bool) {
	t.Helper()
	code, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return Decode(code, at, mode)
}

func must(t *testing.T, s string, mode Mode) Inst {
	t.Helper()
	inst, ok := decodeHex(t, s, mode)
	if !ok {
		t.Fatalf("%s does not decode in %d-bit mode", s, mode)
	}
	return inst
}

func TestDecodeKeepsAddressLengthAndText(t *testing.T) {
	inst := must(t, "4c8bd1c3", Mode64)
	if inst.Address != at || inst.Len != 3 || inst.Text != "mov r10, rcx" || inst.Op() != x86asm.MOV {
		t.Errorf("%+v", inst)
	}
	if Mode32.String() != "intel" || Mode64.String() != "intel64" {
		t.Errorf("mode names %q %q", Mode32, Mode64)
	}
}

func TestWhatTheProcessorWouldRefuseDoesNotDecode(t *testing.T) {
	for _, c := range []struct {
		hex  string
		mode Mode
		why  string
	}{
		{"", Mode64, "empty"},
		{"66", Mode64, "prefix only"},
		{"f3f3f3", Mode64, "prefixes only"},
		{"0f", Mode64, "escape only"},
		{"f031c0", Mode64, "LOCK on a register destination"},
		{"f0443333", Mode64, "LOCK on a register destination with a memory source"},
		{"f090", Mode64, "LOCK on NOP"},
		{"f00f05", Mode64, "LOCK on SYSCALL"},
		{"0f05", Mode32, "SYSCALL outside 64-bit mode"},
		{"0f07", Mode32, "SYSRET outside 64-bit mode"},
		{"0f26e5", Mode32, "0F 26 is blank in the two-byte map"},
		{"0f24e5", Mode32, "0F 24 is blank in the two-byte map"},
		{"d6", Mode64, "D6 is UDB in 64-bit mode"},
		{strings.Repeat("66", 15) + "90", Mode64, "16 bytes"},
		{"62e6b12ea7a2dba4", Mode64, "EVEX map 6"},
		{"62e5b12ea7a2dba4", Mode64, "EVEX map 5"},
	} {
		if inst, ok := decodeHex(t, c.hex, c.mode); ok {
			t.Errorf("%s: %s decodes to %q", c.why, c.hex, inst.Text)
		}
	}
}

func TestLockOnAMemoryDestinationDecodes(t *testing.T) {
	for _, s := range []string{"f00fb111", "f0ff00", "f0480fc10b", "f087 03"} {
		if _, ok := decodeHex(t, strings.ReplaceAll(s, " ", ""), Mode64); !ok {
			t.Errorf("%s does not decode", s)
		}
	}
}

func TestFifteenBytesIsTheLongestInstruction(t *testing.T) {
	if inst := must(t, strings.Repeat("66", 14)+"90", Mode32); inst.Len != 15 {
		t.Errorf("14 prefixes and NOP: %d bytes", inst.Len)
	}
	if inst := must(t, strings.Repeat("2e", 13)+"0f05", Mode64); inst.Len != 15 || !inst.IsSyscall() {
		t.Errorf("13 prefixes and SYSCALL: %d bytes %q", inst.Len, inst.Text)
	}
}

func TestControlTransfers(t *testing.T) {
	for _, c := range []struct {
		hex  string
		mode Mode
		kind string
	}{
		{"e9 00000000", Mode64, "jmp"}, {"eb fe", Mode64, "jmp"}, {"ff e0", Mode64, "jmp"},
		{"ff 2d 00000000", Mode64, "jmp"}, {"ea 00000000 0800", Mode32, "jmp"},
		{"e8 00000000", Mode64, "call"}, {"ff d0", Mode64, "call"}, {"9a 00000000 0800", Mode32, "call"},
		{"c3", Mode64, "ret"}, {"c2 0800", Mode64, "ret"}, {"f3 c3", Mode64, "ret"}, {"f2 c3", Mode64, "ret"},
		{"cb", Mode64, ""}, {"c9", Mode64, "leave"},
		{"cc", Mode64, "int3"}, {"cd 03", Mode64, "int3"}, {"cd 2e", Mode64, ""},
		{"0f 05", Mode64, "syscall"}, {"0f 34", Mode64, ""},
	} {
		inst := must(t, strings.ReplaceAll(c.hex, " ", ""), c.mode)
		got := map[string]bool{
			"jmp": inst.IsJmp(), "call": inst.IsCall(), "ret": inst.IsRet(), "leave": inst.IsLeave(),
			"int3": inst.IsInt3(), "syscall": inst.IsSyscall(),
		}
		for kind, v := range got {
			if v != (kind == c.kind) {
				t.Errorf("%s (%q): Is %s = %v", c.hex, inst.Text, kind, v)
			}
		}
	}
}

func TestMovExcludesTheSixtyFourBitImmediateAndOffsetForms(t *testing.T) {
	for _, c := range []struct {
		hex  string
		mode Mode
		mov  bool
	}{
		{"48b80000000000000000", Mode64, false},
		{"b801000000", Mode64, true},
		{"48c7c001000000", Mode64, true},
		{"48a10000000000000000", Mode64, false},
		{"67a100000000", Mode64, true},
		{"a100000000", Mode32, true},
		{"488b0500000000", Mode64, true},
		{"0fb6c0", Mode64, false},
		{"488d0500000000", Mode64, false},
	} {
		if inst := must(t, c.hex, c.mode); inst.IsMov() != c.mov {
			t.Errorf("%s (%q): IsMov %v", c.hex, inst.Text, inst.IsMov())
		}
	}
	if !must(t, "488d0500000000", Mode64).IsLea() {
		t.Error("lea rax, [rip] is not LEA")
	}
}

func TestRIPRelativeTargetSignExtendsTheDisplacement(t *testing.T) {
	for _, c := range []struct {
		hex    string
		target uint64
		ok     bool
	}{
		{"488b0510000000", at + 7 + 0x10, true},
		{"488b05f0ffffff", at + 7 - 0x10, true},
		{"488d0d00000080", at + 7 - 0x80000000, true},
		{"8b0425 10000000", 0, false},
		{"ff2510000000", 0, false},
		{"488b00", 0, false},
	} {
		inst := must(t, strings.ReplaceAll(c.hex, " ", ""), Mode64)
		if got, ok := inst.RIPRelativeTarget(); ok != c.ok || got != c.target {
			t.Errorf("%s (%q): %#x %v, want %#x %v", c.hex, inst.Text, got, ok, c.target, c.ok)
		}
	}
}

func TestZeroOpcode(t *testing.T) {
	if !must(t, "0000", Mode64).HasZeroOpcode() || must(t, "0100", Mode64).HasZeroOpcode() {
		t.Error("zero opcode test")
	}
}

func TestRegisterWrites(t *testing.T) {
	for _, c := range []struct {
		hex      string
		mode     Mode
		acc, r10 bool
	}{
		{"b818000000", Mode64, true, false},
		{"48c7c018000000", Mode64, true, false},
		{"66b81800", Mode64, false, false},
		{"b018", Mode64, false, false},
		{"4c8bd1", Mode64, false, true},
		{"448bd1", Mode64, false, true},
		{"6644 8bd1", Mode64, false, false},
		{"4d33d2", Mode64, false, true},
		{"4c3bd0", Mode64, false, false},
		{"85c0", Mode64, false, false},
		{"a9 01000000", Mode64, false, false},
		{"50", Mode64, false, false},
		{"f7e1", Mode64, true, false},
		{"48f7e1", Mode64, true, false},
		{"f6e1", Mode64, false, false},
		{"0fafc1", Mode64, true, false},
		{"0fafd0", Mode64, false, false},
		{"6bc005", Mode64, true, false},
		{"99", Mode64, false, false},
		{"4899", Mode64, false, false},
		{"98", Mode64, true, false},
		{"4898", Mode64, true, false},
		{"0fa2", Mode64, true, false},
		{"0f31", Mode64, true, false},
		{"0f01d0", Mode64, true, false},
		{"ad", Mode64, true, false},
		{"48ad", Mode64, true, false},
		{"0fb111", Mode64, false, false},
		{"91", Mode64, true, false},
		{"4c87d0", Mode64, true, true},
		{"61", Mode32, true, false},
		{"6205 00000000", Mode32, false, false},
		{"ed", Mode64, true, false},
	} {
		inst := must(t, strings.ReplaceAll(c.hex, " ", ""), c.mode)
		if inst.WritesAccumulator() != c.acc || inst.WritesR10() != c.r10 {
			t.Errorf("%s (%q): accumulator %v r10 %v, want %v %v", c.hex, inst.Text,
				inst.WritesAccumulator(), inst.WritesR10(), c.acc, c.r10)
		}
	}
}

// The library's own behaviour that Decode is built around.
func TestLibraryBehaviourDecodeDependsOn(t *testing.T) {
	x, err := x86asm.Decode([]byte{0x66, 0x66}, 64)
	if err == nil && x.Op != 0 {
		t.Errorf("a prefix run decodes to %v", x.Op)
	}
	if _, ok := decodeLibrary([]byte("b000"), Mode64); ok {
		t.Error("the four-byte EVEX buffer decodes")
	}
	x, err = x86asm.Decode([]byte{0x48, 0x8B, 0x05, 0xF0, 0xFF, 0xFF, 0xFF}, 64)
	if err != nil {
		t.Fatal(err)
	}
	if m := x.Args[1].(x86asm.Mem); uint32(m.Disp) != 0xFFFFFFF0 {
		t.Errorf("displacement %#x", m.Disp)
	}
	if _, err := x86asm.Decode([]byte{0x0F, 0x05}, 32); err == nil {
		t.Error("the library now decodes SYSCALL in 32-bit mode")
	}
}
