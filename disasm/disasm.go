package disasm

import (
	"golang.org/x/arch/x86/x86asm"
)

type Mode int

const (
	Mode32 Mode = 32
	Mode64 Mode = 64
)

func (m Mode) String() string {
	if m == Mode32 {
		return "intel"
	}
	return "intel64"
}

type Inst struct {
	Address uint64
	Len     int
	Text    string

	x x86asm.Inst
}

const maxInstructionBytes = 15

// Decode refuses what the processor would refuse to execute and what the
// library returns without an opcode (a run of prefixes), so a linear walk over
// data stops instead of stepping through it a byte at a time.
func Decode(code []byte, address uint64, mode Mode) (Inst, bool) {
	if len(code) == 0 {
		return Inst{}, false
	}
	x, ok := decodeLibrary(code, mode)
	if !ok || x.Op == 0 || x.Len < 1 || x.Len > maxInstructionBytes || !lockPermitted(x) ||
		namesTestRegister(x) || !evexMapKnown(code, mode) {
		return Inst{}, false
	}
	return Inst{Address: address, Len: x.Len, Text: x86asm.IntelSyntax(x, 0, nil), x: x}, true
}

// x/arch v0.29.0 panics on some short buffers that start with 0x62, the EVEX
// escape. A panic there is a failed decode, not a crash of the caller's walk.
func decodeLibrary(code []byte, mode Mode) (x x86asm.Inst, ok bool) {
	defer func() {
		if recover() != nil {
			x, ok = x86asm.Inst{}, false
		}
	}()
	x, err := x86asm.Decode(code, int(mode))
	return x, err == nil
}

// The instructions that accept LOCK, and only with a memory destination; any
// other use raises #UD.
var lockable = map[x86asm.Op]bool{
	x86asm.ADD: true, x86asm.ADC: true, x86asm.AND: true,
	x86asm.BTC: true, x86asm.BTR: true, x86asm.BTS: true,
	x86asm.CMPXCHG: true, x86asm.CMPXCHG8B: true, x86asm.CMPXCHG16B: true,
	x86asm.DEC: true, x86asm.INC: true, x86asm.NEG: true, x86asm.NOT: true,
	x86asm.OR: true, x86asm.SBB: true, x86asm.SUB: true, x86asm.XOR: true,
	x86asm.XADD: true, x86asm.XCHG: true,
}

func lockPermitted(x x86asm.Inst) bool {
	if !hasExplicitLock(x) {
		return true
	}
	_, memoryDestination := x.Args[0].(x86asm.Mem)
	return lockable[x.Op] && memoryDestination
}

func hasExplicitLock(x x86asm.Inst) bool {
	for _, p := range x.Prefix {
		if p == 0 {
			return false
		}
		if p&x86asm.PrefixImplicit == 0 && p&0xFF == x86asm.PrefixLOCK {
			return true
		}
	}
	return false
}

// The two-byte map leaves 0F 24 and 0F 26 undefined; the library still reads
// them as moves to and from test registers, which no Intel 64 processor has.
func namesTestRegister(x x86asm.Inst) bool {
	for _, a := range x.Args {
		if r, ok := a.(x86asm.Reg); ok && r >= x86asm.TR0 && r <= x86asm.TR7 {
			return true
		}
	}
	return false
}

func isLegacyPrefix(b byte) bool {
	switch b {
	case 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3:
		return true
	}
	return false
}

// EVEX.mmm selects the opcode map; maps 5 and 6 exist besides 0F, 0F38 and
// 0F3A, but the library reads only the low two bits and so decodes a map 5 or 6
// instruction as some other one. Outside 64-bit mode 62 is EVEX only when the
// next byte's top two bits are set; otherwise it is BOUND.
func evexMapKnown(code []byte, mode Mode) bool {
	p := 0
	for p < len(code) && isLegacyPrefix(code[p]) {
		p++
	}
	if p+1 >= len(code) || code[p] != 0x62 {
		return true
	}
	p0 := code[p+1]
	if mode == Mode32 && p0>>6 != 3 {
		return true
	}
	switch p0 & 7 {
	case 1, 2, 3:
		return true
	}
	return false
}

func (i Inst) Op() x86asm.Op { return i.x.Op }

func (i Inst) opcodeByte() byte { return byte(i.x.Opcode >> 24) }

// Near and far forms both transfer control; the far ones are LJMP and LCALL.
func (i Inst) IsJmp() bool { return i.x.Op == x86asm.JMP || i.x.Op == x86asm.LJMP }

func (i Inst) IsCall() bool { return i.x.Op == x86asm.CALL || i.x.Op == x86asm.LCALL }

// A near return with or without an immediate and with any prefix; a far
// return (LRET) leaves the code segment and is not counted.
func (i Inst) IsRet() bool { return i.x.Op == x86asm.RET }

func (i Inst) IsLeave() bool { return i.x.Op == x86asm.LEAVE }

func (i Inst) IsSyscall() bool { return i.x.Op == x86asm.SYSCALL }

func (i Inst) IsLea() bool { return i.x.Op == x86asm.LEA }

const breakpointVector = 3

// CD 03 raises vector 3 as CC does; assemblers never emit it, so it marks
// hand-made code.
func (i Inst) IsInt3() bool {
	if i.x.Op != x86asm.INT {
		return false
	}
	if i.opcodeByte() == 0xCC {
		return true
	}
	v, ok := i.x.Args[0].(x86asm.Imm)
	return ok && v == breakpointVector
}

// The forms that carry a 64-bit immediate (REX.W B8+r) or a 64-bit absolute
// offset (A0..A3) are left out: neither loads through a RIP-relative operand.
func (i Inst) IsMov() bool {
	if i.x.Op != x86asm.MOV {
		return false
	}
	switch op := i.opcodeByte(); {
	case op >= 0xB8 && op <= 0xBF:
		return i.x.DataSize != 64
	case op >= 0xA0 && op <= 0xA3:
		return i.x.AddrSize != 64
	}
	return true
}

// The address named by a RIP-relative second operand: the end of this
// instruction plus the signed 32-bit displacement.
func (i Inst) RIPRelativeTarget() (uint64, bool) {
	m, ok := i.x.Args[1].(x86asm.Mem)
	if !ok || m.Base != x86asm.RIP {
		return 0, false
	}
	disp := int64(int32(uint32(m.Disp)))
	return i.Address + uint64(i.Len) + uint64(disp), true
}

// The library may keep the ModRM byte in the low bits of Opcode; the opcode
// byte itself is the top one.
func (i Inst) HasZeroOpcode() bool { return i.opcodeByte() == 0 }
