package disasm

import "golang.org/x/arch/x86/x86asm"

// A write is counted when the instruction leaves a new value in the whole
// register: a 64-bit write, or a 32-bit one, which zero-extends in 64-bit mode.
// An 8- or 16-bit write keeps the upper bits and is not counted.

func (i Inst) WritesAccumulator() bool { return i.writesRegister(x86asm.EAX, x86asm.RAX) }

func (i Inst) WritesR10() bool { return i.writesRegister(x86asm.R10L, x86asm.R10) }

func (i Inst) writesRegister(r32, r64 x86asm.Reg) bool {
	for _, r := range implicitDestinations(i.x) {
		if r == r32 || r == r64 {
			return true
		}
	}
	for _, n := range operandDestinations(i.x) {
		if r, ok := i.x.Args[n].(x86asm.Reg); ok && (r == r32 || r == r64) {
			return true
		}
	}
	return false
}

// First operands that the instruction only reads, from the operand-encoding
// tables: comparisons, pushes, branch targets, port and segment operands, the
// sources of one-operand multiply and divide, and FS/GS base writes.
var firstOperandRead = map[x86asm.Op]bool{
	x86asm.CMP: true, x86asm.TEST: true, x86asm.BT: true,
	x86asm.PUSH: true, x86asm.JMP: true, x86asm.LJMP: true, x86asm.CALL: true, x86asm.LCALL: true,
	x86asm.OUT: true, x86asm.VERR: true, x86asm.VERW: true,
	x86asm.LLDT: true, x86asm.LTR: true, x86asm.LMSW: true, x86asm.NOP: true,
	x86asm.MUL: true, x86asm.DIV: true, x86asm.IDIV: true,
	x86asm.BOUND: true, x86asm.INVPCID: true, x86asm.WRFSBASE: true, x86asm.WRGSBASE: true,
	x86asm.SCASB: true, x86asm.SCASW: true, x86asm.SCASD: true, x86asm.SCASQ: true,
	x86asm.CMPSB: true, x86asm.CMPSW: true, x86asm.CMPSD: true, x86asm.CMPSQ: true,
}

// Exchanges write both operands.
var bothOperandsWritten = map[x86asm.Op]bool{x86asm.XCHG: true, x86asm.XADD: true}

func operandDestinations(x x86asm.Inst) []int {
	switch {
	case firstOperandRead[x.Op]:
		return nil
	case x.Op == x86asm.IMUL && x.Args[1] == nil:
		return nil
	case bothOperandsWritten[x.Op]:
		return []int{0, 1}
	}
	return []int{0}
}

// Registers written without being named as operands, counted only when the
// write always happens: CMPXCHG loads the accumulator only on a mismatch and
// is left out. CWD, CDQ and CQO write only the DX half. No instruction writes
// R10 implicitly.
var implicitAccumulator32 = map[x86asm.Op]bool{
	x86asm.CPUID: true, x86asm.RDTSC: true, x86asm.RDTSCP: true, x86asm.RDMSR: true,
	x86asm.RDPMC: true, x86asm.XGETBV: true, x86asm.POPAD: true, x86asm.CWDE: true,
	x86asm.LODSD: true,
}

var implicitAccumulator64 = map[x86asm.Op]bool{x86asm.CDQE: true, x86asm.LODSQ: true}

// One-operand MUL, IMUL, DIV and IDIV put their result in the accumulator at
// the operand's width.
var accumulatorAtOperandWidth = map[x86asm.Op]bool{
	x86asm.MUL: true, x86asm.IMUL: true, x86asm.DIV: true, x86asm.IDIV: true,
}

func implicitDestinations(x x86asm.Inst) []x86asm.Reg {
	switch {
	case implicitAccumulator32[x.Op]:
		return []x86asm.Reg{x86asm.EAX}
	case implicitAccumulator64[x.Op]:
		return []x86asm.Reg{x86asm.RAX}
	case accumulatorAtOperandWidth[x.Op] && x.Args[1] == nil:
		switch operandBits(x) {
		case 32:
			return []x86asm.Reg{x86asm.EAX}
		case 64:
			return []x86asm.Reg{x86asm.RAX}
		}
	}
	return nil
}

// DataSize is the prefix-derived default and reads 32 for `mul cl`, so the
// operand's own width decides when there is one.
func operandBits(x x86asm.Inst) int {
	switch a := x.Args[0].(type) {
	case x86asm.Reg:
		switch {
		case a >= x86asm.AL && a <= x86asm.R15B:
			return 8
		case a >= x86asm.AX && a <= x86asm.R15W:
			return 16
		case a >= x86asm.EAX && a <= x86asm.R15L:
			return 32
		case a >= x86asm.RAX && a <= x86asm.R15:
			return 64
		}
		return 0
	case x86asm.Mem:
		if x.MemBytes > 0 {
			return 8 * x.MemBytes
		}
	}
	return x.DataSize
}
