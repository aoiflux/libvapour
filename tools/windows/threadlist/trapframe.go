package threadlist

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/threadscan"
)

var (
	ErrNoTrapFrame         = errors.New("threadlist: trap frame address is 0")
	ErrTrapFrameLayout     = errors.New("threadlist: symbol table lacks a trap frame member")
	ErrTrapFrameUnread     = errors.New("threadlist: trap frame does not read")
	ErrKernelModeTrapFrame = errors.New("threadlist: trap frame holds kernel-mode state")
)

// R12 to R15 are callee-saved and have no _KTRAP_FRAME member (S50 T5).
type Registers struct {
	Rax, Rcx, Rdx, Rbx uint64
	Rsp, Rbp, Rsi, Rdi uint64
	R8, R9, R10, R11   uint64
	Rip                uint64
	EFlags             uint32
	MxCsr              uint32
	SegCs, SegSs       uint16
	SegDs, SegEs       uint16
	SegFs, SegGs       uint16
}

type register struct {
	name     string
	width    uint64
	required bool
	set      func(*Registers, uint64)
}

var registers = []register{
	{"Rip", 8, true, func(r *Registers, v uint64) { r.Rip = v }},
	{"Rsp", 8, true, func(r *Registers, v uint64) { r.Rsp = v }},
	{"SegCs", 2, true, func(r *Registers, v uint64) { r.SegCs = uint16(v) }},
	{"Rax", 8, false, func(r *Registers, v uint64) { r.Rax = v }},
	{"Rcx", 8, false, func(r *Registers, v uint64) { r.Rcx = v }},
	{"Rdx", 8, false, func(r *Registers, v uint64) { r.Rdx = v }},
	{"Rbx", 8, false, func(r *Registers, v uint64) { r.Rbx = v }},
	{"Rbp", 8, false, func(r *Registers, v uint64) { r.Rbp = v }},
	{"Rsi", 8, false, func(r *Registers, v uint64) { r.Rsi = v }},
	{"Rdi", 8, false, func(r *Registers, v uint64) { r.Rdi = v }},
	{"R8", 8, false, func(r *Registers, v uint64) { r.R8 = v }},
	{"R9", 8, false, func(r *Registers, v uint64) { r.R9 = v }},
	{"R10", 8, false, func(r *Registers, v uint64) { r.R10 = v }},
	{"R11", 8, false, func(r *Registers, v uint64) { r.R11 = v }},
	{"EFlags", 4, false, func(r *Registers, v uint64) { r.EFlags = uint32(v) }},
	{"MxCsr", 4, false, func(r *Registers, v uint64) { r.MxCsr = uint32(v) }},
	{"SegSs", 2, false, func(r *Registers, v uint64) { r.SegSs = uint16(v) }},
	{"SegDs", 2, false, func(r *Registers, v uint64) { r.SegDs = uint16(v) }},
	{"SegEs", 2, false, func(r *Registers, v uint64) { r.SegEs = uint16(v) }},
	{"SegFs", 2, false, func(r *Registers, v uint64) { r.SegFs = uint16(v) }},
	{"SegGs", 2, false, func(r *Registers, v uint64) { r.SegGs = uint16(v) }},
}

type frameMember struct {
	field symbols.IntField
	set   func(*Registers, uint64)
}

type frameLayout struct {
	members []frameMember
	span    uint64
}

func resolveFrameLayout(t symbols.SymbolTable) (frameLayout, error) {
	var l frameLayout
	for _, reg := range registers {
		m := threadscan.ResolveMember(t, "_KTRAP_FRAME", reg.name, reg.width)
		if !m.Present {
			if reg.required {
				return frameLayout{}, fmt.Errorf("_KTRAP_FRAME.%s: %w", reg.name, ErrTrapFrameLayout)
			}
			continue
		}
		l.members = append(l.members, frameMember{field: m.Field, set: reg.set})
		l.span = max(l.span, m.Field.Offset+m.Field.Width)
	}
	return l, nil
}

func (l frameLayout) decode(raw []byte) (Registers, error) {
	var regs Registers
	for _, m := range l.members {
		v, err := m.field.Decode(raw)
		if err != nil {
			return Registers{}, fmt.Errorf("%w: %w", ErrTrapFrameUnread, err)
		}
		m.set(&regs, v)
	}
	// The privilege level is the low two bits of CS (S50 D6); a frame saved on
	// entry from kernel mode holds kernel addresses, which a debugger would
	// follow as a user stack (S50 M9).
	if regs.SegCs&3 != 3 || regs.Rip>>63 != 0 || regs.Rsp>>63 != 0 {
		return Registers{}, fmt.Errorf("SegCs 0x%x, Rip 0x%x, Rsp 0x%x: %w", regs.SegCs, regs.Rip, regs.Rsp,
			ErrKernelModeTrapFrame)
	}
	return regs, nil
}

func ReadTrapFrame(ctx tools.Context, address uint64) (Registers, error) {
	if address == 0 {
		return Registers{}, ErrNoTrapFrame
	}
	if ctx.Symbols == nil || ctx.Memory == nil {
		return Registers{}, fmt.Errorf("%s: trap frame at 0x%x: %w", Name, address, ErrTrapFrameLayout)
	}
	l, err := resolveFrameLayout(ctx.Symbols)
	if err != nil {
		return Registers{}, fmt.Errorf("%s: trap frame at 0x%x: %w", Name, address, err)
	}
	if address+l.span < address {
		return Registers{}, fmt.Errorf("%s: trap frame at 0x%x: passes the end of the address space: %w",
			Name, address, ErrTrapFrameUnread)
	}
	raw, err := ctx.Memory.ReadAt(address, l.span)
	if err != nil {
		return Registers{}, fmt.Errorf("%s: trap frame at 0x%x: %w: %w", Name, address, ErrTrapFrameUnread, err)
	}
	regs, err := l.decode(raw)
	if err != nil {
		return Registers{}, fmt.Errorf("%s: trap frame at 0x%x: %w", Name, address, err)
	}
	return regs, nil
}
