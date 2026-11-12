package memorycode

import (
	"encoding/binary"
	"errors"

	"github.com/aoiflux/libvapour/disasm"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
)

type Header string

const (
	HeaderNone     Header = "none"
	HeaderUnread   Header = "unread"
	HeaderDOS      Header = "dos"
	HeaderNT       Header = "nt"
	HeaderPE32     Header = "pe32"
	HeaderPE32Plus Header = "pe32+"
)

// The PE signature offset sits at 0x3C of the DOS header (S35 D6).
const signatureOffsetAt = 0x3C

func headerKind(b []byte) (Header, uint16) {
	h, err := pe.ParseHeaders(b)
	switch {
	case err == nil && h.Optional.PE32Plus:
		return HeaderPE32Plus, h.File.Machine
	case err == nil:
		return HeaderPE32, h.File.Machine
	case errors.Is(err, pe.ErrNotPE):
		if m, ok := signatureAt(b); ok {
			return HeaderNT, m
		}
		return HeaderNone, 0
	case errors.Is(err, pe.ErrUnsupportedOptionalMagic):
		m, _ := signatureAt(b)
		return HeaderNT, m
	case len(b) >= 2 && binary.LittleEndian.Uint16(b) == pe.DOSMagic:
		if m, ok := signatureAt(b); ok {
			return HeaderNT, m
		}
		return HeaderDOS, 0
	}
	return HeaderNone, 0
}

func signatureAt(b []byte) (uint16, bool) {
	if len(b) < signatureOffsetAt+4 {
		return 0, false
	}
	at := uint64(binary.LittleEndian.Uint32(b[signatureOffsetAt:]))
	if at+4+2 > uint64(len(b)) || binary.LittleEndian.Uint32(b[at:]) != pe.NTSignature {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b[at+4:]), true
}

type Transfer string

const (
	TransferNone       Transfer = ""
	TransferJumpRel32  Transfer = "jmp-rel32"
	TransferCallRel32  Transfer = "call-rel32"
	TransferJumpSlot   Transfer = "jmp-indirect"
	TransferMoveAndJmp Transfer = "mov-jmp-rax"
)

type transfer struct {
	kind   Transfer
	target uint64
	unread bool
}

// Instruction forms of S35 D8. The project's decoder must agree on the
// length, so a prefix or a different opcode extension never passes.
func firstTransfer(code []byte, at uint64, mode disasm.Mode, slots memory.MemoryReader) transfer {
	inst, ok := disasm.Decode(code, at, mode)
	if !ok {
		return transfer{}
	}
	narrow := func(v uint64) uint64 {
		if mode == disasm.Mode32 {
			return v & 0xFFFFFFFF
		}
		return v
	}
	rel32 := func() uint64 {
		return narrow(at + 5 + uint64(int64(int32(binary.LittleEndian.Uint32(code[1:])))))
	}
	switch {
	case code[0] == 0xE9 && inst.Len == 5 && inst.IsJmp():
		return transfer{kind: TransferJumpRel32, target: rel32()}
	case code[0] == 0xE8 && inst.Len == 5 && inst.IsCall():
		return transfer{kind: TransferCallRel32, target: rel32()}
	case len(code) >= 6 && code[0] == 0xFF && code[1] == 0x25 && inst.Len == 6 && inst.IsJmp():
		disp := binary.LittleEndian.Uint32(code[2:])
		slot, width := uint64(disp), uint64(4)
		if mode == disasm.Mode64 {
			slot, width = at+6+uint64(int64(int32(disp))), 8
		}
		t := transfer{kind: TransferJumpSlot}
		raw, err := readExact(slots, slot, width)
		if err != nil {
			t.unread = true
			return t
		}
		if width == 8 {
			t.target = binary.LittleEndian.Uint64(raw)
		} else {
			t.target = uint64(binary.LittleEndian.Uint32(raw))
		}
		return t
	case mode == disasm.Mode64 && len(code) >= 12 && code[0] == 0x48 && code[1] == 0xB8 && inst.Len == 10 &&
		code[10] == 0xFF && code[11] == 0xE0:
		if next, ok := disasm.Decode(code[10:], at+10, mode); ok && next.Len == 2 && next.IsJmp() {
			return transfer{kind: TransferMoveAndJmp, target: binary.LittleEndian.Uint64(code[2:])}
		}
	}
	return transfer{}
}

func readExact(r memory.MemoryReader, at, n uint64) ([]byte, error) {
	if r == nil {
		return nil, memory.ErrOutOfBounds
	}
	b, err := r.ReadAt(at, n)
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) != n {
		return nil, memory.ErrOutOfBounds
	}
	return b, nil
}
