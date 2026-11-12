package interruptcheck

import (
	"errors"
	"fmt"
)

type GateType string

const (
	GateInterrupt   GateType = "interrupt"
	GateTrap        GateType = "trap"
	GateTask        GateType = "task"
	GateInterrupt16 GateType = "interrupt16"
	GateTrap16      GateType = "trap16"
	GateInvalid     GateType = "invalid"
)

const (
	longGateSize   = 16
	legacyGateSize = 8
)

var ErrShortGate = errors.New("interruptcheck: gate descriptor shorter than its mode's size")

type Gate struct {
	Offset   uint64
	Selector uint16
	Type     GateType
	DPL      uint8
	IST      uint8
	Present  bool
}

// 8-byte pointers mean the kernel runs in IA-32e mode.
func gateSize(pointerWidth uint64) uint64 {
	if pointerWidth == 8 {
		return longGateSize
	}
	return legacyGateSize
}

func DecodeGate(b []byte, size uint64) (Gate, error) {
	if size != longGateSize && size != legacyGateSize {
		return Gate{}, fmt.Errorf("interruptcheck: %d-byte gate: %w", size, ErrUnsupported)
	}
	if uint64(len(b)) < size {
		return Gate{}, ErrShortGate
	}
	word := func(i int) uint64 { return uint64(b[i]) | uint64(b[i+1])<<8 }
	attr := word(4)
	g := Gate{
		Offset:   word(0) | word(6)<<16,
		Selector: uint16(word(2)),
		DPL:      uint8(attr >> 13 & 3),
		Present:  attr>>15&1 == 1,
	}
	long := size == longGateSize
	if long {
		g.Offset |= (word(8) | word(10)<<16) << 32
		g.IST = uint8(attr & 7)
	}
	g.Type = gateType(attr>>8&0xf, attr>>12&1 == 1, long)
	if g.Type == GateTask {
		g.Offset = 0
	}
	return g, nil
}

func gateType(typ uint64, segment, long bool) GateType {
	if segment {
		return GateInvalid
	}
	switch typ {
	case 0xe:
		return GateInterrupt
	case 0xf:
		return GateTrap
	}
	if long {
		return GateInvalid
	}
	switch typ {
	case 0x5:
		return GateTask
	case 0x6:
		return GateInterrupt16
	case 0x7:
		return GateTrap16
	}
	return GateInvalid
}
