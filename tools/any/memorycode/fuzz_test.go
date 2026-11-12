package memorycode

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/disasm"
	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/symbols"
)

func FuzzHeaderKind(f *testing.F) {
	f.Add(testsupport.BuildMappedPE(0x140000000)[:pageSize])
	f.Add([]byte("MZ"))
	f.Add(prologue64)
	f.Fuzz(func(t *testing.T, b []byte) {
		h, machine := headerKind(b)
		switch h {
		case HeaderPE32, HeaderPE32Plus:
			if len(b) < 2 || binary.LittleEndian.Uint16(b) != pe.DOSMagic {
				t.Fatalf("%q without the DOS magic", h)
			}
			if _, ok := signatureAt(b); !ok {
				t.Fatalf("%q without the PE signature", h)
			}
		case HeaderNT:
			if _, ok := signatureAt(b); !ok {
				t.Fatalf("%q without the PE signature", h)
			}
		case HeaderDOS, HeaderNone:
			if machine != 0 {
				t.Fatalf("%q with machine %#x", h, machine)
			}
		default:
			t.Fatalf("unknown header %q", h)
		}
	})
}

func FuzzTransfer(f *testing.F) {
	f.Add([]byte{0xE9, 0, 1, 0, 0}, uint64(0x10000), true)
	f.Add([]byte{0xFF, 0x25, 0, 1, 0, 0}, uint64(0xFFFFFFFFFFFFFFF0), true)
	f.Add([]byte{0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8, 0xFF, 0xE0}, uint64(0), false)
	f.Fuzz(func(t *testing.T, code []byte, at uint64, wide bool) {
		mode := disasm.Mode32
		if wide {
			mode = disasm.Mode64
		}
		got := firstTransfer(code, at, mode, slotMemory{})
		switch got.kind {
		case TransferNone:
			if got.target != 0 || got.unread {
				t.Fatalf("no transfer but %+v", got)
			}
		case TransferJumpRel32, TransferCallRel32:
			if len(code) < 5 || code[0] != 0xE9 && code[0] != 0xE8 {
				t.Fatalf("%q from % x", got.kind, code)
			}
		case TransferJumpSlot:
			if !got.unread {
				t.Fatalf("a slot read from empty memory: %+v", got)
			}
		case TransferMoveAndJmp:
			if !wide || len(code) < 12 {
				t.Fatalf("%q from % x in mode %v", got.kind, code, mode)
			}
		default:
			t.Fatalf("unknown transfer %q", got.kind)
		}
		if mode == disasm.Mode32 && got.target > 0xFFFFFFFF {
			t.Fatalf("32-bit target 0x%x", got.target)
		}
	})
}

func FuzzPageEntry(f *testing.F) {
	f.Add(uint64(1), uint8(6))
	f.Add(uint64(1)<<63|1, uint8(3))
	f.Add(uint64(0x2c0), uint8(0))
	table := protectToValue()
	f.Fuzz(func(t *testing.T, entry uint64, drop uint8) {
		p := pageProtections{table: table[:int(drop)%len(table)+1]}
		p.software = symbols.IntField{Width: 8, BitOffset: 5, BitLength: 5}
		p.transition = p.software
		s := p.decode(entry)
		if entry&1 != 0 && (!s.resident || !s.ownProtect || s.executable != (entry>>63 == 0)) {
			t.Fatalf("present entry %#x gave %+v", entry, s)
		}
		if entry&1 == 0 && s.written {
			t.Fatalf("not-present entry %#x is written", entry)
		}
		if s.executable && !s.ownProtect {
			t.Fatalf("%#x is executable without a protection", entry)
		}
	})
}
