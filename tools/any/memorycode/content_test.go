package memorycode

import (
	"encoding/binary"
	"testing"

	"github.com/aoiflux/libvapour/disasm"
	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/memory"
)

func TestHeaderKinds(t *testing.T) {
	pe64 := testsupport.BuildMappedPE(0x140000000)[:pageSize]

	pe32 := append([]byte(nil), pe64...)
	optAt := uint64(binary.LittleEndian.Uint32(pe32[0x3C:])) + 4 + 20
	binary.LittleEndian.PutUint16(pe32[optAt:], 0x10B)

	oddMagic := append([]byte(nil), pe64...)
	binary.LittleEndian.PutUint16(oddMagic[optAt:], 0x107)

	erased := append([]byte(nil), pe64...)
	erased[0], erased[1] = 0, 0

	dosOnly := make([]byte, 0x80)
	copy(dosOnly, "MZ")
	binary.LittleEndian.PutUint32(dosOnly[0x3C:], 0x40)

	farSignature := make([]byte, 0x80)
	copy(farSignature, "MZ")
	binary.LittleEndian.PutUint32(farSignature[0x3C:], 0x10000)

	for _, tc := range []struct {
		name    string
		b       []byte
		want    Header
		machine uint16
	}{
		{"PE32+", pe64, HeaderPE32Plus, testsupport.MappedPEMachine},
		{"PE32", pe32, HeaderPE32, testsupport.MappedPEMachine},
		{"unknown optional magic", oddMagic, HeaderNT, testsupport.MappedPEMachine},
		{"DOS magic erased", erased, HeaderNT, testsupport.MappedPEMachine},
		{"DOS header only", dosOnly, HeaderDOS, 0},
		{"signature beyond the bytes read", farSignature, HeaderDOS, 0},
		{"short MZ", []byte("MZ"), HeaderDOS, 0},
		{"code", prologue64, HeaderNone, 0},
		{"empty", nil, HeaderNone, 0},
	} {
		got, machine := headerKind(tc.b)
		if got != tc.want || machine != tc.machine {
			t.Errorf("%s: got %q machine %#x, want %q %#x", tc.name, got, machine, tc.want, tc.machine)
		}
	}
}

type slotMemory map[uint64][]byte

func (s slotMemory) ReadAt(off, n uint64) ([]byte, error) {
	if b, ok := s[off]; ok && uint64(len(b)) >= n {
		return b[:n], nil
	}
	return nil, memory.ErrOutOfBounds
}

func (s slotMemory) Size() uint64 { return 1 << 48 }

func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
func le64(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }

func TestTransferForms(t *testing.T) {
	const at = uint64(0x10000)
	slots := slotMemory{
		at + 6 + 0x100: le64(0x7FF812345678),
		0x2000:         le32(0x77001000),
	}
	for _, tc := range []struct {
		name   string
		code   []byte
		mode   disasm.Mode
		want   Transfer
		target uint64
		unread bool
	}{
		{"jmp rel32 forward", append([]byte{0xE9}, le32(0x100)...), disasm.Mode64, TransferJumpRel32, at + 5 + 0x100, false},
		{"jmp rel32 backward", append([]byte{0xE9}, le32(0xFFFFFFF0)...), disasm.Mode64, TransferJumpRel32, at + 5 - 0x10, false},
		{"call rel32", append([]byte{0xE8}, le32(0x20)...), disasm.Mode64, TransferCallRel32, at + 5 + 0x20, false},
		{"call rel32 wraps in 32-bit mode", append([]byte{0xE8}, le32(0xFFFE0000)...), disasm.Mode32, TransferCallRel32, 0xFFFF0005, false},
		{"jmp [rip+disp32]", append([]byte{0xFF, 0x25}, le32(0x100)...), disasm.Mode64, TransferJumpSlot, 0x7FF812345678, false},
		{"jmp [disp32] in 32-bit mode", append([]byte{0xFF, 0x25}, le32(0x2000)...), disasm.Mode32, TransferJumpSlot, 0x77001000, false},
		{"jmp through an unreadable slot", append([]byte{0xFF, 0x25}, le32(0x900)...), disasm.Mode64, TransferJumpSlot, 0, true},
		{"mov rax, imm64; jmp rax", append(append([]byte{0x48, 0xB8}, le64(0x7FF800001000)...), 0xFF, 0xE0), disasm.Mode64, TransferMoveAndJmp, 0x7FF800001000, false},
		{"mov rax, imm64; jmp rax is 64-bit only", append(append([]byte{0x48, 0xB8}, le64(0x7FF800001000)...), 0xFF, 0xE0), disasm.Mode32, TransferNone, 0, false},
		{"operand-size prefix", append([]byte{0x66, 0xE9}, le32(0x100)...), disasm.Mode64, TransferNone, 0, false},
		{"jmp rel8", []byte{0xEB, 0x10}, disasm.Mode64, TransferNone, 0, false},
		{"prologue", prologue64, disasm.Mode64, TransferNone, 0, false},
		{"truncated jmp", []byte{0xE9, 0x01}, disasm.Mode64, TransferNone, 0, false},
		{"empty", nil, disasm.Mode64, TransferNone, 0, false},
	} {
		got := firstTransfer(tc.code, at, tc.mode, slots)
		if got.kind != tc.want || got.target != tc.target || got.unread != tc.unread {
			t.Errorf("%s: got %+v, want %q 0x%x unread %v", tc.name, got, tc.want, tc.target, tc.unread)
		}
	}
}

func TestEntryDecoding(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 1, indexReadWrite))
	p, err := readPageProtections(c.context())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		entry uint64
		want  pageState
	}{
		{"present, executable", 1, pageState{resident: true, ownProtect: true, executable: true}},
		{"present, XD", 1 | noExecute, pageState{resident: true, ownProtect: true}},
		{"present, written", 1 | 1<<6, pageState{resident: true, written: true, ownProtect: true, executable: true}},
		{"bit 6 of a software entry is protection", softwareEntry(indexExecuteRead) | 1<<6, pageState{ownProtect: true, executable: true}},
		{"software, data", softwareEntry(indexReadWrite), pageState{ownProtect: true}},
		{"transition, executable", transitionEntry(0x5000, indexExecuteReadWrite), pageState{resident: true, ownProtect: true, executable: true}},
		{"prototype", 1<<10 | indexExecuteRead<<5, pageState{}},
		{"zero", 0, pageState{}},
	} {
		if got := p.decode(tc.entry); got != tc.want {
			t.Errorf("%s (%#x): got %+v, want %+v", tc.name, tc.entry, got, tc.want)
		}
	}
	none := pageProtections{}
	if got := none.decode(softwareEntry(indexExecuteRead)); got.ownProtect {
		t.Errorf("without a table a software entry gave %+v", got)
	}
}
