package minidump

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Offsets follow the member list of the x64 CONTEXT: six 8-byte home slots,
// ContextFlags and MxCsr, six 2-byte segments, EFlags, six debug registers,
// then the sixteen general registers and Rip.
func TestContextLayout(t *testing.T) {
	c := AMD64Context{
		Flags: ContextAMD64 | ContextControl | ContextInteger, MxCsr: 0x1F80, EFlags: 0x246,
		SegCs: 0x33, SegDs: 0x2B, SegEs: 0x2B, SegFs: 0x53, SegGs: 0x2B, SegSs: 0x2B,
		Rax: 1, Rcx: 2, Rdx: 3, Rbx: 4, Rsp: 5, Rbp: 6, Rsi: 7, Rdi: 8,
		R8: 9, R9: 10, R10: 11, R11: 12, R12: 13, R13: 14, R14: 15, R15: 16, Rip: 17,
	}
	b := c.Bytes()
	if len(b) != ContextAMD64Size {
		t.Fatalf("%d bytes", len(b))
	}
	home := 6 * 8
	le := binary.LittleEndian
	if le.Uint32(b[home:]) != c.Flags || le.Uint32(b[home+4:]) != 0x1F80 {
		t.Errorf("flags and MxCsr % x", b[home:home+8])
	}
	for i, want := range []uint16{0x33, 0x2B, 0x2B, 0x53, 0x2B, 0x2B} {
		if got := le.Uint16(b[home+8+2*i:]); got != want {
			t.Errorf("segment %d 0x%x", i, got)
		}
	}
	if le.Uint32(b[home+20:]) != 0x246 {
		t.Errorf("EFlags 0x%x", le.Uint32(b[home+20:]))
	}
	gp := home + 24 + 6*8
	for i := range 17 {
		if got := le.Uint64(b[gp+8*i:]); got != uint64(i+1) {
			t.Errorf("register %d = %d", i, got)
		}
	}
	if !bytes.Equal(b[:home], make([]byte, home)) || !bytes.Equal(b[home+24:gp], make([]byte, 48)) || !bytes.Equal(b[gp+17*8:], make([]byte, ContextAMD64Size-gp-17*8)) {
		t.Error("bytes outside the set members are not zero")
	}
}

// The CONTEXT tail after Rip: a 512-byte FXSAVE area, 26 16-byte vector
// registers and six 8-byte members.
func TestContextSizeFromTheMemberList(t *testing.T) {
	if want := 6*8 + 4 + 4 + 6*2 + 4 + 6*8 + 17*8 + 512 + 26*16 + 6*8; want != ContextAMD64Size {
		t.Errorf("member list sums to %d, ContextAMD64Size %d", want, ContextAMD64Size)
	}
}
