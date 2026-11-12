package minidump

import "encoding/binary"

const (
	ContextAMD64Size = 1232

	ContextAMD64          = uint32(0x00100000)
	ContextControl        = uint32(0x00000001)
	ContextInteger        = uint32(0x00000002)
	ContextSegments       = uint32(0x00000004)
	ContextFloatingPoint  = uint32(0x00000008)
	ContextDebugRegisters = uint32(0x00000010)
)

const (
	ctxFlags  = 0x30
	ctxMxCsr  = 0x34
	ctxSegCs  = 0x38
	ctxEFlags = 0x44
	ctxRax    = 0x78
)

// A debugger trusts every register group that Flags names. Do not name a group
// that was not fully recovered.
type AMD64Context struct {
	Flags               uint32
	Rax, Rcx, Rdx, Rbx  uint64
	Rsp, Rbp, Rsi, Rdi  uint64
	R8, R9, R10, R11    uint64
	R12, R13, R14, R15  uint64
	Rip                 uint64
	EFlags              uint32
	MxCsr               uint32
	SegCs, SegDs, SegEs uint16
	SegFs, SegGs, SegSs uint16
}

// Members outside Flags are written too: they hold the values that were
// recovered, and a reader that honours Flags ignores them.
func (c AMD64Context) Bytes() []byte {
	b := make([]byte, ContextAMD64Size)
	le := binary.LittleEndian
	le.PutUint32(b[ctxFlags:], c.Flags)
	le.PutUint32(b[ctxMxCsr:], c.MxCsr)
	for i, s := range []uint16{c.SegCs, c.SegDs, c.SegEs, c.SegFs, c.SegGs, c.SegSs} {
		le.PutUint16(b[ctxSegCs+2*i:], s)
	}
	le.PutUint32(b[ctxEFlags:], c.EFlags)
	for i, r := range []uint64{
		c.Rax, c.Rcx, c.Rdx, c.Rbx, c.Rsp, c.Rbp, c.Rsi, c.Rdi,
		c.R8, c.R9, c.R10, c.R11, c.R12, c.R13, c.R14, c.R15, c.Rip,
	} {
		le.PutUint64(b[ctxRax+8*i:], r)
	}
	return b
}
