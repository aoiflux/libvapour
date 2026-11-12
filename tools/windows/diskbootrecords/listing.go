package diskbootrecords

import (
	"fmt"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

const realModeBits = 16

// The boot code runs in real-address mode, so it is decoded with 16-bit
// operand and address size. Offsets are from the start of the record: the
// load address is a firmware convention no allowed source fixes (S66 BO3).
func listBootCode(code []byte, maxBytes int64) (string, bool) {
	var b strings.Builder
	for off := 0; off < len(code); {
		var line string
		step := 1
		inst, err := x86asm.Decode(code[off:], realModeBits)
		if err == nil && inst.Len > 0 && inst.Op != 0 {
			line = fmt.Sprintf("%04x %s", off, x86asm.IntelSyntax(inst, uint64(off), nil))
			step = inst.Len
		} else {
			line = fmt.Sprintf("%04x db 0x%02x", off, code[off])
		}
		if int64(b.Len()+len(line)+1) > maxBytes {
			return b.String(), false
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line)
		off += step
	}
	return b.String(), true
}
