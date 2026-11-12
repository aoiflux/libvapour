package credentialkerberoshook

import (
	"strconv"
	"strings"

	"github.com/aoiflux/libvapour/disasm"
	"golang.org/x/arch/x86/x86asm"
)

type Source string

const (
	SourceSymbols Source = "symbols"
	SourceCode    Source = "code"
)

// Public names in cryptdll.pdb on every measured build (S23 M1).
const (
	symbolTable   = "CSystems"
	symbolCount   = "cCSystems"
	locateRoutine = "CDLocateCSystem"
)

// S23 M2: the measured locate routines end in a ret within 0x2e bytes.
const (
	locateWindow       = 0x60
	locateInstructions = 32
)

type tableHead struct {
	count  uint64
	array  uint64
	source Source
}

// The locate routine reads the count with a RIP-relative 32-bit load, takes
// the table's address with a RIP-relative lea and scales the index with shl
// (S23 4.3 step 3, M2). The first of each, before the first ret, is taken.
func headFromLocateCode(code []byte, at uint64) (tableHead, bool) {
	var count, array uint64
	shift := -1
	for off, n := 0, 0; off < len(code) && off < locateWindow && n < locateInstructions; n++ {
		in, ok := disasm.Decode(code[off:], at+uint64(off), disasm.Mode64)
		if !ok {
			return tableHead{}, false
		}
		off += in.Len
		if in.IsRet() {
			break
		}
		switch target, rel := in.RIPRelativeTarget(); {
		case rel && in.IsMov() && count == 0 && strings.Contains(in.Text, "dword ptr"):
			count = target
		case rel && in.IsLea() && array == 0:
			array = target
		case in.Op() == x86asm.SHL && shift < 0:
			shift = immediate(in.Text)
		}
		if count != 0 && array != 0 && shift >= 0 {
			break
		}
	}
	if count == 0 || array == 0 || shift != entryShift {
		return tableHead{}, false
	}
	return tableHead{count: count, array: array, source: SourceCode}, true
}

func immediate(text string) int {
	_, last, ok := strings.Cut(text, ", ")
	if !ok {
		return -1
	}
	v, err := strconv.ParseUint(strings.TrimSpace(last), 0, 8)
	if err != nil {
		return -1
	}
	return int(v)
}
