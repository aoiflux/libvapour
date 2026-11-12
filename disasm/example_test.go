package disasm_test

import (
	"fmt"

	"github.com/aoiflux/libvapour/disasm"
)

func ExampleDecode() {
	code := []byte{0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3}
	address := uint64(0x7FFA00001000)
	for len(code) > 0 {
		inst, ok := disasm.Decode(code, address, disasm.Mode64)
		if !ok {
			return
		}
		fmt.Printf("%#x %s\n", address, inst.Text)
		code, address = code[inst.Len:], address+uint64(inst.Len)
	}
	// Output:
	// 0x7ffa00001000 mov r10, rcx
	// 0x7ffa00001003 mov eax, 0x18
	// 0x7ffa00001008 syscall
	// 0x7ffa0000100a ret
}
