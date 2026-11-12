package wow64

import (
	"fmt"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

// _PEB32.Ldr when the table lacks the type: Learn's PEB declaration with
// 4-byte pointers (S65 D7).
const peb32LdrDefault = uint64(0x0c)

// WoW64 reserves user space above the 32-bit limit (S65 D4).
const highest32BitAddress = uint64(0xffffffff)

type member struct {
	offset uint64
	ok     bool
}

func fieldOf(ctx tools.Context, typ, name string) member {
	f, err := ctx.Symbols.Field(typ, name)
	if err != nil {
		return member{}
	}
	return member{offset: f.Offset, ok: true}
}

type Offsets struct {
	process    member
	processTag string
	ewowPeb    member
	ldr        uint64
	list       winkernel.ListLayout
}

func ResolveOffsets(ctx tools.Context) Offsets {
	var o Offsets
	for _, name := range []string{"WoW64Process", "Wow64Process"} {
		if m := fieldOf(ctx, "_EPROCESS", name); m.ok {
			o.process, o.processTag = m, "_EPROCESS."+name
			break
		}
	}
	o.ewowPeb = fieldOf(ctx, "_EWOW64PROCESS", "Peb")
	o.ldr = peb32LdrDefault
	if m := fieldOf(ctx, "_PEB32", "Ldr"); m.ok {
		o.ldr = m.offset
	}
	// Without the type there is no Blink offset to check, as the S03 walker
	// treats any list type that lacks one.
	o.list = winkernel.ListLayout{Width: 4}
	if l, err := winkernel.ListLayoutOf(ctx.Symbols, "LIST_ENTRY32", 4); err == nil {
		o.list = l
	}
	return o
}

func (o Offsets) PEB32(ctx tools.Context, eprocess uint64) (peb32 uint64, ok bool, why string) {
	if !o.process.ok {
		return 0, false, ""
	}
	at := eprocess + o.process.offset
	wow, err := ctx.Symbols.ReadPointer(ctx.Memory, at)
	if err != nil {
		return 0, false, fmt.Sprintf("%s at 0x%x does not read", o.processTag, at)
	}
	if wow == 0 {
		return 0, false, ""
	}
	if !o.ewowPeb.ok {
		return 0, false, "symbol table has no _EWOW64PROCESS.Peb"
	}
	at = wow + o.ewowPeb.offset
	peb32, err = ctx.Symbols.ReadPointer(ctx.Memory, at)
	switch {
	case err != nil:
		return 0, false, fmt.Sprintf("_EWOW64PROCESS.Peb at 0x%x does not read", at)
	case peb32 == 0:
		return 0, false, fmt.Sprintf("_EWOW64PROCESS.Peb at 0x%x reads 0", at)
	case peb32 > highest32BitAddress:
		return 0, false, fmt.Sprintf("_EWOW64PROCESS.Peb at 0x%x is 0x%x, above the 32-bit limit", at, peb32)
	}
	return peb32, true, ""
}
