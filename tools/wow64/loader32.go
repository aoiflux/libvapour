package wow64

import (
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

type List int

const (
	LoadOrder List = iota
	MemoryOrder
	InitOrder
)

// No table types the 32-bit loader data or records; these are the S56 L1
// offsets, which Learn's declarations and the captures confirm.
var lists = [...]struct {
	head, link uint64
	label      string
}{
	LoadOrder:   {0x0c, 0x00, "32-bit InLoadOrderModuleList"},
	MemoryOrder: {0x14, 0x08, "32-bit InMemoryOrderModuleList"},
	InitOrder:   {0x1c, 0x10, "32-bit InInitializationOrderModuleList"},
}

const recordDllBase = uint64(0x18)

func read32(r memory.MemoryReader, at uint64) (uint64, bool) {
	b, err := r.ReadAt(at, 4)
	if err != nil || len(b) < 4 {
		return 0, false
	}
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24, true
}

// A base maps to true when only the walk back from the head reached it.
func BasesRecovering(ctx tools.Context, space memory.MemoryReader, peb32 uint64, list List) (bases map[uint64]bool, short, backShort string) {
	bases = map[uint64]bool{}
	if list < LoadOrder || list > InitOrder {
		return bases, "wow64: no such loader list", ""
	}
	o := ResolveOffsets(ctx)
	ldr, ok := read32(space, peb32+o.ldr)
	if !ok {
		return bases, "wow64: PEB32 Ldr does not read", ""
	}
	if ldr == 0 {
		return bases, "", ""
	}
	l := lists[list]
	w := winkernel.ListWalker{Tool: "wow64", Memory: space, Layout: o.list, Limit: ctx.Bounds().MaxListEntries}
	walk, err := w.WalkRecovering(ldr+l.head, l.label)
	if err != nil {
		return bases, err.Error(), ""
	}
	forward := len(walk.Entries) - walk.Backward
	for i, link := range walk.Entries {
		record, ok := winkernel.Container(link, l.link)
		if !ok {
			continue
		}
		base, ok := read32(space, record+recordDllBase)
		if !ok {
			continue
		}
		back := i >= forward
		if seen, dup := bases[base]; !dup || seen {
			bases[base] = back
		}
	}
	if walk.Forward != nil {
		short = walk.Forward.Error()
	}
	if walk.Back != nil {
		backShort = walk.Back.Error()
	}
	return bases, short, backShort
}
