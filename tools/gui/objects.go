package gui

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/scan"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/util"
)

var (
	ErrNoKernelTypes = errors.New("gui: kernel table lacks a type the objects are read with")
	ErrUnreadable    = errors.New("gui: member does not read")
	ErrWrongType     = errors.New("gui: pointer does not name an object of the expected type")
)

const (
	typeWindowStation = "WindowStation"
	typeDesktop       = "Desktop"
	typeThread        = "Thread"
	typeProcess       = "Process"
)

type kernel struct {
	bodyOffset, typeIndex uint64
	cookie                byte
	hasCookie             bool
	slots                 map[string]byte
	cid, uniqueThread     uint64
	imageName, pid        uint64
	imageNameSize         uint64
	namer                 scan.ObjectNamer
}

func resolveKernel(sym symbols.SymbolTable, mem memory.MemoryReader) (kernel, error) {
	var k kernel
	field := func(typ, member string) (uint64, error) {
		f, err := sym.Field(typ, member)
		if err != nil {
			return 0, fmt.Errorf("%w: %s.%s", ErrNoKernelTypes, typ, member)
		}
		return f.Offset, nil
	}
	var err error
	steps := []struct {
		typ, member string
		into        *uint64
	}{
		{"_OBJECT_HEADER", "Body", &k.bodyOffset},
		{"_OBJECT_HEADER", "TypeIndex", &k.typeIndex},
		{"_ETHREAD", "Cid", &k.cid},
		{"_CLIENT_ID", "UniqueThread", &k.uniqueThread},
		{"_EPROCESS", "ImageFileName", &k.imageName},
		{"_EPROCESS", "UniqueProcessId", &k.pid},
	}
	for _, s := range steps {
		if *s.into, err = field(s.typ, s.member); err != nil {
			return kernel{}, err
		}
	}
	k.imageNameSize = imageNameBytes
	if sizer, ok := sym.(symbols.FieldSizer); ok {
		if n, err := sizer.FieldSize("_EPROCESS", "ImageFileName"); err == nil && n > 0 && n <= 64 {
			k.imageNameSize = n
		}
	}
	namer, ok := scan.NewObjectNamer(sym)
	if !ok {
		return kernel{}, fmt.Errorf("%w: _OBJECT_HEADER_NAME_INFO", ErrNoKernelTypes)
	}
	k.namer = namer
	if s, err := sym.LookupSymbol("ObHeaderCookie"); err == nil {
		if b, err := mem.ReadAt(s.Address, 1); err == nil && len(b) == 1 {
			k.cookie, k.hasCookie = b[0], true
		}
	}
	k.slots, err = typeSlots(sym, mem)
	if err != nil {
		return kernel{}, err
	}
	return k, nil
}

// _EPROCESS.ImageFileName is 15 bytes in every measured kernel table (S17 M1).
const imageNameBytes = 15

func typeSlots(sym symbols.SymbolTable, mem memory.MemoryReader) (map[string]byte, error) {
	table, err := sym.LookupSymbol("ObTypeIndexTable")
	if err != nil {
		return nil, fmt.Errorf("%w: ObTypeIndexTable", ErrNoKernelTypes)
	}
	nameField, err := sym.Field("_OBJECT_TYPE", "Name")
	if err != nil {
		return nil, fmt.Errorf("%w: _OBJECT_TYPE.Name", ErrNoKernelTypes)
	}
	layout := util.ResolveUnicodeStringLayout(sym)
	want := map[string]bool{typeWindowStation: true, typeDesktop: true, typeThread: true, typeProcess: true}
	slots := map[string]byte{}
	for slot := range 256 {
		p, err := sym.ReadPointer(mem, table.Address+uint64(slot)*pointerSize)
		if err != nil || p == 0 {
			continue
		}
		name, err := util.ReadUnicodeString(mem, p+nameField.Offset, layout, util.MaxUnicodeStringBytes)
		if err == nil && want[name.Value] {
			if _, seen := slots[name.Value]; !seen {
				slots[name.Value] = byte(slot)
			}
		}
	}
	for name := range want {
		if _, ok := slots[name]; !ok {
			return nil, fmt.Errorf("%w: object type %q not in ObTypeIndexTable", ErrNoKernelTypes, name)
		}
	}
	return slots, nil
}

// S31 M2: the stored TypeIndex is the slot XOR the cookie's low byte XOR
// bits 15:8 of the header's virtual address.
func (k kernel) isObject(r memory.MemoryReader, body uint64, typeName string) bool {
	if body < k.bodyOffset {
		return false
	}
	header := body - k.bodyOffset
	b, err := r.ReadAt(header+k.typeIndex, 1)
	if err != nil || len(b) != 1 {
		return false
	}
	stored := b[0]
	if k.hasCookie {
		stored ^= k.cookie ^ byte(header>>8)
	}
	return stored == k.slots[typeName]
}

func (k kernel) objectName(headerReader, kernelReader memory.MemoryReader, body uint64) (string, bool) {
	if body < k.bodyOffset {
		return "", false
	}
	name, present, readable := k.namer.ReadName(headerReader, kernelReader, kernelReader, body-k.bodyOffset)
	return name, present && readable
}

func readU64(r memory.MemoryReader, at uint64) (uint64, error) {
	b, err := r.ReadAt(at, 8)
	if err != nil {
		return 0, fmt.Errorf("%w: 0x%x: %w", ErrUnreadable, at, err)
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("%w: 0x%x", ErrUnreadable, at)
	}
	return binary.LittleEndian.Uint64(b), nil
}

func readU32(r memory.MemoryReader, at uint64) (uint32, error) {
	b, err := r.ReadAt(at, 4)
	if err != nil {
		return 0, fmt.Errorf("%w: 0x%x: %w", ErrUnreadable, at, err)
	}
	if len(b) != 4 {
		return 0, fmt.Errorf("%w: 0x%x", ErrUnreadable, at)
	}
	return binary.LittleEndian.Uint32(b), nil
}
