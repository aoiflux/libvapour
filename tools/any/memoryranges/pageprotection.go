package memoryranges

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aoiflux/libvapour/tools"
)

var ErrProtectTableUnread = errors.New("memoryranges: MmProtectToValue does not read")

// Microsoft Learn, "Memory Protection Constants", in ascending value order
// (S24 D1). PAGE_TARGETS_NO_UPDATE shares 0x40000000 and is not listed apart.
var pageConstants = []struct {
	name  string
	value uint32
}{
	{"PAGE_NOACCESS", 0x01},
	{"PAGE_READONLY", 0x02},
	{"PAGE_READWRITE", 0x04},
	{"PAGE_WRITECOPY", 0x08},
	{"PAGE_EXECUTE", 0x10},
	{"PAGE_EXECUTE_READ", 0x20},
	{"PAGE_EXECUTE_READWRITE", 0x40},
	{"PAGE_EXECUTE_WRITECOPY", 0x80},
	{"PAGE_GUARD", 0x100},
	{"PAGE_NOCACHE", 0x200},
	{"PAGE_WRITECOMBINE", 0x400},
	{"PAGE_TARGETS_INVALID", 0x40000000},
}

const pagePrefix = "PAGE_"

func ProtectionName(value uint32) string {
	if value == 0 {
		return "0x0"
	}
	parts := make([]string, 0, 3)
	rest := value
	for _, c := range pageConstants {
		if value&c.value != 0 {
			parts = append(parts, c.name)
			rest &^= c.value
		}
	}
	if rest != 0 {
		parts = append(parts, fmt.Sprintf("0x%x", rest))
	}
	return strings.Join(parts, "|")
}

// A name that is empty or holds an unknown part gives false: a zero value
// would read as a real protection.
func Win32Protection(name string) (uint32, bool) {
	if name == "" {
		return 0, false
	}
	var value uint32
	for _, part := range strings.Split(name, "|") {
		v, ok := protectionPart(part)
		if !ok {
			return 0, false
		}
		value |= v
	}
	return value, true
}

func protectionPart(part string) (uint32, bool) {
	if hex, ok := strings.CutPrefix(part, "0x"); ok {
		v, err := strconv.ParseUint(hex, 16, 32)
		return uint32(v), err == nil && hex != ""
	}
	if !strings.HasPrefix(part, pagePrefix) {
		part = pagePrefix + part
	}
	for _, c := range pageConstants {
		if c.name == part {
			return c.value, true
		}
	}
	return 0, false
}

// 2 to the width of the Protection field entries; the words after them are
// not protections (S24 M2).
func readProtectTable(ctx tools.Context, l vadLayout) ([]uint32, error) {
	if !l.haveProtection || l.protection.BitLength == 0 || l.protection.BitLength > 8 {
		return nil, fmt.Errorf("%w: no Protection bit field in symbols", ErrProtectTableUnread)
	}
	sym, err := ctx.Symbols.LookupSymbol("MmProtectToValue")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProtectTableUnread, err)
	}
	entries := uint64(1) << l.protection.BitLength
	raw, err := ctx.Memory.ReadAt(sym.Address, entries*4)
	if err != nil {
		return nil, fmt.Errorf("%w: at 0x%x: %w", ErrProtectTableUnread, sym.Address, err)
	}
	if uint64(len(raw)) < entries*4 {
		return nil, fmt.Errorf("%w: at 0x%x: %d of %d bytes", ErrProtectTableUnread, sym.Address, len(raw), entries*4)
	}
	table := make([]uint32, entries)
	for i := range table {
		table[i] = binary.LittleEndian.Uint32(raw[4*i:])
	}
	return table, nil
}

func protectionOf(table []uint32, f vadFlags) string {
	if !f.protectionOK || f.protection >= uint64(len(table)) {
		return ProtectionUnknown
	}
	return ProtectionName(table[f.protection])
}
