package poolbig

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
)

type Pool string

const (
	PoolPaged           Pool = "paged"
	PoolNonPaged        Pool = "nonpaged"
	PoolNonPagedExecute Pool = "nonpaged_execute"
)

type Allocation struct {
	Address   uint64
	Tag       string
	Size      uint64
	Freed     bool
	Pool      Pool
	PoolType  string
	PoolFlags string
	Slot      uint64
}

const freedBit = 1

// The POOL_FLAGS bits the 12-bit PoolFlags member can hold, as Microsoft
// Learn names them.
var poolFlagNames = []struct {
	bit  uint64
	name string
}{
	{0x1, "POOL_FLAG_USE_QUOTA"},
	{0x2, "POOL_FLAG_UNINITIALIZED"},
	{0x4, "POOL_FLAG_SESSION"},
	{0x8, "POOL_FLAG_CACHE_ALIGNED"},
	{0x10, "POOL_FLAG_RESERVED1"},
	{0x20, "POOL_FLAG_RAISE_ON_FAILURE"},
	{0x40, "POOL_FLAG_NON_PAGED"},
	{0x80, "POOL_FLAG_NON_PAGED_EXECUTE"},
	{0x100, "POOL_FLAG_PAGED"},
	{0x200, "POOL_FLAG_RESERVED2"},
	{0x400, "POOL_FLAG_RESERVED3"},
}

const (
	flagNonPaged        = 0x40
	flagNonPagedExecute = 0x80
	flagPaged           = 0x100
)

func flagText(v uint64) string {
	var parts []string
	rest := v
	for _, f := range poolFlagNames {
		if v&f.bit != 0 {
			parts = append(parts, f.name)
			rest &^= f.bit
		}
	}
	if rest != 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("0x%x", rest))
	}
	return strings.Join(parts, "|")
}

// Exactly one of the three page-kind flags is set on every measured entry; a
// value with none or several names no kind.
func poolFromFlags(v uint64) Pool {
	switch v & (flagNonPaged | flagNonPagedExecute | flagPaged) {
	case flagNonPaged:
		return PoolNonPaged
	case flagNonPagedExecute:
		return PoolNonPagedExecute
	case flagPaged:
		return PoolPaged
	}
	return ""
}

func poolFromType(v uint64) Pool {
	if v&1 == 1 {
		return PoolPaged
	}
	return PoolNonPaged
}

// Several _POOL_TYPE names share a value. The shortest is the one Microsoft
// Learn declares first for each shared value (NonPagedPool before
// NonPagedPoolBase and NonPagedPoolExecute).
func poolTypeNames(t symbols.SymbolTable) map[uint64]string {
	lookup, ok := t.(symbols.DeterministicLookup)
	if !ok {
		return nil
	}
	typ, err := lookup.LookupType("_POOL_TYPE")
	if err != nil || typ.Kind != symbols.TypeKindEnum {
		return nil
	}
	names := map[uint64]string{}
	for _, v := range typ.Enum {
		if v.Value < 0 {
			continue
		}
		have, ok := names[uint64(v.Value)]
		if !ok || cmp.Or(cmp.Compare(len(v.Name), len(have)), strings.Compare(v.Name, have)) < 0 {
			names[uint64(v.Value)] = v.Name
		}
	}
	return names
}

// Tags of fewer than four characters are stored with zero bytes after them.
// Any other byte outside the documented 0x20-0x7e range is shown escaped.
func tagText(key uint32) string {
	b := []byte{byte(key), byte(key >> 8), byte(key >> 16), byte(key >> 24)}
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "\\x%02x", c)
		}
	}
	return sb.String()
}

type decoder struct {
	layout    entryLayout
	typeNames map[uint64]string
}

// A slot whose Key is 0 has never held an allocation: on every measured
// table its Va is 1.
func (d decoder) allocation(e rawEntry) (Allocation, bool) {
	if e.key == 0 {
		return Allocation{}, false
	}
	a := Allocation{
		Address: e.va &^ freedBit,
		Tag:     tagText(uint32(e.key)),
		Size:    e.bytes,
		Freed:   e.va&freedBit != 0,
		Slot:    e.slot,
	}
	switch {
	case d.layout.poolType.present:
		a.Pool = poolFromType(e.typ)
		if name, ok := d.typeNames[e.typ]; ok {
			a.PoolType = name
		} else {
			a.PoolType = strconv.FormatUint(e.typ, 10)
		}
	case d.layout.poolFlags.present:
		a.Pool = poolFromFlags(e.flags)
		a.PoolFlags = flagText(e.flags)
	}
	return a, true
}

func compareAllocations(a, b Allocation) int {
	if c := cmp.Compare(a.Address, b.Address); c != 0 {
		return c
	}
	if a.Freed != b.Freed {
		if a.Freed {
			return 1
		}
		return -1
	}
	return cmp.Compare(a.Slot, b.Slot)
}
