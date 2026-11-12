package testsupport

import (
	"encoding/binary"
	"fmt"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

// _POOL_HEADER on x64 (S79 T6): two 16-bit words of byte-wide bit fields,
// then the tag. A block is 16 bytes, the header's own size (S31 M7).
const (
	PoolHeaderSize = 0x10
	PoolTagOffset  = 0x04
	PoolAlignment  = PoolHeaderSize

	poolIndexWord = 0x00
	poolTypeWord  = 0x02

	// 0 is free, odd paged, nonzero even nonpaged (S31 T5, M7).
	FreePoolType     = 0
	NonPagedPoolType = 2
	PagedPoolType    = 3

	bigPageEntrySize = 0x18
	bigPageTypeWord  = 0x0c
)

func poolBits(word uint64, bit uint8, name string) symbols.Field {
	return symbols.Field{Name: name, Offset: word,
		Type: symbols.TypeRef{Name: "unsigned short", BitOffset: bit, BitLength: 8}}
}

func poolHeaderFields() []symbols.Field {
	return []symbols.Field{
		poolBits(poolIndexWord, 0, "PreviousSize"),
		poolBits(poolIndexWord, 8, "PoolIndex"),
		poolBits(poolTypeWord, 0, "BlockSize"),
		poolBits(poolTypeWord, 8, "PoolType"),
		{Name: "PoolTag", Offset: PoolTagOffset, Type: symbols.TypeRef{Name: "unsigned int"}},
	}
}

// The 14393 and 19045 big-page entry; 26100 has PoolFlags in place of
// PoolType (S52 T1, T2).
func bigPageTypeField() symbols.Field {
	return symbols.Field{Name: "PoolType", Offset: bigPageTypeWord,
		Type: symbols.TypeRef{Name: "unsigned int", BitOffset: 8, BitLength: 12}}
}

func AddPoolHeaderSymbols(fields map[string]symbols.Field, structs map[string]symbols.StructType) {
	header := poolHeaderFields()
	for _, f := range header {
		fields["_POOL_HEADER."+f.Name] = f
	}
	fields["_POOL_TRACKER_BIG_PAGES.PoolType"] = bigPageTypeField()
	structs["_POOL_HEADER"] = symbols.StructType{Name: "_POOL_HEADER", Size: PoolHeaderSize, Fields: header}
	structs["_POOL_TRACKER_BIG_PAGES"] = symbols.StructType{Name: "_POOL_TRACKER_BIG_PAGES", Size: bigPageEntrySize,
		Fields: []symbols.Field{bigPageTypeField()}}
}

func ReadPoolHeader(r memory.MemoryReader, typeName string, off uint64) (symbols.StructInstance, error) {
	if typeName != "_POOL_HEADER" {
		return symbols.StructInstance{}, fmt.Errorf("testsupport: no fixture layout for %s", typeName)
	}
	raw, err := r.ReadAt(off, PoolHeaderSize)
	if err != nil {
		return symbols.StructInstance{}, err
	}
	le := binary.LittleEndian
	index, kind := le.Uint16(raw[poolIndexWord:]), le.Uint16(raw[poolTypeWord:])
	return symbols.StructInstance{Offset: off, Fields: map[string]uint64{
		"PoolIndex": uint64(index >> 8),
		"BlockSize": uint64(kind & 0xff),
		"PoolType":  uint64(kind >> 8),
		"PoolTag":   uint64(le.Uint32(raw[PoolTagOffset:])),
	}}, nil
}

// PreviousSize and PoolIndex stay 0: every measured header has PreviousSize
// 0, and 0 is among the PoolIndex values measured (S31 M7).
func WritePoolHeader(buf []byte, off uint64, tag string, blocks, poolType byte) {
	binary.LittleEndian.PutUint16(buf[off+poolTypeWord:], uint16(poolType)<<8|uint16(blocks))
	copy(buf[off+PoolTagOffset:off+PoolTagOffset+4], tag)
}

func BlocksFor(size uint64) byte {
	return byte((size + PoolAlignment - 1) / PoolAlignment)
}
