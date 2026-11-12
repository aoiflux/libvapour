package scan

import (
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

var (
	ErrStructureUndescribed = errors.New("scan: pool filter body type not in symbols")
	ErrNoPoolHeader         = errors.New("scan: symbol table has no _POOL_HEADER")
)

// Frames the kernel maps, and under which virtual addresses: a physical hit
// has no address of its own, and both the TypeIndex decoding and the
// reported address need one.
type Residency interface {
	Contains(physicalAddress uint64) bool
	SecondAddressBytes(physicalAddress uint64) []byte
	LowestAddresses(queries []layers.AddressQuery) ([]layers.LowestAddress, error)
}

type PageType uint8

const (
	PagedPool    PageType = 1
	NonPagedPool PageType = 2
	FreePool     PageType = 4
)

func poolClass(poolType uint64) PageType {
	switch {
	case poolType == 0:
		return FreePool
	case poolType&1 != 0:
		return PagedPool
	default:
		return NonPagedPool
	}
}

func (p PageType) admits(class PageType) bool { return p == 0 || p&class != 0 }

type PoolHeader struct {
	Offset    uint64
	BlockSize uint64
	PoolType  uint64
	PoolIndex uint64
}

func (h PoolHeader) bytes(granularity uint64) uint64 { return h.BlockSize * granularity }

type PoolHeaderLayout struct {
	TagOffset uint64
	Size      uint64
	Alignment uint64
	PageSize  uint64

	table     symbols.SymbolTable
	residency Residency
	everyCopy bool
}

const pageSize = 0x1000

func ResolvePoolHeaderLayout(sym symbols.SymbolTable) (PoolHeaderLayout, error) {
	if sym == nil {
		return PoolHeaderLayout{}, ErrNoPoolHeader
	}
	st, err := sym.Struct("_POOL_HEADER")
	if err != nil || st.Size == 0 {
		return PoolHeaderLayout{}, fmt.Errorf("%w: %v", ErrNoPoolHeader, err)
	}
	tag, err := sym.Field("_POOL_HEADER", "PoolTag")
	if err != nil {
		return PoolHeaderLayout{}, fmt.Errorf("%w: PoolTag: %v", ErrNoPoolHeader, err)
	}
	for _, member := range []string{"BlockSize", "PoolType"} {
		if _, err := sym.Field("_POOL_HEADER", member); err != nil {
			return PoolHeaderLayout{}, fmt.Errorf("%w: %s: %v", ErrNoPoolHeader, member, err)
		}
	}
	return PoolHeaderLayout{
		TagOffset: tag.Offset,
		Size:      st.Size,
		Alignment: poolGranularity(sym.PointerSize()),
		PageSize:  pageSize,
		table:     sym,
	}, nil
}

func poolGranularity(pointerSize uint8) uint64 {
	if pointerSize == 4 {
		return 8
	}
	return 16
}

func (l PoolHeaderLayout) WithResidency(r Residency) PoolHeaderLayout {
	l.residency = r
	return l
}

func (l PoolHeaderLayout) ReportingEveryCopy() PoolHeaderLayout {
	l.everyCopy = true
	return l
}

func (l PoolHeaderLayout) MinimumSize(f PoolFilter) (uint64, error) {
	body, err := bodySize(l.table, f)
	if err != nil {
		return 0, err
	}
	return max(l.Size+body, f.MinSize), nil
}

func bodySize(sym symbols.SymbolTable, f PoolFilter) (uint64, error) {
	if f.Body == "" {
		return 0, nil
	}
	if sym == nil {
		return 0, fmt.Errorf("%w: %s", ErrStructureUndescribed, f.Body)
	}
	st, err := sym.Struct(f.Body)
	if err != nil {
		return 0, fmt.Errorf("%w: %s", ErrStructureUndescribed, f.Body)
	}
	return st.Size, nil
}

// The table decodes the members, bit fields included: the header packs
// several of them into 16-bit words, and their placement is the table's.
func (l PoolHeaderLayout) read(reader memory.MemoryReader, at uint64) (PoolHeader, error) {
	inst, err := l.table.ReadStruct(reader, "_POOL_HEADER", at)
	if err != nil {
		return PoolHeader{}, err
	}
	block, ok := inst.Fields["BlockSize"]
	if !ok {
		return PoolHeader{}, fmt.Errorf("%w: BlockSize not decoded", ErrNoPoolHeader)
	}
	return PoolHeader{Offset: at, BlockSize: block, PoolType: inst.Fields["PoolType"],
		PoolIndex: inst.Fields["PoolIndex"]}, nil
}

type headerVerdict int

const (
	headerPassed headerVerdict = iota
	headerMisaligned
	headerUnreadable
	headerPageType
	headerSize
	headerIndex
	headerPastPage
)

func (l PoolHeaderLayout) judge(reader memory.MemoryReader, at uint64, f PoolFilter, minimum uint64) (PoolHeader, headerVerdict) {
	if l.Alignment != 0 && at%l.Alignment != 0 {
		return PoolHeader{}, headerMisaligned
	}
	h, err := l.read(reader, at)
	if err != nil {
		return PoolHeader{}, headerUnreadable
	}
	if !f.PageType.admits(poolClass(h.PoolType)) {
		return h, headerPageType
	}
	size := h.bytes(l.Alignment)
	if size < minimum || f.MaxSize != 0 && size > f.MaxSize {
		return h, headerSize
	}
	if f.MaxIndex != 0 && (h.PoolIndex < f.MinIndex || h.PoolIndex > f.MaxIndex) {
		return h, headerIndex
	}
	if l.PageSize != 0 && at%l.PageSize+size > l.PageSize {
		return h, headerPastPage
	}
	return h, headerPassed
}

type HeaderRejections struct {
	Size       int
	PageType   int
	Index      int
	Alignment  int
	Unreadable int
}

func (r *HeaderRejections) count(v headerVerdict) {
	switch v {
	case headerMisaligned:
		r.Alignment++
	case headerUnreadable:
		r.Unreadable++
	case headerPageType:
		r.PageType++
	case headerSize:
		r.Size++
	case headerIndex:
		r.Index++
	}
}

func (r HeaderRejections) total() int {
	return r.Size + r.PageType + r.Index + r.Alignment + r.Unreadable
}

func (r *HeaderRejections) add(o HeaderRejections) {
	r.Size += o.Size
	r.PageType += o.PageType
	r.Index += o.Index
	r.Alignment += o.Alignment
	r.Unreadable += o.Unreadable
}
