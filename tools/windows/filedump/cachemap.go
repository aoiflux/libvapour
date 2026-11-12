package filedump

import (
	"errors"
	"fmt"
	"sort"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

const (
	sharedCacheMapNode = 0x2FF
	viewGranule        = uint64(256 << 10)
)

var ErrCacheLayout = errors.New("filedump: symbol table lacks a member the shared cache map reader needs")

type cacheView struct {
	address, offset, size uint64
}

// A single sweep of the cache manager's VACB arrays reaches each view, and
// each VACB points back at its map, so the per-map index and its layout are
// never needed.
type cacheReader struct {
	ctx tools.Context
	err error

	node, byteSize, fileSize, sectionSize, fileRef symbols.IntField
	mapSize                                        uint64

	vacbBase, vacbMap, vacbHead symbols.IntField
	vacbOverlay, vacbSize       uint64
	arrayIndex                  symbols.IntField
	headerSize                  uint64
	arraysAt, highestAt         uint64

	built      bool
	buildErr   error
	byMap      map[uint64][]cacheView
	arrays     int
	badArrays  int
	vacbsSeen  int
	vacbsInUse int
}

func newCacheReader(ctx tools.Context) *cacheReader {
	c := &cacheReader{ctx: ctx}
	t := ctx.Symbols
	need := func(dst *symbols.IntField, typeName, member string) {
		if c.err != nil {
			return
		}
		var err error
		if *dst, err = symbols.ResolveIntField(t, typeName, member); err != nil {
			c.err = fmt.Errorf("%w: %v", ErrCacheLayout, err)
		}
	}
	need(&c.node, "_SHARED_CACHE_MAP", "NodeTypeCode")
	need(&c.byteSize, "_SHARED_CACHE_MAP", "NodeByteSize")
	need(&c.fileSize, "_SHARED_CACHE_MAP", "FileSize")
	need(&c.sectionSize, "_SHARED_CACHE_MAP", "SectionSize")
	need(&c.fileRef, "_SHARED_CACHE_MAP", "FileObjectFastRef")
	need(&c.vacbBase, "_VACB", "BaseAddress")
	need(&c.vacbMap, "_VACB", "SharedCacheMap")
	need(&c.vacbHead, "_VACB", "ArrayHead")
	need(&c.arrayIndex, "_VACB_ARRAY_HEADER", "VacbArrayIndex")
	if c.err != nil {
		return c
	}
	size := func(name string) uint64 {
		st, err := t.Struct(name)
		if err != nil || st.Size == 0 {
			c.err = fmt.Errorf("%w: size of %s", ErrCacheLayout, name)
		}
		return st.Size
	}
	c.mapSize, c.vacbSize, c.headerSize = size("_SHARED_CACHE_MAP"), size("_VACB"), size("_VACB_ARRAY_HEADER")
	overlay, err := t.Field("_VACB", "Overlay")
	if err != nil {
		c.err = fmt.Errorf("%w: %v", ErrCacheLayout, err)
		return c
	}
	c.vacbOverlay = overlay.Offset
	for _, s := range []struct {
		name string
		dst  *uint64
	}{{"CcVacbArrays", &c.arraysAt}, {"CcVacbArraysHighestUsedIndex", &c.highestAt}} {
		sym, err := t.LookupSymbol(s.name)
		if err != nil {
			c.err = fmt.Errorf("%w: %v", ErrCacheLayout, err)
			return c
		}
		*s.dst = sym.Address
	}
	return c
}

// Returns the map's FileSize.
func (c *cacheReader) check(f fields, scm, sop uint64) (uint64, error) {
	mem := c.ctx.Memory
	node, err1 := c.node.Read(mem, scm)
	size, err2 := c.byteSize.Read(mem, scm)
	if err := errors.Join(err1, err2); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrCacheMapNode, err)
	}
	if node != sharedCacheMapNode || size != c.mapSize {
		return 0, fmt.Errorf("%w: NodeTypeCode 0x%x, NodeByteSize %d", ErrCacheMapNode, node, size)
	}
	fileSize, _, err := c.sizes(scm)
	if err != nil {
		return 0, err
	}
	ref, err := c.fileRef.Read(mem, scm)
	if err != nil {
		return 0, fmt.Errorf("%w: FileObjectFastRef: %v", ErrOtherStream, err)
	}
	if streamOf(c.ctx, f, ref) != sop {
		return 0, fmt.Errorf("%w: FileObjectFastRef 0x%x", ErrOtherStream, ref)
	}
	return fileSize, nil
}

func (c *cacheReader) sizes(scm uint64) (fileSize, sectionSize uint64, err error) {
	fileSize, err1 := c.fileSize.Read(c.ctx.Memory, scm)
	sectionSize, err2 := c.sectionSize.Read(c.ctx.Memory, scm)
	if err := errors.Join(err1, err2); err != nil {
		return 0, 0, fmt.Errorf("%w: %v", ErrCacheMapSizes, err)
	}
	if int64(fileSize) < 0 || int64(sectionSize) < 0 || fileSize > sectionSize || sectionSize%viewGranule != 0 {
		return 0, 0, fmt.Errorf("%w: FileSize 0x%x, SectionSize 0x%x", ErrCacheMapSizes, fileSize, sectionSize)
	}
	return fileSize, sectionSize, nil
}

func (c *cacheReader) build() {
	c.built = true
	c.byMap = map[uint64][]cacheView{}
	ctx, mem := c.ctx, c.ctx.Memory
	high, err := ctx.Symbols.ReadUint32(mem, c.highestAt)
	if err != nil {
		c.buildErr = fmt.Errorf("CcVacbArraysHighestUsedIndex: %w", err)
		return
	}
	arrays, err := ctx.Symbols.ReadPointer(mem, c.arraysAt)
	if err != nil || arrays == 0 {
		c.buildErr = fmt.Errorf("CcVacbArrays at 0x%x does not read", c.arraysAt)
		return
	}
	limit := uint64(ctx.Bounds().MaxTableEntries)
	width := uint64(ctx.Symbols.PointerSize())
	for i := uint64(0); i <= uint64(high) && i < limit; i++ {
		header, err := ctx.Symbols.ReadPointer(mem, arrays+i*width)
		if err != nil || header == 0 {
			c.badArrays++
			continue
		}
		if index, err := c.arrayIndex.Read(mem, header); err != nil || index != i {
			c.badArrays++
			continue
		}
		c.arrays++
		for k := uint64(0); k < limit; k++ {
			v := header + c.headerSize + k*c.vacbSize
			if head, err := c.vacbHead.Read(mem, v); err != nil || head != header {
				break
			}
			c.vacbsSeen++
			base, err1 := c.vacbBase.Read(mem, v)
			scm, err2 := c.vacbMap.Read(mem, v)
			raw, err3 := ctx.Symbols.ReadUint64(mem, v+c.vacbOverlay)
			if errors.Join(err1, err2, err3) != nil || base == 0 || scm == 0 {
				continue
			}
			c.vacbsInUse++
			c.byMap[scm] = append(c.byMap[scm], cacheView{address: base, offset: raw &^ (viewGranule - 1)})
		}
	}
	if c.badArrays > 0 {
		ctx.AddDiagnostic("%s: %d of %d VACB arrays do not read or carry another index", Name, c.badArrays,
			uint64(high)+1)
	}
}

// Views past the file's end hold no file bytes; the map's check has already
// held FileSize to SectionSize. A view that is not granule-aligned or repeats
// an offset is not one the cache manager made.
func (c *cacheReader) views(scm, fileSize uint64) []cacheView {
	if !c.built {
		c.build()
		if c.buildErr != nil {
			c.ctx.AddDiagnostic("%s: VACB arrays not read, shared cache maps carve nothing: %v", Name, c.buildErr)
		}
	}
	byOffset := map[uint64]bool{}
	var out []cacheView
	dropped := 0
	for _, v := range c.byMap[scm] {
		switch {
		case v.offset >= fileSize:
			continue
		case v.address%viewGranule != 0, byOffset[v.offset]:
			dropped++
			continue
		}
		byOffset[v.offset] = true
		v.size = min(viewGranule, fileSize-v.offset)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].offset < out[j].offset })
	if dropped > 0 {
		c.ctx.AddDiagnostic("%s: shared cache map at 0x%x: %d views misaligned or repeated, not carved", Name, scm, dropped)
	}
	return out
}
