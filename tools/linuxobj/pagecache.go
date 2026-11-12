package linuxobj

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools/linuxwalk"
)

var (
	ErrPageOutside    = errors.New("linuxobj: page entry outside the struct page array")
	ErrPageMisaligned = errors.New("linuxobj: page entry not on a struct page boundary")
	ErrPageUnread     = errors.New("linuxobj: struct page does not read")
	ErrPageMapping    = errors.New("linuxobj: page belongs to another mapping")
	ErrPageIndex      = errors.New("linuxobj: page index disagrees with its slot")
	ErrFrameUnread    = errors.New("linuxobj: page frame does not read")
	ErrNoFrameReader  = errors.New("linuxobj: no physical layer and no direct map")
)

const FrameSize = 4096

// S12 P8, P9: the struct page array base and span when vmemmap_base is not
// in the symbol table.
const (
	pageArrayL4     = 0xffffea0000000000
	pageArrayL5     = 0xffd4000000000000
	pageArraySpanL4 = 1 << 40
	pageArraySpanL5 = 1 << 49
)

// S12 P10: MAX_XAS_ORDER with 64-slot nodes bounds a folio at 2^11 pages.
const maxFolioPages = 1 << 11

type PageCache struct {
	r         linuxwalk.Reader
	phys      memory.MemoryReader
	pageSize  uint64
	array     uint64
	span      uint64
	direct    uint64
	hasDirect bool
	owner     string
	flags     symbols.IntField
	mapping   symbols.IntField
	index     symbols.IntField
	head      symbols.IntField
	hasHead   bool
	iPages    uint64
	treeType  string
	nrpages   symbols.IntField
	bits      [][]string
}

type CachedPage struct {
	Address  uint64
	Physical uint64
	Index    uint64
	Flags    uint64
}

type Rejects struct {
	Outside    int
	Misaligned int
	Unread     int
	Foreign    int
	Misplaced  int
}

func (r Rejects) Total() int { return r.Outside + r.Misaligned + r.Unread + r.Foreign + r.Misplaced }

func (r *Rejects) count(err error) {
	switch {
	case errors.Is(err, ErrPageOutside):
		r.Outside++
	case errors.Is(err, ErrPageMisaligned):
		r.Misaligned++
	case errors.Is(err, ErrPageMapping):
		r.Foreign++
	case errors.Is(err, ErrPageIndex):
		r.Misplaced++
	default:
		r.Unread++
	}
}

type MappingPages struct {
	Pages   []CachedPage
	Rejects Rejects
	Tree    linuxwalk.Tree
	Capped  bool
}

func intField(sym symbols.SymbolTable, typ, member string) (symbols.IntField, error) {
	f, err := symbols.ResolveIntField(sym, typ, member)
	if err != nil {
		return symbols.IntField{}, fmt.Errorf("linuxobj: %s.%s: %w: %w", typ, member, linuxwalk.ErrUnsupported, err)
	}
	return f, nil
}

func typeSize(sym symbols.SymbolTable, typ string) (uint64, error) {
	st, err := sym.Struct(typ)
	if err != nil || st.Size == 0 {
		return 0, fmt.Errorf("linuxobj: struct %s has no size: %w", typ, linuxwalk.ErrUnsupported)
	}
	return st.Size, nil
}

func has(sym symbols.SymbolTable, typ, member string) bool {
	_, err := sym.Field(typ, member)
	return err == nil
}

func NewPageCache(r linuxwalk.Reader, phys memory.MemoryReader, la57 bool) (*PageCache, error) {
	if r.Mem == nil || r.Sym == nil {
		return nil, errors.New("linuxobj: page cache: no memory or no symbol table")
	}
	if r.Sym.PointerSize() != 8 {
		return nil, fmt.Errorf("linuxobj: page cache: %d-byte pointers: %w", r.Sym.PointerSize(), linuxwalk.ErrUnsupported)
	}
	c := &PageCache{r: r, phys: phys}
	var err error
	if c.pageSize, err = typeSize(r.Sym, "page"); err != nil {
		return nil, err
	}
	c.owner = "page"
	if has(r.Sym, "folio", "index") && has(r.Sym, "folio", "mapping") && has(r.Sym, "folio", "flags") {
		c.owner = "folio"
	}
	if c.flags, err = intField(r.Sym, c.owner, "flags"); err != nil {
		return nil, err
	}
	if c.mapping, err = intField(r.Sym, c.owner, "mapping"); err != nil {
		return nil, err
	}
	if c.index, err = intField(r.Sym, c.owner, "index"); err != nil {
		return nil, err
	}
	if c.head, err = intField(r.Sym, "page", "compound_head"); err == nil {
		c.hasHead = true
	}
	f, err := r.Sym.Field("address_space", "i_pages")
	if err != nil || f.Type.Name == "" {
		return nil, fmt.Errorf("linuxobj: address_space.i_pages: %w", linuxwalk.ErrUnsupported)
	}
	c.iPages, c.treeType = f.Offset, f.Type.Name
	if c.nrpages, err = intField(r.Sym, "address_space", "nrpages"); err != nil {
		return nil, err
	}
	c.array, c.span = pageArrayL4, pageArraySpanL4
	if la57 {
		c.array, c.span = pageArrayL5, pageArraySpanL5
	}
	if v, ok := c.variable("vmemmap_base"); ok {
		c.array = v
	}
	c.array = c.form(c.array)
	if v, ok := c.variable("page_offset_base"); ok {
		c.direct, c.hasDirect = v, true
	}
	c.bits = flagBits(r.Sym)
	return c, nil
}

func (c *PageCache) form(v uint64) uint64 {
	if c.r.Address == nil {
		return v
	}
	return c.r.Address(v)
}

func (c *PageCache) variable(name string) (uint64, bool) {
	s, err := c.r.Sym.LookupSymbol(name)
	if err != nil {
		return 0, false
	}
	b, err := c.r.Mem.ReadAt(c.form(s.Address), 8)
	if err != nil || len(b) < 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

// S12 P6: bits at and above __NR_PAGEFLAGS hold section, node and zone
// numbers, not flags.
func flagBits(sym symbols.SymbolTable) [][]string {
	det, ok := sym.(symbols.DeterministicLookup)
	if !ok {
		return nil
	}
	t, err := det.LookupType("pageflags")
	if err != nil {
		return nil
	}
	nr := int64(-1)
	for _, v := range t.Enum {
		if v.Name == "__NR_PAGEFLAGS" {
			nr = v.Value
		}
	}
	if nr <= 0 || nr > 64 {
		return nil
	}
	bits := make([][]string, nr)
	for _, v := range t.Enum {
		if v.Value >= 0 && v.Value < nr && !strings.HasPrefix(v.Name, "__") {
			bits[v.Value] = append(bits[v.Value], v.Name)
		}
	}
	return bits
}

func (c *PageCache) PageStructSize() uint64 { return c.pageSize }

func (c *PageCache) PageArray() uint64 { return c.array }

func (c *PageCache) FlagNames(flags uint64) []string {
	var out []string
	for bit, names := range c.bits {
		if flags&(1<<uint(bit)) != 0 {
			out = append(out, names...)
		}
	}
	return out
}

func (c *PageCache) NrPages(mapping uint64) (uint64, error) {
	v, err := c.nrpages.Read(c.r.Mem, mapping)
	if err != nil {
		return 0, fmt.Errorf("linuxobj: address_space at %#x: nrpages: %w", mapping, err)
	}
	return v, nil
}

type pageFields struct {
	flags, mapping, index, head uint64
}

func (c *PageCache) read(page uint64) (pageFields, error) {
	if page < c.array || page-c.array >= c.span {
		return pageFields{}, ErrPageOutside
	}
	if (page-c.array)%c.pageSize != 0 {
		return pageFields{}, ErrPageMisaligned
	}
	b, err := c.r.Mem.ReadAt(page, c.pageSize)
	if err != nil || uint64(len(b)) < c.pageSize {
		return pageFields{}, ErrPageUnread
	}
	var p pageFields
	var errs [4]error
	p.flags, errs[0] = c.flags.Decode(b)
	p.mapping, errs[1] = c.mapping.Decode(b)
	p.index, errs[2] = c.index.Decode(b)
	if c.hasHead {
		p.head, errs[3] = c.head.Decode(b)
	}
	if err := errors.Join(errs[:]...); err != nil {
		return pageFields{}, fmt.Errorf("%w: %w", ErrPageUnread, err)
	}
	p.mapping = c.form(p.mapping)
	return p, nil
}

func (c *PageCache) tailOf(raw uint64) (uint64, bool) {
	if !c.hasHead || raw&1 == 0 {
		return 0, false
	}
	return c.form(raw - 1), true
}

func (c *PageCache) physical(page uint64) uint64 {
	return (page - c.array) / c.pageSize * FrameSize
}

func (c *PageCache) Check(mapping, entry, index uint64) (CachedPage, bool, error) {
	p, err := c.read(entry)
	if err != nil {
		return CachedPage{}, false, err
	}
	owner, offset, ownerFields := entry, uint64(0), p
	if head, tail := c.tailOf(p.head); tail {
		if ownerFields, err = c.read(head); err != nil {
			return CachedPage{}, false, err
		}
		if entry < head {
			return CachedPage{}, false, ErrPageIndex
		}
		owner, offset = head, (entry-head)/c.pageSize
	}
	if ownerFields.mapping != c.form(mapping) {
		return CachedPage{}, false, ErrPageMapping
	}
	if ownerFields.index+offset != index {
		return CachedPage{}, false, ErrPageIndex
	}
	return CachedPage{Address: entry, Physical: c.physical(entry), Index: index, Flags: ownerFields.flags}, owner == entry, nil
}

func (c *PageCache) Pages(mapping, filePages uint64) (MappingPages, error) {
	tree, err := c.r.Tree(mapping+c.iPages, c.treeType)
	if err != nil {
		return MappingPages{}, err
	}
	out := MappingPages{Tree: tree}
	most := c.r.Limits.Effective().MaxTableEntries
	for n, entry := range tree.Entries {
		index := tree.Indexes[n]
		cp, isHead, err := c.Check(mapping, entry, index)
		if err != nil {
			out.Rejects.count(err)
			continue
		}
		if len(out.Pages) >= most {
			out.Capped = true
			break
		}
		out.Pages = append(out.Pages, cp)
		if !isHead {
			continue
		}
		limit := uint64(maxFolioPages)
		if n+1 < len(tree.Entries) {
			limit = min(limit, tree.Indexes[n+1]-index)
		} else if filePages > index {
			limit = min(limit, filePages-index)
		} else {
			limit = 1
		}
		for j := uint64(1); j < limit; j++ {
			tail := entry + j*c.pageSize
			p, err := c.read(tail)
			if err != nil {
				break
			}
			if head, ok := c.tailOf(p.head); !ok || head != entry {
				break
			}
			if len(out.Pages) >= most {
				out.Capped = true
				return out, nil
			}
			out.Pages = append(out.Pages, CachedPage{Address: tail, Physical: c.physical(tail), Index: index + j, Flags: cp.Flags})
		}
	}
	return out, nil
}

func (c *PageCache) Frame(p CachedPage) ([]byte, error) {
	var b []byte
	var err error
	switch {
	case c.phys != nil:
		b, err = c.phys.ReadAt(p.Physical, FrameSize)
	case c.hasDirect:
		b, err = c.r.Mem.ReadAt(c.form(c.direct+p.Physical), FrameSize)
	default:
		return nil, ErrNoFrameReader
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFrameUnread, err)
	}
	if len(b) < FrameSize {
		return nil, ErrFrameUnread
	}
	return b, nil
}

func (k *Kernel) InodeSize(inode uint64) (int64, error) {
	return k.Int(k.mem, inode, "inode", "i_size")
}
