package linuxobj

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
)

var (
	ErrNoPhysicalLayer = errors.New("linuxobj: no physical memory layer")
	ErrPagingMode      = errors.New("linuxobj: paging mode not recognised")
	ErrTableUnread     = errors.New("linuxobj: page table does not read")
	ErrReadTooLarge    = errors.New("linuxobj: read larger than Limits.MaxBufferBytes")
)

// S46 G1: bit 0 of every entry is P, bit 6 of a leaf is D and bit 7 of
// an entry that may map a page is PS.
const (
	entryPresent = 1 << 0
	entryDirty   = 1 << 6
	entryLarge   = 1 << 7
)

const (
	pageShift = 12
	pageBytes = 1 << pageShift
	// S46 G3: __PHYSICAL_MASK_SHIFT is 52 for 64-bit and PAE kernels and 32
	// for the 2-level one.
	physicalBitsWide   = 52
	physicalBitsNarrow = 32
	pagingPrefix       = "linux-"
)

type pageLevel struct {
	bits  uint
	shift uint
	large bool
}

type pageShape struct {
	name       string
	entryBytes uint64
	rootMask   uint64
	levels     []pageLevel
}

// S46 G1, G2: the table walks of SDM Vol. 3A sections 5.3, 5.4 and 5.5.
var (
	shapeX86 = pageShape{name: "x86", entryBytes: 4, rootMask: 0xfffff000,
		levels: []pageLevel{{10, 22, true}, {10, 12, false}}}
	shapePAE = pageShape{name: "x86pae", entryBytes: 8, rootMask: 0xffffffe0,
		levels: []pageLevel{{2, 30, false}, {9, 21, true}, {9, 12, false}}}
	shapeX64 = pageShape{name: "x64", entryBytes: 8, rootMask: 0x000ffffffffff000,
		levels: []pageLevel{{9, 39, false}, {9, 30, true}, {9, 21, true}, {9, 12, false}}}
	shapeLA57 = pageShape{name: "la57", entryBytes: 8, rootMask: 0x000ffffffffff000,
		levels: []pageLevel{{9, 48, false}, {9, 39, false}, {9, 30, true}, {9, 21, true}, {9, 12, false}}}
)

func shapeNamed(mode string) (pageShape, bool) {
	mode = strings.TrimPrefix(mode, pagingPrefix)
	for _, s := range []pageShape{shapeX64, shapeLA57, shapePAE, shapeX86} {
		if s.name == mode {
			return s, true
		}
	}
	return pageShape{}, false
}

func (s pageShape) tableBytes(level int) uint64 {
	return s.entryBytes << s.levels[level].bits
}

type PageFault struct {
	Virtual  uint64
	Level    int
	Entry    uint64
	Reserved bool
	span     uint64
}

func (f *PageFault) Error() string {
	why := "is not present"
	if f.Reserved {
		why = "sets PS where no page can be mapped"
	}
	return fmt.Sprintf("linuxobj: virtual address %#x: level %d entry %#x %s", f.Virtual, f.Level, f.Entry, why)
}

func (f *PageFault) Span() uint64 { return f.span }

type PageTables struct {
	physical  memory.MemoryReader
	dtb       uint64
	root      uint64
	shape     pageShape
	frameMask uint64
	maxRead   uint64

	tables map[uint64][]byte
	order  []uint64
	most   int
}

// S46 4.6 step 1: a session that records no paging mode is taken to use 4-level
// paging when its pointers are 8 bytes; 32-bit modes must be named.
func (k *Kernel) pagingShape() (pageShape, memory.MemoryReader, error) {
	physical := k.ctx.PhysicalMemory()
	if physical == nil {
		return pageShape{}, nil, ErrNoPhysicalLayer
	}
	mode := k.ctx.PagingMode()
	if mode == "" && k.PointerSize() == 8 {
		mode = shapeX64.name
	}
	shape, ok := shapeNamed(mode)
	if !ok {
		return pageShape{}, nil, fmt.Errorf("%w: %q", ErrPagingMode, k.ctx.PagingMode())
	}
	return shape, physical, nil
}

// S46 G3: physical_mask is __PHYSICAL_MASK when the kernel makes it a
// variable, and AMD memory encryption clears its encryption bit from it.
func (k *Kernel) physicalMask(shape pageShape) uint64 {
	if !k.physSet {
		k.physSet = true
		k.phys = 1<<physicalBitsWide - 1
		if shape.entryBytes == 4 {
			k.phys = 1<<physicalBitsNarrow - 1
		}
		if s, err := k.sym.LookupSymbol("physical_mask"); err == nil && shape.entryBytes == 8 {
			if b, err := k.mem.ReadAt(s.Address, 8); err == nil && len(b) == 8 {
				if v := binary.LittleEndian.Uint64(b); v > pageBytes {
					k.phys = v
				}
			}
		}
	}
	return k.phys
}

// S46 section 8: one cached table is 512 entries, so the cache holds as many tables
// as Limits.PTECacheEntries holds entries.
func (k *Kernel) PageTables(dtb uint64) (*PageTables, error) {
	shape, physical, err := k.pagingShape()
	if err != nil {
		return nil, err
	}
	b := k.ctx.Bounds()
	return &PageTables{
		physical:  physical,
		dtb:       dtb,
		root:      dtb & shape.rootMask,
		shape:     shape,
		frameMask: k.physicalMask(shape) &^ (pageBytes - 1),
		maxRead:   uint64(b.MaxBufferBytes),
		tables:    map[uint64][]byte{},
		most:      max(1, b.PTECacheEntries/512),
	}, nil
}

func (k *Kernel) Translator(dtb uint64) (*layers.IntelTranslator, error) {
	shape, physical, err := k.pagingShape()
	if err != nil {
		return nil, err
	}
	mode, ok := layers.PagingModeByName(shape.name)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrPagingMode, shape.name)
	}
	wide := uint64(1<<physicalBitsWide - 1)
	t := &layers.IntelTranslator{Physical: physical, CR3: dtb,
		Mode: layers.LinuxMode(mode, 0, wide&^k.physicalMask(shape))}
	if memory.IsImmutableSnapshot(physical) {
		t.EnableCache(k.ctx.Bounds().PTECacheEntries)
	}
	return t, nil
}

func (p *PageTables) DTB() uint64 { return p.dtb }

func (p *PageTables) PageSize() uint64 { return pageBytes }

func (p *PageTables) Size() uint64 { return ^uint64(0) }

func Dirty(entry uint64) bool { return entry&entryPresent != 0 && entry&entryDirty != 0 }

func (p *PageTables) table(base uint64, n uint64) ([]byte, error) {
	if t, ok := p.tables[base]; ok {
		return t, nil
	}
	t, err := p.physical.ReadAt(base, n)
	if err != nil {
		return nil, fmt.Errorf("%w: %#x: %w", ErrTableUnread, base, err)
	}
	if uint64(len(t)) < n {
		return nil, fmt.Errorf("%w: %#x: %w", ErrTableUnread, base, ErrShortRead)
	}
	if len(p.order) >= p.most {
		delete(p.tables, p.order[0])
		p.order = p.order[1:]
	}
	p.tables[base] = t
	p.order = append(p.order, base)
	return t, nil
}

// S46 G2: each level takes its index from the linear address, a present
// entry either maps a page (PS where allowed, or the last level) or names
// the next table, and the page's offset comes from the address.
func (p *PageTables) Translate(virtual uint64) (physical, size, entry uint64, err error) {
	s := p.shape
	base := p.root
	for i, lvl := range s.levels {
		t, err := p.table(base, s.tableBytes(i))
		if err != nil {
			return 0, 0, 0, err
		}
		index := virtual >> lvl.shift & (1<<lvl.bits - 1)
		e := uint64(binary.LittleEndian.Uint32(t[index*s.entryBytes:]))
		if s.entryBytes == 8 {
			e = binary.LittleEndian.Uint64(t[index*s.entryBytes:])
		}
		span := uint64(1) << lvl.shift
		if e&entryPresent == 0 {
			return 0, 0, e, &PageFault{Virtual: virtual, Level: i, Entry: e, span: span}
		}
		last := i == len(s.levels)-1
		if e&entryLarge != 0 && !last && !lvl.large {
			return 0, 0, e, &PageFault{Virtual: virtual, Level: i, Entry: e, Reserved: true, span: span}
		}
		if last || (lvl.large && e&entryLarge != 0) {
			frame := e & p.frameMask &^ (span - 1)
			if s.entryBytes == 4 {
				frame = e &^ (span - 1) & (1<<physicalBitsNarrow - 1)
			}
			return frame | virtual&(span-1), span, e, nil
		}
		base = e & p.frameMask
		if s.entryBytes == 4 {
			base = e &^ (pageBytes - 1)
		}
	}
	return 0, 0, 0, &PageFault{Virtual: virtual, Level: len(s.levels)}
}

func (p *PageTables) ReadAt(virtual, size uint64) ([]byte, error) {
	if size > p.maxRead {
		return nil, fmt.Errorf("%w: %d bytes at %#x", ErrReadTooLarge, size, virtual)
	}
	out := make([]byte, 0, size)
	for at := virtual; uint64(len(out)) < size; {
		n := min(size-uint64(len(out)), pageBytes-at%pageBytes)
		pa, _, _, err := p.Translate(at)
		if err != nil {
			return nil, err
		}
		b, err := p.physical.ReadAt(pa, n)
		if err != nil {
			return nil, fmt.Errorf("linuxobj: virtual address %#x at physical %#x: %w", at, pa, err)
		}
		if uint64(len(b)) < n {
			return nil, fmt.Errorf("linuxobj: virtual address %#x: %w", at, ErrShortRead)
		}
		out = append(out, b...)
		at += n
	}
	return out, nil
}

// Pages that do not translate or read are zeros; padded counts those bytes.
func (p *PageTables) ReadPadded(virtual, size uint64) (data []byte, padded int) {
	size = min(size, p.maxRead)
	out := make([]byte, 0, size)
	for at := virtual; uint64(len(out)) < size; {
		n := min(size-uint64(len(out)), pageBytes-at%pageBytes)
		var b []byte
		if pa, _, _, err := p.Translate(at); err == nil {
			if r, err := p.physical.ReadAt(pa, n); err == nil && uint64(len(r)) == n {
				b = r
			}
		}
		if b == nil {
			b = make([]byte, n)
			padded += int(n)
		}
		out = append(out, b...)
		at += n
	}
	return out, padded
}
