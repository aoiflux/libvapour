package kernelpattern

import (
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"unicode/utf8"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/tools"
)

// A chunk is read and matched at once; the lookahead after it lets a match
// that starts in the chunk run on into the next one.
const (
	ChunkSize = uint64(0x1000000)
	Overlap   = uint64(0x1000)
)

var (
	ErrNoPattern       = errors.New("kernelpattern: no pattern given")
	ErrNoPhysical      = errors.New("kernelpattern: no physical memory for page table walks")
	ErrPagingMode      = errors.New("kernelpattern: paging mode not known")
	ErrMaxSizeNotAbove = errors.New("kernelpattern: the match size must be above 0")
	ErrMaxSizeTooLarge = errors.New("kernelpattern: the match size is above MaxBufferBytes")
)

type Section struct {
	Start, Size uint64
}

func (s Section) End() uint64 { return s.Start + s.Size }

type piece struct {
	at, physical, size uint64
}

// A block is a stretch of virtual addresses mapped without a gap. Its
// frames need not be contiguous: Source is the first piece's frame and the
// pieces carry the rest.
type Block struct {
	Start, Size, Source uint64
	pieces              []piece
}

func (b *Block) extend(virtual, physical, size uint64) bool {
	if len(b.pieces) > 0 && b.Start+b.Size != virtual {
		return false
	}
	if len(b.pieces) == 0 {
		b.Start, b.Source = virtual, physical
	}
	b.pieces = append(b.pieces, piece{at: b.Size, physical: physical, size: size})
	b.Size += size
	return true
}

func (b Block) read(r memory.MemoryReader, off, n uint64) ([]byte, error) {
	out := make([]byte, 0, n)
	i, _ := slices.BinarySearchFunc(b.pieces, off, func(p piece, at uint64) int {
		if at < p.at {
			return 1
		}
		if at-p.at >= p.size {
			return -1
		}
		return 0
	})
	for ; i < len(b.pieces) && uint64(len(out)) < n; i++ {
		p := b.pieces[i]
		skip := off + uint64(len(out)) - p.at
		take := min(p.size-skip, n-uint64(len(out)))
		raw, err := r.ReadAt(p.physical+skip, take)
		if err != nil {
			return nil, err
		}
		if uint64(len(raw)) != take {
			return nil, fmt.Errorf("frame 0x%x: read 0x%x of 0x%x bytes", p.physical+skip, len(raw), take)
		}
		out = append(out, raw...)
	}
	return out, nil
}

// ScanBlock hands fn each chunk with its lookahead. A chunk that does not
// read is skipped and counted.
func ScanBlock(r memory.MemoryReader, b Block, fn func(data []byte, start uint64)) (unread int) {
	for pos := uint64(0); pos < b.Size; pos += ChunkSize {
		n := min(ChunkSize+Overlap, b.Size-pos)
		data, err := b.read(r, pos, n)
		if err != nil {
			unread++
			continue
		}
		fn(data, b.Start+pos)
	}
	return unread
}

func Coalesce(sections []Section) []Section {
	s := slices.Clone(sections)
	slices.SortFunc(s, func(a, b Section) int { return cmp.Compare(a.Start, b.Start) })
	var out []Section
	for _, x := range s {
		if x.Size == 0 {
			continue
		}
		if n := len(out); n > 0 && x.Start <= out[n-1].End() && out[n-1].End() >= out[n-1].Start {
			if end := x.End(); end > out[n-1].End() || end < x.Start {
				out[n-1].Size = end - out[n-1].Start
			}
			continue
		}
		out = append(out, x)
	}
	return out
}

func Translator(ctx tools.Context, dtb uint64) (*layers.IntelTranslator, error) {
	physical := ctx.PhysicalMemory()
	if physical == nil {
		return nil, ErrNoPhysical
	}
	mode, ok := layers.PagingModeByName(ctx.PagingMode())
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrPagingMode, ctx.PagingMode())
	}
	tr := &layers.IntelTranslator{Physical: physical, CR3: dtb, Mode: mode}
	tr.EnableCache(ctx.Bounds().PTECacheEntries)
	return tr, nil
}

func MappedBlocks(tr *layers.IntelTranslator, mask uint64, fn func(Block)) (layers.MappingStats, error) {
	return SectionBlocks(tr, mask, nil, fn)
}

// Sections are compared with the runs on their masked addresses, so a
// section given in either canonical or masked form selects the same pages;
// a block keeps the section's own form. No sections means every run.
func SectionBlocks(tr *layers.IntelTranslator, mask uint64, sections []Section, fn func(Block)) (layers.MappingStats, error) {
	if mask == 0 {
		mask = ^uint64(0)
	}
	type span struct{ start, end, form uint64 }
	var spans []span
	for _, s := range Coalesce(sections) {
		start := s.Start & mask
		end := start + s.Size
		if end < start || end-1 > mask {
			end = mask + 1
			if mask == ^uint64(0) {
				end = 0
			}
		}
		spans = append(spans, span{start: start, end: end, form: s.Start - start})
	}
	var cur Block
	flush := func() {
		if cur.Size > 0 {
			fn(cur)
		}
		cur = Block{}
	}
	emit := func(virtual, physical, size uint64) {
		if !cur.extend(virtual, physical, size) {
			flush()
			cur.extend(virtual, physical, size)
		}
	}
	stats, err := tr.Mapping(func(r layers.MappedRun) error {
		if sections == nil {
			emit(r.Virtual, r.Physical, r.Size)
			return nil
		}
		v := r.Virtual & mask
		for _, s := range spans {
			lo, hi := max(v, s.start), v+r.Size
			if s.end != 0 && s.end < hi {
				hi = s.end
			}
			if hi <= lo || hi < v {
				continue
			}
			emit(lo+s.form, r.Physical+(lo-v), hi-lo)
		}
		return nil
	})
	flush()
	return stats, err
}

type Pattern struct {
	re *regexp.Regexp
}

// Matching is on bytes, one character per byte: (?s) lets . match a newline
// byte, and the data is read as Latin-1 so \xff is the byte 0xff.
func CompilePattern(text string) (*Pattern, error) {
	if text == "" {
		return nil, ErrNoPattern
	}
	re, err := regexp.Compile("(?s:" + text + ")")
	if err != nil {
		return nil, err
	}
	return &Pattern{re: re}, nil
}

func PatternOption(ctx tools.Context, key string) (*Pattern, error) {
	if _, err := ctx.PatternOption(key, false); err != nil {
		return nil, err
	}
	text, err := ctx.StringOption(key)
	if err != nil {
		return nil, err
	}
	if text == "" {
		return nil, fmt.Errorf("option %q: %w", key, ErrNoPattern)
	}
	return CompilePattern(text)
}

// latin1 maps each byte to the rune of the same value; offsets maps an
// index of the encoded text back to the byte it came from.
func latin1(data []byte, buf []byte, offsets []int) ([]byte, []int) {
	buf, offsets = buf[:0], offsets[:0]
	for i, c := range data {
		if c < utf8.RuneSelf {
			buf = append(buf, c)
			offsets = append(offsets, i)
			continue
		}
		buf = utf8.AppendRune(buf, rune(c))
		offsets = append(offsets, i, i)
	}
	offsets = append(offsets, len(data))
	return buf, offsets
}

func ascii(data []byte) bool {
	for _, c := range data {
		if c >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func (p *Pattern) find(data []byte, buf *[]byte, offsets *[]int, n int) [][2]int {
	if ascii(data) {
		var out [][2]int
		for _, m := range p.re.FindAllIndex(data, n) {
			out = append(out, [2]int{m[0], m[1]})
		}
		return out
	}
	*buf, *offsets = latin1(data, *buf, *offsets)
	var out [][2]int
	for _, m := range p.re.FindAllIndex(*buf, n) {
		out = append(out, [2]int{(*offsets)[m[0]], (*offsets)[m[1]]})
	}
	return out
}

func (p *Pattern) Match(data []byte) ([]byte, bool) {
	var buf []byte
	var offsets []int
	m := p.find(data, &buf, &offsets, 1)
	if len(m) == 0 {
		return nil, false
	}
	return data[m[0][0]:m[0][1]], true
}

// Limit caps the matches taken from one chunk (0 is no cap); Capped counts
// the chunks that reached it.
type Scanner struct {
	Pattern *Pattern
	Limit   int
	Capped  int
	buf     []byte
	offsets []int
}

// Chunks come from ScanBlock: the bytes past ChunkSize are the lookahead and
// belong to the next chunk, so a match starting there is the next chunk's.
func (s *Scanner) Matches(data []byte, start uint64, emit func(at uint64, match []byte)) {
	if s.Pattern == nil {
		return
	}
	n := -1
	if s.Limit > 0 {
		n = s.Limit + 1
	}
	found := s.Pattern.find(data, &s.buf, &s.offsets, n)
	taken := 0
	for _, m := range found {
		if uint64(m[0]) >= ChunkSize {
			break
		}
		if s.Limit > 0 && taken == s.Limit {
			s.Capped++
			break
		}
		taken++
		emit(start+uint64(m[0]), data[m[0]:m[1]])
	}
}

func (s *Scanner) Chunk(data []byte, start uint64, emit func(uint64)) {
	s.Matches(data, start, func(at uint64, _ []byte) { emit(at) })
}

func Truncate(match []byte, maxSize uint64) []byte {
	if uint64(len(match)) > maxSize {
		match = match[:maxSize]
	}
	return slices.Clone(match)
}

// Unset, a match keeps the project's row preview length.
func MaxSizeOption(ctx tools.Context, key string) (uint64, error) {
	v, set, err := ctx.UintOption(key)
	if err != nil {
		return 0, err
	}
	if !set {
		return uint64(ctx.Bounds().RowPreviewBytes), nil
	}
	if v == 0 {
		return 0, fmt.Errorf("option %q: %w", key, ErrMaxSizeNotAbove)
	}
	// A kept match is a buffer in a row.
	if v > uint64(ctx.Bounds().MaxBufferBytes) {
		return 0, fmt.Errorf("option %q: %d: %w", key, v, ErrMaxSizeTooLarge)
	}
	return v, nil
}

func ReportMapping(ctx tools.Context, tool, space string, stats layers.MappingStats) {
	if stats.UnreadableTables > 0 || stats.UncapturedPages > 0 {
		ctx.AddDiagnostic("%s: %s: %d page tables did not read and %d mapped pages are not in the image; they were not searched",
			tool, space, stats.UnreadableTables, stats.UncapturedPages)
	}
}
