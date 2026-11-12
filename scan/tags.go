package scan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"sync"

	"github.com/aoiflux/libvapour/memory"
)

var ErrNilReader = errors.New("scan: no memory to scan")

type TagMatch struct {
	Tag    string
	Offset uint64
}

func TagValue(tag string) uint64 {
	var b [4]byte
	copy(b[:], tag)
	return uint64(binary.LittleEndian.Uint32(b[:]))
}

const (
	sweepChunk = 1 << 20
	sweepPage  = 0x1000
)

type sweepSpan struct{ start, end uint64 }

// One pass per chunk serves every tag, and chunks overlap by a tag's length
// less one so a tag across a chunk edge is seen once, in the chunk where it
// starts. A chunk that does not read is retried page by page, so a hole in a
// sparse image costs only its own pages.
func SweepTags(reader memory.MemoryReader, tags []string, workers int) ([]TagMatch, error) {
	if reader == nil {
		return nil, ErrNilReader
	}
	needles := uniqueTags(tags)
	if len(needles) == 0 {
		return nil, nil
	}
	width := uint64(0)
	for _, n := range needles {
		width = max(width, uint64(len(n)))
	}
	var spans []sweepSpan
	for _, r := range memory.MappedRanges(reader) {
		for at := r.Start; at < r.End; {
			end := min(r.End, at+sweepChunk)
			if end <= at {
				break
			}
			spans = append(spans, sweepSpan{at, end})
			at = end
		}
	}
	if workers < 1 {
		workers = 1
	}
	results := make([][]TagMatch, len(spans))
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(workers, max(len(spans), 1)) {
		wg.Go(func() {
			for i := range next {
				results[i] = sweepSpanTags(reader, spans[i], width, needles)
			}
		})
	}
	for i := range spans {
		next <- i
	}
	close(next)
	wg.Wait()
	var out []TagMatch
	for _, r := range results {
		out = append(out, r...)
	}
	slices.SortFunc(out, func(a, b TagMatch) int {
		if a.Offset != b.Offset {
			if a.Offset < b.Offset {
				return -1
			}
			return 1
		}
		return bytesCompare(a.Tag, b.Tag)
	})
	return out, nil
}

func bytesCompare(a, b string) int { return bytes.Compare([]byte(a), []byte(b)) }

func uniqueTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		if t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

func sweepSpanTags(reader memory.MemoryReader, s sweepSpan, width uint64, needles []string) []TagMatch {
	limit := reader.Size()
	readEnd := s.end + width - 1
	if limit > 0 && readEnd > limit {
		readEnd = limit
	}
	if buf, err := reader.ReadAt(s.start, readEnd-s.start); err == nil {
		return findTags(buf, s.start, s.end, needles)
	}
	var out []TagMatch
	for at := s.start; at < s.end; at += sweepPage {
		end := min(at+sweepPage, s.end)
		buf, err := reader.ReadAt(at, min(end+width-1, readEnd)-at)
		if err != nil {
			buf, err = reader.ReadAt(at, end-at)
			if err != nil {
				continue
			}
		}
		out = append(out, findTags(buf, at, end, needles)...)
	}
	return out
}

func findTags(buf []byte, base, end uint64, needles []string) []TagMatch {
	var out []TagMatch
	for _, n := range needles {
		needle := []byte(n)
		for i := 0; i+len(needle) <= len(buf); {
			j := bytes.Index(buf[i:], needle)
			if j < 0 {
				break
			}
			at := base + uint64(i+j)
			if at >= end {
				break
			}
			out = append(out, TagMatch{Tag: n, Offset: at})
			i += j + 1
		}
	}
	return out
}
