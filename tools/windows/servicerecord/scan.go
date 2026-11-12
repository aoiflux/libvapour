package servicerecord

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/aoiflux/libvapour/memory"
)

type scanBounds struct {
	regionBytes uint64
	hits        int
}

type candidates struct {
	byTag map[uint32][]uint64
	cuts  []string
}

func tagOffset(tag uint32) uint64 {
	if ls := layoutsWithTag(tag); len(ls) > 0 {
		return ls[0].tagAt
	}
	return 0
}

// A tag whose start would not be heap-aligned is not kept (S34 M2).
func scanRegions(r memory.MemoryReader, regions []addressRange, b scanBounds) candidates {
	c := candidates{byTag: map[uint32][]uint64{}}
	tags := recordTags()
	for _, reg := range regions {
		end := reg.end
		if b.regionBytes > 0 && end-reg.start > b.regionBytes {
			end = reg.start + b.regionBytes
			c.cuts = append(c.cuts, fmt.Sprintf("VAD at 0x%x of 0x%x bytes scanned to 0x%x", reg.start, reg.end-reg.start, end))
		}
		hits := 0
	pages:
		for page := reg.start &^ (pageSize - 1); page < end; page += pageSize {
			data, err := r.ReadAt(page, pageSize)
			if err != nil || len(data) < pageSize {
				continue
			}
			for off := 0; off+4 <= len(data); off += 4 {
				v := binary.LittleEndian.Uint32(data[off:])
				for _, tag := range tags {
					if v != tag {
						continue
					}
					at := page + uint64(off)
					delta := tagOffset(tag)
					if at < delta || at < reg.start || (at-delta)%recordAlignment != 0 {
						continue
					}
					if b.hits > 0 && hits == b.hits {
						c.cuts = append(c.cuts, fmt.Sprintf("VAD at 0x%x: tag hits stopped at %d, from 0x%x", reg.start, b.hits, at))
						break pages
					}
					hits++
					c.byTag[tag] = append(c.byTag[tag], at-delta)
				}
			}
			if page+pageSize < page {
				break
			}
		}
	}
	return c
}

type fitResult struct {
	layout   layout
	records  []record
	rejected map[rejection]int
	tie      []string
}

func (f fitResult) found() bool { return len(f.records) > 0 }

func fitLayouts(r memory.MemoryReader, c candidates, image addressRange) fitResult {
	var best fitResult
	for _, l := range layouts {
		var cur fitResult
		cur.layout, cur.rejected = l, map[rejection]int{}
		for _, at := range c.byTag[l.tag] {
			rec, why := decode(r, l, at, image)
			if why != "" {
				cur.rejected[why]++
				continue
			}
			cur.records = append(cur.records, rec)
		}
		switch {
		case len(cur.records) > len(best.records):
			best = cur
		case len(cur.records) == len(best.records) && len(cur.records) > 0:
			best.tie = append(best.tie, l.name)
		}
	}
	sort.Slice(best.records, func(i, j int) bool { return best.records[i].address < best.records[j].address })
	return best
}
