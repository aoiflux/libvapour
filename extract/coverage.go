package extract

import "sort"

// Cached-file pages arrive out of order and leave sparse holes that read back
// as zeroes; Coverage records what was really written so the holes can be
// reported.
type Coverage struct {
	spans  []Gap
	sorted bool
}

func (c *Coverage) Add(start, length uint64) {
	length = clipEnd(start, length) - start
	if length == 0 {
		return
	}
	c.spans = append(c.spans, Gap{Start: start, Length: length})
	c.sorted = false
}

// Overlaps are merged: two sources may describe the same file offset.
func (c *Coverage) Covered() []Gap {
	c.merge()
	return append([]Gap(nil), c.spans...)
}

func (c *Coverage) Bytes() uint64 {
	c.merge()
	return GapMap(c.spans).PaddedBytes()
}

func (c *Coverage) End() uint64 {
	c.merge()
	if len(c.spans) == 0 {
		return 0
	}
	return c.spans[len(c.spans)-1].End()
}

func (c *Coverage) Holes(total uint64) GapMap {
	c.merge()
	var holes GapMap
	for _, r := range GapMap(c.spans).Runs(0, total) {
		holes = append(holes, Gap{Start: r.Offset, Length: r.Length})
	}
	return holes
}

func (c *Coverage) merge() {
	if c.sorted {
		return
	}
	sort.Slice(c.spans, func(i, j int) bool { return c.spans[i].Start < c.spans[j].Start })
	out := c.spans[:0]
	for _, s := range c.spans {
		if n := len(out); n > 0 && s.Start <= out[n-1].End() {
			out[n-1].Length = max(out[n-1].End(), s.End()) - out[n-1].Start
			continue
		}
		out = append(out, s)
	}
	c.spans = out
	c.sorted = true
}
