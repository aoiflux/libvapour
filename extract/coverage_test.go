package extract

import (
	"fmt"
	"testing"
)

func TestCoverageMergesOutOfOrderPieces(t *testing.T) {
	var c Coverage
	c.Add(0x3000, 0x1000)
	c.Add(0x0, 0x1000)
	c.Add(0x800, 0x1000)
	c.Add(0x1800, 0x800)
	c.Add(0x9000, 0)
	got := c.Covered()
	if fmt.Sprint(got) != fmt.Sprint([]Gap{{0, 0x2000}, {0x3000, 0x1000}}) {
		t.Errorf("Covered %v", got)
	}
	if c.Bytes() != 0x3000 || c.End() != 0x4000 {
		t.Errorf("Bytes 0x%x End 0x%x", c.Bytes(), c.End())
	}
	if h := c.Holes(0x6000); fmt.Sprint(h) != fmt.Sprint(GapMap{{0x2000, 0x1000}, {0x4000, 0x2000}}) {
		t.Errorf("Holes %v", h)
	}
	if h := c.Holes(0x1000); len(h) != 0 {
		t.Errorf("Holes inside the covered start: %v", h)
	}
}

func TestCoverageCopiesAndAddsAfterReading(t *testing.T) {
	var c Coverage
	c.Add(0x1000, 0x1000)
	got := c.Covered()
	got[0].Length = 1
	c.Add(0x0, 0x1000)
	if c.Bytes() != 0x2000 || len(c.Covered()) != 1 {
		t.Errorf("Covered %v", c.Covered())
	}
}

func TestEmptyCoverage(t *testing.T) {
	var c Coverage
	if c.Bytes() != 0 || c.End() != 0 || len(c.Covered()) != 0 {
		t.Error("empty coverage reports bytes")
	}
	if h := c.Holes(0x10); len(h) != 1 || h[0] != (Gap{0, 0x10}) {
		t.Errorf("Holes %v", h)
	}
}

func TestCoverageClipsAtTheTop(t *testing.T) {
	var c Coverage
	c.Add(^uint64(0)-0xF, 0x100)
	if c.Bytes() != 0xF {
		t.Errorf("Bytes 0x%x", c.Bytes())
	}
}
