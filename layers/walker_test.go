package layers

import (
	"errors"
	"testing"
)

const kva = uint64(0xfffff80000200000)

func translateOK(t *testing.T, tr *IntelTranslator, va, want uint64) {
	t.Helper()
	got, err := tr.Translate(va)
	if err != nil || got != want {
		t.Fatalf("%s: Translate(0x%x) = 0x%x, %v; want 0x%x", tr.Mode.Name(), va, got, err, want)
	}
}

func TestFourKilobytePagesTranslate(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(kva, 0x80000)
	pt.page(0x7ff000, 0x81000)
	tr := pt.translator()
	translateOK(t, tr, kva+0x123, 0x80123)
	translateOK(t, tr, 0x7ff456, 0x81456)
}

func TestTheZeroModeIsFourLevel(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(kva, 0x80000)
	translateOK(t, &IntelTranslator{Physical: img, CR3: 0x1000}, kva+8, 0x80008)
}

func TestCR3FlagBitsAreNotPartOfTheRoot(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(kva, 0x80000)
	translateOK(t, &IntelTranslator{Physical: img, CR3: 0x1000 | 0x018, Mode: ModeX64}, kva, 0x80000)
}

func TestLargePagesDropTheirLowEntryBits(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pat := uint64(1) << 12
	pt.set(2, kva, 0x40000000|pat|fP|fPS|fNX)
	pt.set(1, 0xfffff80080000000, 0x80000000|pat|fP|fPS)
	tr := pt.translator()
	translateOK(t, tr, kva+0x1abcde, 0x401abcde)
	translateOK(t, tr, 0xfffff80080000000+0x2345678, 0x82345678)
}

func TestReservedBitsAreReadPast(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.set(2, kva, 0x40000000|uint64(1)<<17|fP|fPS)
	translateOK(t, pt.translator(), kva+0x5000, 0x40005000)
}

func TestFiveLevelPaging(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeLA57, 0x1000, 0x2000)
	va := uint64(0xff11000000201000)
	pt.page(va, 0x90000)
	translateOK(t, pt.translator(), va+5, 0x90005)
	if got := ModeLA57.canonical(0x0111000000201000); got != va {
		t.Fatalf("canonical = 0x%x", got)
	}
}

func TestPAEPaging(t *testing.T) {
	img := newPhys(0x100000)
	img.put8(0x1020+8*3, 0x2000|fP)
	img.put8(0x2000+8*0x1ff, 0x3000|fP|fRW)
	img.put8(0x3000+8*0x1ff, 0x80000|fP|fRW|fNX)
	img.put8(0x2000+8*0x1fe, 0x400000|fP|fPS)
	tr := &IntelTranslator{Physical: img, CR3: 0x1020, Mode: ModeX86PAE}
	translateOK(t, tr, 0xfffff123, 0x80123)
	translateOK(t, tr, 0xffc12345, 0x412345)
}

func TestThirtyTwoBitPagingWithPSE36(t *testing.T) {
	img := newPhys(0x100000)
	img.put4(0x1000+4*0x300, uint32(0x2000|fP|fRW))
	img.put4(0x2000+4*0x005, uint32(0x81000|fP|fRW))
	img.put4(0x1000+4*0x301, uint32(0x00800000|0x3<<13|fP|fPS))
	tr := &IntelTranslator{Physical: img, CR3: 0x1000, Mode: ModeX86NonPAE}
	translateOK(t, tr, 0xc0005abc, 0x81abc)
	translateOK(t, tr, 0xc0412345, 0x3_00812345)
}

func TestAMissAboveTheLeafCarriesItsSpan(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(kva, 0x80000)
	tr := pt.translator()
	for _, c := range []struct {
		va, span uint64
	}{
		{0x0000100000000000, 1 << 39},
		{0xfffff88000000000, 1 << 39},
		{kva + 1<<30, 1 << 30},
		{kva + 1<<21, 1 << 21},
		{kva + 0x1000, 0},
	} {
		_, err := tr.Translate(c.va)
		miss, ok := missOf(err)
		if !ok || miss.Kind != PageInvalid || miss.Span != c.span || !errors.Is(err, ErrPageInvalid) {
			t.Errorf("0x%x: %v (%+v), want a miss over 0x%x", c.va, err, miss, c.span)
		}
	}
}

func TestATableOutsideTheImageIsNotCaptured(t *testing.T) {
	img := newPhys(0x10000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.set(2, kva, 0x7000000|fP)
	_, err := pt.translator().Translate(kva)
	miss, ok := missOf(err)
	if !ok || miss.Kind != PageNotCaptured || miss.Span != 1<<21 || !errors.Is(err, ErrPageNotCaptured) {
		t.Fatalf("got %v (%+v)", err, miss)
	}
	if _, err := (&IntelTranslator{Physical: img, CR3: 0x100000}).Translate(0); err == nil {
		t.Fatal("a root outside the image translated")
	}
}

func TestWindowsNotPresentLeaves(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	tr := pt.translator()
	cases := []struct {
		entry uint64
		kind  PageErrorKind
		file  int
		off   uint64
	}{
		{0x55000 | fTr | 4<<5, -1, 0, 0},
		{0xffffa00012345000 | fPro | fTr, PagePrototype, 0, 0},
		{0x0000001200000000 | 3<<1 | 4<<5, PageInPagefile, 3, 0x12000},
		{4 << 5, PageDemandZero, 0, 0},
		{0, PageInvalid, 0, 0},
		{1 << 4, PageInvalid, 0, 0},
	}
	for i, c := range cases {
		va := kva + uint64(i)*0x1000
		pt.set(3, va, c.entry)
		pa, err := tr.Translate(va + 0x10)
		leaf, lerr := tr.LeafEntry(va)
		if lerr != nil || leaf != c.entry {
			t.Errorf("entry 0x%x: LeafEntry = 0x%x, %v", c.entry, leaf, lerr)
		}
		if c.kind < 0 {
			if err != nil || pa != 0x55010 {
				t.Errorf("transition entry: 0x%x, %v", pa, err)
			}
			continue
		}
		miss, ok := missOf(err)
		if !ok || miss.Kind != c.kind || miss.PageFileNumber != c.file || miss.PageFileOffset != c.off || miss.Span != 0 {
			t.Errorf("entry 0x%x: %v (%+v), want %s", c.entry, err, miss, c.kind)
		}
	}
}

func TestATransitionEntryAboveTheLeafNamesATable(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.page(kva, 0x80000)
	pd := pt.table(2, kva)
	ptab := pt.table(3, kva)
	img.put8(pd+8*pt.mode.index(kva, 2), ptab|fTr|fPS)
	translateOK(t, pt.translator(), kva+1, 0x80001)
	img.put8(pd+8*pt.mode.index(kva, 2), ptab|fTr|fPro)
	if _, err := pt.translator().Translate(kva); err == nil {
		t.Fatal("a prototype directory entry was followed")
	}
}

func TestLinuxModeFollowsOnlyPresentEntries(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.set(3, kva, 0x55000|fTr)
	tr := &IntelTranslator{Physical: img, CR3: 0x1000, Mode: LinuxMode(ModeX64, 46, 0)}
	if _, err := tr.Translate(kva); err == nil {
		t.Fatal("a not-present Linux entry translated")
	}
	if got := LinuxMode(ModeLA57, 0, 0).Name(); got != "linux-la57" {
		t.Fatalf("name %q", got)
	}
	if got := LinuxMode(PagingMode{}, 0, 0).Name(); got != "linux-x64" {
		t.Fatalf("name %q", got)
	}
}

func TestLinuxModeMasksTheFrame(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	sme := uint64(1) << 47
	pt.set(3, kva, 0x80000|sme|fP)
	pt.set(2, kva+1<<21, 0x200000|sme|fP|fPS)
	tr := &IntelTranslator{Physical: img, CR3: 0x1000 | sme, Mode: LinuxMode(ModeX64, 46, sme)}
	translateOK(t, tr, kva+3, 0x80003)
	translateOK(t, tr, kva+1<<21+0x1234, 0x201234)

	wide := &IntelTranslator{Physical: img, CR3: 0x1000, Mode: LinuxMode(ModeX64, 52, 0)}
	if pa, err := wide.Translate(kva); err != nil || pa != 0x80000|sme {
		t.Fatalf("52-bit frame: 0x%x, %v", pa, err)
	}
	if pae := LinuxMode(ModeX86PAE, 46, sme); pae.frameMask != ModeX86PAE.frameMask {
		t.Fatal("a 32-bit mode's frame field changed")
	}
}

func TestLeafEntryAboveTheLeafIsAnError(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	pt.set(2, kva, 0x400000|fP|fPS|fD)
	tr := pt.translator()
	if e, err := tr.LeafEntry(kva + 0x5000); err != nil || e != 0x400000|fP|fPS|fD {
		t.Fatalf("large-page entry: 0x%x, %v", e, err)
	}
	if _, err := tr.LeafEntry(kva + 1<<30); err == nil {
		t.Fatal("a miss above the leaf gave an entry")
	}
}

func TestTheEntryCacheSavesReads(t *testing.T) {
	img := newPhys(0x100000)
	pt := newTables(img, ModeX64, 0x1000, 0x2000)
	for i := range uint64(64) {
		pt.page(kva+i*0x1000, 0x80000+i*0x1000)
	}
	walk := func(tr *IntelTranslator) int {
		img.reads = 0
		for range 3 {
			for i := range uint64(64) {
				translateOK(t, tr, kva+i*0x1000, 0x80000+i*0x1000)
			}
		}
		return img.reads
	}
	plain := walk(pt.translator())
	cached := pt.translator()
	cached.EnableCache(1024)
	if got := walk(cached); got != 64+3 || plain != 3*64*4 {
		t.Fatalf("reads: %d cached, %d plain", got, plain)
	}
}

func TestTheEntryCacheKeepsItsCapacity(t *testing.T) {
	c := newEntryCache(4)
	for i := range uint64(10) {
		c.store(i*8, i)
	}
	if c.len() != 4 {
		t.Fatalf("cache holds %d", c.len())
	}
	for i := range uint64(6) {
		if _, ok := c.lookup(i * 8); ok {
			t.Errorf("evicted entry %d still cached", i)
		}
	}
	c.lookup(6 * 8)
	c.store(80, 10)
	if v, ok := c.lookup(6 * 8); !ok || v != 6 {
		t.Fatal("a used entry lost its second chance")
	}
	if newEntryCache(0).slots == nil || cap(newEntryCache(0).slots) == 0 {
		t.Fatal("a zero capacity is not the default")
	}
}
