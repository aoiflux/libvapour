package linuxobj_test

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxobj"
	lt "github.com/aoiflux/libvapour/tools/linuxobj/linuxobjtest"
)

const (
	pP   = 1 << 0
	pRW  = 1 << 1
	pUS  = 1 << 2
	pD   = 1 << 6
	pPS  = 1 << 7
	pNX  = 1 << 63
	pTab = pP | pRW | pUS
)

type tables struct {
	phys *lt.Memory
	ctx  tools.Context
	k    *linuxobj.Kernel
}

func pageKernel(t *testing.T, mode string, width uint8, l limits.Limits) *tables {
	t.Helper()
	phys := lt.NewMemory()
	tab := symbols.NewTable("s46pages", width)
	ctx := tools.Context{Memory: lt.NewMemory(), Symbols: tab, Profile: profiles.LinuxX64Profile{}, Limits: l,
		Options: map[string]any{tools.OptionPhysicalMemory: phys, tools.OptionPagingMode: mode}}
	return &tables{phys: phys, ctx: ctx, k: linuxobj.New(ctx)}
}

func (p *tables) entry(table uint64, index int, v uint64) { p.phys.U64(table+uint64(index)*8, v) }

func (p *tables) entry32(table uint64, index int, v uint32) { p.phys.U32(table+uint64(index)*4, v) }

// One PML4 at 0x1000 maps three areas: a 4 KiB dirty page, a 2 MiB page with
// its PAT bit 12 set and a 1 GiB page with software bits above bit 51; PML4
// slot 1 is absent and slot 2 sets PS, which no PML4E may.
func (p *tables) x64() {
	p.phys.Map(0x1000, 0x5000)
	p.entry(0x1000, 0, 0x2000|pTab)
	p.entry(0x1000, 2, 0x9000|pTab|pPS)
	p.entry(0x2000, 0, 0x3000|pTab)
	p.entry(0x2000, 1, 0x4000_0000|pP|pPS|pNX|1<<52|1<<58)
	p.entry(0x3000, 0, 0x4000|pTab)
	p.entry(0x3000, 1, 0x60_0000|pP|pPS|pD|1<<12)
	p.entry(0x4000, 5, 0x10_0000|pP|pD|pNX)
	p.entry(0x4000, 6, 0x11_0000|pP)
	p.phys.Write(0x10_0000, []byte("dirty page"))
	p.phys.Write(0x11_0ffc, []byte("WXYZ"))
}

func TestFourLevelWalkMapsEachPageSize(t *testing.T) {
	p := pageKernel(t, "linux-x64", 8, limits.Limits{})
	p.x64()
	pt, err := p.k.PageTables(0x1000 | 0x18)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		va, pa, size uint64
		dirty        bool
	}{
		{0x5123, 0x10_0123, 0x1000, true},
		{0x6ffc, 0x11_0ffc, 0x1000, false},
		{0x20_0000 + 0x1234, 0x60_1234, 0x20_0000, true},
		{0x4000_0000 + 0x12_3456, 0x4012_3456, 0x4000_0000, false},
	}
	for _, c := range cases {
		pa, size, entry, err := pt.Translate(c.va)
		if err != nil || pa != c.pa || size != c.size || linuxobj.Dirty(entry) != c.dirty {
			t.Errorf("%#x: %#x size %#x dirty %t, %v; want %#x size %#x dirty %t", c.va, pa, size,
				linuxobj.Dirty(entry), err, c.pa, c.size, c.dirty)
		}
	}
	if pt.DTB() != 0x1018 || pt.PageSize() != 0x1000 {
		t.Errorf("DTB %#x page %#x", pt.DTB(), pt.PageSize())
	}
}

func TestFaultsSayHowMuchTheMissingEntryCovers(t *testing.T) {
	p := pageKernel(t, "linux-x64", 8, limits.Limits{})
	p.x64()
	pt, _ := p.k.PageTables(0x1000)
	for _, c := range []struct {
		va       uint64
		level    int
		span     uint64
		reserved bool
	}{
		{1 << 39, 0, 1 << 39, false},
		{2 << 39, 0, 1 << 39, true},
		{2 << 30, 1, 1 << 30, false},
		{0x40_0000, 2, 1 << 21, false},
		{0x7000, 3, 1 << 12, false},
	} {
		_, _, _, err := pt.Translate(c.va)
		var f *linuxobj.PageFault
		if !errors.As(err, &f) || f.Level != c.level || f.Span() != c.span || f.Reserved != c.reserved || f.Virtual != c.va {
			t.Errorf("%#x: %v (%+v)", c.va, err, f)
		}
	}
	p.entry(0x1000, 3, 0x7700_0000|pTab)
	pt, _ = p.k.PageTables(0x1000)
	if _, _, _, err := pt.Translate(3 << 39); !errors.Is(err, linuxobj.ErrTableUnread) {
		t.Errorf("table outside the image: %v", err)
	}
}

func TestTheWalkAgreesWithTheSharedTranslator(t *testing.T) {
	p := pageKernel(t, "linux-x64", 8, limits.Limits{PTECacheEntries: 512})
	p.x64()
	pt, _ := p.k.PageTables(0x1000)
	tr, err := p.k.Translator(0x1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, va := range []uint64{0x5000, 0x6010, 0x20_0000, 0x3f_ffff, 0x4000_0000, 0x7fff_ffff, 0x7000, 1 << 39} {
		pa, _, _, werr := pt.Translate(va)
		tpa, terr := tr.Translate(va)
		if (werr == nil) != (terr == nil) || pa != tpa {
			t.Errorf("%#x: walk %#x %v, translator %#x %v", va, pa, werr, tpa, terr)
		}
	}
}

func TestPhysicalMaskDropsTheEncryptionBit(t *testing.T) {
	p := pageKernel(t, "linux-x64", 8, limits.Limits{})
	p.x64()
	c := uint64(1) << 47
	p.entry(0x4000, 7, 0x12_0000|pP|c)
	plain, _ := p.k.PageTables(0x1000)
	tab := p.ctx.Symbols.(*symbols.Table)
	kmem := p.ctx.Memory.(*lt.Memory)
	kmem.U64(lt.Base, (1<<52-1)&^c)
	tab.AddSymbol(symbols.Symbol{Name: "physical_mask", Address: lt.Base})
	k := linuxobj.New(p.ctx)
	pt, _ := k.PageTables(0x1000)
	if pa, _, _, err := pt.Translate(0x7008); err != nil || pa != 0x12_0008 {
		t.Errorf("encrypted page: %#x, %v", pa, err)
	}
	if pa, _, _, _ := plain.Translate(0x7008); pa != 0x12_0008|c {
		t.Errorf("without physical_mask the C-bit stays: %#x", pa)
	}
}

func TestFiveLevelAndThirtyTwoBitShapes(t *testing.T) {
	p := pageKernel(t, "linux-la57", 8, limits.Limits{})
	p.phys.Map(0x1000, 0x5000)
	p.entry(0x1000, 1, 0x2000|pTab)
	p.entry(0x2000, 0, 0x3000|pTab)
	p.entry(0x3000, 0, 0x4000|pTab)
	p.entry(0x4000, 0, 0x5000|pTab)
	p.entry(0x5000, 3, 0xab_c000|pP)
	pt, _ := p.k.PageTables(0x1000)
	if pa, size, _, err := pt.Translate(1<<48 | 0x3010); err != nil || pa != 0xab_c010 || size != 0x1000 {
		t.Errorf("la57: %#x %#x %v", pa, size, err)
	}

	pae := pageKernel(t, "linux-x86pae", 4, limits.Limits{})
	pae.phys.Map(0x1000, 0x3000)
	pae.entry(0x1020, 3, 0x2000|pP)
	pae.entry(0x2000, 1, 0x3000|pTab)
	pae.entry(0x2000, 2, 0x40_0000|pP|pPS)
	pae.entry(0x3000, 4, 0x1_2345_6000|pP)
	pt, _ = pae.k.PageTables(0x1020)
	if pa, size, _, err := pt.Translate(0xc020_4abc); err != nil || pa != 0x1_2345_6abc || size != 0x1000 {
		t.Errorf("pae 4 KiB: %#x %#x %v", pa, size, err)
	}
	if pa, size, _, err := pt.Translate(0xc040_0010); err != nil || pa != 0x40_0010 || size != 0x20_0000 {
		t.Errorf("pae 2 MiB: %#x %#x %v", pa, size, err)
	}

	x86 := pageKernel(t, "linux-x86", 4, limits.Limits{})
	x86.phys.Map(0x1000, 0x2000)
	x86.entry32(0x1000, 0x300, 0x2000|pTab)
	x86.entry32(0x1000, 0x301, 0x80_0000|pP|pPS)
	x86.entry32(0x2000, 2, 0x5_6000|pP|pD)
	pt, _ = x86.k.PageTables(0x1000)
	if pa, size, e, err := pt.Translate(0xc000_2010); err != nil || pa != 0x5_6010 || size != 0x1000 || !linuxobj.Dirty(e) {
		t.Errorf("x86 4 KiB: %#x %#x %v", pa, size, err)
	}
	if pa, size, _, err := pt.Translate(0xc040_0010); err != nil || pa != 0x80_0010 || size != 0x40_0000 {
		t.Errorf("x86 4 MiB: %#x %#x %v", pa, size, err)
	}
}

func TestReadsCrossPagesAndPadWhatDoesNotTranslate(t *testing.T) {
	p := pageKernel(t, "linux-x64", 8, limits.Limits{MaxNameBytes: 0x100, MaxTextBytes: 0x1000, MaxBufferBytes: 0x3000})
	p.x64()
	p.phys.Write(0x10_0000+0x1000-2, []byte("ab"))
	p.phys.Write(0x11_0000, []byte("cd"))
	pt, _ := p.k.PageTables(0x1000)
	b, err := pt.ReadAt(0x5ffe, 4)
	if err != nil || string(b) != "abcd" {
		t.Errorf("ReadAt across pages: %q, %v", b, err)
	}
	if _, err := pt.ReadAt(0x6ffe, 4); err == nil {
		t.Error("a read into an absent page succeeded")
	}
	if _, err := pt.ReadAt(0x5000, 0x4000); !errors.Is(err, linuxobj.ErrReadTooLarge) {
		t.Errorf("read past MaxBufferBytes: %v", err)
	}
	b, padded := pt.ReadPadded(0x6ffc, 8)
	if string(b[:4]) != "WXYZ" || padded != 4 || len(b) != 8 || b[4] != 0 {
		t.Errorf("ReadPadded: %q padded %d", b, padded)
	}
}

func TestPageTablesNeedPhysicalMemoryAndAKnownMode(t *testing.T) {
	p := pageKernel(t, "linux-x64", 8, limits.Limits{})
	p.ctx.Options = map[string]any{tools.OptionPagingMode: "linux-x64"}
	if _, err := linuxobj.New(p.ctx).PageTables(0x1000); !errors.Is(err, linuxobj.ErrNoPhysicalLayer) {
		t.Errorf("no physical layer: %v", err)
	}
	q := pageKernel(t, "linux-sv48", 8, limits.Limits{})
	if _, err := q.k.PageTables(0x1000); !errors.Is(err, linuxobj.ErrPagingMode) {
		t.Errorf("unknown mode: %v", err)
	}
	if _, err := q.k.Translator(0x1000); !errors.Is(err, linuxobj.ErrPagingMode) {
		t.Errorf("unknown mode for the translator: %v", err)
	}
	r := pageKernel(t, "", 8, limits.Limits{})
	r.x64()
	pt, err := r.k.PageTables(0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if pa, _, _, err := pt.Translate(0x5000); err != nil || pa != 0x10_0000 {
		t.Errorf("no recorded mode on 8-byte pointers walks 4 levels: %#x %v", pa, err)
	}
	s := pageKernel(t, "", 4, limits.Limits{})
	if _, err := s.k.PageTables(0x1000); !errors.Is(err, linuxobj.ErrPagingMode) {
		t.Errorf("no recorded mode on 4-byte pointers: %v", err)
	}
}
