package linuxobj_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	kt "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const mask48 = 1<<48 - 1

func pageCache(t *testing.T, f *kt.PageCacheFixture, opts map[string]any) *linuxobj.PageCache {
	t.Helper()
	ctx, _ := f.Context(t, opts)
	k, err := linuxkern.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := linuxobj.NewPageCache(k.Walker(), ctx.PhysicalMemory(), false)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func file(f *kt.PageCacheFixture, size int64) uint64 {
	sb, _ := f.AddSuperBlock("ext4", "sda1", 8, 1)
	return f.AddInode(sb, kt.InodeSpec{Mode: 0o100644, Ino: 12, Size: size})
}

func TestPagesAreTheEntriesOfTheirMapping(t *testing.T) {
	f := kt.NewPageCacheFixture(kt.PageCacheOptions{Folio: true})
	in := file(f, 6*kt.PageSize)
	p0 := f.Cache(in, 0, []byte("zero"))
	p5 := f.Cache(in, 5, []byte("five"))
	c := pageCache(t, f, nil)
	mp, err := c.Pages((in+kt.InData)&mask48, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(mp.Pages) != 2 || mp.Rejects.Total() != 0 {
		t.Fatalf("pages %+v rejects %+v", mp.Pages, mp.Rejects)
	}
	if mp.Pages[0].Address != p0&mask48 || mp.Pages[1].Index != 5 || mp.Pages[1].Address != p5&mask48 {
		t.Errorf("pages %+v", mp.Pages)
	}
	wantPhys := (p5 - kt.PCPageArray) / kt.PCPageSize * kt.PageSize
	if mp.Pages[1].Physical != wantPhys {
		t.Errorf("physical %#x, want %#x", mp.Pages[1].Physical, wantPhys)
	}
	frame, err := c.Frame(mp.Pages[1])
	if err != nil || !bytes.HasPrefix(frame, []byte("five")) {
		t.Errorf("frame %q, %v", frame[:8], err)
	}
	if got := c.FlagNames(mp.Pages[0].Flags); !slices.Equal(got, []string{"PG_uptodate", "PG_lru"}) {
		t.Errorf("flags %q", got)
	}
	if n, err := c.NrPages((in + kt.InData) & mask48); err != nil || n != 2 {
		t.Errorf("nrpages %d, %v", n, err)
	}
}

func TestFlagNamesStopAtNRPageFlagsAndKeepAliases(t *testing.T) {
	f := kt.NewPageCacheFixture(kt.PageCacheOptions{})
	file(f, 1)
	c := pageCache(t, f, nil)
	got := c.FlagNames(1<<10 | 1<<25 | 1<<40)
	if !slices.Equal(got, []string{"PG_checked", "PG_owner_priv_1"}) {
		t.Errorf("flags %q: bits from __NR_PAGEFLAGS up are not flags", got)
	}
}

func TestEntriesFailTheirRule(t *testing.T) {
	f := kt.NewPageCacheFixture(kt.PageCacheOptions{})
	in := file(f, 64*kt.PageSize)
	other := f.AddInode(f.SuperOf(in), kt.InodeSpec{Mode: 0o100644, Ino: 13, Size: kt.PageSize})
	f.Cache(in, 1, nil)
	foreign := f.Cache(other, 0, nil)
	f.SetEntry(in, 2, foreign)
	misplaced := f.Cache(in, 3, nil)
	f.SetEntry(in, 4, misplaced)
	f.SetEntry(in, 5, kt.PCPageArray+kt.PCPageSize+8)
	f.SetEntry(in, 6, 0xffff888000001000)
	f.Mem.Map(0xffff888000001000, 64)
	unread := f.PageAt(0x7fff0)
	f.SetEntry(in, 7, unread)
	c := pageCache(t, f, nil)
	mp, err := c.Pages((in+kt.InData)&mask48, 64)
	if err != nil {
		t.Fatal(err)
	}
	want := linuxobj.Rejects{Outside: 1, Misaligned: 1, Unread: 1, Foreign: 1, Misplaced: 1}
	if mp.Rejects != want || len(mp.Pages) != 2 {
		t.Errorf("rejects %+v pages %d, want %+v and 2", mp.Rejects, len(mp.Pages), want)
	}
	for _, e := range []struct {
		entry, index uint64
		want         error
	}{{foreign, 2, linuxobj.ErrPageMapping}, {misplaced, 4, linuxobj.ErrPageIndex},
		{kt.PCPageArray + kt.PCPageSize + 8, 5, linuxobj.ErrPageMisaligned},
		{0xffff888000001000, 6, linuxobj.ErrPageOutside}, {unread, 7, linuxobj.ErrPageUnread}} {
		if _, _, err := c.Check((in+kt.InData)&mask48, e.entry&mask48, e.index); !errors.Is(err, e.want) {
			t.Errorf("entry %#x at %d: %v, want %v", e.entry, e.index, err, e.want)
		}
	}
}

func TestAFolioStandsForItsTailPages(t *testing.T) {
	f := kt.NewPageCacheFixture(kt.PageCacheOptions{Folio: true})
	in := file(f, 12*kt.PageSize)
	data := bytes.Repeat([]byte{'a'}, 4*kt.PageSize)
	head := f.CacheFolio(in, 4, 2, data)
	f.Cache(in, 8, nil)
	c := pageCache(t, f, nil)
	mp, err := c.Pages((in+kt.InData)&mask48, 12)
	if err != nil {
		t.Fatal(err)
	}
	var idx []uint64
	for _, p := range mp.Pages {
		idx = append(idx, p.Index)
	}
	if !slices.Equal(idx, []uint64{4, 5, 6, 7, 8}) || mp.Pages[3].Address != (head+3*kt.PCPageSize)&mask48 {
		t.Errorf("indexes %v pages %+v", idx, mp.Pages)
	}
}

func TestATailEntryTakesItsHeadsMappingAndIndex(t *testing.T) {
	f := kt.NewPageCacheFixture(kt.PageCacheOptions{})
	in := file(f, 4*kt.PageSize)
	head := f.CacheFolio(in, 0, 1, nil)
	f.SetEntry(in, 1, head+kt.PCPageSize)
	c := pageCache(t, f, nil)
	mp, err := c.Pages((in+kt.InData)&mask48, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(mp.Pages) != 2 || mp.Pages[1].Index != 1 || mp.Rejects.Total() != 0 {
		t.Errorf("pages %+v rejects %+v", mp.Pages, mp.Rejects)
	}
	if _, isHead, err := c.Check((in+kt.InData)&mask48, (head+kt.PCPageSize)&mask48, 1); err != nil || isHead {
		t.Errorf("tail: head %v, %v", isHead, err)
	}
	if _, _, err := c.Check((in+kt.InData)&mask48, (head+kt.PCPageSize)&mask48, 2); !errors.Is(err, linuxobj.ErrPageIndex) {
		t.Errorf("tail at the wrong index: %v", err)
	}
}

func TestFramesComeFromTheDirectMapWithoutAPhysicalLayer(t *testing.T) {
	f := kt.NewPageCacheFixture(kt.PageCacheOptions{})
	in := file(f, kt.PageSize)
	f.Cache(in, 0, []byte("direct"))
	c := pageCache(t, f, map[string]any{tools.OptionPhysicalMemory: nil})
	mp, _ := c.Pages((in+kt.InData)&mask48, 1)
	if len(mp.Pages) != 1 {
		t.Fatalf("pages %+v", mp)
	}
	if frame, err := c.Frame(mp.Pages[0]); err != nil || !bytes.HasPrefix(frame, []byte("direct")) {
		t.Errorf("frame %v", err)
	}
	g := kt.NewPageCacheFixture(kt.PageCacheOptions{NoDirect: true})
	in = file(g, kt.PageSize)
	g.Cache(in, 0, nil)
	c = pageCache(t, g, map[string]any{tools.OptionPhysicalMemory: nil})
	mp, _ = c.Pages((in+kt.InData)&mask48, 1)
	if _, err := c.Frame(mp.Pages[0]); !errors.Is(err, linuxobj.ErrNoFrameReader) {
		t.Errorf("no physical layer and no direct map: %v", err)
	}
}

func TestTheArrayBaseIsVmemmapBaseOrTheDocumentedOne(t *testing.T) {
	f := kt.NewPageCacheFixture(kt.PageCacheOptions{})
	file(f, 1)
	f.Mem.U64(kt.PCVmemmapVar, 0xffffea0000400000)
	if c := pageCache(t, f, nil); c.PageArray() != 0xffffea0000400000&mask48 {
		t.Errorf("array %#x: want vmemmap_base's value", c.PageArray())
	}
	g := kt.NewPageCacheFixture(kt.PageCacheOptions{NoArray: true})
	file(g, 1)
	if c := pageCache(t, g, nil); c.PageArray() != 0xffffea0000000000&mask48 {
		t.Errorf("array %#x: want the 4-level vmemmap base", c.PageArray())
	}
}

func TestMappingTreeCapsAtMaxTableEntries(t *testing.T) {
	f := kt.NewPageCacheFixture(kt.PageCacheOptions{})
	in := file(f, 8*kt.PageSize)
	for i := uint64(0); i < 8; i++ {
		f.Cache(in, i, nil)
	}
	ctx, _ := f.Context(t, nil)
	ctx.Limits.MaxTableEntries = 3
	k, _ := linuxkern.New(ctx)
	c, err := linuxobj.NewPageCache(k.Walker(), ctx.PhysicalMemory(), false)
	if err != nil {
		t.Fatal(err)
	}
	mp, _ := c.Pages((in+kt.InData)&mask48, 8)
	if len(mp.Pages) > 3 || !(mp.Capped || mp.Tree.Capped) {
		t.Errorf("pages %d capped %v %v", len(mp.Pages), mp.Capped, mp.Tree.Capped)
	}
}

func TestInodeSizeIsSigned(t *testing.T) {
	f := kt.NewPageCacheFixture(kt.PageCacheOptions{})
	in := file(f, -2)
	ctx, _ := f.Context(t, nil)
	if n, err := linuxobj.New(ctx).InodeSize(in); err != nil || n != -2 {
		t.Errorf("size %d, %v", n, err)
	}
}
