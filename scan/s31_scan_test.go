package scan

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const fxVA = uint64(0xffffa00012340000)

func liveProcess(pool uint64, mask byte, padding uint32) fxObject {
	return fxObject{pool: pool, tag: "Proc", poolType: fxNonPagedType, mask: mask, padding: padding,
		slot: fxProcessSlot, va: fxVA + pool, pointers: 3, handles: 1, dispatch: ProcessObject}
}

func TestTheSweepFindsEveryTagOnceAcrossChunksAndHoles(t *testing.T) {
	mem := &flat{buf: make([]byte, 3*sweepChunk)}
	want := []uint64{5, sweepChunk - 2, sweepChunk + 7, 2*sweepChunk + 0x3000}
	for _, at := range want {
		copy(mem.buf[at:], "Proc")
	}
	copy(mem.buf[2*sweepChunk+0x1004:], "Proc")
	mem.holes = [][2]uint64{{2*sweepChunk + 0x1000, 2*sweepChunk + 0x2000}}
	got, err := SweepTags(mem, []string{"Proc", "Proc", ""}, 3)
	if err != nil {
		t.Fatal(err)
	}
	var at []uint64
	for _, m := range got {
		at = append(at, m.Offset)
	}
	if !equalU64(at, want) {
		t.Fatalf("hits %#x, want %#x", at, want)
	}
}

func equalU64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTagValueIsLittleEndian(t *testing.T) {
	if v := TagValue("Proc"); v != 0x636f7250 {
		t.Fatalf("TagValue(Proc) = %#x", v)
	}
}

func TestAProcessBehindEachOptionalHeaderShapeIsFound(t *testing.T) {
	for _, c := range []struct {
		name    string
		mask    byte
		padding uint32
	}{
		{"none", 0, 0}, {"quota", 0x08, 0}, {"name and quota", 0x0a, 0},
		{"quota and padding", 0x88, 0x20}, {"padding only", 0x80, 0x30},
	} {
		t.Run(c.name, func(t *testing.T) {
			mem := newFlat(2)
			res := &fxResidency{}
			res.mapPage(fxFirstPool, fxVA+fxFirstPool)
			_, body := mem.object(liveProcess(fxFirstPool, c.mask, c.padding))
			rows, stats := newScan(mem, res).processes()
			if len(rows) != 1 || rows[0].Row != body {
				t.Fatalf("rows %+v, want body %#x (%s)", rows, body, stats.Describe())
			}
			p := rows[0].Place
			if !p.Virtual || p.VirtualPool != fxVA+fxFirstPool || p.VirtualBody != p.VirtualPool+(body-fxFirstPool) {
				t.Errorf("place %+v", p)
			}
			if stats.TypeIndexAccepted != 1 || stats.Accepted != 1 {
				t.Errorf("stats %+v", stats)
			}
		})
	}
}

func TestAPaddingAmountBelowThePaddingInfoIsRefused(t *testing.T) {
	for _, mask := range []byte{0x88, 0x80} {
		mem := newFlat(1)
		res := &fxResidency{}
		res.mapPage(fxFirstPool, fxVA+fxFirstPool)
		mem.object(liveProcess(fxFirstPool, mask, 0))
		rows, stats := newScan(mem, res).processes()
		if len(rows) != 0 || stats.InfoMaskRejected+stats.PointerCountRejected+stats.TypeIndexRejected != 1 {
			t.Fatalf("mask %#x with PaddingAmount 0: rows %+v, stats %+v", mask, rows, stats)
		}
	}
}

func TestPoolHeaderRulesRefuseWithTheirCounter(t *testing.T) {
	mem := newFlat(4)
	mem.object(fxObject{pool: fxFirstPool, tag: "Proc", poolType: fxPagedType, slot: fxProcessSlot, dispatch: ProcessObject, pointers: 1})
	mem.object(fxObject{pool: fxFirstPool + 0x1000, tag: "Proc", poolType: fxNonPagedType, blocks: 4, slot: fxProcessSlot, pointers: 1})
	mem.object(fxObject{pool: fxFirstPool + 0x2f00, tag: "Proc", poolType: fxNonPagedType, slot: fxProcessSlot, pointers: 1})
	copy(mem.buf[fxFirstPool+0x3008:], "Proc")
	_, stats := newScan(mem, nil).processes()
	if stats.Rejected.PageType != 1 || stats.Rejected.Size != 1 || stats.PageCrossing != 1 ||
		stats.Rejected.Alignment != 1 || stats.Accepted != 0 || stats.TagHits != 4 {
		t.Fatalf("stats %+v", stats)
	}
}

func TestAFreedAllocationIsScanned(t *testing.T) {
	mem := newFlat(1)
	o := liveProcess(fxFirstPool, 0x08, 0)
	o.poolType, o.pointers, o.handles = 0, 0, 0
	mem.object(o)
	if rows, stats := newScan(mem, nil).processes(); len(rows) != 1 {
		t.Fatalf("freed process not found: %s", stats.Describe())
	}
}

func TestHeaderGeometryAndCountsAreChecked(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(o *fxObject, mem *flat, header uint64)
		check func(s ObjectScanStats) bool
	}{
		{"padding of a cache line", func(o *fxObject, mem *flat, header uint64) {
			mem.u32(header-optionalLength(o.mask)-4, 0x40)
		}, func(s ObjectScanStats) bool {
			return s.InfoMaskRejected+s.PointerCountRejected+s.TypeIndexRejected == 1
		}},
		{"mask naming absent headers", func(o *fxObject, mem *flat, header uint64) {
			mem.u8(header+fxInfoMask, 0x0b)
		}, func(s ObjectScanStats) bool {
			return s.InfoMaskRejected+s.PointerCountRejected+s.TypeIndexRejected == 1
		}},
		{"negative references", func(o *fxObject, mem *flat, header uint64) {
			mem.u64(header, ^uint64(0))
		}, func(s ObjectScanStats) bool { return s.PointerCountRejected == 1 }},
		{"more handles than references", func(o *fxObject, mem *flat, header uint64) {
			mem.u64(header+fxHandleCount, 9)
		}, func(s ObjectScanStats) bool { return s.PointerCountRejected == 1 }},
		{"another type", func(o *fxObject, mem *flat, header uint64) {
			mem.u8(header+fxTypeIndex, mem.buf[header+fxTypeIndex]^1)
		}, func(s ObjectScanStats) bool { return s.TypeIndexRejected == 1 }},
		{"another body type", func(o *fxObject, mem *flat, header uint64) {
			mem.u8(header+fxHeaderBody, ThreadObject)
		}, func(s ObjectScanStats) bool { return s.TypeTagRejected == 1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mem := newFlat(1)
			res := &fxResidency{}
			res.mapPage(fxFirstPool, fxVA+fxFirstPool)
			o := liveProcess(fxFirstPool, 0x88, 0x10)
			header, _ := mem.object(o)
			c.edit(&o, mem, header)
			rows, stats := newScan(mem, res).processes()
			if len(rows) != 0 || !c.check(stats) {
				t.Fatalf("rows %d, stats %+v", len(rows), stats)
			}
		})
	}
}

func TestAKeptTypeIndexMismatchIsFlagged(t *testing.T) {
	mem := newFlat(1)
	res := &fxResidency{}
	res.mapPage(fxFirstPool, fxVA+fxFirstPool)
	header, _ := mem.object(liveProcess(fxFirstPool, 0, 0))
	mem.u8(header+fxTypeIndex, mem.buf[header+fxTypeIndex]^0x40)
	s := newScan(mem, res)
	s.identity.KeepIndexMismatch = true
	rows, stats := s.processes()
	if len(rows) != 1 || !rows[0].TypeIndexFailed || stats.TypeIndexFailed != 1 {
		t.Fatalf("rows %+v stats %+v", rows, stats)
	}
}

func TestAnUnmappedFrameLeavesTheTypeToTheBody(t *testing.T) {
	mem := newFlat(1)
	header, _ := mem.object(liveProcess(fxFirstPool, 0, 0))
	mem.u8(header+fxTypeIndex, 0)
	rows, stats := newScan(mem, &fxResidency{}).processes()
	if len(rows) != 1 || rows[0].Place.Virtual || stats.TypeIndexAccepted != 0 {
		t.Fatalf("rows %+v stats %+v", rows, stats)
	}
}

func TestTheKernelMaskTableWinsOverTypeSizes(t *testing.T) {
	mem := newFlat(1)
	o := liveProcess(fxFirstPool, 0x40, 0)
	o.mask = 0x08
	mem.object(o)
	mem.u8(fxMaskTableAt+0x08, 0x40)
	if rows, _ := newScan(mem, nil).processes(); len(rows) != 0 {
		t.Fatalf("table says 0x40, object placed at 0x20: %d rows", len(rows))
	}
	s := newScan(mem, nil)
	s.identity.hasMasks = false
	if rows, _ := s.processes(); len(rows) != 1 {
		t.Fatal("type sizes place the object at 0x20 but it was not found")
	}
}

func TestCopiesFollowTheKernelMapping(t *testing.T) {
	build := func(mapped ...bool) (fxScan, []uint64) {
		mem := newFlat(3)
		res := &fxResidency{}
		var pools []uint64
		for i, m := range mapped {
			pool := uint64(fxFirstPool + i*fxPageSize)
			mem.object(liveProcess(pool, 0, 0))
			copy(mem.buf[pool:pool+fxPageSize], mem.buf[fxFirstPool:fxFirstPool+fxPageSize])
			if m {
				res.mapPage(pool, fxVA+fxFirstPool+uint64(i)*0x10000)
			}
			pools = append(pools, pool)
		}
		return newScan(mem, res), pools
	}
	t.Run("one mapped", func(t *testing.T) {
		s, pools := build(false, true)
		rows, stats := s.processes()
		if len(rows) != 1 || rows[0].Place.Pool != pools[1] || len(rows[0].Copies) != 1 ||
			rows[0].Copies[0] != (Copy{Pool: pools[0]}) || stats.DuplicateCopies != 1 {
			t.Fatalf("rows %+v stats %+v", rows, stats)
		}
	})
	t.Run("two mapped", func(t *testing.T) {
		s, pools := build(true, true, false)
		rows, stats := s.processes()
		if len(rows) != 2 || stats.MappedCopies != 1 || stats.DuplicateCopies != 1 ||
			rows[0].OtherMappedPool() != pools[1] || rows[1].OtherMappedPool() != pools[0] {
			t.Fatalf("rows %+v stats %+v", rows, stats)
		}
		if rows[0].OtherMappedBody()-rows[0].OtherMappedPool() != rows[0].Place.Body-rows[0].Place.Pool {
			t.Error("other body is not at the body's distance")
		}
	})
	t.Run("none mapped", func(t *testing.T) {
		s, pools := build(false, false)
		rows, _ := s.processes()
		if len(rows) != 1 || rows[0].Place.Pool != pools[0] {
			t.Fatalf("rows %+v", rows)
		}
	})
	t.Run("every copy", func(t *testing.T) {
		s, _ := build(false, false)
		s.layout = s.layout.ReportingEveryCopy()
		if rows, _ := s.processes(); len(rows) != 2 {
			t.Fatalf("rows %d", len(rows))
		}
	})
}

func TestRowsComeInVirtualAddressOrder(t *testing.T) {
	mem := newFlat(3)
	res := &fxResidency{}
	for i, va := range []uint64{0x30000, 0x10000} {
		pool := uint64(fxFirstPool + i*fxPageSize)
		o := liveProcess(pool, 0, 0)
		o.va = fxVA + va
		o.pointers = int64(i + 1)
		mem.object(o)
		res.mapPage(pool, fxVA+va)
	}
	o := liveProcess(fxFirstPool+2*fxPageSize, 0, 0)
	o.pointers = 7
	mem.object(o)
	rows, _ := newScan(mem, res).processes()
	if len(rows) != 3 || rows[0].Place.VirtualPool != fxVA+0x10000 || rows[1].Place.VirtualPool != fxVA+0x30000 ||
		rows[2].Place.Virtual {
		t.Fatalf("order %+v", rows)
	}
}

func TestTheTypeSlotIsFoundByNameAndIndex(t *testing.T) {
	mem := newFlat(0)
	tbl := fxTable()
	ti, err := ResolveTypeIndexTest(tbl, mem, "Thread")
	if err != nil || ti.want != fxThreadSlot || !ti.hasCookie || ti.cookie != fxCookie {
		t.Fatalf("%+v %v", ti, err)
	}
	if _, err := ResolveTypeIndexTest(tbl, mem, "Mutant"); !errors.Is(err, ErrTypeNotListed) {
		t.Fatalf("Mutant: %v", err)
	}
	mem.u8(fxTypesAt+fxThreadSlot*0x40-0x10+0x28, 3)
	if _, err := ResolveTypeIndexTest(tbl, mem, "Thread"); !errors.Is(err, ErrTypeNotListed) {
		t.Fatalf("slot with another Index: %v", err)
	}
}

func TestAnIdentityWithoutTheTypeTableStillScans(t *testing.T) {
	mem := newFlat(1)
	mem.object(liveProcess(fxFirstPool, 0, 0))
	tbl := fxTable()
	for i := range 256 * 8 {
		mem.buf[fxTypeTableAt+i] = 0
	}
	id, err := ResolveObjectIdentity(tbl, mem, ProcessFilter, fxProcessTag(tbl))
	if !errors.Is(err, ErrTypeNotListed) || !id.hasMasks || id.Index.Resolved() {
		t.Fatalf("identity %+v, %v", id, err)
	}
}

func TestStructureScanFirstFilterWinsAndCrossingsAreKept(t *testing.T) {
	mem := newFlat(2)
	tbl := fxTable()
	layout, err := ResolvePoolHeaderLayout(tbl)
	if err != nil {
		t.Fatal(err)
	}
	mem.u16(fxFirstPool+2, 4|fxPagedType<<8)
	copy(mem.buf[fxFirstPool+4:], "AtmT")
	mem.u16(fxFirstPool+0xff0+2, 4|fxPagedType<<8)
	copy(mem.buf[fxFirstPool+0xff4:], "AtmT")
	filters := []PoolFilter{{Tag: "AtmT", Body: "_RTL_ATOM_TABLE", PageType: NonPagedPool}, AtomTableFilter,
		{Tag: "AtmT"}}
	rows, stats, err := FindFilteredStructsPlaced(mem, layout, filters,
		func(c PoolFilter, body uint64, h PoolHeader) (string, bool) { return c.Body, true }, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Row != "_RTL_ATOM_TABLE" || stats.Passed != 1 || stats.PageCrossing != 1 ||
		len(stats.PageCrossingHits) != 1 || stats.PageCrossingHits[0].Header.Offset != fxFirstPool+0xff0 {
		t.Fatalf("rows %+v stats %+v", rows, stats)
	}
	if n, _ := layout.MinimumSize(AtomTableFilter); n != 16+0x28 {
		t.Errorf("minimum %d", n)
	}
	if _, err := layout.MinimumSize(HiveFilter); !errors.Is(err, ErrStructureUndescribed) {
		t.Errorf("undescribed body: %v", err)
	}
}

func TestObjectNames(t *testing.T) {
	mem := newFlat(1)
	header, _ := mem.object(liveProcess(fxFirstPool, 0x0a, 0))
	info := header - fxOptionalSizes[1]
	mem.ustr(info+8, fxFirstPool+0x800, `\BaseNamedObjects\Example`)
	n, ok := NewObjectNamer(fxTable())
	if !ok {
		t.Fatal("no namer")
	}
	if name, present, readable := n.ReadName(mem, mem, mem, header); name != `\BaseNamedObjects\Example` || !present || !readable {
		t.Fatalf("name %q %v %v", name, present, readable)
	}
	mem.ustr(info+8, fxFirstPool+0x800, "Ex\x00ample\x00\x00")
	if name, _, _ := n.ReadName(mem, mem, mem, header); name != "Ex\u2400ample" {
		t.Fatalf("name %q: an inner NUL shows, the terminating NULs do not", name)
	}
	mem.u8(header+fxInfoMask, 0x08)
	if _, present, readable := n.ReadName(mem, mem, mem, header); present || !readable {
		t.Fatal("no name bit, yet a name")
	}
	mem.u8(header+fxInfoMask, 0x0a)
	mem.u64(info+16, 1<<40)
	if _, present, readable := n.ReadName(mem, mem, mem, header); !present || readable {
		t.Fatal("unreadable buffer read")
	}
}

// The name info's MaximumLength byte doubles as an InfoMask that places a
// header 16 bytes past the pool header, whose body byte is the real header's
// PointerCount: two headers pass in one allocation, the nearer unnamed.
func TestANamedHeaderWinsOverANearerUnnamedOne(t *testing.T) {
	mem := newFlat(1)
	header, body := mem.object(liveProcess(fxFirstPool, 0x0a, 0))
	mem.ustr(header-fxOptionalSizes[1]+8, fxFirstPool+0x800, "Ab")
	s := newScan(mem, nil)
	rows, stats := s.processes()
	if len(rows) != 1 || rows[0].Row != header || stats.MultiValid != 1 {
		t.Fatalf("without a name reader: rows %+v, stats %+v; want the nearer header's body %#x", rows, stats, header)
	}
	s.layout = s.layout.PreferringNamed(mem)
	rows, stats = s.processes()
	if len(rows) != 1 || rows[0].Row != body || stats.MultiValid != 1 {
		t.Fatalf("with a name reader: rows %+v, stats %+v; want the named header's body %#x", rows, stats, body)
	}
	mem.u64(header-fxOptionalSizes[1]+16, 1<<40)
	if rows, _ := s.processes(); len(rows) != 1 || rows[0].Row != header {
		t.Fatalf("rows %+v: a header whose name does not read won over the nearer one", rows)
	}
}

func TestUnaccountedLooksWhereTheScanLooks(t *testing.T) {
	mem := newFlat(1)
	header, _ := mem.object(liveProcess(fxFirstPool, 0x8a, 0x30))
	l, _ := ResolveObjectLayout(fxTable())
	if l.Unaccounted(mem, []string{"Proc"}, header) {
		t.Fatal("a pool header in reach counted as missing")
	}
	if !l.Unaccounted(mem, []string{"Thre"}, header) {
		t.Fatal("another tag accounted for the header")
	}
}

func TestDescribeNamesOnlyWhatHappened(t *testing.T) {
	s := ObjectScanStats{Accepted: 2, TypeIndexRejected: 1}
	if d := s.Describe(); d != "2 accepted, 1 of another TypeIndex" {
		t.Fatalf("%q", d)
	}
	var sum ObjectScanStats
	sum.Add(s)
	sum.Add(s)
	if sum.Accepted != 4 || !strings.Contains(sum.Describe(), "2 of another") {
		t.Fatal(sum.Describe())
	}
}

func TestModuleEntryTypePrefersTheKernelEntry(t *testing.T) {
	tbl := fxTable()
	if _, ok := ModuleEntryType(tbl); ok {
		t.Fatal("no loader entry in the table")
	}
	if f := ModuleFilterFor(tbl); f.Body != kernelLoaderEntry {
		t.Fatal(f.Body)
	}
}

func FuzzSweepTags(f *testing.F) {
	f.Add([]byte("xxProcxxThre"), uint16(3))
	f.Fuzz(func(t *testing.T, data []byte, cut uint16) {
		mem := &flat{buf: data}
		if len(data) > 0 {
			at := uint64(cut) % uint64(len(data))
			mem.holes = [][2]uint64{{at, at + 1}}
		}
		got, err := SweepTags(mem, []string{"Proc", "Thre"}, 2)
		if err != nil {
			t.Fatal(err)
		}
		for i, m := range got {
			if i > 0 && got[i-1].Offset > m.Offset {
				t.Fatal("not sorted")
			}
			if m.Offset+4 > uint64(len(data)) || !bytes.Equal(data[m.Offset:m.Offset+4], []byte(m.Tag)) {
				t.Fatalf("false hit %+v", m)
			}
		}
		if len(mem.holes) == 0 {
			want := bytes.Count(data, []byte("Proc")) + bytes.Count(data, []byte("Thre"))
			if len(got) < want {
				t.Fatalf("%d hits, at least %d", len(got), want)
			}
		}
	})
}

// Arbitrary bytes behind a Proc tag: no panic, and every accepted object's
// header sits where its InfoMask places it.
func FuzzObjectScan(f *testing.F) {
	seed := newFlat(1)
	seed.object(liveProcess(fxFirstPool, 0x88, 0x20))
	f.Add(seed.buf[fxFirstPool : fxFirstPool+fxPageSize])
	f.Fuzz(func(t *testing.T, page []byte) {
		mem := newFlat(1)
		copy(mem.buf[fxFirstPool:], page)
		copy(mem.buf[fxFirstPool+4:], "Proc")
		res := &fxResidency{}
		res.mapPage(fxFirstPool, fxVA+fxFirstPool)
		rows, _ := newScan(mem, res).processes()
		for _, r := range rows {
			header := r.Row - fxHeaderBody
			mask := mem.buf[header+fxInfoMask]
			want := optionalLength(mask)
			if mask&paddingBit != 0 {
				want += uint64(mem.buf[header-optionalLength(mask)-4])
			}
			if header-fxFirstPool-fxPoolHeader != want {
				t.Fatalf("header at %#x, mask %#x wants distance %#x", header, mask, want)
			}
		}
	})
}
