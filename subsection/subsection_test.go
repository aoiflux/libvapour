package subsection

import (
	"errors"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
)

const (
	fxCA      = uint64(0x1000)
	fxSegment = uint64(0x2000)
	fxSub2    = uint64(0x3000)
	fxSub3    = uint64(0x3100)
	fxArray1  = uint64(0x4000)
	fxArray2  = uint64(0x5000)
	fxArray3  = uint64(0x6000)
	fxVAD     = uint64(0x7000)
	fxMemSize = 0x10000
)

var fxSub1 = fxCA + testsupport.S19ControlAreaSize

type fixture struct {
	pm    *testsupport.PagedMemory
	table *symbols.Table
}

func newFixture(image bool, total uint32) *fixture {
	f := &fixture{pm: testsupport.NewPagedMemory(fxMemSize), table: testsupport.S19Table()}
	testsupport.WriteS19ControlArea(f.pm, testsupport.S19ControlArea{Address: fxCA, Segment: fxSegment,
		TotalPtes: total, Image: image, File: true})
	return f
}

func (f *fixture) sub(s testsupport.S19Subsection) {
	if s.ControlArea == 0 {
		s.ControlArea = fxCA
	}
	testsupport.WriteS19Subsection(f.pm, s)
}

func (f *fixture) resolver(t *testing.T, r memory.MemoryReader) *Resolver {
	t.Helper()
	if r == nil {
		r = f.pm
	}
	res, err := NewResolver(r, f.table)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return res
}

func samePages(t *testing.T, got, want []AvailablePage) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d pages %+v, want %d %+v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("page %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestDataSubsectionsGiveResidentPagesAtTheirFileOffsets(t *testing.T) {
	f := newFixture(false, 8)
	f.sub(testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Next: fxSub2, Ptes: 4, FullSectors: 3})
	f.sub(testsupport.S19Subsection{Address: fxSub2, Base: fxArray2, Ptes: 4, Sector: 4, FullSectors: 1, EndOffset: 0x234})
	f.pm.WriteU64(fxArray1, testsupport.S19ValidPTE(0x8000))
	f.pm.WriteU64(fxArray1+8, testsupport.S19SubsectionPTE())
	f.pm.WriteU64(fxArray1+16, testsupport.S19TransitionPTE(0x9000))
	f.pm.WriteU64(fxArray1+24, testsupport.S19ValidPTE(0xF000))
	f.pm.WriteU64(fxArray2, testsupport.S19ValidPTE(0xA000))
	f.pm.WriteU64(fxArray2+8, testsupport.S19TransitionPTE(0xB000))
	f.pm.WriteU64(fxArray2+16, testsupport.S19ValidPTE(0xE000))

	got, err := f.resolver(t, nil).AvailablePages(fxCA)
	if err != nil {
		t.Fatal(err)
	}
	samePages(t, got, []AvailablePage{
		{PhysicalOffset: 0x8000, FileOffset: 0, PageSize: 0x1000},
		{PhysicalOffset: 0x9000, FileOffset: 0x2000, PageSize: 0x1000},
		{PhysicalOffset: 0xA000, FileOffset: 0x4000, PageSize: 0x1000},
		{PhysicalOffset: 0xB000, FileOffset: 0x5000, PageSize: 0x234},
	})
}

func TestImageSubsectionsCountSectorsOf512Bytes(t *testing.T) {
	f := newFixture(true, 4)
	f.sub(testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Next: fxSub2, Ptes: 1, FullSectors: 2})
	f.sub(testsupport.S19Subsection{Address: fxSub2, Base: fxArray2, Ptes: 3, Sector: 2, FullSectors: 9, EndOffset: 0x10})
	f.pm.WriteU64(fxArray1, testsupport.S19ValidPTE(0x8000))
	for i := uint64(0); i < 3; i++ {
		f.pm.WriteU64(fxArray2+8*i, testsupport.S19ValidPTE(0xA000+i*0x1000))
	}
	got, err := f.resolver(t, nil).AvailablePages(fxCA)
	if err != nil {
		t.Fatal(err)
	}
	samePages(t, got, []AvailablePage{
		{PhysicalOffset: 0x8000, FileOffset: 0, PageSize: 0x400},
		{PhysicalOffset: 0xA000, FileOffset: 0x400, PageSize: 0x1000},
		{PhysicalOffset: 0xB000, FileOffset: 0x1400, PageSize: 0x210},
	})
}

func TestTheHighSectorBitsExtendTheStartingSector(t *testing.T) {
	f := newFixture(false, 1)
	f.sub(testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Ptes: 1, Sector: 5, SectorHigh: 3, FullSectors: 1})
	f.pm.WriteU64(fxArray1, testsupport.S19ValidPTE(0x8000))
	got, err := f.resolver(t, nil).AvailablePages(fxCA)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %+v", err, got)
	}
	if want := (uint64(3)<<32 | 5) * 0x1000; got[0].FileOffset != want {
		t.Fatalf("file offset 0x%x, want 0x%x", got[0].FileOffset, want)
	}
}

func TestAFirstSubsectionOfAnotherControlAreaIsRefused(t *testing.T) {
	f := newFixture(false, 1)
	f.sub(testsupport.S19Subsection{Address: fxSub1, ControlArea: 0xDEAD000, Base: fxArray1, Ptes: 1, FullSectors: 1})
	got, err := f.resolver(t, nil).AvailablePages(fxCA)
	if !errors.Is(err, ErrNoSubsections) || got != nil {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestTheCallersListCapCutsTheSubsections(t *testing.T) {
	f := newFixture(false, 8)
	f.sub(testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Next: fxSub2, Ptes: 4, FullSectors: 3})
	f.sub(testsupport.S19Subsection{Address: fxSub2, Base: fxArray2, Ptes: 4, Sector: 4, FullSectors: 1})
	f.pm.WriteU64(fxArray1, testsupport.S19ValidPTE(0x8000))
	f.pm.WriteU64(fxArray2, testsupport.S19ValidPTE(0xA000))
	r := f.resolver(t, nil)
	r.SetLimits(limits.Limits{MaxListEntries: 1})
	got, err := r.AvailablePages(fxCA)
	if !errors.Is(err, ErrListCut) {
		t.Fatalf("err %v, pages %+v", err, got)
	}
	samePages(t, got, []AvailablePage{{PhysicalOffset: 0x8000, FileOffset: 0, PageSize: 0x1000}})
}

func TestAListThatLeavesItsControlAreaKeepsThePagesBefore(t *testing.T) {
	for name, next := range map[string]uint64{"other owner": fxSub2, "cycle": fxSub1} {
		f := newFixture(false, 4)
		f.sub(testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Next: next, Ptes: 1, FullSectors: 1})
		f.sub(testsupport.S19Subsection{Address: fxSub2, ControlArea: 0xDEAD000, Base: fxArray2, Ptes: 1, FullSectors: 1})
		f.pm.WriteU64(fxArray1, testsupport.S19ValidPTE(0x8000))
		got, err := f.resolver(t, nil).AvailablePages(fxCA)
		if !errors.Is(err, ErrListCut) || len(got) != 1 {
			t.Errorf("%s: %v %+v", name, err, got)
		}
	}
}

func TestExtentsThatDoNotFitThePrototypeArrayAreRefused(t *testing.T) {
	for name, c := range map[string]struct {
		image bool
		s     testsupport.S19Subsection
	}{
		"more pages than ptes":       {false, testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Ptes: 1, FullSectors: 1, EndOffset: 1}},
		"end offset past the sector": {true, testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Ptes: 2, FullSectors: 1, EndOffset: 0x200}},
		"array past the top":         {false, testsupport.S19Subsection{Address: fxSub1, Base: ^uint64(0) - 8, Ptes: 3, FullSectors: 1}},
	} {
		f := newFixture(c.image, 4)
		f.sub(c.s)
		if _, err := f.resolver(t, nil).AvailablePages(fxCA); !errors.Is(err, ErrExtent) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestFilePagesPastTheSegmentsPtesCutTheList(t *testing.T) {
	f := newFixture(false, 2)
	f.sub(testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Next: fxSub2, Ptes: 2, FullSectors: 2})
	f.sub(testsupport.S19Subsection{Address: fxSub2, Base: fxArray2, Ptes: 1, Sector: 2, FullSectors: 1})
	f.pm.WriteU64(fxArray1, testsupport.S19ValidPTE(0x8000))
	got, err := f.resolver(t, nil).AvailablePages(fxCA)
	if !errors.Is(err, ErrBudget) || len(got) != 1 {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestUnusedPtesPastTheExtentAreNotChargedOrRead(t *testing.T) {
	f := newFixture(false, 1)
	f.sub(testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Ptes: 512, FullSectors: 1})
	f.pm.WriteU64(fxArray1, testsupport.S19ValidPTE(0x8000))
	f.pm.WriteU64(fxArray1+8, testsupport.S19ValidPTE(0x9000))
	got, err := f.resolver(t, nil).AvailablePages(fxCA)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %+v", err, got)
	}
}

type hole struct {
	memory.MemoryReader
	start, end uint64
}

func (h hole) ReadAt(offset, size uint64) ([]byte, error) {
	if offset < h.end && offset+size > h.start {
		return nil, memory.ErrOutOfBounds
	}
	return h.MemoryReader.ReadAt(offset, size)
}

func TestAnUnreadablePageOfPrototypePtesLosesOnlyItsEntries(t *testing.T) {
	f := newFixture(false, 600)
	f.sub(testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Ptes: 600, FullSectors: 600})
	f.pm.WriteU64(fxArray2, testsupport.S19ValidPTE(0x8000))
	f.pm.WriteU64(fxArray2+8, testsupport.S19TransitionPTE(0x9000))
	r := f.resolver(t, hole{MemoryReader: f.pm, start: fxArray1, end: fxArray2})
	got, err := r.AvailablePages(fxCA)
	if err != nil {
		t.Fatal(err)
	}
	samePages(t, got, []AvailablePage{
		{PhysicalOffset: 0x8000, FileOffset: 512 * 0x1000, PageSize: 0x1000},
		{PhysicalOffset: 0x9000, FileOffset: 513 * 0x1000, PageSize: 0x1000},
	})
}

func TestAWalkWithoutThePteLayoutsIsRefused(t *testing.T) {
	f := newFixture(false, 1)
	table := symbols.NewTable("partial", 8)
	for _, name := range []string{"_CONTROL_AREA", "_SUBSECTION", "_MMSECTION_FLAGS", "_SEGMENT", "_MMPTE"} {
		st, _ := f.table.Struct(name)
		table.AddStruct(st)
	}
	r, err := NewResolver(f.pm, table)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.AvailablePages(fxCA); !errors.Is(err, ErrWalkFields) {
		t.Fatalf("%v", err)
	}
}

func (f *fixture) vad(sub, firstProto, last uint64, start, end uint32) {
	f.pm.WriteU64(fxVAD+testsupport.S19VadSubsection, sub)
	f.pm.WriteU64(fxVAD+testsupport.S19VadFirstProto, firstProto)
	f.pm.WriteU64(fxVAD+testsupport.S19VadLastContig, last)
	f.pm.WriteU32(fxVAD+testsupport.S19VadStartVpn, start)
	f.pm.WriteU32(fxVAD+testsupport.S19VadEndVpn, end)
}

func TestAViewRunsFromItsFirstPrototypePteAcrossSubsections(t *testing.T) {
	f := newFixture(false, 9)
	f.sub(testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Next: fxSub2, Ptes: 3, FullSectors: 3})
	f.sub(testsupport.S19Subsection{Address: fxSub2, Base: fxArray2, Next: fxSub3, Ptes: 3, Sector: 3, FullSectors: 3})
	f.sub(testsupport.S19Subsection{Address: fxSub3, Base: fxArray3, Ptes: 3, Sector: 6, FullSectors: 3})
	for i, arr := range []uint64{fxArray1, fxArray2, fxArray3} {
		for j := uint64(0); j < 3; j++ {
			f.pm.WriteU64(arr+8*j, testsupport.S19ValidPTE(0x10000*uint64(i+1)+j*0x1000))
		}
	}
	f.vad(fxSub2, fxArray2+8, fxArray3+16, 0x100, 0x102)
	got, err := f.resolver(t, nil).AvailablePagesFromVAD(fxVAD)
	if err != nil {
		t.Fatal(err)
	}
	samePages(t, got, []AvailablePage{
		{PhysicalOffset: 0x21000, FileOffset: 0x4000, PageSize: 0x1000},
		{PhysicalOffset: 0x22000, FileOffset: 0x5000, PageSize: 0x1000},
		{PhysicalOffset: 0x30000, FileOffset: 0x6000, PageSize: 0x1000},
	})
}

func TestControlAreaFromVADAndResolveVAFollowTheVAD(t *testing.T) {
	f := newFixture(false, 2)
	f.sub(testsupport.S19Subsection{Address: fxSub1, Base: fxArray1, Ptes: 2, FullSectors: 2})
	f.pm.WriteU64(fxArray1, testsupport.S19ValidPTE(0x8000))
	f.pm.WriteU64(fxArray1+8, testsupport.S19ValidPTE(0x9000))
	f.vad(fxSub1, fxArray1, fxArray1, 0x100, 0x101)
	r := f.resolver(t, nil)
	ca, sub, err := r.ControlAreaFromVAD(fxVAD)
	if err != nil || ca != fxCA || sub != fxSub1 {
		t.Fatalf("control area 0x%x subsection 0x%x: %v", ca, sub, err)
	}
	if pa, err := r.ResolveVA(fxVAD, 0x100123); err != nil || pa != 0x8123 {
		t.Fatalf("first page: 0x%x %v", pa, err)
	}
	if _, err := r.ResolveVA(fxVAD, 0x101000); err == nil {
		t.Fatal("an entry past LastContiguousPte resolved")
	}
}
