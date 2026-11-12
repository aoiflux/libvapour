package filedump

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/tools"
)

func TestADataSectionIsCarvedUpToTheFileSize(t *testing.T) {
	f := newFixture(t)
	art := only(t, f.run(t), cacheDataSection)
	if !art.Written() || !art.Complete() || !art.FileSizeKnown || art.FileSize != 0x1800 || art.Size != 0x1800 {
		t.Fatalf("%+v", art)
	}
	if art.Name != fxName || art.MemoryObject != fxDataCA || art.Pages != 2 {
		t.Errorf("name %q object 0x%x pages %d", art.Name, art.MemoryObject, art.Pages)
	}
	want := append(fill('A'), fill('B')[:0x800]...)
	if got := f.artefact(t, art); !bytes.Equal(got, want) {
		t.Fatalf("content differs: %d bytes", len(got))
	}
}

func TestWithoutAFileSizeTheExtentEndsTheArtefact(t *testing.T) {
	f := newFixture(t)
	testsupport.WriteS19FileObject(f.k, testsupport.S19FileObject{Address: fxFO, Type: 5,
		Size: testsupport.S19FileObjectSize, Device: fxDevice, SOP: fxSOP})
	art := only(t, f.run(t), cacheDataSection)
	if art.FileSizeKnown || art.Size != 0x2000 || art.Name != "" {
		t.Fatalf("%+v", art)
	}
}

func TestAZeroFileSizeInTheFileHeaderIsUnknown(t *testing.T) {
	f := newFixture(t)
	testsupport.WriteS19FileSize(f.k, fxFCB, 0)
	art := only(t, f.run(t), cacheDataSection)
	if !art.Written() || art.FileSizeKnown || art.Size != 0x2000 {
		t.Fatalf("%+v", art)
	}
}

func TestAnImageSectionIsWrittenInFileLayout(t *testing.T) {
	f := newFixture(t)
	f.withImage(t)
	art := only(t, f.run(t), cacheImageSection)
	if !art.Written() || art.Size != 0x800 {
		t.Fatalf("%+v", art)
	}
	want := append(fill('C')[:0x400], fill('D')[:0x200]...)
	want = append(want, make([]byte, 0x200)...)
	if got := f.artefact(t, art); !bytes.Equal(got, want) {
		t.Fatalf("image artefact differs")
	}
	if len(art.Gaps) != 1 || art.Gaps[0].Start != 0x600 || art.Gaps[0].Length != 0x200 {
		t.Errorf("gaps %+v", art.Gaps)
	}
}

func TestTheRunsListCapBoundsTheSubsectionWalk(t *testing.T) {
	f := newFixture(t)
	f.withImage(t)
	ctx := f.context()
	ctx.Limits = limits.Limits{MaxListEntries: 1}
	out, err := RunAny(ctx)
	if err != nil {
		t.Fatal(err)
	}
	art := only(t, out.([]Artifact), cacheImageSection)
	if art.Written() && art.Complete() {
		t.Errorf("a walk past the cap was complete: %+v", art)
	}
	if !f.said("past 1 subsections") && !strings.Contains(art.Skipped, "past 1 subsections") {
		t.Errorf("skipped %q, diagnostics %q", art.Skipped, f.diags)
	}
}

func TestFileObjectChecksRejectWhatIsNoFileOnStorage(t *testing.T) {
	cases := map[string]struct {
		edit func(f *fixture)
		want error
	}{
		"type":        {func(f *fixture) { f.k.WriteU16(fxFO, 6) }, ErrNotFileObject},
		"size":        {func(f *fixture) { f.k.WriteU16(fxFO+2, 0xD0) }, ErrNotFileObject},
		"no device":   {func(f *fixture) { f.k.WriteU64(fxFO+8, 0) }, ErrDeviceUnread},
		"named pipe":  {func(f *fixture) { testsupport.WriteS19Device(f.k, fxDevice, 0x11) }, ErrNoFiles},
		"unknown dev": {func(f *fixture) { testsupport.WriteS19Device(f.k, fxDevice, 0x8000) }, ErrNoFiles},
	}
	for name, c := range cases {
		f := newFixture(t)
		c.edit(f)
		if rows := f.run(t); len(rows) != 0 {
			t.Errorf("%s: %d rows", name, len(rows))
		}
		if !f.said(OptionVirtAddr, "not carved", c.want.Error()) {
			t.Errorf("%s: diagnostics %q", name, f.diags)
		}
	}
	for _, device := range []uint32{deviceDiskFileSystem, deviceNetworkFileSystem, deviceCDROM, deviceVirtualDisk} {
		f := newFixture(t)
		testsupport.WriteS19Device(f.k, fxDevice, device)
		if art := only(t, f.run(t), cacheDataSection); !art.Written() {
			t.Errorf("device 0x%x: %+v", device, art)
		}
	}
}

func TestControlAreaChecksKeepAnotherStreamsBytesOut(t *testing.T) {
	cases := map[string]struct {
		ca   testsupport.S19ControlArea
		want error
	}{
		"segment owner": {testsupport.S19ControlArea{Segment: fxDataSeg, SegmentOwner: fxImageCA, File: true, FilePointer: fxFO}, ErrSegment},
		"no segment":    {testsupport.S19ControlArea{File: true, FilePointer: fxFO}, ErrSegment},
		"image flag":    {testsupport.S19ControlArea{Segment: fxDataSeg, Image: true, File: true, FilePointer: fxFO}, ErrSectionFlags},
		"no file flag":  {testsupport.S19ControlArea{Segment: fxDataSeg, FilePointer: fxFO}, ErrSectionFlags},
		"null file":     {testsupport.S19ControlArea{Segment: fxDataSeg, File: true}, ErrOtherStream},
		"other stream":  {testsupport.S19ControlArea{Segment: fxDataSeg, File: true, FilePointer: fxFO2}, ErrOtherStream},
	}
	for name, c := range cases {
		f := newFixture(t)
		testsupport.WriteS19FileObject(f.k, testsupport.S19FileObject{Address: fxFO2, Type: 5,
			Size: testsupport.S19FileObjectSize, Device: fxDevice, SOP: fxSOP + 0x100})
		c.ca.Address, c.ca.TotalPtes = fxDataCA, 2
		testsupport.WriteS19ControlArea(f.k, c.ca)
		art := only(t, f.run(t), cacheDataSection)
		if art.Written() || !strings.Contains(art.Skipped, c.want.Error()) {
			t.Errorf("%s: %+v", name, art)
		}
	}
}

func TestAControlAreaBeingDeletedIsCarvedAndFlagged(t *testing.T) {
	f := newFixture(t)
	testsupport.WriteS19ControlArea(f.k, testsupport.S19ControlArea{Address: fxDataCA, Segment: fxDataSeg,
		TotalPtes: 2, SizeOfSegment: 0x2000, File: true, Deleting: true, FilePointer: fxFO | 3})
	art := only(t, f.run(t), cacheDataSection)
	if !art.Written() || !art.Complete() || !art.BeingDeleted {
		t.Fatalf("%+v", art)
	}
	want := append(fill('A'), fill('B')[:0x800]...)
	if got := f.artefact(t, art); !bytes.Equal(got, want) {
		t.Fatal("content differs")
	}

	f = newFixture(t)
	testsupport.WriteS19ControlArea(f.k, testsupport.S19ControlArea{Address: fxDataCA, Segment: fxDataSeg,
		TotalPtes: 2, SizeOfSegment: 0x2000, File: true, Deleting: true})
	if art = only(t, f.run(t), cacheDataSection); !art.Written() || !art.BeingDeleted {
		t.Errorf("deleting with its FilePointer cleared: %+v", art)
	}

	f = newFixture(t)
	testsupport.WriteS19ControlArea(f.k, testsupport.S19ControlArea{Address: fxDataCA, Segment: fxDataSeg,
		TotalPtes: 2, File: true, Deleting: true, FilePointer: fxFO2})
	art = only(t, f.run(t), cacheDataSection)
	if art.Written() || !art.BeingDeleted || !strings.Contains(art.Skipped, ErrOtherStream.Error()) {
		t.Errorf("deleting and of another stream: %+v", art)
	}
	if plain := only(t, newFixture(t).run(t), cacheDataSection); plain.BeingDeleted {
		t.Errorf("flag set on a live control area: %+v", plain)
	}
}

func TestASecondFileObjectOfOneStreamIsNotCarvedAgain(t *testing.T) {
	f := newFixture(t)
	testsupport.WriteS19FileObject(f.k, testsupport.S19FileObject{Address: fxFO2, Type: 5,
		Size: testsupport.S19FileObjectSize, Device: fxDevice, SOP: fxSOP})
	f.opts[OptionVirtAddr] = []uint64{fxFO, fxFO2}
	rows := f.run(t)
	if len(rows) != 1 || rows[0].FileObject != fxFO {
		t.Fatalf("%+v", rows)
	}
	if !f.said("stream already carved") {
		t.Errorf("diagnostics %q", f.diags)
	}
}

func (f *fixture) writeView(page int, b byte) {
	f.pm.WriteAt(f.k.at(fxView+uint64(page)*0x1000), fill(b))
}

func TestACacheMapIsCarvedFromTheVacbArrays(t *testing.T) {
	f := newFixture(t)
	f.writeView(0, 'X')
	f.writeView(1, 'Y')
	f.withCacheMap(0x1800, viewGranule, testsupport.S19Vacb{Base: fxView, CacheMap: fxMap, Overlay: 0x3})
	art := only(t, f.run(t), cacheSharedMap)
	if !art.Written() || !art.Complete() || art.FileSize != 0x1800 || art.Size != 0x1800 {
		t.Fatalf("%+v", art)
	}
	want := append(fill('X'), fill('Y')[:0x800]...)
	if !bytes.Equal(f.artefact(t, art), want) {
		t.Fatal("cache artefact differs")
	}
}

func TestOnlyViewsTheCacheManagerCouldMakeAreCarved(t *testing.T) {
	f := newFixture(t)
	f.writeView(0, 'X')
	other := fxKernel + 0x80000
	f.withCacheMap(3*viewGranule, 2*viewGranule,
		testsupport.S19Vacb{Base: fxView, CacheMap: fxMap, Overlay: 0},
		testsupport.S19Vacb{Base: fxView + 0x1000, CacheMap: fxMap, Overlay: viewGranule},
		testsupport.S19Vacb{Base: other, CacheMap: fxMap, Overlay: 0},
		testsupport.S19Vacb{Base: other, CacheMap: fxMap, Overlay: 2 * viewGranule},
		testsupport.S19Vacb{Base: other, CacheMap: fxMap + 0x1000, Overlay: viewGranule},
		testsupport.S19Vacb{Base: 0, CacheMap: fxMap, Overlay: viewGranule},
	)
	testsupport.WriteS19CacheMap(f.k, testsupport.S19CacheMap{Address: fxMap, Node: sharedCacheMapNode,
		ByteSize: testsupport.S19CacheMapSize, FileSize: viewGranule + 0x10, SectionSize: 2 * viewGranule, FileRef: fxFO})
	art := only(t, f.run(t), cacheSharedMap)
	if art.Pages != 1 || !f.said("2 views misaligned or repeated") {
		t.Fatalf("%+v %q", art, f.diags)
	}
}

func TestCacheMapChecks(t *testing.T) {
	cases := map[string]struct {
		m    testsupport.S19CacheMap
		want error
	}{
		"node":      {testsupport.S19CacheMap{Node: 0x2FE, ByteSize: testsupport.S19CacheMapSize, FileSize: 1, SectionSize: viewGranule, FileRef: fxFO}, ErrCacheMapNode},
		"byte size": {testsupport.S19CacheMap{Node: sharedCacheMapNode, ByteSize: 552, FileSize: 1, SectionSize: viewGranule, FileRef: fxFO}, ErrCacheMapNode},
		"order":     {testsupport.S19CacheMap{Node: sharedCacheMapNode, ByteSize: testsupport.S19CacheMapSize, FileSize: 2 * viewGranule, SectionSize: viewGranule, FileRef: fxFO}, ErrCacheMapSizes},
		"granule":   {testsupport.S19CacheMap{Node: sharedCacheMapNode, ByteSize: testsupport.S19CacheMapSize, FileSize: 1, SectionSize: 0x1000, FileRef: fxFO}, ErrCacheMapSizes},
		"stream":    {testsupport.S19CacheMap{Node: sharedCacheMapNode, ByteSize: testsupport.S19CacheMapSize, FileSize: 1, SectionSize: viewGranule}, ErrOtherStream},
	}
	for name, c := range cases {
		f := newFixture(t)
		f.withCacheMap(1, viewGranule)
		c.m.Address = fxMap
		testsupport.WriteS19CacheMap(f.k, c.m)
		art := only(t, f.run(t), cacheSharedMap)
		if art.Written() || !strings.Contains(art.Skipped, c.want.Error()) {
			t.Errorf("%s: %+v", name, art)
		}
	}
}

func TestACacheMapsFileSizeBoundsItsDataSection(t *testing.T) {
	f := newFixture(t)
	f.withCacheMap(0x1000, viewGranule)
	testsupport.WriteS19SectionPointers(f.k, fxSOP, fxDataCA, fxMap, 0)
	art := only(t, f.run(t), cacheDataSection)
	if art.Size != 0x1000 || art.FileSize != 0x1000 {
		t.Fatalf("%+v", art)
	}
}

func TestBytesPastTheDumpCeilingAreWithheld(t *testing.T) {
	f := newFixture(t)
	f.opts[tools.OptionMaxDumpSize] = uint64(0x1000)
	art := only(t, f.run(t), cacheDataSection)
	if art.Size != 0x1000 || len(art.Withheld) != 1 || art.Withheld[0].Start != 0x1000 || art.Withheld[0].Length != 0x800 {
		t.Fatalf("%+v", art)
	}
	if art.Complete() || !f.said("dump ceiling") {
		t.Errorf("complete %v, diagnostics %q", art.Complete(), f.diags)
	}
}

func TestWithoutVacbArraysNoCacheMapIsRead(t *testing.T) {
	f := newFixture(t)
	f.withCacheMap(0x1000, viewGranule)
	f.table = testsupport.S19Table()
	if rows := f.run(t); len(rows) != 0 || !f.said("shared cache maps not read") {
		t.Fatalf("%+v %q", rows, f.diags)
	}
}

func TestAPhysicalAddressReadsTheFileObjectPhysically(t *testing.T) {
	f := newFixture(t)
	delete(f.opts, OptionVirtAddr)
	f.opts[OptionPhysAddr] = []uint64{f.k.at(fxFO)}
	art := only(t, f.run(t), cacheDataSection)
	if !art.Written() || !art.FileObjectPhysical || art.FileObject != f.k.at(fxFO) {
		t.Fatalf("%+v", art)
	}
}

func TestRunNeedsAnOutputDirectory(t *testing.T) {
	f := newFixture(t)
	delete(f.opts, tools.OptionOutputDir)
	if _, err := RunAny(f.context()); !errors.Is(err, ErrNoOutputDir) {
		t.Fatalf("%v", err)
	}
}
