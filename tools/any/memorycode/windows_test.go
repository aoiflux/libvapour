package memorycode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/any/memoryranges"
)

var prologue64 = []byte{0x55, 0x48, 0x89, 0xe5, 0xc3}

func privateVAD(start, pages uint64, index uint32) testsupport.FixtureVAD {
	return testsupport.FixtureVAD{Start: start, End: start + pages*pageSize - 1, Protection: index}
}

func (c *codeFixture) hasDiag(parts ...string) bool {
	for _, d := range c.diags {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(d, p)
		}
		if all {
			return true
		}
	}
	return false
}

func TestAnExecutableAllocationThatHoldsBytesIsReported(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 2, indexExecuteReadWrite))
	c.page(regionVA, true, prologue64)
	rows := c.run(c.context())
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Rule != RuleAllocation || r.Kind != memoryranges.KindPrivate || r.Backing != BackingNone || r.PID != testPID || r.Process != "code.exe" {
		t.Errorf("row %+v", r)
	}
	if r.Protection != "PAGE_EXECUTE_READWRITE" || r.Start != regionVA || r.End != regionVA+2*pageSize-1 || r.VadAddress == 0 {
		t.Errorf("range or protection %+v", r)
	}
	// The second page has no entry and takes the VAD's protection (S35 4.3 step 5).
	if r.Pages != 2 || r.ExecutablePages != 2 || r.ResidentPages != 1 || r.ContentPages != 1 || r.FirstContent != regionVA {
		t.Errorf("page counts %+v", r)
	}
	if r.Header != HeaderNone || r.Transfer != TransferNone || len(r.Preview) != limits.DefaultRowPreviewBytes || string(r.Preview[:len(prologue64)]) != string(prologue64) {
		t.Errorf("start facts %+v", r)
	}
}

func TestPagesMadeExecutableAfterAllocationAreFound(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 3, indexReadWrite))
	c.page(regionVA, false, []byte("data"))
	c.page(regionVA+pageSize, true, prologue64)
	rows := c.run(c.context())
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	r := rows[0]
	if r.Rule != RulePage || r.Protection != "PAGE_READWRITE" {
		t.Errorf("rule %q protection %q", r.Rule, r.Protection)
	}
	if r.ExecutablePages != 1 || r.ContentPages != 1 || r.ResidentPages != 2 || r.FirstContent != regionVA+pageSize {
		t.Errorf("page counts %+v", r)
	}
	if r.Header != HeaderNone {
		t.Errorf("header %q", r.Header)
	}
}

func TestDataPagesAreNotCode(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 2, indexReadWrite))
	c.page(regionVA, false, prologue64)
	if rows := c.run(c.context()); len(rows) != 0 {
		t.Fatalf("got %+v, want none", rows)
	}
	if len(c.diags) != 0 {
		t.Errorf("diagnostics %q", c.diags)
	}
}

func TestAPagesOwnProtectionWinsOverTheVADs(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 1, indexExecuteRead))
	c.page(regionVA, false, prologue64)
	if rows := c.run(c.context()); len(rows) != 0 {
		t.Fatalf("an executable VAD whose only page has XD set gave %+v", rows)
	}
	if !c.hasDiag("1 executable regions hold no readable nonzero byte") {
		t.Errorf("diagnostics %q", c.diags)
	}
}

func TestNotPresentEntriesCarryTheirOwnProtection(t *testing.T) {
	t.Run("software entry", func(t *testing.T) {
		c := newCodeFixture(t, privateVAD(regionVA, 1, indexReadWrite))
		c.entry(regionVA, softwareEntry(indexExecuteReadWrite))
		if rows := c.run(c.context()); len(rows) != 0 {
			t.Fatalf("a page with nothing readable gave %+v", rows)
		}
		if !c.hasDiag("1 executable regions hold no readable nonzero byte") {
			t.Errorf("the candidate was not counted: %q", c.diags)
		}
	})
	t.Run("software entry without an execute right", func(t *testing.T) {
		c := newCodeFixture(t, privateVAD(regionVA, 1, indexReadWrite))
		c.entry(regionVA, softwareEntry(indexReadWrite))
		if rows := c.run(c.context()); len(rows) != 0 || len(c.diags) != 0 {
			t.Fatalf("rows %+v, diagnostics %q", rows, c.diags)
		}
	})
	t.Run("transition entry", func(t *testing.T) {
		c := newCodeFixture(t, privateVAD(regionVA, 1, indexReadWrite))
		frame := c.f.Memory.AllocPage()
		c.f.Memory.WriteAt(frame, prologue64)
		c.entry(regionVA, transitionEntry(frame, indexExecuteRead))
		rows := c.run(c.context())
		if len(rows) != 1 || rows[0].Rule != RulePage || rows[0].ResidentPages != 1 || rows[0].ContentPages != 1 {
			t.Fatalf("got %+v", rows)
		}
	})
	t.Run("prototype entry in a data VAD", func(t *testing.T) {
		c := newCodeFixture(t, privateVAD(regionVA, 1, indexReadWrite))
		c.entry(regionVA, 1<<10|indexExecuteReadWrite<<5)
		if rows := c.run(c.context()); len(rows) != 0 {
			t.Fatalf("a prototype entry gave its own protection: %+v", rows)
		}
	})
}

func TestARegionOfZerosIsCountedNotListed(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 1, indexExecuteReadWrite))
	c.page(regionVA, true, nil)
	if rows := c.run(c.context()); len(rows) != 0 {
		t.Fatalf("got %+v", rows)
	}
	if !c.hasDiag("any.memory.find_code: 1 executable regions hold no readable nonzero byte in an executable page and are not listed") {
		t.Errorf("diagnostics %q", c.diags)
	}
}

func TestSectionViews(t *testing.T) {
	const viewVA = uint64(0x20000000)
	view := testsupport.FixtureVAD{Start: viewVA, End: viewVA + pageSize - 1, Path: `\Windows\code.bin`, Protection: indexExecuteReadWrite}

	t.Run("data file", func(t *testing.T) {
		c := newCodeFixture(t, view)
		c.page(viewVA, true, prologue64)
		rows := c.run(c.context())
		if len(rows) != 1 || rows[0].Kind != memoryranges.KindMapped || rows[0].Backing != BackingFile || rows[0].Path != `\Windows\code.bin` {
			t.Fatalf("got %+v", rows)
		}
	})
	t.Run("section without a file", func(t *testing.T) {
		c := newCodeFixture(t, view)
		c.page(viewVA, true, prologue64)
		ctx := c.context()
		files, err := memoryranges.ResolveFileNames(ctx)
		if err != nil {
			t.Fatal(err)
		}
		mf, _ := files.Resolve(ctx, c.vadBase(viewVA))
		fp, err := c.f.Table.Field("_CONTROL_AREA", "FilePointer")
		if err != nil || mf.ControlArea == 0 {
			t.Fatalf("control area %+v: %v", mf, err)
		}
		c.writeKernel(mf.ControlArea+fp.Offset, make([]byte, 8))
		rows := c.run(c.context())
		if len(rows) != 1 || rows[0].Backing != BackingSection || rows[0].Path != "" {
			t.Fatalf("got %+v", rows)
		}
	})
	t.Run("control area that does not read", func(t *testing.T) {
		c := newCodeFixture(t, view)
		c.page(viewVA, true, prologue64)
		raw, err := c.f.Context().Memory.ReadAt(c.vadBase(viewVA)+testsupport.FixtureVadSubsectionOffset, 8)
		if err != nil {
			t.Fatal(err)
		}
		unmapped := make([]byte, 8)
		binary.LittleEndian.PutUint64(unmapped, 0xffff_f8ff_0000_0000)
		c.writeKernel(binary.LittleEndian.Uint64(raw), unmapped)
		rows := c.run(c.context())
		if len(rows) != 1 || rows[0].Backing != BackingUnknown || rows[0].Path != "" {
			t.Fatalf("got %+v", rows)
		}
	})
	t.Run("image view", func(t *testing.T) {
		c := newCodeFixture(t, view)
		c.page(viewVA, true, prologue64)
		c.markImage(viewVA)
		if rows := c.run(c.context()); len(rows) != 0 {
			t.Fatalf("an image view was listed: %+v", rows)
		}
	})
}

func TestARegionThatStartsWithAPEHeader(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 1, indexExecuteReadWrite))
	c.page(regionVA, true, testsupport.BuildMappedPE(regionVA)[:pageSize])
	rows := c.run(c.context())
	if len(rows) != 1 || rows[0].Header != HeaderPE32Plus || rows[0].HeaderMachine != testsupport.MappedPEMachine {
		t.Fatalf("got %+v", rows)
	}
}

func TestAnUnreadableStartGivesNoHeader(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 2, indexExecuteReadWrite))
	c.page(regionVA+pageSize, true, prologue64)
	rows := c.run(c.context())
	if len(rows) != 1 || rows[0].Header != HeaderUnread || rows[0].FirstContent != regionVA+pageSize {
		t.Fatalf("got %+v", rows)
	}
}

func TestAJumpIntoAnImageNamesTheImage(t *testing.T) {
	const imageVA = uint64(0x30000000)
	image := testsupport.FixtureVAD{Start: imageVA, End: imageVA + 4*pageSize - 1, Path: `\Windows\System32\target.dll`, Protection: indexExecuteRead}
	c := newCodeFixture(t, privateVAD(regionVA, 1, indexExecuteReadWrite), image)
	c.markImage(imageVA)
	target := imageVA + 0x1234
	disp := int32(int64(target) - int64(regionVA+5))
	code := []byte{0xE9, byte(disp), byte(disp >> 8), byte(disp >> 16), byte(disp >> 24)}
	c.page(regionVA, true, code)
	rows := c.run(c.context())
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	r := rows[0]
	if r.Transfer != TransferJumpRel32 || r.TransferTarget != target || r.TransferImage != `\Windows\System32\target.dll` {
		t.Errorf("transfer %q 0x%x %q", r.Transfer, r.TransferTarget, r.TransferImage)
	}
}

func TestPreviewLength(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 1, indexExecuteReadWrite))
	c.page(regionVA, true, prologue64)
	ctx := c.context()
	ctx.Options[OptionHexdumpSize] = 4
	rows := c.run(ctx)
	if len(rows) != 1 || string(rows[0].Preview) != string(prologue64[:4]) {
		t.Fatalf("got %+v", rows)
	}
	ctx.Options[OptionHexdumpSize] = uint64(limits.DefaultMaxArtifactBytes) + 1
	if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("a preview above MaxArtifactBytes gave %v", err)
	}
	ctx.Options[OptionHexdumpSize] = "lots"
	if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("a preview of the wrong type gave %v", err)
	}
}

func TestDumpWritesEachRegion(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 2, indexExecuteReadWrite))
	c.page(regionVA, true, prologue64)
	dir := t.TempDir()
	ctx := c.context()
	ctx.Options[OptionDumpRegions] = true
	ctx.Options[tools.OptionOutputDir] = dir
	rows := c.run(ctx)
	if len(rows) != 1 || rows[0].Artifact == "" {
		t.Fatalf("got %+v", rows)
	}
	data, err := os.ReadFile(filepath.Join(dir, rows[0].Artifact))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 2*int(pageSize) || string(data[:len(prologue64)]) != string(prologue64) {
		t.Errorf("artefact of %d bytes starting % x", len(data), data[:8])
	}

	ctx.Options[tools.OptionMaxDumpSize] = uint64(pageSize)
	dir2 := t.TempDir()
	ctx.Options[tools.OptionOutputDir] = dir2
	rows = c.run(ctx)
	if len(rows) != 1 || rows[0].Artifact != "" || !c.hasDiag("1 regions not written") {
		t.Errorf("a region above the dump limit: rows %+v, diagnostics %q", rows, c.diags)
	}

	delete(ctx.Options, tools.OptionOutputDir)
	if _, err := Run(ctx); !errors.Is(err, tools.ErrOptionType) {
		t.Errorf("dump without a directory gave %v", err)
	}
}

func TestTheKernelLayerIsNeverUsedForUserReads(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 1, indexExecuteReadWrite))
	c.page(regionVA, true, prologue64)
	ctx, kernelReads := testsupport.RefuseProcessSpace(c.context(), c.f.DirectoryTableBase(testPID))
	rows := c.run(ctx)
	if len(rows) != 0 {
		t.Errorf("rows %+v", rows)
	}
	if got := kernelReads.Addresses(); len(got) != 0 {
		t.Errorf("user addresses %#x read through the kernel layer", got)
	}
	if !c.hasDiag(fmt.Sprintf("any.memory.find_code: pid %d _EPROCESS at 0x", testPID), "address space not built") {
		t.Errorf("diagnostics %q", c.diags)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); !errors.Is(err, tools.ErrProcessSpaceUnavailable) {
		t.Errorf("strict mode gave %v", err)
	}
}

type flatReader struct{ memory.MemoryReader }

func TestASpaceWithoutPageEntriesIsSkipped(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 1, indexExecuteReadWrite))
	c.page(regionVA, true, prologue64)
	ctx := c.context()
	inner := ctx.ProcessMemory
	ctx.ProcessMemory = func(dtb uint64) (memory.MemoryReader, error) {
		r, err := inner(dtb)
		return flatReader{r}, err
	}
	if rows := c.run(ctx); len(rows) != 0 {
		t.Errorf("rows %+v", rows)
	}
	if !c.hasDiag("page-table entries not read", ErrNoPageEntries.Error()) {
		t.Errorf("diagnostics %q", c.diags)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); !errors.Is(err, ErrNoPageEntries) {
		t.Errorf("strict mode gave %v", err)
	}
}

func TestTheWalkStopsAtMaxRegionScanBytes(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 3, indexExecuteReadWrite))
	c.page(regionVA, true, prologue64)
	c.page(regionVA+pageSize, true, prologue64)
	c.page(regionVA+2*pageSize, true, prologue64)
	ctx := c.context()
	ctx.Limits = limits.Limits{MaxRegionScanBytes: int64(2 * pageSize)}
	rows := c.run(ctx)
	if len(rows) != 1 || rows[0].ContentPages != 2 {
		t.Fatalf("got %+v", rows)
	}
	if !c.hasDiag("VAD at 0x", "page walk stopped after 2 entries", ErrRegionScanCut.Error()) {
		t.Errorf("diagnostics %q", c.diags)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); !errors.Is(err, ErrRegionScanCut) {
		t.Errorf("strict mode gave %v", err)
	}
}

// 2^39 bytes is 2^27 pages; only the span skip of S35 4.3 step 1 keeps the
// walk inside the default budget.
func TestAHugeReservationIsWalkedThroughItsTables(t *testing.T) {
	const size = uint64(1) << 39
	start := uint64(1) << 40
	c := newCodeFixture(t, testsupport.FixtureVAD{Start: start, End: start + size - 1, Protection: indexReadWrite})
	c.page(start+size-pageSize, true, prologue64)
	ctx := c.context()
	inner := ctx.ProcessMemory
	var lookups int
	ctx.ProcessMemory = func(dtb uint64) (memory.MemoryReader, error) {
		r, err := inner(dtb)
		if err != nil {
			return nil, err
		}
		return countingSpace{MemoryReader: r, entries: r.(leafEntries), n: &lookups}, nil
	}
	rows := c.run(ctx)
	if len(rows) != 1 || rows[0].FirstContent != start+size-pageSize || rows[0].Pages != size/pageSize {
		t.Fatalf("got %+v", rows)
	}
	if c.hasDiag("page walk stopped") {
		t.Errorf("diagnostics %q", c.diags)
	}
	if lookups > 4096 {
		t.Errorf("%d leaf lookups for a region with one page table", lookups)
	}
}

type countingSpace struct {
	memory.MemoryReader
	entries leafEntries
	n       *int
}

func (c countingSpace) LeafEntry(va uint64) (uint64, error) {
	*c.n++
	return c.entries.LeafEntry(va)
}

func TestAMissingPageProtectionTableIsReportedOnce(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 1, indexReadWrite))
	c.f.Table.AddStruct(symbols.StructType{Name: "_MMPTE_SOFTWARE", Size: 8})
	c.entry(regionVA, softwareEntry(indexExecuteReadWrite))
	if rows := c.run(c.context()); len(rows) != 0 {
		t.Fatalf("got %+v", rows)
	}
	if !c.hasDiag("any.memory.find_code: MmProtectToValue: not read, protections of not-present pages unknown") {
		t.Errorf("diagnostics %q", c.diags)
	}
}

type otherProfile struct{}

func (otherProfile) Name() string       { return "other" }
func (otherProfile) OS() string         { return "plan9" }
func (otherProfile) PointerSize() uint8 { return 8 }

func TestOnlyWindowsIsRun(t *testing.T) {
	c := newCodeFixture(t, privateVAD(regionVA, 1, indexReadWrite))
	ctx := c.context()
	ctx.Profile = otherProfile{}
	if _, err := Run(ctx); !errors.Is(err, ErrUnsupportedOS) {
		t.Errorf("got %v", err)
	}
}

func TestRowsFollowProcessThenAddressOrder(t *testing.T) {
	f := testsupport.BuildProcessFixture([]testsupport.FixtureProcess{
		{PID: 8, Name: "a.exe", VADs: []testsupport.FixtureVAD{privateVAD(0x40000000, 1, indexExecuteReadWrite), privateVAD(regionVA, 1, indexExecuteReadWrite)}},
		{PID: 12, Name: "b.exe", VADs: []testsupport.FixtureVAD{privateVAD(regionVA, 1, indexExecuteReadWrite)}},
	})
	for _, pid := range []uint64{8, 12} {
		f.Memory.WriteAt(f.Space(pid).MapPage(regionVA), prologue64)
	}
	f.Memory.WriteAt(f.Space(8).MapPage(0x40000000), prologue64)
	rows, err := Run(f.Context())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, fmt.Sprintf("%d@%#x", r.PID, r.Start))
	}
	if want := "8@0x10000000 8@0x40000000 12@0x10000000"; strings.Join(got, " ") != want {
		t.Errorf("order %q, want %q", strings.Join(got, " "), want)
	}
}

func TestAWoW64ProcessIsDecodedAs32Bit(t *testing.T) {
	code := append([]byte{0xE8}, le32(0x80000000)...)
	for _, wow64 := range []bool{false, true} {
		f := testsupport.BuildProcessFixture([]testsupport.FixtureProcess{{PID: testPID, Name: "code.exe", Wow64PebNull: wow64,
			VADs: []testsupport.FixtureVAD{privateVAD(regionVA, 1, indexExecuteReadWrite)}}})
		f.Memory.WriteAt(f.Space(testPID).MapPage(regionVA), code)
		rows, err := Run(f.Context())
		if err != nil || len(rows) != 1 {
			t.Fatalf("wow64 %v: rows %+v: %v", wow64, rows, err)
		}
		base := regionVA
		want := base + 5 - 0x80000000
		if wow64 {
			want &= 0xFFFFFFFF
		}
		if rows[0].Transfer != TransferCallRel32 || rows[0].TransferTarget != want {
			t.Errorf("wow64 %v: %q 0x%x, want 0x%x", wow64, rows[0].Transfer, rows[0].TransferTarget, want)
		}
	}
}
