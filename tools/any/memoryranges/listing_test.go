package memoryranges

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

func twoProcesses(pooled bool) *testsupport.ProcessFixture {
	procs := []testsupport.FixtureProcess{
		{PID: 4, Name: "System", NoPeb: true, VADs: []testsupport.FixtureVAD{
			{Start: 0x30000, End: 0x30fff, Protection: testsupport.FixtureProtectionReadWrite},
			{Start: 0x10000, End: 0x1ffff, Protection: testsupport.FixtureProtectionReadWrite},
		}},
		{PID: 404, Name: "smss.exe", VADs: []testsupport.FixtureVAD{
			{Start: 0x7ff60000, End: 0x7ff63fff, Path: `\Windows\System32\smss.exe`,
				Protection: testsupport.FixtureProtectionExecuteWriteCopy},
			{Start: 0x40000, End: 0x4ffff, Protection: testsupport.FixtureProtectionExecuteReadWrite},
		}},
	}
	if pooled {
		return testsupport.BuildPooledProcessFixture(procs)
	}
	return testsupport.BuildProcessFixture(procs)
}

func withDiagnostics(ctx tools.Context) (tools.Context, *[]string) {
	diags := []string{}
	ctx.Options["diagnostics"] = &diags
	return ctx, &diags
}

func TestMemoryListGivesEachProcessItsRangesInOrder(t *testing.T) {
	ctx, diags := withDiagnostics(twoProcesses(false).Context())
	out, err := tools.Execute(ctx, MemoryListName)
	if err != nil {
		t.Fatal(err)
	}
	rows := out.([]Mapping)
	got := starts(rows, func(m Mapping) uint64 { return m.Start })
	if want := []uint64{0x10000, 0x30000, 0x40000, 0x7ff60000}; !slices.Equal(got, want) {
		t.Fatalf("starts %x, want %x", got, want)
	}
	if rows[0].PID != 4 || rows[2].PID != 404 || rows[3].Path != `\Windows\System32\smss.exe` ||
		rows[3].Protection != "PAGE_EXECUTE_WRITECOPY" || rows[3].Type != KindMapped ||
		rows[2].Protection != "PAGE_EXECUTE_READWRITE" || rows[2].Type != KindPrivate || rows[0].Tag != "VadS" {
		t.Errorf("rows %+v", rows)
	}
	if len(*diags) != 0 {
		t.Errorf("diagnostics %q", *diags)
	}
}

func TestMemoryListKeepsThePIDAsked(t *testing.T) {
	ctx := twoProcesses(false).Context()
	ctx.Options["pid"] = uint64(404)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 2 || rows[0].PID != 404 {
		t.Errorf("rows %+v, %v", rows, err)
	}
}

func TestTheAddressOptionKeepsTheRangesThatHoldIt(t *testing.T) {
	ctx, diags := withDiagnostics(twoProcesses(false).Context())
	ctx.Options[OptionMemoryListAddress] = uint64(0x7ff61234)
	out, err := RunMemoryList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rows := out.([]Mapping); len(rows) != 1 || rows[0].Start != 0x7ff60000 {
		t.Errorf("rows %+v", rows)
	}
	if len(*diags) != 1 || (*diags)[0] != "any.memory.list: any.memory.list.address 0x7ff61234 falls in 1 of 4 ranges" {
		t.Errorf("diagnostics %q", *diags)
	}
	ctx.Options[OptionMemoryListAddress] = "not a number"
	if _, err := RunMemoryList(ctx); err == nil {
		t.Error("a string address was accepted")
	}
	ctx.Options[OptionMemoryListAddress] = uint64(1)
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := RunMemoryList(ctx); !errors.Is(err, ErrAddressUnsupported) {
		t.Errorf("Linux: err %v", err)
	}
}

func TestAnAddressFilterKeepsInclusiveEnds(t *testing.T) {
	ctx := twoProcesses(false).Context()
	ctx.Options["k"] = uint64(0x1ffff)
	f, err := ReadAddressFilter(ctx, "k")
	if err != nil || !f.Active() || !f.Keeps(0x10000, 0x1ffff) || f.Keeps(0x20000, 0x2ffff) {
		t.Errorf("filter %+v, %v", f, err)
	}
	none, _ := ReadAddressFilter(ctx, "absent")
	if none.Active() || !none.Keeps(0, 0) {
		t.Errorf("an unset filter drops rows")
	}
}

func TestTheListingsAreRegistered(t *testing.T) {
	for _, name := range []string{Name, MemoryListName} {
		if _, err := tools.Get(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func addKernelRoot(f *testsupport.ProcessFixture) {
	st, _ := f.Table.Struct("_EPROCESS")
	st.Fields = append(st.Fields, symbols.Field{Name: "Pcb", Offset: 0})
	f.Table.AddStruct(st)
	f.Table.AddStruct(symbols.StructType{Name: "_KPROCESS", Size: 0x100, Fields: []symbols.Field{
		{Name: "DirectoryTableBase", Offset: testsupport.FixtureDTBOffset},
	}})
}

func TestThePageListingWalksEachProcessKernelRoot(t *testing.T) {
	f := twoProcesses(true)
	addKernelRoot(f)
	ctx := f.Context()
	ctx.Options["pid"] = uint64(404)
	out, err := tools.Execute(ctx, Name)
	if err != nil {
		t.Fatal(err)
	}
	runs := out.([]PageRun)
	if len(runs) == 0 {
		t.Fatal("no runs")
	}
	offset := uint64(0)
	for _, r := range runs {
		if r.PID != 404 || r.FileOffset != offset || r.Size == 0 {
			t.Errorf("run %+v, want file offset 0x%x", r, offset)
		}
		offset += r.Size
	}
}

func TestThePageListingIsWindowsOnlyAndNeedsItsMembers(t *testing.T) {
	f := twoProcesses(true)
	ctx := f.Context()
	if _, err := RunPages(ctx); err == nil || !strings.Contains(err.Error(), "_EPROCESS.Pcb") {
		t.Errorf("without Pcb: %v", err)
	}
	addKernelRoot(f)
	ctx = f.Context()
	delete(ctx.Options, tools.OptionPhysicalMemory)
	if _, err := RunPages(ctx); !errors.Is(err, ErrNoPhysicalLayer) {
		t.Errorf("without physical memory: %v", err)
	}
	ctx = f.Context()
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := RunPages(ctx); err == nil || !strings.Contains(err.Error(), MemoryListName) {
		t.Errorf("Linux: %v", err)
	}
}
